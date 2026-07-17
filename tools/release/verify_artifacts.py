#!/usr/bin/env python3
"""Fail-closed checksum and archive-boundary validation."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
import runpy

ROOT = Path(__file__).resolve().parents[2]
VERSION = str(runpy.run_path(str(ROOT / "src" / "imprint" / "_version.py"))["__version__"])
MAX_FILES = 1000
MAX_TOTAL = 50 * 1024 * 1024
MAX_MEMBER = 20 * 1024 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def safe_name(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return bool(path.parts) and not path.is_absolute() and ".." not in path.parts


def inspect_zip(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if len(names) > MAX_FILES or len(set(names)) != len(names):
            raise RuntimeError("ZIP member count or uniqueness check failed")
        if any(not safe_name(name) for name in names):
            raise RuntimeError("ZIP contains an unsafe path")
        for item in members:
            kind = stat.S_IFMT(item.external_attr >> 16)
            if kind not in {stat.S_IFREG, stat.S_IFDIR}:
                raise RuntimeError("ZIP contains a link or special file")
        if any(item.file_size > MAX_MEMBER for item in members) or sum(item.file_size for item in members) > MAX_TOTAL:
            raise RuntimeError("ZIP expansion limit exceeded")


def inspect_tar(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        if len(names) > MAX_FILES or len(set(names)) != len(names):
            raise RuntimeError("tar member count or uniqueness check failed")
        if any(not safe_name(name) for name in names):
            raise RuntimeError("tar contains an unsafe path")
        if any(item.issym() or item.islnk() or item.isdev() for item in members):
            raise RuntimeError("tar contains a link or device")
        if any(item.size > MAX_MEMBER for item in members) or sum(item.size for item in members) > MAX_TOTAL:
            raise RuntimeError("tar expansion limit exceeded")


def archive_files(path: Path) -> dict[str, bytes]:
    """Return the exact regular-file payload, after the archive safety gate."""
    files: dict[str, bytes] = {}
    if path.suffix == ".zip":
        inspect_zip(path)
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                if not item.is_dir():
                    files[item.filename] = archive.read(item)
    else:
        inspect_tar(path)
        with tarfile.open(path, "r:gz") as archive:
            for item in archive.getmembers():
                if item.isreg():
                    source = archive.extractfile(item)
                    if source is None:
                        raise RuntimeError(f"tar member cannot be read: {item.name}")
                    files[item.name] = source.read()
    return files


def git_blob(root: Path, revision: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{revision}:{relative}"], cwd=root,
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"source input is not an exact Git blob: {relative}")
    return result.stdout


def git_source_paths(root: Path, revision: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", revision, "--", "src/imprint"],
        cwd=root, text=True, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("unable to enumerate Git Python sources")
    paths = [line for line in result.stdout.splitlines() if line.endswith(".py")]
    if not paths:
        raise RuntimeError("Git revision contains no Imprint Python sources")
    return sorted(paths)


def git_allowlist(root: Path, revision: str) -> list[str]:
    try:
        text = git_blob(root, revision, "release/allowlist.txt").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("source release allowlist is not UTF-8") from exc
    values = [line.strip() for line in text.splitlines() if line.strip()]
    if values != sorted(values) or len(values) != len(set(values)):
        raise RuntimeError("source release allowlist is invalid")
    return values


def source_tree_digest(root: Path, revision: str = "HEAD") -> str:
    """Recompute the platform-stable digest from exact Git blobs."""
    root = root.resolve(strict=True)
    values = git_allowlist(root, revision)
    candidates = sorted(set(values) | {
        ".gitignore", "pyproject.toml", "tools/release/package.py",
        *git_source_paths(root, revision),
    })
    digest_value = hashlib.sha256()
    for relative in candidates:
        digest_value.update(relative.encode() + b"\0" + git_blob(root, revision, relative) + b"\0")
    return digest_value.hexdigest()


def validate_source_bindings(files: dict[str, bytes], source_root: Path, revision: str) -> None:
    """Bind every shipped source and both Python distributions to Git blobs."""
    root = source_root.resolve(strict=True)
    prefix = f"imprint-{VERSION}/"
    allowlist = git_allowlist(root, revision)
    expected_outer = {
        *(prefix + item for item in allowlist),
        prefix + f"dist/imprint_local-{VERSION}-py3-none-any.whl",
        prefix + f"dist/imprint_local-{VERSION}.tar.gz",
        prefix + "release/BUILD-PROVENANCE.json",
        prefix + "release/SBOM.spdx.json",
    }
    if set(files) != expected_outer:
        raise RuntimeError("release archive manifest is not the exact Git allowlist")
    for relative in allowlist:
        if files[prefix + relative] != git_blob(root, revision, relative):
            raise RuntimeError(f"release archive file differs from Git blob: {relative}")

    sources = git_source_paths(root, revision)
    expected_python = {
        relative.removeprefix("src/"): git_blob(root, revision, relative)
        for relative in sources
    }
    wheel_bytes = files[prefix + f"dist/imprint_local-{VERSION}-py3-none-any.whl"]
    with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as wheel:
        members = wheel.infolist()
        names = [item.filename for item in members]
        if (
            len(names) > MAX_FILES or len(names) != len(set(names))
            or any(not safe_name(name) for name in names)
            or any(stat.S_IFMT(item.external_attr >> 16) != stat.S_IFREG for item in members)
            or any(item.file_size > MAX_MEMBER for item in members)
            or sum(item.file_size for item in members) > MAX_TOTAL
        ):
            raise RuntimeError("wheel member safety contract failed")
        wheel_sources = {name: wheel.read(name) for name in names if name.startswith("imprint/")}
        dist_info = f"imprint_local-{VERSION}.dist-info/"
        allowed_metadata = {
            dist_info + "licenses/LICENSE", dist_info + "METADATA", dist_info + "WHEEL",
            dist_info + "entry_points.txt", dist_info + "top_level.txt", dist_info + "RECORD",
        }
        if set(names) != set(expected_python) | allowed_metadata or wheel_sources != expected_python:
            raise RuntimeError("wheel Python payload is not the exact Git source")
        metadata = wheel.read(dist_info + "METADATA").decode("utf-8")
        if wheel.read(dist_info + "licenses/LICENSE") != git_blob(root, revision, "LICENSE"):
            raise RuntimeError("wheel license differs from Git blob")
        if wheel.read(dist_info + "entry_points.txt") != b"[console_scripts]\nimprint = imprint.cli:main\n":
            raise RuntimeError("wheel entry point contract is invalid")
        if wheel.read(dist_info + "top_level.txt") != b"imprint\n":
            raise RuntimeError("wheel top-level contract is invalid")
        wheel_contract = wheel.read(dist_info + "WHEEL").decode("ascii")
        if "Root-Is-Purelib: true\n" not in wheel_contract or "Tag: py3-none-any\n" not in wheel_contract:
            raise RuntimeError("wheel compatibility contract is invalid")

    sdist_bytes = files[prefix + f"dist/imprint_local-{VERSION}.tar.gz"]
    sdist_prefix = f"imprint_local-{VERSION}/"
    with tarfile.open(fileobj=io.BytesIO(sdist_bytes), mode="r:gz") as sdist:
        all_members = sdist.getmembers()
        if (
            len(all_members) > MAX_FILES
            or any(not safe_name(member.name) for member in all_members)
            or any(not (member.isdir() or member.isreg()) for member in all_members)
            or any(member.size > MAX_MEMBER for member in all_members)
            or sum(member.size for member in all_members) > MAX_TOTAL
        ):
            raise RuntimeError("sdist member safety contract failed")
        members = [member for member in all_members if member.isfile()]
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise RuntimeError("sdist contains duplicate members")
        payload = {}
        for member in members:
            source = sdist.extractfile(member)
            if source is None:
                raise RuntimeError(f"sdist member cannot be read: {member.name}")
            payload[member.name] = source.read()
    expected_sdist_sources = {sdist_prefix + "src/" + name: content for name, content in expected_python.items()}
    generated = {
        sdist_prefix + "PKG-INFO", sdist_prefix + "setup.cfg",
        *(sdist_prefix + "src/imprint_local.egg-info/" + name for name in (
            "PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt",
            "requires.txt", "top_level.txt",
        )),
    }
    tracked_sdist = {
        sdist_prefix + name: git_blob(root, revision, name)
        for name in ("LICENSE", "README.md", "pyproject.toml")
    }
    if set(payload) != set(expected_sdist_sources) | set(tracked_sdist) | generated:
        raise RuntimeError("sdist manifest contains unbound or missing files")
    if any(payload[name] != content for name, content in {**expected_sdist_sources, **tracked_sdist}.items()):
        raise RuntimeError("sdist payload is not the exact Git source")
    if payload[sdist_prefix + "setup.cfg"] != b"[egg_info]\ntag_build = \ntag_date = 0\n\n":
        raise RuntimeError("sdist build configuration is invalid")
    sdist_metadata = payload[sdist_prefix + "PKG-INFO"].decode("utf-8")
    if f"Version: {VERSION}\n" not in metadata or "Requires-Python: <3.15,>=3.10\n" not in metadata:
        raise RuntimeError("wheel metadata does not match the supported product contract")
    if f"Version: {VERSION}\n" not in sdist_metadata or "Requires-Python: <3.15,>=3.10\n" not in sdist_metadata:
        raise RuntimeError("sdist metadata does not match the supported product contract")


def validate_provenance(
    files: dict[str, bytes], expected_revision: str | None,
    expected_source_digest: str | None = None,
) -> None:
    prefix = f"imprint-{VERSION}/"
    if not files or any(not name.startswith(prefix) for name in files):
        raise RuntimeError("archive top-level product/version boundary mismatch")
    provenance_name = prefix + "release/BUILD-PROVENANCE.json"
    try:
        provenance = json.loads(files[provenance_name].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("embedded build provenance is missing or invalid") from exc
    revision = provenance.get("source_revision")
    source_digest = provenance.get("source_tree_sha256")
    if (
        provenance.get("format") != 1
        or provenance.get("product") != "imprint-local"
        or provenance.get("version") != VERSION
        or not isinstance(revision, str)
        or re.fullmatch(r"[0-9a-f]{40}", revision) is None
        or not isinstance(source_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_digest) is None
    ):
        raise RuntimeError("embedded build provenance identity is invalid")
    if expected_revision is not None and revision != expected_revision:
        raise RuntimeError("embedded source revision does not match expected revision")
    if expected_source_digest is not None and source_digest != expected_source_digest:
        raise RuntimeError("embedded source digest does not match expected source tree")
    distributions = provenance.get("python_distributions")
    if not isinstance(distributions, list):
        raise RuntimeError("embedded Python distribution provenance is invalid")
    expected_dist: dict[str, tuple[str, int]] = {}
    for item in distributions:
        if not isinstance(item, dict) or set(item) != {"fileName", "sha256", "size"}:
            raise RuntimeError("embedded Python distribution entry is invalid")
        name, wanted, size = item["fileName"], item["sha256"], item["size"]
        if (
            not isinstance(name, str)
            or PurePosixPath(name).name != name
            or not isinstance(wanted, str)
            or re.fullmatch(r"[0-9a-f]{64}", wanted) is None
            or not isinstance(size, int)
            or size < 0
            or name in expected_dist
        ):
            raise RuntimeError("embedded Python distribution entry is invalid")
        expected_dist[name] = (wanted, size)
    actual_dist = {
        name.removeprefix(prefix + "dist/"): content
        for name, content in files.items()
        if name.startswith(prefix + "dist/")
    }
    if set(expected_dist) != {
        f"imprint_local-{VERSION}-py3-none-any.whl",
        f"imprint_local-{VERSION}.tar.gz",
    }:
        raise RuntimeError("embedded Python distribution allowlist mismatch")
    if set(actual_dist) != set(expected_dist):
        raise RuntimeError("embedded Python distribution manifest mismatch")
    for name, content in actual_dist.items():
        wanted, size = expected_dist[name]
        if len(content) != size or hashlib.sha256(content).hexdigest() != wanted:
            raise RuntimeError(f"embedded Python distribution digest mismatch: {name}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="release-artifacts")
    parser.add_argument("--expected-revision")
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args(argv[1:])
    root = Path(args.root)
    expected = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2 or re.fullmatch(r"[0-9a-f]{64}", parts[0]) is None or parts[1] in expected:
            raise RuntimeError("checksum manifest is malformed or contains duplicates")
        expected[parts[1]] = parts[0]
    archive_payloads: dict[str, dict[str, bytes]] = {}
    for name, wanted in expected.items():
        path = root / name
        if not path.is_file() or digest(path) != wanted:
            raise RuntimeError(f"checksum failure: {name}")
        archive_payloads[name] = archive_files(path)
    if set(expected) != {f"imprint-{VERSION}.zip", f"imprint-{VERSION}.tar.gz"}:
        raise RuntimeError("checksum allowlist mismatch")
    zip_files = archive_payloads[f"imprint-{VERSION}.zip"]
    tar_files = archive_payloads[f"imprint-{VERSION}.tar.gz"]
    if zip_files != tar_files:
        raise RuntimeError("ZIP and tar release payloads are not byte-equivalent")
    revision = args.expected_revision
    if args.source_root and revision is None:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=args.source_root,
            text=True, capture_output=True, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("unable to resolve source revision")
        revision = result.stdout.strip()
    expected_source_digest = source_tree_digest(args.source_root, revision) if args.source_root else None
    validate_provenance(zip_files, revision, expected_source_digest)
    if args.source_root:
        assert revision is not None
        validate_source_bindings(zip_files, args.source_root, revision)
    print("artifact verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
