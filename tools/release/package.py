#!/usr/bin/env python3
"""Build deterministic, exactly allowlisted Imprint release archives."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
import runpy

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from confidentiality import scan_paths

ROOT = Path(__file__).resolve().parents[2]
VERSION = str(runpy.run_path(str(ROOT / "src" / "imprint" / "_version.py"))["__version__"])
OUTPUT = ROOT / "release-artifacts"
DIST = ROOT / "dist"
STAGE = OUTPUT / f"imprint-{VERSION}"
ALLOWLIST = ROOT / "release" / "allowlist.txt"
FORBIDDEN_SUFFIXES = (".db", ".db-wal", ".db-shm", ".log", ".bak", ".tmp", ".pyc")
FORBIDDEN_NAMES = {"__pycache__", ".DS_Store", ".pytest_cache", ".venv", ".git"}
PRIVATE_MARKERS = (b"/Users/", b"\\Users\\", b"xoxb-", b"Bearer ")
SOURCE_DATE_EPOCH = 1767225600
EPOCH = (2026, 1, 1, 0, 0, 0)
GENERATED = {"release/SBOM.spdx.json", "release/BUILD-PROVENANCE.json"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def guarded_reset(path: Path, expected_name: str) -> None:
    resolved_parent = path.parent.resolve(strict=True)
    if resolved_parent != ROOT.resolve() or path.name != expected_name or path.is_symlink():
        raise RuntimeError(f"refusing unsafe release cleanup: {path}")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(mode=0o700)


def guarded_remove(path: Path, expected_relative: str) -> None:
    if path.is_symlink() or path.resolve(strict=False) != (ROOT / expected_relative).resolve(strict=False):
        raise RuntimeError(f"refusing unsafe build cleanup: {path}")
    if path.exists():
        shutil.rmtree(path)


def load_allowlist() -> list[str]:
    values = [line.strip() for line in ALLOWLIST.read_text(encoding="utf-8").splitlines() if line.strip()]
    if values != sorted(values) or len(values) != len(set(values)):
        raise RuntimeError("release allowlist must be sorted and unique")
    for value in values:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or not (ROOT / path).is_file():
            raise RuntimeError(f"invalid or missing allowlist entry: {value}")
    return values


def release_inputs(allowlist: list[str]) -> list[Path]:
    candidates = {
        ROOT / ".gitignore",
        ROOT / "pyproject.toml",
        ROOT / "tools" / "release" / "package.py",
        *(ROOT / item for item in allowlist),
        *sorted((ROOT / "src").rglob("*.py")),
    }
    missing = [path for path in candidates if not path.is_file()]
    if missing:
        raise RuntimeError(f"missing release build input: {missing[0]}")
    return sorted(candidates, key=lambda path: path.relative_to(ROOT).as_posix())


def git_blob(revision: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{revision}:{relative}"], cwd=ROOT,
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"release input is not an exact Git blob: {relative}")
    return result.stdout


def source_digest(allowlist: list[str], revision: str | None = None) -> str:
    revision = revision or "HEAD"
    digest = hashlib.sha256()
    for path in release_inputs(allowlist):
        relative_text = path.relative_to(ROOT).as_posix()
        digest.update(relative_text.encode() + b"\0" + git_blob(revision, relative_text) + b"\0")
    return digest.hexdigest()


def source_revision() -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if status.returncode != 0:
        raise RuntimeError("unable to verify clean release worktree")
    if status.stdout.strip():
        raise RuntimeError("refusing a release build from a dirty worktree")
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("unable to resolve the release source revision")
    return result.stdout.strip()


def export_git_source(revision: str, destination: Path) -> None:
    result = subprocess.run(
        ["git", "archive", "--format=tar", revision], cwd=ROOT,
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("unable to export the exact Git source tree")
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or not (member.isdir() or member.isreg()):
                raise RuntimeError(f"unsafe Git archive member: {member.name}")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(f"unreadable Git archive member: {member.name}")
                target.write_bytes(source.read())


def build_python_dist(revision: str) -> None:
    guarded_remove(ROOT / "build", "build")
    guarded_remove(ROOT / "src" / "imprint_local.egg-info", "src/imprint_local.egg-info")
    if any(DIST.glob("*")) if DIST.exists() else False:
        guarded_reset(DIST, "dist")
    else:
        DIST.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update({"SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH), "PYTHONHASHSEED": "0"})
    with tempfile.TemporaryDirectory(prefix="imprint-git-build-") as temporary:
        source_root = Path(temporary) / "source"
        source_root.mkdir()
        export_git_source(revision, source_root)
        subprocess.run(
            [sys.executable, "-m", "build", "--outdir", str(DIST), str(source_root)],
            check=True, env=env,
        )
    names = sorted(path.name for path in DIST.iterdir() if path.is_file())
    if len(names) != 2 or not any(name.endswith(".whl") for name in names) or not any(name.endswith(".tar.gz") for name in names):
        raise RuntimeError(f"unexpected Python distribution set: {names}")
    normalize_sdist(next(DIST.glob("*.tar.gz")))


def normalize_sdist(path: Path) -> None:
    """Setuptools preserves source mtimes in sdists; rewrite them deterministically."""
    records: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            if not (member.isdir() or member.isreg()):
                raise RuntimeError(f"unsupported sdist member type: {member.name}")
            extracted = source.extractfile(member) if member.isreg() else None
            records.append((member, extracted.read() if extracted is not None else None))
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=SOURCE_DATE_EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as output:
                for original, content in records:
                    info = tarfile.TarInfo(original.name)
                    info.type = tarfile.DIRTYPE if original.isdir() else tarfile.REGTYPE
                    info.size = 0 if content is None else len(content)
                    info.mtime = SOURCE_DATE_EPOCH
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755 if original.isdir() or original.mode & 0o111 else 0o644
                    output.addfile(info, io.BytesIO(content) if content is not None else None)
    os.replace(temporary, path)


def write_supply_chain_metadata(source_tree_sha256: str, revision: str) -> None:
    release_dir = STAGE / "release"
    release_dir.mkdir(parents=True, exist_ok=True)
    distributions = [
        {"fileName": path.name, "sha256": sha256(path), "size": path.stat().st_size}
        for path in sorted((STAGE / "dist").iterdir())
    ]
    sbom = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": f"imprint-local-{VERSION}",
        "documentNamespace": f"https://github.com/RichSchefren/imprint-local/spdx/{VERSION}",
        "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": [f"Tool: imprint-release-builder-{VERSION}"]},
        "packages": [{
            "SPDXID": "SPDXRef-Package-imprint-local",
            "name": "imprint-local",
            "versionInfo": VERSION,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "externalRefs": [],
        }],
        "annotations": [{"annotationType": "OTHER", "annotator": f"Tool: imprint-release-builder-{VERSION}", "annotationDate": "2026-01-01T00:00:00Z", "comment": json.dumps(distributions, sort_keys=True)}],
    }
    provenance = {
        "format": 1,
        "product": "imprint-local",
        "version": VERSION,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "source_tree_sha256": source_tree_sha256,
        "source_revision": revision,
        "builder": "tools/release/package.py",
        "build_backend": "setuptools==80.9.0",
        "frontend": "build==1.3.0",
        "python_distributions": distributions,
    }
    (release_dir / "SBOM.spdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (release_dir / "BUILD-PROVENANCE.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_stage(allowlist: list[str]) -> None:
    actual = {path.relative_to(STAGE).as_posix() for path in STAGE.rglob("*") if path.is_file()}
    dist_files = {f"dist/{path.name}" for path in (STAGE / "dist").iterdir() if path.is_file()}
    expected = set(allowlist) | dist_files | GENERATED
    if actual != expected:
        raise RuntimeError(f"staged manifest mismatch; missing={sorted(expected-actual)} unexpected={sorted(actual-expected)}")
    for path in sorted(STAGE.rglob("*")):
        relative = path.relative_to(STAGE)
        if any(part in FORBIDDEN_NAMES for part in relative.parts) or path.is_symlink():
            raise RuntimeError(f"forbidden package path: {relative}")
        if path.is_file():
            if path.name.endswith(FORBIDDEN_SUFFIXES):
                raise RuntimeError(f"private runtime artifact: {relative}")
            content = path.read_bytes()
            for marker in PRIVATE_MARKERS:
                if marker in content:
                    raise RuntimeError(f"private marker {marker!r} in {relative}")
    confidentiality_failures = scan_paths(
        (path for path in STAGE.rglob("*") if path.is_file()), root=STAGE,
    )
    if confidentiality_failures:
        raise RuntimeError(
            "release confidentiality scan failed:\n" + "\n".join(confidentiality_failures)
        )


def build_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source in sorted(STAGE.rglob("*")):
            if not source.is_file():
                continue
            name = (Path(STAGE.name) / source.relative_to(STAGE)).as_posix()
            info = zipfile.ZipInfo(name, EPOCH)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o100755 if source.suffix in {".sh", ".py"} else 0o100644
            info.external_attr = mode << 16
            archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def build_tar(path: Path) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=SOURCE_DATE_EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for source in sorted(STAGE.rglob("*")):
                    name = Path(STAGE.name) / source.relative_to(STAGE)
                    info = archive.gettarinfo(str(source), str(name))
                    info.mtime = SOURCE_DATE_EPOCH
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    if source.is_file():
                        info.mode = 0o755 if source.suffix in {".sh", ".py"} else 0o644
                        with source.open("rb") as handle:
                            archive.addfile(info, handle)
                    else:
                        info.mode = 0o755
                        archive.addfile(info)


def main() -> int:
    allowlist = load_allowlist()
    revision = source_revision()
    initial_source_digest = source_digest(allowlist, revision)
    guarded_reset(OUTPUT, "release-artifacts")
    build_python_dist(revision)
    if source_digest(allowlist, revision) != initial_source_digest or source_revision() != revision:
        raise RuntimeError("source tree changed during release build; retry from a stable revision")
    STAGE.mkdir()
    for item in allowlist:
        destination = STAGE / item
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(git_blob(revision, item))
    shutil.copytree(DIST, STAGE / "dist")
    write_supply_chain_metadata(initial_source_digest, revision)
    validate_stage(allowlist)
    archive_zip = OUTPUT / f"imprint-{VERSION}.zip"
    archive_tar = OUTPUT / f"imprint-{VERSION}.tar.gz"
    build_zip(archive_zip)
    build_tar(archive_tar)
    sums = OUTPUT / "SHA256SUMS"
    sums.write_text("".join(f"{sha256(path)}  {path.name}\n" for path in (archive_tar, archive_zip)), encoding="utf-8")
    shutil.rmtree(STAGE)
    print(f"built {archive_zip.name} {archive_tar.name} {sums.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
