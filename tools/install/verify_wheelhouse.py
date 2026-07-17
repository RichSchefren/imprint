#!/usr/bin/env python3
"""Standalone pre-install verifier for the offline Imprint wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
import zipfile
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = str(runpy.run_path(str(ROOT / "src" / "imprint" / "_version.py"))["__version__"])

SUPPORTED = {
    "macos": {"x86_64", "arm64"},
    "linux": {"x86_64", "aarch64"},
    "windows": {"amd64"},
}
REQUIRED_DISTRIBUTIONS = {
    "imprint-local": PRODUCT_VERSION,
    "cryptography": "48.0.1",
    "rfc8785": "0.1.4",
    "cffi": "2.0.0",
    "pycparser": "3.0",
}
HEX = re.compile(r"^[0-9a-f]{64}$")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def runtime_target() -> tuple[str, str]:
    if platform.python_implementation() != "CPython" or sys.version_info[:2] not in {
        (3, 10), (3, 11), (3, 12), (3, 13), (3, 14),
    }:
        raise RuntimeError("requires standard CPython 3.10 through 3.14")
    system = platform.system().lower()
    lane = {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(system)
    machine = platform.machine().lower()
    machine = {"x86-64": "x86_64", "arm64": "arm64", "aarch64": "aarch64"}.get(machine, machine)
    if lane is None or machine not in SUPPORTED[lane]:
        raise RuntimeError(f"unsupported installed-artifact target: {system}/{machine}")
    return lane, machine


def verify(root: Path, lane: str, manifest_sha256: str) -> None:
    manifest_path = root / "release" / "wheelhouse" / "manifest.json"
    if not HEX.fullmatch(manifest_sha256) or digest(manifest_path) != manifest_sha256:
        raise RuntimeError("wheelhouse manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "1.0.0" or manifest.get("product_version") != PRODUCT_VERSION:
        raise RuntimeError("wheelhouse manifest identity mismatch")
    entries = manifest.get("platforms", {}).get(lane)
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("wheelhouse platform lane is absent")
    expected = {entry.get("path"): entry for entry in entries if isinstance(entry, dict)}
    if len(expected) != len(entries) or any(not isinstance(name, str) for name in expected):
        raise RuntimeError("wheelhouse manifest entries are invalid")
    lane_root = root / "release" / "wheelhouse" / lane
    actual = {
        path.relative_to(root).as_posix()
        for path in lane_root.iterdir()
        if path.is_file()
    }
    lock = root / "requirements" / f"runtime-{lane}.lock"
    actual.add(lock.relative_to(root).as_posix())
    if actual != set(expected):
        raise RuntimeError("wheelhouse contains a missing, extra, or unmanifested file")
    seen: dict[str, str] = {}
    for relative, entry in expected.items():
        path = root / relative
        if not path.is_file() or not HEX.fullmatch(str(entry.get("sha256", ""))):
            raise RuntimeError(f"invalid wheelhouse entry: {relative}")
        if digest(path) != entry["sha256"]:
            raise RuntimeError(f"wheelhouse file digest mismatch: {relative}")
        if path.suffix == ".whl":
            allowed_tags = {
                "macos": ("-any.whl", "_universal2.whl", "_x86_64.whl", "_arm64.whl"),
                "linux": ("-any.whl", "_x86_64.whl", "_aarch64.whl"),
                "windows": ("-any.whl", "-win_amd64.whl"),
            }[lane]
            if not path.name.endswith(allowed_tags):
                raise RuntimeError(f"wrong-platform wheel in {lane} lane: {relative}")
            with zipfile.ZipFile(path) as wheel:
                metadata_names = [name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")]
                if len(metadata_names) != 1:
                    raise RuntimeError(f"wheel metadata is ambiguous: {relative}")
                metadata = wheel.read(metadata_names[0]).decode("utf-8")
            name = re.search(r"(?m)^Name: (.+)$", metadata)
            version = re.search(r"(?m)^Version: (.+)$", metadata)
            if name is None or version is None:
                raise RuntimeError(f"wheel metadata is incomplete: {relative}")
            normalized_name = re.sub(r"[-_.]+", "-", name.group(1).strip().lower())
            seen[normalized_name] = version.group(1).strip()
    for name, version in REQUIRED_DISTRIBUTIONS.items():
        if seen.get(name) != version:
            raise RuntimeError(f"locked distribution missing or wrong version: {name}=={version}")
    if sys.version_info[:2] == (3, 10) and seen.get("typing-extensions") != "4.16.0":
        raise RuntimeError("Python 3.10 wheelhouse requires typing-extensions==4.16.0")
    text = lock.read_text(encoding="utf-8")
    if f"imprint-local=={PRODUCT_VERSION}" not in text or "--hash=sha256:" not in text:
        raise RuntimeError("runtime lock is not exact and hash-pinned")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--lane", choices=sorted(SUPPORTED), required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    runtime_lane, _ = runtime_target()
    if args.lane != runtime_lane:
        raise RuntimeError("selected wheelhouse lane does not match this platform")
    verify(args.root.resolve(strict=True), args.lane, args.manifest_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
