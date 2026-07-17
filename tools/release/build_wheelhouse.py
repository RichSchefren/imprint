#!/usr/bin/env python3
"""Build exact multi-platform offline wheelhouses and hash-pinned locks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_VERSION = str(runpy.run_path(str(ROOT / "src" / "imprint" / "_version.py"))["__version__"])
VERSIONS = {
    "imprint-local": PRODUCT_VERSION,
    "cryptography": "48.0.1",
    "rfc8785": "0.1.4",
    # 2.1.0 does not publish Intel macOS wheels. 2.0.0 is the newest release
    # satisfying cryptography 48.0.1's >=2.0.0 contract across every declared
    # Imprint platform and Python 3.10-3.14 lane.
    "cffi": "2.0.0",
    "pycparser": "3.0",
    "typing-extensions": "4.16.0",
}
TARGETS = {
    "macos": ("macosx_10_13_x86_64", "macosx_11_0_arm64"),
    "linux": ("manylinux2014_x86_64", "manylinux2014_aarch64"),
    "windows": ("win_amd64",),
}
PYTHONS = ("310", "311", "312", "313", "314")


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def metadata(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as wheel:
        names = [name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise RuntimeError(f"ambiguous wheel metadata: {path.name}")
        fields = {}
        for line in wheel.read(names[0]).decode("utf-8").splitlines():
            if ": " in line:
                key, value = line.split(": ", 1)
                fields.setdefault(key, value)
    # Distribution names are case-insensitive and '-', '_' and '.' are
    # equivalent under the Python packaging name-normalization contract.
    return re.sub(r"[-_.]+", "-", fields["Name"].lower()), fields["Version"]


def download(lane: str, output: Path) -> None:
    packages = [f"{name}=={version}" for name, version in VERSIONS.items() if name != "imprint-local"]
    for platform_tag in TARGETS[lane]:
        for python_version in PYTHONS:
            command = [
                sys.executable, "-m", "pip", "download", "--disable-pip-version-check",
                "--only-binary=:all:", "--no-deps", "--implementation", "cp",
                "--python-version", python_version, "--platform", platform_tag,
                "--dest", str(output), *packages,
            ]
            subprocess.run(command, check=True)


def lock_for(lane: str, wheelhouse: Path) -> str:
    hashes: dict[str, list[str]] = {name: [] for name in VERSIONS}
    for wheel in sorted(wheelhouse.glob("*.whl")):
        name, version = metadata(wheel)
        if name not in VERSIONS or version != VERSIONS[name]:
            raise RuntimeError(f"unexpected wheel distribution: {name}=={version}")
        hashes[name].append(sha256(wheel))
    missing = [name for name, values in hashes.items() if not values]
    if missing:
        raise RuntimeError(f"wheelhouse is missing distributions: {missing}")
    rows = []
    for name in VERSIONS:
        condition = '; python_version == "3.10"' if name == "typing-extensions" else ""
        digest_rows = " \\\n    ".join(f"--hash=sha256:{value}" for value in sorted(set(hashes[name])))
        rows.append(f"{name}=={VERSIONS[name]}{condition} \\\n    {digest_rows}")
    return "\n".join(rows) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--imprint-wheel", type=Path, required=True)
    args = parser.parse_args()
    imprint = args.imprint_wheel.resolve(strict=True)
    if metadata(imprint) != ("imprint-local", PRODUCT_VERSION):
        raise RuntimeError(f"expected exact imprint-local {PRODUCT_VERSION} wheel")
    root = ROOT / "release" / "wheelhouse"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    manifest = {"schema_version": "1.0.0", "product_version": PRODUCT_VERSION, "platforms": {}}
    for lane in TARGETS:
        lane_root = root / lane
        lane_root.mkdir()
        shutil.copy2(imprint, lane_root / f"imprint_local-{PRODUCT_VERSION}-py3-none-any.whl")
        with tempfile.TemporaryDirectory(prefix=f"imprint-{lane}-") as temporary:
            download(lane, Path(temporary))
            for wheel in Path(temporary).glob("*.whl"):
                destination = lane_root / wheel.name
                if not destination.exists():
                    shutil.copy2(wheel, destination)
        lock = ROOT / "requirements" / f"runtime-{lane}.lock"
        lock.write_text(lock_for(lane, lane_root), encoding="utf-8")
        files = [*sorted(lane_root.glob("*.whl")), lock]
        manifest["platforms"][lane] = [
            {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)} for path in files
        ]
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "manifest.sha256").write_text(sha256(manifest_path) + "\n", encoding="ascii")
    print(sha256(manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
