#!/usr/bin/env python3
"""Extract a verified release archive without trusting archive metadata."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILES = 1000
MAX_TOTAL = 50 * 1024 * 1024
MAX_MEMBER = 20 * 1024 * 1024


def safe_relative(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not path.parts or path.is_absolute() or ".." in path.parts or path.parts[0].endswith(":"):
        raise RuntimeError(f"unsafe archive path: {name!r}")
    return path


def target_path(root: Path, name: str) -> Path:
    relative = safe_relative(name)
    target = root.joinpath(*relative.parts)
    if root.resolve() not in (target.parent.resolve(), *target.parent.resolve().parents):
        raise RuntimeError(f"archive path escapes destination: {name!r}")
    return target


def _prepare(destination: Path) -> Path:
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("extraction destination must not exist")
    destination.mkdir(parents=True, mode=0o700)
    return destination.resolve()


def extract_zip(archive_path: Path, destination: Path) -> None:
    root = _prepare(destination)
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if len(members) > MAX_FILES or len(names) != len(set(names)):
            raise RuntimeError("ZIP member count or uniqueness check failed")
        if any(item.file_size > MAX_MEMBER for item in members) or sum(item.file_size for item in members) > MAX_TOTAL:
            raise RuntimeError("ZIP expansion limit exceeded")
        for item in members:
            target = target_path(root, item.filename)
            unix_mode = item.external_attr >> 16
            kind = stat.S_IFMT(unix_mode)
            is_directory = item.is_dir() or kind == stat.S_IFDIR
            if kind not in {stat.S_IFREG, stat.S_IFDIR}:
                raise RuntimeError(f"ZIP contains a link or special file: {item.filename}")
            if is_directory:
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if any(parent.is_symlink() for parent in (target.parent, *target.parent.parents) if parent != root.parent):
                raise RuntimeError(f"ZIP destination crosses a symlink: {item.filename}")
            with archive.open(item, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if unix_mode & 0o111 else 0o644)


def extract_tar(archive_path: Path, destination: Path) -> None:
    root = _prepare(destination)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        if len(members) > MAX_FILES or len(names) != len(set(names)):
            raise RuntimeError("tar member count or uniqueness check failed")
        if any(item.size > MAX_MEMBER for item in members) or sum(item.size for item in members) > MAX_TOTAL:
            raise RuntimeError("tar expansion limit exceeded")
        for item in members:
            if not (item.isdir() or item.isreg()):
                raise RuntimeError(f"tar contains a link or special file: {item.name}")
            target = target_path(root, item.name)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(item)
            if source is None:
                raise RuntimeError(f"tar member cannot be read: {item.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if item.mode & 0o111 else 0o644)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("destination")
    args = parser.parse_args()
    archive = Path(args.archive).resolve(strict=True)
    destination = Path(args.destination).resolve(strict=False)
    if archive.suffix == ".zip":
        extract_zip(archive, destination)
    elif archive.name.endswith(".tar.gz"):
        extract_tar(archive, destination)
    else:
        raise SystemExit("supported archives are .zip and .tar.gz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
