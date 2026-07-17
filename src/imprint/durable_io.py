"""Crash-safe, no-follow publication for Imprint-owned files."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .errors import SafetyError
from .permissions import PRIVATE_FILE_MODE, assert_safe_path_chain, secure_file


def _identity(path: Path) -> tuple[int, int]:
    value = path.stat(follow_symlinks=False)
    return value.st_dev, value.st_ino


def _fsync_directory(path: Path) -> None:
    """Persist directory entries where the platform exposes directory fsync."""
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_temporary(parent: Path, prefix: str, content: bytes) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=parent)
    temporary = Path(name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(temporary)
        return temporary
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def publish_new_private(path: Path, content: bytes) -> Path:
    """Durably create a private file without following or replacing anything."""
    target = Path(path)
    parent = target.parent
    assert_safe_path_chain(parent, require_leaf=True)
    parent_before = _identity(parent)
    if target.exists() or target.is_symlink():
        raise SafetyError(f"refusing to replace existing publication target: {target}")
    temporary = _write_temporary(parent, f".{target.name}.", content)
    try:
        if _identity(parent) != parent_before:
            raise SafetyError("publication parent changed before commit")
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise SafetyError(f"refusing to replace existing publication target: {target}") from exc
        if _identity(parent) != parent_before:
            try:
                target.unlink()
            finally:
                _fsync_directory(parent)
            raise SafetyError("publication parent changed during commit")
        final = target.stat(follow_symlinks=False)
        staged = temporary.stat(follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (staged.st_dev, staged.st_ino):
            raise SafetyError("published file identity does not match staged file")
        secure_file(target)
        temporary.unlink()
        _fsync_directory(parent)
        if target.stat(follow_symlinks=False).st_nlink != 1:
            raise SafetyError("published file has an unexpected hard-link count")
        return target
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def publish_staged_private(staged: Path, path: Path) -> Path:
    """Publish an already-fsynced same-directory private file create-new."""
    source, target = Path(staged), Path(path)
    if source.parent != target.parent:
        raise SafetyError("staged publication must share the final directory")
    assert_safe_path_chain(target.parent, require_leaf=True)
    parent_before = _identity(target.parent)
    if target.exists() or target.is_symlink():
        raise SafetyError(f"refusing to replace existing publication target: {target}")
    secure_file(source)
    # Windows rejects fsync() on a read-only descriptor.  The staged file is
    # Imprint-owned, private, and about to be published, so opening it read/write
    # gives every supported platform a descriptor that can be durably flushed.
    descriptor = os.open(source, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if _identity(target.parent) != parent_before:
        raise SafetyError("publication parent changed before commit")
    try:
        os.link(source, target, follow_symlinks=False)
    except FileExistsError as exc:
        raise SafetyError(f"refusing to replace existing publication target: {target}") from exc
    if _identity(target.parent) != parent_before:
        target.unlink(missing_ok=True)
        _fsync_directory(target.parent)
        raise SafetyError("publication parent changed during commit")
    if _identity(source) != _identity(target):
        raise SafetyError("published file identity does not match staged file")
    source.unlink()
    secure_file(target)
    _fsync_directory(target.parent)
    if target.stat(follow_symlinks=False).st_nlink != 1:
        raise SafetyError("published file has an unexpected hard-link count")
    return target


def replace_private(path: Path, content: bytes) -> Path:
    """Durably replace an Imprint-owned private regular file."""
    target = Path(path)
    parent = target.parent
    assert_safe_path_chain(parent, require_leaf=True)
    parent_before = _identity(parent)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise SafetyError(f"refusing unsafe private publication target: {target}")
    temporary = _write_temporary(parent, f".{target.name}.", content)
    try:
        if _identity(parent) != parent_before:
            raise SafetyError("publication parent changed before replace")
        os.replace(temporary, target)
        if _identity(parent) != parent_before:
            raise SafetyError("publication parent changed during replace")
        secure_file(target)
        _fsync_directory(parent)
        return target
    finally:
        temporary.unlink(missing_ok=True)
