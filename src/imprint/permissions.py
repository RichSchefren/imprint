"""Private local-storage permissions for Imprint-owned state."""

from __future__ import annotations

import os
import json
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Iterable

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_WINDOWS_HARDENED_DIRECTORIES: set[Path] = set()


def _cache_hardened_windows_directories(paths: list[Path]) -> None:
    if os.name == "nt":
        _WINDOWS_HARDENED_DIRECTORIES.update(
            path.absolute() for path in paths if path.is_dir()
        )


def assert_safe_path_chain(path: Path, *, require_leaf: bool = False) -> Path:
    """Reject links/reparse points in every existing path component."""
    target = Path(path).expanduser()
    if require_leaf and not target.exists():
        raise OSError(f"required path does not exist: {target}")
    absolute = target if target.is_absolute() else target.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists() and not current.is_symlink():
            continue
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise OSError(f"refusing linked private path component: {current}")
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if os.name == "nt" and attributes & reparse:
            raise OSError(f"refusing reparse-point private path component: {current}")
    return absolute


def _secure_windows_paths(paths: list[Path]) -> None:
    """Set current-user ownership and an exact user/SYSTEM DACL."""
    if not paths:
        return
    executable = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if executable is None:
        raise OSError("PowerShell is required to secure private Imprint state")
    script = r"""
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User
foreach ($path in $paths) {
  $item = Get-Item -Force -LiteralPath $path
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "refusing reparse-point private state"
  }
  $existingAcl = Get-Acl -LiteralPath $path
  $owner = $existingAcl.GetOwner([Security.Principal.SecurityIdentifier])
  $acl = if ($item.PSIsContainer) {
    [Security.AccessControl.DirectorySecurity]::new()
  } else {
    [Security.AccessControl.FileSecurity]::new()
  }
  if ($owner.Value -ne $current.Value) {
    $principal = [Security.Principal.WindowsPrincipal]::new(
      [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin -and $owner.Value -eq 'S-1-5-32-544') {
      $acl.SetOwner($current)
    } else {
      throw "refusing private state not owned by the current user"
    }
  }
  $acl.SetAccessRuleProtection($true, $false)
  $inheritance = if ($item.PSIsContainer) {
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else { [Security.AccessControl.InheritanceFlags]::None }
  foreach ($allowed in @($current, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $grant = [Security.AccessControl.FileSystemAccessRule]::new(
      $allowed,
      [Security.AccessControl.FileSystemRights]::FullControl,
      $inheritance,
      [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($grant)
  }
  if ($item.PSIsContainer) {
    [IO.FileSystemAclExtensions]::SetAccessControl(
      [IO.DirectoryInfo]$item,
      [Security.AccessControl.DirectorySecurity]$acl
    )
  } else {
    [IO.FileSystemAclExtensions]::SetAccessControl(
      [IO.FileInfo]$item,
      [Security.AccessControl.FileSecurity]$acl
    )
  }
}
"""
    result = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        input=json.dumps([str(path) for path in paths]),
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        if os.environ.get("IMPRINT_ACCEPTANCE_DEBUG") == "1":
            detail = (result.stderr or result.stdout or "no PowerShell detail").strip()
            raise OSError(f"unable to secure private Imprint state on Windows: {detail}")
        raise OSError("unable to secure private Imprint state on Windows")
    _cache_hardened_windows_directories(paths)


def secure_directory(path: Path) -> Path:
    """Create or tighten an Imprint-owned directory without following links."""
    target = Path(path)
    assert_safe_path_chain(target)
    if target.is_symlink():
        raise OSError(f"refusing symlinked private directory: {target}")
    missing: list[Path] = []
    cursor = target
    while not cursor.exists():
        if cursor.is_symlink():
            raise OSError(f"refusing symlinked private directory: {cursor}")
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    target.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIRECTORY_MODE)
    created = list(reversed(missing))
    candidates = created if created else [target]
    if os.name == "nt":
        if not created:
            # Harden existing immediate children in this same process so later
            # secure_file calls may safely rely on the directory's exact,
            # protected inheritable DACL.
            candidates.extend(sorted(target.iterdir(), key=lambda item: item.name))
        _secure_windows_paths(candidates)
    else:
        for candidate in candidates:
            os.chmod(candidate, PRIVATE_DIRECTORY_MODE, follow_symlinks=False)
    return target


def secure_files(paths: Iterable[Path]) -> tuple[Path, ...]:
    """Tighten exact existing private files in one platform ACL batch."""
    targets = tuple(Path(path) for path in paths)
    for target in targets:
        if target.is_symlink() or not target.is_file():
            raise OSError(f"private file is not a regular file: {target}")
    if os.name == "nt":
        parents = sorted({
            target.parent.absolute() for target in targets
            if target.parent.absolute() not in _WINDOWS_HARDENED_DIRECTORIES
        }, key=str)
        # Cached parents prove only their inheritable DACL. Exact leaves must
        # still be hardened after SQLite, link, move, or replace semantics.
        _secure_windows_paths([*parents, *targets])
    else:
        for target in targets:
            os.chmod(target, PRIVATE_FILE_MODE, follow_symlinks=False)
    return targets


def secure_file(path: Path) -> Path:
    """Tighten an existing Imprint-owned regular file."""
    target = Path(path)
    secure_files((target,))
    return target


def assert_private_file(path: Path) -> Path:
    """Inspect private-file ownership and permissions without repairing them."""
    target = Path(path)
    try:
        assert_safe_path_chain(target, require_leaf=True)
        info = target.lstat()
    except OSError as exc:
        raise OSError(f"private file path is unsafe: {target}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise OSError(f"private file is not a single-link regular file: {target}")
    if os.name == "nt":
        if unsafe_windows_permissions(target):
            raise OSError(f"private file has unsafe Windows ownership or ACL: {target}")
    else:
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE:
            raise OSError(f"private file has unsafe owner or mode: {target}")
    return target


def secure_tree(root: Path) -> None:
    """Tighten every existing item in an Imprint-owned state tree."""
    base = Path(root)
    if base.is_symlink():
        raise OSError(f"refusing symlinked private directory: {base}")
    base.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIRECTORY_MODE)
    if os.name == "nt":
        candidates = [base, *base.rglob("*")]
        if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in candidates):
            raise OSError("refusing unsafe private state path")
        _secure_windows_paths(candidates)
        _cache_hardened_windows_directories(
            [path for path in candidates if path.is_dir()]
        )
        return
    secure_directory(base)
    for current, directories, files in os.walk(base, followlinks=False):
        current_path = Path(current)
        secure_directory(current_path)
        for name in directories:
            secure_directory(current_path / name)
        for name in files:
            secure_file(current_path / name)


def unsafe_posix_permissions(root: Path) -> tuple[str, ...]:
    """Return content-free relative paths that are group/world accessible."""
    if os.name == "nt":
        return ()
    base = Path(root)
    if not base.exists():
        return ()
    unsafe: list[str] = []
    candidates = [base, *base.rglob("*")]
    for path in candidates:
        if path.is_symlink():
            unsafe.append(str(path.relative_to(base)) or ".")
            continue
        if not (path.is_dir() or path.is_file()):
            continue
        mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
        if mode & 0o077:
            unsafe.append(str(path.relative_to(base)) or ".")
    return tuple(sorted(set(unsafe)))


def unsafe_windows_permissions(root: Path) -> tuple[str, ...]:
    """Return paths granting read/write access beyond the user and SYSTEM."""
    if os.name != "nt":
        return ()
    base = Path(root)
    if not base.exists():
        return ()
    candidates = [base, *base.rglob("*")]
    unsafe = [
        str(path.relative_to(base)) or "."
        for path in candidates
        if path.is_symlink() or not (path.is_dir() or path.is_file())
    ]
    inspectable = [str(path) for path in candidates if path.is_dir() or path.is_file()]
    script = r"""
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8
[Console]::OutputEncoding = $utf8
$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($current, 'S-1-5-18')
$unsafe = @()
foreach ($path in $paths) {
  $item = Get-Item -Force -LiteralPath $path
  $acl = Get-Acl -LiteralPath $path
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $allowed -notcontains $owner) {
    $unsafe += $path
    continue
  }
  $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  foreach ($rule in $rules) {
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $allowed -notcontains $rule.IdentityReference.Value) {
      $unsafe += $path
      break
    }
  }
}
ConvertTo-Json -Compress -InputObject @($unsafe)
"""
    try:
        executable = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
        if executable is None:
            return ("<acl-inspection-failed>",)
        result = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            input=json.dumps(inspectable),
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            return ("<acl-inspection-failed>",)
        reported = json.loads(result.stdout or "[]")
        if not isinstance(reported, list) or any(not isinstance(item, str) for item in reported):
            return ("<acl-inspection-failed>",)
        unsafe.extend(str(Path(item).relative_to(base)) or "." for item in reported)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
        return ("<acl-inspection-failed>",)
    return tuple(sorted(set(unsafe)))


def unsafe_private_permissions(root: Path) -> tuple[str, ...]:
    """Dispatch to the platform's fail-closed private-state permission scan."""
    return unsafe_windows_permissions(root) if os.name == "nt" else unsafe_posix_permissions(root)
