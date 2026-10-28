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


class _NativeAclRefusal(OSError):
    """The native writer refused private state, exactly as the script would."""


class _NativeAclUnavailable(Exception):
    """The native writer could not run; the PowerShell writer takes over."""


def _secure_windows_paths_native(paths: list[Path]) -> None:
    """Apply the PowerShell writer's exact owner/DACL policy in-process.

    Same policy as _secure_windows_paths_powershell: refuse reparse points;
    require the current user as owner (an elevated administrator may take
    over state owned by BUILTIN\\Administrators); write a protected DACL with
    exactly current-user and SYSTEM FullControl, inheritable on directories.
    Only the owner (when taken over) and DACL sections are written, never the
    SACL. Starting PowerShell cost about a second per call, and compile and
    retrieval make tens of calls, which pushed hooks towards their watchdog.
    """
    import ctypes
    from ctypes import wintypes

    se_file_object = 1
    owner_information = 0x00000001
    dacl_information = 0x00000004
    protected_dacl_information = 0x80000000
    acl_revision = 2
    full_control = 0x001F01FF
    inherit_to_children = 0x1 | 0x2  # OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    token_query = 0x0008
    token_user = 1
    gone = {2, 3}  # ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND

    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psid = ctypes.c_void_p
        advapi32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.OpenThreadToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE))
        advapi32.OpenThreadToken.restype = wintypes.BOOL
        kernel32.GetCurrentThread.restype = wintypes.HANDLE
        advapi32.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertStringSidToSidW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(psid))
        advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
        advapi32.CheckTokenMembership.argtypes = (wintypes.HANDLE, psid, ctypes.POINTER(wintypes.BOOL))
        advapi32.CheckTokenMembership.restype = wintypes.BOOL
        advapi32.EqualSid.argtypes = (psid, psid)
        advapi32.EqualSid.restype = wintypes.BOOL
        advapi32.GetLengthSid.argtypes = (psid,)
        advapi32.GetLengthSid.restype = wintypes.DWORD
        advapi32.InitializeAcl.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD)
        advapi32.InitializeAcl.restype = wintypes.BOOL
        advapi32.AddAccessAllowedAceEx.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, psid)
        advapi32.AddAccessAllowedAceEx.restype = wintypes.BOOL
        advapi32.GetNamedSecurityInfoW.argtypes = (
            wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(psid), ctypes.POINTER(psid),
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.SetNamedSecurityInfoW.argtypes = (
            wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, psid, psid, ctypes.c_void_p, ctypes.c_void_p,
        )
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel32.LocalFree.restype = ctypes.c_void_p
    except (OSError, AttributeError) as exc:
        raise _NativeAclUnavailable(str(exc)) from exc

    def fail(call: str) -> None:
        raise _NativeAclUnavailable(f"{call} failed: WinError {ctypes.get_last_error()}")

    # Use the effective identity, as WindowsIdentity.GetCurrent() in the
    # PowerShell writer does: the thread's impersonation token when there is
    # one, else the process token. CheckTokenMembership(None, ...) below
    # makes the same choice, so owner and admin checks see one user.
    error_no_token = 1008
    token = wintypes.HANDLE()
    if not advapi32.OpenThreadToken(kernel32.GetCurrentThread(), token_query, True, ctypes.byref(token)):
        if ctypes.get_last_error() != error_no_token:
            fail("OpenThreadToken")
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)):
            fail("OpenProcessToken")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, token_user, None, 0, ctypes.byref(needed))
        user_buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, token_user, user_buffer, needed, ctypes.byref(needed)):
            fail("GetTokenInformation")
    finally:
        kernel32.CloseHandle(token)
    # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is the PSID.
    current = psid(ctypes.cast(user_buffer, ctypes.POINTER(ctypes.c_void_p))[0])

    system, administrators = psid(), psid()
    if not advapi32.ConvertStringSidToSidW("S-1-5-18", ctypes.byref(system)):
        fail("ConvertStringSidToSidW")
    try:
        if not advapi32.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(administrators)):
            fail("ConvertStringSidToSidW")
        try:
            elevated = wintypes.BOOL()
            if not advapi32.CheckTokenMembership(None, administrators, ctypes.byref(elevated)):
                fail("CheckTokenMembership")

            def private_acl(directory: bool):
                buffer = ctypes.create_string_buffer(1024)
                if not advapi32.InitializeAcl(buffer, len(buffer), acl_revision):
                    fail("InitializeAcl")
                flags = inherit_to_children if directory else 0
                # SYSTEM first: the order .NET writes, so ACEs inherited by
                # later children come out identical to the PowerShell writer's.
                # Running as LocalSystem, current is SYSTEM: write one ACE, as
                # the .NET writer does when it merges identical rules.
                sids = (system,) if advapi32.EqualSid(system, current) else (system, current)
                for sid in sids:
                    if not advapi32.AddAccessAllowedAceEx(buffer, acl_revision, flags, full_control, sid):
                        fail("AddAccessAllowedAceEx")
                return buffer

            for path in paths:
                name = str(path)
                try:
                    info = os.lstat(name)
                except FileNotFoundError:
                    continue  # removed by a concurrent writer; nothing to secure
                if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise _NativeAclRefusal("refusing reparse-point private state")
                owner, descriptor = psid(), ctypes.c_void_p()
                error = advapi32.GetNamedSecurityInfoW(
                    name, se_file_object, owner_information, ctypes.byref(owner), None, None, None,
                    ctypes.byref(descriptor),
                )
                if error in gone:
                    continue
                if error:
                    raise _NativeAclUnavailable(f"GetNamedSecurityInfoW failed: WinError {error}")
                try:
                    take_ownership = None
                    if not advapi32.EqualSid(owner, current):
                        if elevated.value and advapi32.EqualSid(owner, administrators):
                            take_ownership = current
                        else:
                            raise _NativeAclRefusal("refusing private state not owned by the current user")
                finally:
                    kernel32.LocalFree(descriptor)
                acl = private_acl(stat.S_ISDIR(info.st_mode))
                sections = dacl_information | protected_dacl_information
                if take_ownership is not None:
                    sections |= owner_information
                error = advapi32.SetNamedSecurityInfoW(
                    name, se_file_object, sections, take_ownership, None, acl, None,
                )
                if error in gone:
                    continue
                if error:
                    raise _NativeAclUnavailable(f"SetNamedSecurityInfoW failed: WinError {error}")
        finally:
            kernel32.LocalFree(administrators)
    finally:
        kernel32.LocalFree(system)


def _secure_windows_paths(paths: list[Path]) -> None:
    """Set current-user ownership and an exact user/SYSTEM DACL."""
    if not paths:
        return
    try:
        _secure_windows_paths_native(paths)
    except _NativeAclRefusal as exc:
        raise OSError(f"unable to secure private Imprint state on Windows: {exc}") from exc
    except _NativeAclUnavailable:
        _secure_windows_paths_powershell(paths)
        return
    _cache_hardened_windows_directories(paths)


def _secure_windows_paths_powershell(paths: list[Path]) -> None:
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
  try {
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
  # Write only the sections this script modified. PowerShell's ACL-writing
  # cmdlet additionally requests SACL access, which a standard user does not
  # hold, so it is not an option here. .NET Framework carries SetAccessControl
  # on FileSystemInfo; .NET moved it to an extension class absent from the
  # Windows PowerShell 5.1 host this module also selects, and 5.1 is the only
  # PowerShell on a stock Windows 11 machine.
  if ($PSVersionTable.PSEdition -eq 'Core') {
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
  } else {
    $item.SetAccessControl($acl)
  }
  } catch {
    # Another Imprint writer may remove its temporary between the Python
    # walk and this loop. Tolerate only a not-found error for a path that is
    # gone. Get-Item -Force sees a dangling link that Test-Path would miss,
    # and every refusal, including reparse-point and owner refusals, stays fatal.
    # .NET method calls (SetAccessControl) surface their error wrapped in
    # MethodInvocationException; unwrap to the root cause first.
    $root = $_.Exception
    while ($null -ne $root.InnerException -and (
      $root -is [Management.Automation.MethodInvocationException] -or
      $root -is [Management.Automation.ActionPreferenceStopException] -or
      $root -is [Reflection.TargetInvocationException])) {
      $root = $root.InnerException
    }
    $notFound = $root -is [Management.Automation.ItemNotFoundException] -or
      $root -is [IO.FileNotFoundException] -or
      $root -is [IO.DirectoryNotFoundException]
    $stillThere = $null -ne (Get-Item -Force -LiteralPath $path -ErrorAction SilentlyContinue)
    if (-not $notFound -or $stillThere) { throw }
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
        # The detail can name private state paths, so it stays behind the debug
        # switch; the switch itself must be discoverable without reading source.
        raise OSError(
            "unable to secure private Imprint state on Windows "
            f"(host {Path(executable).name}; set IMPRINT_ACCEPTANCE_DEBUG=1 "
            "to see the PowerShell detail)"
        )
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
            if target.absolute() in _WINDOWS_HARDENED_DIRECTORIES:
                # Already hardened, children included, by this process. Doing it
                # again on every write cost one PowerShell pass over every child,
                # so each acknowledgement grew slower until a Stop-hook compile
                # outran the hook watchdog and leaked the compiler lock.
                return target
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


def _private_tree_candidates(base: Path) -> list[Path]:
    """List a private tree's real files and folders, refusing anything else.

    Path.rglob silently skips folders it cannot read, which would let
    secure_tree report success with a subtree unchecked. os.walk with an
    error handler surfaces those errors. Only FileNotFoundError means a
    concurrent writer removed the path after the walk; every other error
    propagates. Each entry is classified before the walk descends into it.
    """
    def classify(path: Path) -> bool:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return False
        if (
            stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
        ):
            raise OSError("refusing unsafe private state path")
        return True

    def walk_error(error: OSError) -> None:
        if not isinstance(error, FileNotFoundError):
            raise error

    candidates = [base] if classify(base) else []
    for current, dirnames, filenames in os.walk(base, onerror=walk_error, followlinks=False):
        kept = []
        for name in sorted(dirnames):
            path = Path(current) / name
            if classify(path):
                candidates.append(path)
                kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            path = Path(current) / name
            if classify(path):
                candidates.append(path)
    return candidates


def secure_tree(root: Path) -> None:
    """Tighten every existing item in an Imprint-owned state tree."""
    base = Path(root)
    if base.is_symlink():
        raise OSError(f"refusing symlinked private directory: {base}")
    base.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIRECTORY_MODE)
    if os.name == "nt":
        candidates = _private_tree_candidates(base)
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
