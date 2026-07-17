from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import imprint.permissions as permissions


def test_existing_windows_directory_and_children_use_one_acl_batch(tmp_path, monkeypatch):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    calls: list[list[Path]] = []

    def fake_secure(paths: list[Path]) -> None:
        calls.append(paths)
        permissions._WINDOWS_HARDENED_DIRECTORIES.update(
            path.absolute() for path in paths if path.is_dir()
        )

    permissions._WINDOWS_HARDENED_DIRECTORIES.clear()
    monkeypatch.setattr(permissions, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(permissions, "_secure_windows_paths", fake_secure)

    permissions.secure_directory(tmp_path)
    permissions.secure_file(first)
    permissions.secure_file(second)

    assert calls == [[tmp_path, first, second], [first], [second]]


def test_windows_acl_helper_batches_exact_paths_in_one_powershell_process(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    permissions._WINDOWS_HARDENED_DIRECTORIES.clear()
    monkeypatch.setattr(permissions, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(permissions.shutil, "which", lambda name: "powershell.exe")
    monkeypatch.setattr(permissions.subprocess, "run", fake_run)
    paths = [tmp_path, tmp_path / "a", tmp_path / "b"]

    permissions._secure_windows_paths(paths)

    assert len(calls) == 1
    assert calls[0][1]["input"] == '["%s", "%s", "%s"]' % tuple(paths)
    script = calls[0][0][-1]
    assert "$existingAcl.GetOwner([Security.Principal.SecurityIdentifier])" in script
    assert "[Security.AccessControl.DirectorySecurity]::new()" in script
    assert "[Security.AccessControl.FileSecurity]::new()" in script
    assert "RemoveAccessRuleSpecific" not in script
    assert "[IO.FileSystemAclExtensions]::SetAccessControl(" in script
    assert "Set-Acl -LiteralPath $path" not in script
    assert "$isAdmin -and $owner.Value -eq 'S-1-5-32-544'" in script
    assert "$acl.SetOwner($current)" in script
    assert tmp_path.absolute() in permissions._WINDOWS_HARDENED_DIRECTORIES


def test_cached_windows_parent_still_hardens_exact_files_in_one_batch(tmp_path, monkeypatch):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    calls: list[list[Path]] = []

    permissions._WINDOWS_HARDENED_DIRECTORIES.clear()
    permissions._WINDOWS_HARDENED_DIRECTORIES.add(tmp_path.absolute())
    monkeypatch.setattr(permissions, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(permissions, "_secure_windows_paths", lambda paths: calls.append(paths))

    assert permissions.secure_files((first, second)) == (first, second)
    assert calls == [[first, second]]


def test_windows_acl_detail_is_exposed_only_for_acceptance_debug(tmp_path, monkeypatch):
    result = SimpleNamespace(returncode=1, stderr="precise ACL failure", stdout="")
    monkeypatch.setattr(permissions.shutil, "which", lambda name: "powershell.exe")
    monkeypatch.setattr(permissions.subprocess, "run", lambda *args, **kwargs: result)
    monkeypatch.setattr(permissions, "os", SimpleNamespace(name="nt", environ={}))
    try:
        permissions._secure_windows_paths([tmp_path])
    except OSError as exc:
        assert str(exc) == "unable to secure private Imprint state on Windows"
    else:
        raise AssertionError("generic ACL failure was not raised")
    permissions.os.environ["IMPRINT_ACCEPTANCE_DEBUG"] = "1"
    try:
        permissions._secure_windows_paths([tmp_path])
    except OSError as exc:
        assert "precise ACL failure" in str(exc)
    else:
        raise AssertionError("debug ACL failure was not raised")
