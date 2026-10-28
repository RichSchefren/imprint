"""Lease recovery after a hook watchdog kill (3.1.2 Windows hotfix)."""
from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timedelta, timezone

import pytest

from imprint import permissions
from imprint.compiler import compile_spools
import imprint.compiler.spool as spool_module
from imprint.compiler.spool import (
    ABANDON_GRACE_SECONDS,
    LOCK_STALE_SECONDS,
    abandon_held_compiler_leases,
    compiler_lock_state,
    recover_stale_compiler_lock,
)
from imprint.errors import SafetyError
from imprint.store import ImprintStore

DEAD_PID = 99999999
NONCE = "a" * 32
PAST_GRACE = ABANDON_GRACE_SECONDS + 5


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _plant(tmp_path, *, pid: int, abandoned_seconds_ago: int | None,
           heartbeat_seconds_ago: int | None = None,
           host: str | None = None, extra: dict | None = None):
    """Plant a lease. By default an abandonment mark covers the heartbeat."""
    now = datetime.now(timezone.utc)
    if heartbeat_seconds_ago is None:
        heartbeat_seconds_ago = 0 if abandoned_seconds_ago is None else abandoned_seconds_ago + 1
    owner = {
        "lock_schema_version": "1.0.0", "nonce": NONCE, "pid": pid,
        "host": host or socket.gethostname(),
        "created_at": _stamp(now - timedelta(seconds=LOCK_STALE_SECONDS + 600)),
        "heartbeat_at": _stamp(now - timedelta(seconds=heartbeat_seconds_ago)),
    }
    if abandoned_seconds_ago is not None:
        owner["abandoned_at"] = _stamp(now - timedelta(seconds=abandoned_seconds_ago))
    owner.update(extra or {})
    lock = tmp_path / "compiler.lock"
    lock.mkdir()
    (lock / "owner.json").write_text(json.dumps(owner))
    return lock


def _compile(tmp_path, store=None):
    return compile_spools(
        tmp_path, store or ImprintStore(tmp_path / "imprint.db"), compiler_authorized=True,
    )


# Lease state ---------------------------------------------------------------

def test_abandoned_lease_with_dead_owner_is_reclaimable_after_grace(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=PAST_GRACE)
    state = compiler_lock_state(tmp_path)
    assert state["state"] == "held" and state["abandoned"] is True
    assert state["reclaimable"] is True and state["stale"] is True


def test_abandoned_lease_inside_grace_is_protected(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=0, heartbeat_seconds_ago=0)
    state = compiler_lock_state(tmp_path)
    assert state["reclaimable"] is False and state["stale"] is False


def test_abandoned_lease_with_live_owner_is_protected(tmp_path):
    # Another live process (our parent), so the mark is still inside its run.
    _plant(tmp_path, pid=os.getppid(), abandoned_seconds_ago=PAST_GRACE)
    state = compiler_lock_state(tmp_path)
    assert state["pid_alive"] is True
    assert state["reclaimable"] is False and state["stale"] is False


def test_abandoned_lease_from_other_host_is_reclaimable_after_grace(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=PAST_GRACE,
           host="another-host.invalid")
    assert compiler_lock_state(tmp_path)["reclaimable"] is True


def test_heartbeat_after_abandonment_cancels_the_mark(tmp_path):
    # The writer kept running after it marked the lease.
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=PAST_GRACE,
           heartbeat_seconds_ago=0)
    state = compiler_lock_state(tmp_path)
    assert state["abandoned"] is False
    assert state["reclaimable"] is False and state["stale"] is False


def test_age_stale_lease_is_stale_but_not_reclaimable(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=None,
           heartbeat_seconds_ago=LOCK_STALE_SECONDS + 60)
    state = compiler_lock_state(tmp_path)
    assert state["stale"] is True and state["reclaimable"] is False


def test_unknown_lease_field_is_still_invalid(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=None, extra={"surprise": 1})
    assert compiler_lock_state(tmp_path)["state"] == "invalid"


def test_abandoned_before_created_is_invalid(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=LOCK_STALE_SECONDS + 3600,
           heartbeat_seconds_ago=0)
    assert compiler_lock_state(tmp_path)["state"] == "invalid"


# Automatic and manual recovery ---------------------------------------------

def test_compile_reclaims_abandoned_lease_and_heartbeat_temporary(tmp_path):
    lock = _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=PAST_GRACE)
    (lock / ".owner.json.0123abcd.tmp").write_bytes(b"{")
    _compile(tmp_path)
    assert not lock.exists()


def test_compile_still_refuses_fresh_unabandoned_lease(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=None)
    with pytest.raises(SafetyError, match="already held"):
        _compile(tmp_path)


def test_compile_does_not_reclaim_an_age_stale_lease(tmp_path):
    # An old heartbeat alone does not prove the writer died; recovery of an
    # ordinary stale lease stays an explicit operator action.
    lock = _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=None,
                  heartbeat_seconds_ago=LOCK_STALE_SECONDS + 60)
    with pytest.raises(SafetyError, match="already held"):
        _compile(tmp_path)
    assert (lock / "owner.json").is_file()
    recover_stale_compiler_lock(tmp_path, confirmation=NONCE)
    assert not lock.exists()


def test_compile_does_not_reclaim_a_lease_heartbeated_after_its_mark(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=PAST_GRACE,
           heartbeat_seconds_ago=0)
    with pytest.raises(SafetyError, match="already held"):
        _compile(tmp_path)


def test_manual_recovery_accepts_heartbeat_temporary(tmp_path):
    lock = _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=PAST_GRACE)
    (lock / ".owner.json.0123abcd.tmp").write_bytes(b"{")
    assert recover_stale_compiler_lock(tmp_path, confirmation=NONCE)["status"] != "absent"
    assert not lock.exists()


# Watchdog marking ----------------------------------------------------------

def test_watchdog_marks_held_lease_abandoned(tmp_path):
    seen = {}
    store = ImprintStore(tmp_path / "imprint.db")

    def watchdog_fires():
        # The watchdog thread runs this just before os._exit.
        abandon_held_compiler_leases()
        seen.update(json.loads((tmp_path / "compiler.lock" / "owner.json").read_text(encoding="ascii")))
        raise RuntimeError("simulated os._exit")

    store.initialize = watchdog_fires
    with pytest.raises(RuntimeError):
        _compile(tmp_path, store)
    assert "abandoned_at" in seen and seen["pid"] == os.getpid()
    assert seen["abandoned_at"] >= seen["heartbeat_at"]
    assert spool_module._HELD_LEASES == {}


def test_lease_is_registered_before_the_first_owner_write(tmp_path, monkeypatch):
    registered = []
    original = spool_module._write_lock_owner

    def record(path, owner):
        registered.append(owner["nonce"] in spool_module._HELD_LEASES)
        return original(path, owner)

    monkeypatch.setattr(spool_module, "_write_lock_owner", record)
    _compile(tmp_path)
    assert registered and registered[0] is True


def test_lease_stays_registered_until_release_finishes(tmp_path, monkeypatch):
    during_release = []
    original = spool_module._release_compiler_lock

    def record(operator_root, nonce, owner=None):
        during_release.append(nonce in spool_module._HELD_LEASES)
        return original(operator_root, nonce, owner)

    monkeypatch.setattr(spool_module, "_release_compiler_lock", record)
    _compile(tmp_path)
    assert during_release == [True]
    assert spool_module._HELD_LEASES == {}


def test_abandon_without_held_lease_is_a_no_op(tmp_path):
    abandon_held_compiler_leases()
    assert not (tmp_path / "compiler.lock").exists()


# Heartbeat fencing ---------------------------------------------------------

def test_heartbeat_refuses_a_lease_another_writer_took(tmp_path):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    before = (lock / "owner.json").read_bytes()
    ours = {"nonce": "b" * 32}
    with pytest.raises(SafetyError, match="lease lost"):
        spool_module._refresh_heartbeat(lock / "owner.json", ours)
    assert (lock / "owner.json").read_bytes() == before


def test_heartbeat_refuses_a_lease_that_is_gone(tmp_path):
    with pytest.raises(SafetyError, match="lease lost"):
        spool_module._refresh_heartbeat(tmp_path / "compiler.lock" / "owner.json", {"nonce": NONCE})
    assert not (tmp_path / "compiler.lock").exists()


# Release -------------------------------------------------------------------

def test_release_never_removes_a_lock_without_owner_file(tmp_path):
    lock = tmp_path / "compiler.lock"
    lock.mkdir()  # a new writer between mkdir and its owner.json write
    spool_module._release_compiler_lock(tmp_path, NONCE)
    assert lock.is_dir()


def test_release_leaves_another_writers_lease(tmp_path):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    spool_module._release_compiler_lock(tmp_path, "b" * 32)
    assert (lock / "owner.json").is_file()


def test_release_removes_own_lease_and_heartbeat_temporary(tmp_path):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    (lock / ".owner.json.0123abcd.tmp").write_bytes(b"{")
    spool_module._release_compiler_lock(tmp_path, NONCE)
    assert not lock.exists()
    assert list(tmp_path.iterdir()) == []


def test_release_retries_a_transient_rename_failure(tmp_path, monkeypatch):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    monkeypatch.setattr(spool_module.time, "sleep", lambda _seconds: None)
    real_rename = os.rename
    failures = {"left": 2}

    def flaky_rename(source, destination):
        if failures["left"]:
            failures["left"] -= 1
            raise PermissionError("held by a scanner")
        return real_rename(source, destination)

    monkeypatch.setattr(spool_module.os, "rename", flaky_rename)
    spool_module._release_compiler_lock(tmp_path, NONCE)
    assert not lock.exists() and list(tmp_path.iterdir()) == []


def test_release_that_cannot_rename_keeps_owner_and_marks_it_abandoned(
    tmp_path, monkeypatch, capsys,
):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    owner = json.loads((lock / "owner.json").read_text(encoding="ascii"))
    monkeypatch.setattr(spool_module.time, "sleep", lambda _seconds: None)

    def stuck_rename(source, destination):
        raise PermissionError("held by a scanner")

    monkeypatch.setattr(spool_module.os, "rename", stuck_rename)
    spool_module._release_compiler_lock(tmp_path, NONCE, owner)
    assert "marked abandoned" in capsys.readouterr().err
    published = json.loads((lock / "owner.json").read_text(encoding="ascii"))
    assert published["nonce"] == NONCE and "abandoned_at" in published


def test_release_residue_is_not_a_lock(tmp_path, monkeypatch, capsys):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    monkeypatch.setattr(spool_module.time, "sleep", lambda _seconds: None)
    real_rmdir = type(lock).rmdir

    def stuck_rmdir(self):
        if self.name.startswith(".compiler-lock-release-"):
            raise PermissionError("held by a scanner")
        return real_rmdir(self)

    monkeypatch.setattr(type(lock), "rmdir", stuck_rmdir)
    spool_module._release_compiler_lock(tmp_path, NONCE)
    assert "left residue" in capsys.readouterr().err
    assert not lock.exists()
    assert compiler_lock_state(tmp_path)["state"] == "absent"
    _compile(tmp_path)  # the next writer is not blocked


# secure_tree path classification (portable logic, used on Windows) --------

def test_secure_tree_skips_only_paths_that_vanished(tmp_path, monkeypatch):
    (tmp_path / "gone.tmp").write_bytes(b"")
    (tmp_path / "kept.json").write_bytes(b"")
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        if str(path).endswith("gone.tmp"):
            raise FileNotFoundError(path)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(permissions.os, "lstat", lstat)
    names = {path.name for path in permissions._private_tree_candidates(tmp_path)}
    assert "kept.json" in names and "gone.tmp" not in names


def test_secure_tree_propagates_other_stat_errors(tmp_path, monkeypatch):
    (tmp_path / "locked.json").write_bytes(b"")
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        if str(path).endswith("locked.json"):
            raise PermissionError(path)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(permissions.os, "lstat", lstat)
    with pytest.raises(PermissionError):
        permissions._private_tree_candidates(tmp_path)


def test_secure_tree_refuses_a_dangling_link(tmp_path):
    (tmp_path / "dangling").symlink_to(tmp_path / "missing")
    with pytest.raises(OSError, match="refusing unsafe private state path"):
        permissions._private_tree_candidates(tmp_path)


# Windows process probe (decision logic against a fake kernel32) ------------

class _FakeFunction:
    def __init__(self, result):
        self.result = result
        self.argtypes = self.restype = None
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.result


class _FakeKernel32:
    def __init__(self, *, handle, wait_result=0x102):
        self.OpenProcess = _FakeFunction(handle)
        self.WaitForSingleObject = _FakeFunction(wait_result)
        self.CloseHandle = _FakeFunction(1)


def _probe(monkeypatch, kernel32, last_error=0):
    import ctypes
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: last_error, raising=False)
    return spool_module._windows_pid_alive(1234)


@pytest.mark.parametrize(("last_error", "alive"), [
    (87, False),    # ERROR_INVALID_PARAMETER: no such process
    (5, True),      # ERROR_ACCESS_DENIED: a live process we may not inspect
    (8, True),      # ERROR_NOT_ENOUGH_MEMORY: inconclusive, so not dead
    (1450, True),   # ERROR_NO_SYSTEM_RESOURCES: inconclusive, so not dead
])
def test_windows_probe_treats_only_no_such_process_as_dead(monkeypatch, last_error, alive):
    assert _probe(monkeypatch, _FakeKernel32(handle=None), last_error) is alive


@pytest.mark.parametrize(("wait_result", "alive"), [
    (0x0, False),          # WAIT_OBJECT_0: the process has ended
    (0x102, True),         # WAIT_TIMEOUT: still running
    (0xFFFFFFFF, True),    # WAIT_FAILED: inconclusive, so not dead
])
def test_windows_probe_uses_the_process_handle_not_the_exit_code(
    monkeypatch, wait_result, alive,
):
    kernel32 = _FakeKernel32(handle=42, wait_result=wait_result)
    assert _probe(monkeypatch, kernel32) is alive
    access = kernel32.OpenProcess.calls[0][0]
    assert access & 0x00100000  # SYNCHRONIZE, needed for the wait
    assert kernel32.WaitForSingleObject.calls == [(42, 0)]
    assert kernel32.CloseHandle.calls == [(42,)]


# Second review: marks, residue, and startup failures -----------------------

class _BusyGuard:
    """A lease guard another thread holds for longer than the watchdog waits."""

    def acquire(self, timeout=-1):
        return False

    def release(self):
        raise AssertionError("never acquired")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _hold(tmp_path, owner):
    path = tmp_path / "compiler.lock" / "owner.json"
    spool_module._HELD_LEASES[owner["nonce"]] = (path, owner)
    return path


def test_watchdog_publishes_the_mark_even_when_the_guard_stays_busy(tmp_path, monkeypatch):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    owner = json.loads((lock / "owner.json").read_text(encoding="ascii"))
    _hold(tmp_path, owner)
    monkeypatch.setattr(spool_module, "_LEASE_GUARD", _BusyGuard())
    try:
        abandon_held_compiler_leases()
    finally:
        spool_module._HELD_LEASES.clear()
    assert "abandoned_at" in json.loads((lock / "owner.json").read_text(encoding="ascii"))


def test_watchdog_never_marks_another_writers_lease(tmp_path):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    before = (lock / "owner.json").read_bytes()
    ours = dict(json.loads(before), nonce="b" * 32)
    _hold(tmp_path, ours)
    try:
        abandon_held_compiler_leases()
    finally:
        spool_module._HELD_LEASES.clear()
    assert (lock / "owner.json").read_bytes() == before


def test_heartbeat_does_not_refresh_over_the_mark(tmp_path):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=PAST_GRACE)
    owner = json.loads((lock / "owner.json").read_text(encoding="ascii"))
    before = (lock / "owner.json").read_bytes()
    spool_module._refresh_heartbeat(lock / "owner.json", owner)
    assert (lock / "owner.json").read_bytes() == before


def test_marked_lease_this_process_finished_with_is_reclaimable(tmp_path):
    # A release that could not rename leaves a mark; this process keeps running.
    _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=PAST_GRACE)
    state = compiler_lock_state(tmp_path)
    assert state["pid_alive"] is True and state["reclaimable"] is True


def test_marked_lease_this_process_still_compiles_under_is_protected(tmp_path):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=PAST_GRACE)
    _hold(tmp_path, json.loads((lock / "owner.json").read_text(encoding="ascii")))
    try:
        assert compiler_lock_state(tmp_path)["reclaimable"] is False
    finally:
        spool_module._HELD_LEASES.clear()


def test_same_process_compiles_again_after_a_failed_release(tmp_path):
    _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=PAST_GRACE)
    _compile(tmp_path)
    assert compiler_lock_state(tmp_path)["state"] == "absent"


def test_release_reports_when_the_mark_could_not_be_written(tmp_path, monkeypatch, capsys):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    owner = json.loads((lock / "owner.json").read_text(encoding="ascii"))
    monkeypatch.setattr(spool_module.time, "sleep", lambda _seconds: None)

    def stuck_rename(source, destination):
        raise PermissionError("held by a scanner")

    def failing_write(path, data):
        raise OSError("disk full")

    monkeypatch.setattr(spool_module.os, "rename", stuck_rename)
    monkeypatch.setattr(spool_module, "replace_private", failing_write)
    spool_module._release_compiler_lock(tmp_path, NONCE, owner)
    err = capsys.readouterr().err
    assert "could not be marked abandoned" in err and NONCE in err
    assert "abandoned_at" not in json.loads((lock / "owner.json").read_text(encoding="ascii"))


def test_compile_removes_earlier_release_residue(tmp_path):
    residue = tmp_path / ".compiler-lock-release-0123"
    residue.mkdir()
    (residue / "owner.json").write_text("{}")
    (residue / ".owner.json.abcd.tmp").write_bytes(b"{")
    _compile(tmp_path)
    assert not residue.exists()


def test_compile_leaves_release_residue_with_unknown_content(tmp_path):
    residue = tmp_path / ".compiler-lock-release-0123"
    residue.mkdir()
    (residue / "surprise.bin").write_bytes(b"x")
    _compile(tmp_path)
    assert (residue / "surprise.bin").is_file()


def test_health_reports_release_residue(tmp_path):
    from imprint.health import _temporary_residue

    residue = tmp_path / ".compiler-lock-release-0123"
    residue.mkdir()
    assert residue in _temporary_residue(tmp_path)


def test_failed_lock_hardening_leaves_no_lock(tmp_path, monkeypatch):
    real = spool_module.secure_directory

    def refuse_lock(path):
        if path.name == "compiler.lock":
            raise OSError("ACL write refused")
        return real(path)

    monkeypatch.setattr(spool_module, "secure_directory", refuse_lock)
    with pytest.raises(OSError, match="ACL write refused"):
        _compile(tmp_path)
    assert not (tmp_path / "compiler.lock").exists()
    assert spool_module._HELD_LEASES == {}


def test_failed_first_owner_write_leaves_no_lock(tmp_path, monkeypatch):
    def failing_write(path, data):
        raise OSError("disk full")

    monkeypatch.setattr(spool_module, "replace_private", failing_write)
    with pytest.raises(OSError, match="disk full"):
        _compile(tmp_path)
    assert not (tmp_path / "compiler.lock").exists()


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs POSIX permissions as non-root")
def test_secure_tree_does_not_skip_an_unreadable_folder(tmp_path):
    locked = tmp_path / "locked"
    (locked / "child").mkdir(parents=True)
    locked.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            permissions._private_tree_candidates(tmp_path)
    finally:
        locked.chmod(0o700)


def test_secure_tree_lists_the_whole_tree(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "f.json").write_bytes(b"")
    (tmp_path / "g.json").write_bytes(b"")
    found = {path.relative_to(tmp_path).as_posix() for path in permissions._private_tree_candidates(tmp_path)}
    assert found == {".", "a", "a/b", "a/b/f.json", "g.json"}
