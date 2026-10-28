"""Lease recovery after a hook watchdog kill (3.1.2 Windows hotfix)."""
from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timedelta, timezone

import pytest

from imprint.compiler import compile_spools
import imprint.compiler.spool as spool_module
from imprint.compiler.spool import (
    ABANDON_GRACE_SECONDS,
    abandon_held_compiler_leases,
    compiler_lock_state,
    recover_stale_compiler_lock,
)
from imprint.errors import SafetyError
from imprint.store import ImprintStore

DEAD_PID = 99999999
NONCE = "a" * 32


def _stamp(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _plant(tmp_path, *, pid: int, abandoned_seconds_ago: int | None,
           host: str | None = None, extra: dict | None = None):
    now = datetime.now(timezone.utc)
    owner = {
        "lock_schema_version": "1.0.0", "nonce": NONCE, "pid": pid,
        "host": host or socket.gethostname(),
        "created_at": _stamp(now - timedelta(minutes=5)),
        "heartbeat_at": _stamp(now),
    }
    if abandoned_seconds_ago is not None:
        owner["abandoned_at"] = _stamp(now - timedelta(seconds=abandoned_seconds_ago))
    owner.update(extra or {})
    lock = tmp_path / "compiler.lock"
    lock.mkdir()
    (lock / "owner.json").write_text(json.dumps(owner))
    return lock


def test_abandoned_lease_with_dead_owner_is_stale_after_grace(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=ABANDON_GRACE_SECONDS + 5)
    state = compiler_lock_state(tmp_path)
    assert state["state"] == "held" and state["abandoned"] is True
    assert state["stale"] is True


def test_abandoned_lease_inside_grace_is_protected(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=0)
    assert compiler_lock_state(tmp_path)["stale"] is False


def test_abandoned_lease_with_live_owner_is_protected(tmp_path):
    _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=ABANDON_GRACE_SECONDS + 5)
    state = compiler_lock_state(tmp_path)
    assert state["pid_alive"] is True and state["stale"] is False


def test_abandoned_lease_from_other_host_is_stale_after_grace(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=ABANDON_GRACE_SECONDS + 5,
           host="another-host.invalid")
    assert compiler_lock_state(tmp_path)["stale"] is True


def test_unknown_lease_field_is_still_invalid(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=None, extra={"surprise": 1})
    assert compiler_lock_state(tmp_path)["state"] == "invalid"


def test_abandoned_before_created_is_invalid(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=3600)
    assert compiler_lock_state(tmp_path)["state"] == "invalid"


def test_compile_reclaims_abandoned_lease_and_heartbeat_temporary(tmp_path):
    lock = _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=ABANDON_GRACE_SECONDS + 5)
    (lock / ".owner.json.0123abcd.tmp").write_bytes(b"{")
    compile_spools(tmp_path, ImprintStore(tmp_path / "imprint.db"), compiler_authorized=True)
    assert not lock.exists()


def test_compile_still_refuses_fresh_unabandoned_lease(tmp_path):
    _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=None)
    with pytest.raises(SafetyError, match="already held"):
        compile_spools(tmp_path, ImprintStore(tmp_path / "imprint.db"), compiler_authorized=True)


def test_manual_recovery_accepts_heartbeat_temporary(tmp_path):
    lock = _plant(tmp_path, pid=DEAD_PID, abandoned_seconds_ago=ABANDON_GRACE_SECONDS + 5)
    (lock / ".owner.json.0123abcd.tmp").write_bytes(b"{")
    assert recover_stale_compiler_lock(tmp_path, confirmation=NONCE)["status"] != "absent"
    assert not lock.exists()


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
        compile_spools(tmp_path, store, compiler_authorized=True)
    assert "abandoned_at" in seen and seen["pid"] == os.getpid()
    assert spool_module._HELD_LEASES == {}


def test_abandon_without_held_lease_is_a_no_op(tmp_path):
    abandon_held_compiler_leases()
    assert not (tmp_path / "compiler.lock").exists()


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


def test_release_retries_a_transient_rmdir_failure(tmp_path, monkeypatch):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    monkeypatch.setattr(spool_module.time, "sleep", lambda _seconds: None)
    real_rmdir = type(lock).rmdir
    failures = {"left": 2}

    def flaky_rmdir(self):
        if self == lock and failures["left"]:
            failures["left"] -= 1
            raise PermissionError("held by a scanner")
        return real_rmdir(self)

    monkeypatch.setattr(type(lock), "rmdir", flaky_rmdir)
    spool_module._release_compiler_lock(tmp_path, NONCE)
    assert not lock.exists()


def test_release_warns_when_it_gives_up(tmp_path, monkeypatch, capsys):
    lock = _plant(tmp_path, pid=os.getpid(), abandoned_seconds_ago=None)
    monkeypatch.setattr(spool_module.time, "sleep", lambda _seconds: None)

    def stuck_rmdir(self):
        raise PermissionError("held by a scanner")

    monkeypatch.setattr(type(lock), "rmdir", stuck_rmdir)
    spool_module._release_compiler_lock(tmp_path, NONCE)
    assert "compiler lock was not released" in capsys.readouterr().err
