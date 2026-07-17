from __future__ import annotations

import copy
import sqlite3
import subprocess
import sys

import pytest

from imprint.capture.schema import build_capture_envelope, new_urn
from imprint.compiler import compile_spools, write_envelope
from imprint.errors import SafetyError, ValidationError
from imprint.store import ImprintStore
from imprint.store.service import _sqlite_is_identity_conflict, _sqlite_is_lock_conflict


def test_sqlite_legacy_error_classification_is_narrow() -> None:
    """Python 3.10 exceptions lack sqlite_errorcode; fixed diagnostics remain safe."""
    assert _sqlite_is_lock_conflict(sqlite3.OperationalError("database is locked"))
    assert _sqlite_is_lock_conflict(sqlite3.OperationalError("database table is locked"))
    assert not _sqlite_is_lock_conflict(sqlite3.OperationalError("disk I/O error"))
    assert _sqlite_is_identity_conflict(
        sqlite3.IntegrityError("UNIQUE constraint failed: nodes.node_id")
    )
    assert not _sqlite_is_identity_conflict(
        sqlite3.IntegrityError("FOREIGN KEY constraint failed")
    )


def test_retrieval_generation_is_stable_and_transactional(tmp_path, capture_envelope) -> None:
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    identity, initial = store.retrieval_generation()
    assert identity.startswith("urn:imprint:store:")
    assert initial == 0

    assert store.apply_capture(capture_envelope) == "captured"
    changed = store.retrieval_generation()
    assert changed[0] == identity
    assert changed[1] > initial

    # Idempotent ingestion changes no graph row and therefore no generation.
    assert store.apply_capture(capture_envelope) == "duplicate"
    assert store.retrieval_generation() == changed


def test_store_recover_replays_crash_wal_without_deleting_it_directly(tmp_path) -> None:
    path = tmp_path / "imprint.db"
    store = ImprintStore(path)
    store.initialize()
    script = """
import os, sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute('PRAGMA journal_mode=WAL')
conn.execute('PRAGMA wal_autocheckpoint=0')
conn.execute('CREATE TABLE recovery_probe(value TEXT NOT NULL)')
conn.execute("INSERT INTO recovery_probe VALUES('committed-before-crash')")
conn.commit()
os._exit(0)
"""
    result = subprocess.run([sys.executable, "-c", script, str(path)], check=False)
    assert result.returncode == 0
    wal = path.with_name(path.name + "-wal")
    assert wal.exists() and wal.stat().st_size > 0

    with pytest.raises(ValidationError, match="explicit store recover"):
        with store.connect():
            pass

    recovered = store.recover()
    assert recovered["status"] == "recovered"
    assert recovered["wal_bytes_before"] > 0
    assert recovered["checkpoint_busy"] == 0
    assert recovered["integrity"] == "ok"
    with store.connect() as conn:
        assert conn.execute("SELECT value FROM recovery_probe").fetchone()[0] == "committed-before-crash"
    assert not wal.exists() or wal.stat().st_size == 0


def test_store_recover_refuses_live_sqlite_writer(tmp_path) -> None:
    path = tmp_path / "imprint.db"
    store = ImprintStore(path)
    store.initialize()
    writer = sqlite3.connect(path)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("BEGIN IMMEDIATE")
        with pytest.raises(SafetyError, match="live SQLite connection"):
            store.recover()
    finally:
        writer.rollback()
        writer.close()


def test_duplicate_case_is_quarantined_and_compiler_continues(tmp_path, capture_envelope) -> None:
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    assert store.apply_capture(capture_envelope) == "captured"

    duplicate_case = build_capture_envelope(
        operator_id=capture_envelope["operator_id"],
        session_id=new_urn("session"), node_id=capture_envelope["node_id"],
        case_description="A second event improperly reused an existing case identity.",
        raw_operator_text="This poison event must not stop the following valid event.",
        call_type="correct", capture_mechanism="explicit_cli",
        captured_by="imprint-test", reason="Identity collision.",
        captured_at="2026-07-14T18:01:00Z",
    )
    duplicate_case["case"]["case_id"] = capture_envelope["case"]["case_id"]
    valid_after = copy.deepcopy(build_capture_envelope(
        operator_id=capture_envelope["operator_id"],
        session_id=new_urn("session"), node_id=capture_envelope["node_id"],
        case_description="A valid event follows the poison event.",
        raw_operator_text="The compiler must continue after quarantine.",
        call_type="correct", capture_mechanism="explicit_cli",
        captured_by="imprint-test", reason="Continue safely.",
        captured_at="2026-07-14T18:02:00Z",
    ))
    write_envelope(root, duplicate_case)
    write_envelope(root, valid_after)

    assert compile_spools(root, store, compiler_authorized=True) == {
        "captured": 1, "duplicate": 0, "quarantined": 1,
    }
    assert len(list((root / "quarantine").glob("*.json"))) == 1
    assert any(
        item["node_id"] == valid_after["case"]["case_id"]
        for item in store.current_nodes(["Case"])
    )
