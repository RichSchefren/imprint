from __future__ import annotations

import gc
import sqlite3
import sys
import warnings

import imprint.store.service as service
from imprint.store import ImprintStore


def test_store_context_closes_handle_before_return(tmp_path) -> None:
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    with store.connect() as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError as exc:
        assert "closed" in str(exc).lower()
    else:  # pragma: no cover - release-blocking ownership failure
        raise AssertionError("SQLite connection remained open after context return")


def test_repeated_store_contexts_are_warning_clean(tmp_path) -> None:
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    unraisable = []
    prior_hook = sys.unraisablehook
    sys.unraisablehook = unraisable.append
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            for _ in range(25):
                assert store.integrity_check() == "ok"
            gc.collect()
            gc.collect()
    finally:
        sys.unraisablehook = prior_hook
    assert unraisable == []


def test_read_connection_secures_sqlite_state_after_open_and_close(
    tmp_path, monkeypatch,
) -> None:
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    secured = []
    monkeypatch.setattr(
        service, "secure_files", lambda paths: secured.append(tuple(paths)),
    )

    with store.read_connection() as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1

    resolved = store.path.resolve(strict=True)
    assert len(secured) == 2
    assert all(batch[0] == resolved for batch in secured)
    # WAL-mode read activity can materialize sidecars after the connection is
    # opened. The post-close batch is therefore the security boundary that
    # must cover the exact leaves left behind by the reader.
    assert {path.name for path in secured[-1]} == {
        "imprint.db", "imprint.db-wal", "imprint.db-shm",
    }
