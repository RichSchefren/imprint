from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from imprint.backup import create_backup
from imprint.errors import ConflictError, ValidationError
from imprint.portability import Migration, MigrationRunner
from imprint.portability.migrations import _logical_digest
from imprint.store import ImprintStore
from imprint.ontology.schema import make_urn


def migration(**changes):
    values = {
        "migration_id": "3.0.0-add-labels",
        "from_version": "3.0.0",
        "to_version": "3.0.1",
        "statements": ("CREATE TABLE IF NOT EXISTS labels (label_id TEXT PRIMARY KEY, value TEXT NOT NULL)",),
        "backup_receipt": "missing-backup.sqlite3",
    }
    values.update(changes)
    return Migration(**values)


def test_logical_backup_digest_excludes_only_ephemeral_replay_state():
    with closing(sqlite3.connect(":memory:")) as conn:
        for table in (
            "authority_challenges", "authority_prepared_mutations",
            "authority_keys", "authority_ledger", "authority_provenance",
        ):
            conn.execute(f"CREATE TABLE {table} (id TEXT PRIMARY KEY, value TEXT)")
        baseline = _logical_digest(conn)
        conn.execute("INSERT INTO authority_challenges VALUES('challenge','ephemeral')")
        conn.execute("INSERT INTO authority_prepared_mutations VALUES('prepared','ephemeral')")
        assert _logical_digest(conn) == baseline
        conn.execute("INSERT INTO authority_keys VALUES('key','canonical trust')")
        assert _logical_digest(conn) != baseline


def test_signed_backup_contains_the_exact_canonical_trust_state(tmp_path, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", make_urn("operator"))
    backup = authority.signed_backup(root)
    with closing(sqlite3.connect(backup["path"])) as copied, authority.store.connect() as live:
        assert _logical_digest(copied) == _logical_digest(live)
        for table in ("authority_trust_anchor", "authority_checkpoint_pins", "authority_ledger"):
            assert copied.execute(f"SELECT * FROM {table}").fetchall() == [
                tuple(row) for row in live.execute(f"SELECT * FROM {table}").fetchall()
            ]


def test_failed_snapshot_keeps_committed_checkpoint_and_publishes_no_backup(
    tmp_path, signed_store, monkeypatch,
):
    from imprint.authority.ledger import verify_authority_chain
    import imprint.backup as backup_module

    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", make_urn("operator"))
    with authority.store.connect() as conn:
        before = conn.execute("SELECT COUNT(*) FROM authority_checkpoint_pins").fetchone()[0]

    def fail_publish(_source, _target):
        raise RuntimeError("injected snapshot publication failure")

    monkeypatch.setattr(backup_module, "publish_staged_private", fail_publish)
    with pytest.raises(RuntimeError, match="injected snapshot"):
        authority.signed_backup(root)
    with authority.store.connect() as conn:
        after = conn.execute("SELECT COUNT(*) FROM authority_checkpoint_pins").fetchone()[0]
        verify_authority_chain(conn, expected_operator_id=authority.service.operator_id)
    assert after == before + 1
    assert not list((root / "backups").glob("*.sqlite3"))


def test_migration_is_additive_atomic_and_idempotent(tmp_path, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", make_urn("operator"))
    store = authority.store
    runner = MigrationRunner(store)
    backup = authority.signed_backup(root)
    item = migration(backup_receipt=backup["path"])
    assert authority.call(runner.apply, item) == "applied"
    assert runner.apply(item) == "already-applied"
    with store._migration_connection(store_versions=frozenset({"3.0.1"})) as conn:
        assert conn.execute("SELECT value FROM meta WHERE key='store_schema_version'").fetchone()[0] == "3.0.1"
        assert conn.execute("SELECT COUNT(*) FROM migrations").fetchone()[0] == 1
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='labels'").fetchone()[0] == "labels"


def test_failed_migration_rolls_back_schema_and_version(tmp_path, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", make_urn("operator"))
    store = authority.store
    runner = MigrationRunner(store)
    backup = authority.signed_backup(root)
    broken = migration(
        migration_id="broken",
        backup_receipt=backup["path"],
        statements=(
            "CREATE TABLE transient_table (id TEXT PRIMARY KEY)",
            "ALTER TABLE table_that_does_not_exist ADD COLUMN x TEXT",
        ),
    )
    with pytest.raises(Exception):
        authority.call(runner.apply, broken)
    with store.connect() as conn:
        assert conn.execute("SELECT value FROM meta WHERE key='store_schema_version'").fetchone()[0] == "3.0.0"
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='transient_table'").fetchone() is None
        assert conn.execute("SELECT COUNT(*) FROM migrations").fetchone()[0] == 0


def test_migration_rejects_destructive_sql_missing_backup_and_code_reuse(tmp_path, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", make_urn("operator"))
    store = authority.store
    runner = MigrationRunner(store)
    with pytest.raises(ValidationError):
        runner.apply(migration(statements=("DROP TABLE events",)))
    with pytest.raises(ValidationError):
        runner.apply(migration(backup_receipt=""))
    backup = authority.signed_backup(root)
    authority.call(runner.apply, migration(backup_receipt=backup["receipt_path"]))
    with pytest.raises(ConflictError):
        runner.apply(migration(to_version="3.0.2", backup_receipt=backup["path"]))


def test_arbitrary_hash_and_unrelated_verified_backup_are_rejected(tmp_path, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", make_urn("operator"))
    store = authority.store
    runner = MigrationRunner(store)
    with pytest.raises(ValidationError, match="does not exist"):
        authority.call(runner.apply, migration(backup_receipt="sha256:" + "a" * 64))

    other_root = tmp_path / "other"
    other = ImprintStore(other_root / "imprint.db")
    other.initialize()
    with other.connect() as conn:
        conn.execute("INSERT INTO meta(key,value) VALUES('other','content')")
    unrelated = create_backup(other, other_root)
    with pytest.raises(ValidationError, match="exact logical snapshot"):
        authority.call(runner.apply, migration(backup_receipt=unrelated["path"]))
