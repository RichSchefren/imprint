from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from imprint.backup import create_backup
from imprint.health import health_report
from imprint.permissions import secure_tree
from imprint.retrieve import commit_payload_delivery, retrieve_payload
from imprint.store import ImprintStore


def _config(root: Path) -> dict[str, object]:
    hooks = root.parent / "installed-hooks"
    hooks.mkdir(exist_ok=True)
    for name in ("session_start.py", "user_prompt_submit.py", "stop_capture.py", "health_check.py"):
        (hooks / name).write_text("# synthetic hook\n", encoding="utf-8")
    return {
        "compiler": True,
        "context_budget_bytes": 32 * 1024,
        "experimental": {"digest": False, "profile_learning": False},
        "hooks_dir": str(hooks),
    }


def test_health_uses_real_ages_backup_verification_and_permission_evidence(
    tmp_path, capture_envelope,
):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope, source_path="synthetic.json")
    (root / "projections").mkdir()
    (root / "projections" / "imprint.jsonld").write_text("{}\n", encoding="utf-8")
    spool = root / "spool" / "node-a" / "old.json"
    spool.parent.mkdir(parents=True)
    spool.write_text("{}\n", encoding="utf-8")
    old = spool.stat().st_mtime - 7200
    os.utime(spool, (old, old))
    create_backup(store, root)
    secure_tree(root)

    report = health_report(root, store, _config(root), deep=True)

    assert report["status"] == "degraded"
    assert "spool_stale" in report["degraded_reasons"]
    assert report["metrics"]["oldest_spool_age_seconds"] >= 7190
    assert report["metrics"]["verified_backup_count"] == 1
    assert report["metrics"]["backup_state"] == "verified"
    assert report["metrics"]["permissions_state"] == "safe"
    assert report["metrics"]["database_evidence"] == "sqlite_pragma_integrity_check"


def test_quarantine_temp_fake_backup_and_open_permissions_cannot_report_healthy(
    tmp_path,
):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    (root / "quarantine").mkdir()
    (root / "quarantine" / "failure.json").write_text("{}\n", encoding="utf-8")
    (root / ".restore-crash.tmp").write_text("partial", encoding="utf-8")
    (root / "backups").mkdir()
    (root / "backups" / "fake.sqlite3.receipt.json").write_text(json.dumps({
        "backup_schema_version": "1.0.0", "file": "fake.sqlite3", "sha256": "0" * 64,
    }), encoding="utf-8")
    if os.name != "nt":
        os.chmod(root, 0o755)

    report = health_report(root, store, _config(root), deep=True)

    assert report["status"] == "degraded"
    assert {"quarantine_present", "abandoned_temp_present", "backup_unverified"}.issubset(
        report["degraded_reasons"]
    )
    if os.name != "nt":
        assert "unsafe_permissions" in report["degraded_reasons"]
    assert report["metrics"]["invalid_backup_count"] == 1
    assert report["metrics"]["backup_state"] == "invalid"


def test_health_of_absent_store_is_degraded_without_creating_a_database(tmp_path):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")

    report = health_report(root, store, _config(root))

    assert report["status"] == "degraded"
    assert report["metrics"]["database_state"] == "absent"
    assert report["metrics"]["migration_state"] == "not_checked"
    assert not store.path.exists()


def test_interrupted_delivery_replays_identical_cached_bounded_payload(
    tmp_path, capture_envelope,
):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope, source_path="synthetic.json")
    first = retrieve_payload(store, root=root, session_id="crash-session", budget=32 * 1024)

    pending = next((root / "receipts").glob("*/*.pending.json"))
    expected = json.loads(pending.read_text(encoding="utf-8"))["response"]
    assert len(expected["payload"].encode("utf-8")) <= expected["budget_bytes"]

    recovered = retrieve_payload(store, root=root, session_id="crash-session", budget=32 * 1024)
    assert first == recovered == expected
    assert pending.exists(), "a pre-output crash must leave the replay cache pending"
    assert commit_payload_delivery(
        root=root, session_id="crash-session", snapshot_id=str(recovered["snapshot_id"]),
    ) is True
    assert not pending.exists()
    assert retrieve_payload(
        store, root=root, session_id="crash-session", budget=32 * 1024,
    )["status"] == "already_delivered"
