from __future__ import annotations

import json

from imprint.health import health_report
from imprint.store import ImprintStore


def _config(root):
    hooks = root / "hooks"
    hooks.mkdir(parents=True)
    for name in ("session_start.py", "user_prompt_submit.py", "stop_capture.py", "health_check.py"):
        (hooks / name).write_text("# test\n")
    return {
        "compiler": True, "context_budget_bytes": 32768,
        "experimental": {"digest": False, "profile_learning": False},
        "hooks_dir": str(hooks),
    }


def test_health_reports_fresh_bare_lock_as_invalid_but_not_stale(tmp_path):
    root = tmp_path / "operator"
    root.mkdir()
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    (root / "compiler.lock").mkdir()
    report = health_report(root, store, _config(root), deep=True)
    assert report["status"] == "degraded"
    assert report["metrics"]["stale_lock_count"] == 0
    assert report["metrics"]["compiler_state"] == "invalid"
    assert "compiler_lock_invalid" in report["degraded_reasons"]
    assert "stale_lock_present" not in report["degraded_reasons"]
    encoded = json.dumps(report)
    assert str(root) not in encoded


def test_shallow_health_does_not_claim_unrun_checks_and_fresh_store_is_not_degraded(tmp_path):
    root = tmp_path / "operator"
    root.mkdir()
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    report = health_report(root, store, _config(root))
    assert report["metrics"]["projection_snapshot_present"] is False
    assert report["metrics"]["backup_state"] == "never_created"
    assert report["metrics"]["database_state"] == "present"
    assert report["metrics"]["migration_state"] == "not_checked"
    assert report["status"] == "healthy"
