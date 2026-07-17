import json

import pytest

from imprint.health import HealthInputs, evaluate_health


def healthy(**changes):
    values = dict(compiler_count=1, database_state="verified", migration_state="current", check_mode="deep")
    values.update(changes)
    return evaluate_health(HealthInputs(**values))


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"compiler_count": 0}, "compiler_missing"),
        ({"compiler_count": 2}, "compiler_duplicate"),
        ({"database_state": "invalid"}, "database_integrity_failed"),
        ({"migration_state": "invalid"}, "migration_invalid"),
        ({"config_ok": False}, "config_invalid"),
        ({"spool_depth": 1, "oldest_spool_age_seconds": 3601}, "spool_stale"),
        ({"selected_bytes": 33000}, "retrieval_budget_violated"),
        ({"stale_lock_count": 1}, "stale_lock_present"),
        ({"abandoned_temp_count": 1}, "abandoned_temp_present"),
        ({"backup_state": "invalid"}, "backup_unverified"),
    ],
)
def test_required_failures_turn_health_red(changes, reason):
    report = healthy(**changes)
    assert report.status == "red" and report.exit_code == 1
    assert reason in report.degraded_reasons


def test_recent_activity_is_not_a_health_input_and_output_is_content_free():
    report = healthy(compiler_count=0, spool_depth=7, quarantine_count=2)
    encoded = json.dumps(report.as_dict(), sort_keys=True)
    assert "operator secret sentence" not in encoded
    assert set(report.as_dict()) == {"health_schema_version", "status", "degraded_reasons", "metrics"}
    assert "compiler_missing" in report.degraded_reasons


def test_explicit_higher_budget_is_visible_and_allowed():
    report = healthy(retrieval_budget_bytes=40 * 1024, higher_budget_explicit=True)
    assert report.status == "green"
    assert report.metrics["higher_budget_explicit"] is True
    assert healthy(retrieval_budget_bytes=40 * 1024).status == "red"


def test_unchecked_facts_and_never_backed_up_are_visible_without_false_degradation():
    report = evaluate_health(HealthInputs(
        compiler_count=1, database_state="present", migration_state="not_checked",
        backup_state="never_created",
    ))
    assert report.status == "green"
    assert report.metrics["database_evidence"] == "regular_file_presence_only"
    assert report.metrics["migration_state"] == "not_checked"
    assert report.metrics["backup_state"] == "never_created"
