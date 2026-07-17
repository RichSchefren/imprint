from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

HEALTH_SCHEMA_VERSION = "1.1.0"


@dataclass(frozen=True)
class HealthInputs:
    compiler_count: int
    database_state: Literal["absent", "present", "verified", "invalid"]
    migration_state: Literal["not_checked", "current", "invalid"]
    check_mode: Literal["shallow", "deep"] = "shallow"
    config_ok: bool = True
    hook_parity_ok: bool = True
    spool_depth: int = -1
    oldest_spool_age_seconds: int = -1
    spool_stale_after_seconds: int = 3600
    quarantine_count: int = -1
    permissions_state: Literal["not_checked", "safe", "unsafe"] = "not_checked"
    unsafe_permission_count: int = -1
    selected_bytes: int = -1
    retrieval_omitted_count: int = -1
    retrieval_budget_bytes: int = 32 * 1024
    higher_budget_explicit: bool = False
    latch_state: Literal["not_checked", "valid", "invalid"] = "not_checked"
    projection_snapshot_present: bool = False
    last_compile_age_seconds: int = -1
    last_retrieval_age_seconds: int = -1
    disk_free_bytes: int = 1
    stale_lock_count: int = 0
    abandoned_temp_count: int = -1
    backup_state: Literal["never_created", "present_unverified", "verified", "invalid"] = "never_created"
    verified_backup_count: int = -1
    invalid_backup_count: int = -1
    compiler_state: Literal["absent", "held", "invalid"] = "absent"


@dataclass(frozen=True)
class HealthReport:
    health_schema_version: str
    status: Literal["green", "red"]
    degraded_reasons: tuple[str, ...]
    metrics: dict[str, int | bool | str]

    @property
    def exit_code(self) -> int:
        return 0 if self.status == "green" else 1

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_health(values: HealthInputs) -> HealthReport:
    """Evaluate only facts the caller actually observed.

    ``not_checked`` and ``present_unverified`` are explicit states, never
    synthetic success claims. A new store with no backup is visible but is not
    degraded; an observed invalid backup is.
    """
    reasons: list[str] = []
    if values.compiler_count == 0:
        reasons.append("compiler_missing")
    elif values.compiler_count > 1:
        reasons.append("compiler_duplicate")
    if values.database_state == "absent":
        reasons.append("database_missing")
    elif values.database_state == "invalid":
        reasons.append("database_integrity_failed")
    if values.migration_state == "invalid":
        reasons.append("migration_invalid")
    if not values.config_ok:
        reasons.append("config_invalid")
    if not values.hook_parity_ok:
        reasons.append("hook_parity_failed")
    if (
        values.spool_depth > 0
        and values.oldest_spool_age_seconds > values.spool_stale_after_seconds
    ):
        reasons.append("spool_stale")
    if values.quarantine_count > 0:
        reasons.append("quarantine_present")
    if values.permissions_state == "unsafe" or values.unsafe_permission_count > 0:
        reasons.append("unsafe_permissions")
    if values.selected_bytes > values.retrieval_budget_bytes:
        reasons.append("retrieval_budget_violated")
    if values.retrieval_budget_bytes > 32 * 1024 and not values.higher_budget_explicit:
        reasons.append("retrieval_budget_unapproved")
    if values.latch_state == "invalid":
        reasons.append("domain_latch_unsafe")
    if values.disk_free_bytes <= 0:
        reasons.append("disk_space_exhausted")
    if values.stale_lock_count > 0:
        reasons.append("stale_lock_present")
    if values.compiler_state == "invalid":
        reasons.append("compiler_lock_invalid")
    if values.abandoned_temp_count > 0:
        reasons.append("abandoned_temp_present")
    if values.backup_state == "invalid":
        reasons.append("backup_unverified")

    metrics: dict[str, int | bool | str] = {
        "check_mode": values.check_mode,
        "compiler_count": values.compiler_count,
        "compiler_state": values.compiler_state,
        "compiler_evidence": "configured_authority_plus_compiler_lock",
        "database_state": values.database_state,
        "database_evidence": (
            "sqlite_pragma_integrity_check"
            if values.check_mode == "deep" else "regular_file_presence_only"
        ),
        "migration_state": values.migration_state,
        "hook_parity_ok": values.hook_parity_ok,
        "hook_evidence": "configured_hook_directory_required_sources",
        "spool_depth": values.spool_depth,
        "oldest_spool_age_seconds": values.oldest_spool_age_seconds,
        "quarantine_count": values.quarantine_count,
        "permissions_state": values.permissions_state,
        "unsafe_permission_count": values.unsafe_permission_count,
        "selected_bytes": values.selected_bytes,
        "retrieval_omitted_count": values.retrieval_omitted_count,
        "retrieval_budget_bytes": values.retrieval_budget_bytes,
        "higher_budget_explicit": values.higher_budget_explicit,
        "latch_state": values.latch_state,
        "projection_snapshot_present": values.projection_snapshot_present,
        "last_compile_age_seconds": values.last_compile_age_seconds,
        "last_retrieval_age_seconds": values.last_retrieval_age_seconds,
        "disk_free_bytes": max(0, values.disk_free_bytes),
        "stale_lock_count": values.stale_lock_count,
        "abandoned_temp_count": values.abandoned_temp_count,
        "backup_state": values.backup_state,
        "verified_backup_count": values.verified_backup_count,
        "invalid_backup_count": values.invalid_backup_count,
    }
    return HealthReport(
        health_schema_version=HEALTH_SCHEMA_VERSION,
        status="red" if reasons else "green",
        degraded_reasons=tuple(sorted(set(reasons))),
        metrics=metrics,
    )
