"""Content-free invariant health reporting."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from imprint.constants import STORE_SCHEMA_VERSION
from .report import HealthInputs, HealthReport, evaluate_health


_TEMP_PREFIXES = (
    ".ack-", ".backup-", ".imprint-", ".owner-", ".proposal-",
    ".quarantine-", ".receipt-", ".restore-",
)
_SUPPORTED_BACKUP_RECEIPT_VERSIONS = frozenset({"1.0.0", "1.1.0"})


def _age_seconds(path: Path, now: float) -> int:
    try:
        return max(0, int(now - path.stat(follow_symlinks=False).st_mtime))
    except OSError:
        return -1


def _latest_age(paths: list[Path], now: float) -> int:
    ages = [_age_seconds(path, now) for path in paths]
    known = [age for age in ages if age >= 0]
    return min(known) if known else -1


def _temporary_residue(root: Path) -> list[Path]:
    if not root.exists():
        return []
    residue: list[Path] = []
    for path in root.rglob("*"):
        name = path.name
        if name.endswith((".tmp", ".pending.json")) or name.startswith(_TEMP_PREFIXES):
            residue.append(path)
    return residue


def _hooks_ok(hook_root: Path, required: set[str]) -> bool:
    if not hook_root.is_dir() or hook_root.is_symlink():
        return False
    for name in required:
        source = hook_root / name
        if source.is_symlink() or not source.is_file():
            return False
        try:
            if source.stat().st_size <= 0:
                return False
        except OSError:
            return False
    manifest = hook_root / "hooks.json"
    if manifest.exists():
        try:
            value = json.loads(manifest.read_text(encoding="utf-8"))
            if value.get("hook_schema_version") != "1.0.0":
                return False
            declared = {item.get("source") for item in value.get("hooks", []) if isinstance(item, dict)}
            if not required.issubset(declared):
                return False
        except (OSError, AttributeError, json.JSONDecodeError):
            return False
    return True


def health_report(root: Path, store, config: dict, *, deep: bool = False) -> dict[str, object]:
    """Inspect operational invariants without emitting captured content."""
    root = Path(root)
    now = time.time()
    database_state = "present" if store.path.is_file() and not store.path.is_symlink() else "absent"
    if deep and database_state == "present":
        try:
            database_state = "verified" if store.integrity_check() == "ok" else "invalid"
        except Exception:
            database_state = "invalid"
    spool_files = [
        path for path in (root / "spool").glob("*/*.json")
        if path.is_file() and not path.is_symlink()
    ] if deep and (root / "spool").exists() else []
    spool_ages = [_age_seconds(path, now) for path in spool_files]
    oldest_spool_age = max((age for age in spool_ages if age >= 0), default=0)
    configured_hooks = config.get("hooks_dir")
    hook_root = Path(configured_hooks) if isinstance(configured_hooks, str) else Path(__file__).resolve().parents[3] / "hooks"
    required_hooks = {"session_start.py", "user_prompt_submit.py", "stop_capture.py", "health_check.py"}
    hook_parity = _hooks_ok(hook_root, required_hooks)
    disk_free = shutil.disk_usage(root if root.exists() else root.parent).free if (root.exists() or root.parent.exists()) else 0
    from imprint.compiler import compiler_lock_state
    lock_state = compiler_lock_state(root)
    migration_state = "not_checked"
    if deep and store.path.exists():
        try:
            with store.connect() as conn:
                row = conn.execute("SELECT value FROM meta WHERE key='store_schema_version'").fetchone()
                migration_state = "current" if row and row[0] == STORE_SCHEMA_VERSION else "invalid"
        except Exception:
            migration_state = "invalid"
    projection_present = (root / "projections" / "imprint.jsonld").is_file()
    acknowledgement_files = [
        path for path in (root / "runtime" / "acknowledgements").glob("*/*.json")
        if path.is_file() and not path.is_symlink()
    ] if deep and (root / "runtime" / "acknowledgements").exists() else []
    delivery_files = [
        path for path in (root / "receipts").glob("*/*.json")
        if path.is_file() and not path.is_symlink() and not path.name.endswith(".pending.json")
    ] if deep and (root / "receipts").exists() else []
    selected_bytes = 0 if deep else -1
    omitted_count = 0 if deep else -1
    retrieval_budget = int(config.get("context_budget_bytes", 32 * 1024))
    latch_ok = True
    if delivery_files:
        latest_delivery = max(delivery_files, key=lambda path: path.stat().st_mtime)
        try:
            from imprint.retrieve.receipts import DeliveryReceipts
            delivery = DeliveryReceipts._decode_prepared(latest_delivery)
            selected_bytes = int(delivery["selected_bytes"])
            omitted_count = int(delivery["omitted_count"])
            retrieval_budget = int(delivery["budget_bytes"])
        except (OSError, ValueError, KeyError, TypeError):
            latch_ok = False
    backup_receipts = root / "backups"
    backup_state = (
        "present_unverified"
        if backup_receipts.exists() and next(backup_receipts.glob("*.receipt.json"), None)
        else "never_created"
    )
    verified_backup_count = 0
    invalid_backup_count = 0
    for receipt in backup_receipts.glob("*.receipt.json") if deep and backup_receipts.exists() else ():
        try:
            value = json.loads(receipt.read_text(encoding="utf-8"))
            backup = receipt.parent / value["file"]
            from imprint.backup import verify_backup_for_store
            verified = verify_backup_for_store(store, backup)
            if (
                value.get("backup_schema_version") not in _SUPPORTED_BACKUP_RECEIPT_VERSIONS
                or verified.get("backup_schema_version") != value.get("backup_schema_version")
                or verified.get("status") != "verified-dry-run"
            ):
                raise ValueError("backup receipt contract invalid")
            verified_backup_count += 1
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            invalid_backup_count += 1
        except Exception:
            # ValidationError is deliberately collapsed into content-free health evidence.
            invalid_backup_count += 1
    if deep:
        backup_state = (
            "invalid" if invalid_backup_count else
            "verified" if verified_backup_count else "never_created"
        )
        from imprint.permissions import unsafe_private_permissions
        unsafe_permissions = unsafe_private_permissions(root)
        temporary_residue = _temporary_residue(root)
    else:
        unsafe_permissions = []
        temporary_residue = []
    report = evaluate_health(HealthInputs(
        compiler_count=1 if config.get("compiler") else 0,
        database_state=database_state,
        migration_state=migration_state,
        check_mode="deep" if deep else "shallow",
        config_ok=True,
        hook_parity_ok=hook_parity,
        spool_depth=len(spool_files) if deep else -1,
        oldest_spool_age_seconds=oldest_spool_age if deep else -1,
        quarantine_count=(len(list((root / "quarantine").glob("*.json"))) if (root / "quarantine").exists() else 0) if deep else -1,
        permissions_state=("unsafe" if unsafe_permissions else "safe") if deep else "not_checked",
        unsafe_permission_count=len(unsafe_permissions) if deep else -1,
        selected_bytes=selected_bytes,
        retrieval_omitted_count=omitted_count,
        retrieval_budget_bytes=retrieval_budget,
        higher_budget_explicit=bool(config.get("allow_higher_budget", False)),
        projection_snapshot_present=projection_present,
        latch_state=("valid" if latch_ok else "invalid") if deep else "not_checked",
        last_compile_age_seconds=_latest_age(acknowledgement_files, now),
        last_retrieval_age_seconds=_latest_age(delivery_files, now),
        disk_free_bytes=disk_free,
        stale_lock_count=1 if lock_state.get("stale") else 0,
        abandoned_temp_count=len(temporary_residue) if deep else -1,
        backup_state=backup_state,
        verified_backup_count=verified_backup_count if deep else -1,
        invalid_backup_count=invalid_backup_count if deep else -1,
        compiler_state=str(lock_state.get("state", "invalid")),
    ))
    result = report.as_dict()
    # CLI contract uses healthy/degraded while the invariant engine remains green/red.
    result["status"] = "healthy" if report.status == "green" else "degraded"
    return result

__all__ = ["HealthInputs", "HealthReport", "evaluate_health", "health_report"]
