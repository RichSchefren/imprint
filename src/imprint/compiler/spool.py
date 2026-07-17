"""Per-node immutable spools. Compilation never rewrites foreign inputs."""

from __future__ import annotations

import json
import hashlib
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from imprint.errors import ConflictError, SafetyError, ValidationError
from imprint.durable_io import publish_new_private, replace_private
from imprint.capture.schema import validate_capture_envelope
from imprint.ontology.schema import canonical_bytes, payload_sha256
from imprint.permissions import secure_directory, secure_file, secure_tree
from imprint.store import ImprintStore

LOCK_STALE_SECONDS = 300
CAPTURE_BATCH_SIZE = 100
INVALID_LOCK_CONFIRMATION = "RECOVER-INVALID-LOCK"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _lock_owner_path(operator_root: Path) -> Path:
    return operator_root / "compiler.lock" / "owner.json"


def _write_lock_owner(path: Path, owner: dict[str, Any]) -> None:
    data = json.dumps(owner, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    replace_private(path, data)


def _local_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _lease_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("lease timestamp must be UTC")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("lease timestamp must be timezone-aware UTC")
    return parsed


def _compiler_lock_directory_state(lock: Path) -> dict[str, Any]:
    if not lock.exists():
        return {"state": "absent", "stale": False}
    owner_path = lock / "owner.json"
    try:
        owner = json.loads(owner_path.read_text(encoding="ascii"))
        if not isinstance(owner, dict) or set(owner) != {
            "lock_schema_version", "nonce", "pid", "host", "created_at", "heartbeat_at",
        }:
            raise ValueError("lease fields are invalid")
        created = _lease_timestamp(owner["created_at"])
        heartbeat = _lease_timestamp(owner["heartbeat_at"])
        valid = (
            owner["lock_schema_version"] == "1.0.0"
            and isinstance(owner["nonce"], str) and len(owner["nonce"]) == 32
            and all(ch in "0123456789abcdef" for ch in owner["nonce"])
            and isinstance(owner["pid"], int) and not isinstance(owner["pid"], bool) and owner["pid"] > 0
            and isinstance(owner["host"], str) and bool(owner["host"].strip())
            and owner["host"] == owner["host"].strip() and "\x00" not in owner["host"]
            and heartbeat >= created
        )
        if not valid:
            raise ValueError("lease values are invalid")
        age = max(0, int((datetime.now(timezone.utc) - heartbeat).total_seconds()))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        try:
            age = max(0, int(datetime.now(timezone.utc).timestamp() - lock.stat().st_mtime))
        except OSError:
            age = -1
        return {
            "state": "invalid",
            "stale": age >= LOCK_STALE_SECONDS,
            "age_seconds": age,
        }
    local_owner = owner["host"] == socket.gethostname()
    pid_alive = _local_pid_alive(owner["pid"]) if local_owner else None
    stale = age >= LOCK_STALE_SECONDS and (not local_owner or pid_alive is False)
    return {"state": "held", "stale": stale,
            "age_seconds": age, "nonce": owner.get("nonce"), "host": owner.get("host"),
            "pid": owner.get("pid"), "local_owner": local_owner, "pid_alive": pid_alive}


def compiler_lock_state(operator_root: Path) -> dict[str, Any]:
    return _compiler_lock_directory_state(Path(operator_root) / "compiler.lock")


def recover_stale_compiler_lock(operator_root: Path, *, confirmation: str) -> dict[str, Any]:
    """Atomically claim and remove only a stale, Imprint-owned lease directory."""
    root = Path(operator_root)
    lock = root / "compiler.lock"
    if lock.is_symlink() or (lock.exists() and not lock.is_dir()):
        raise SafetyError("compiler lock must be a real directory")
    state = compiler_lock_state(root)
    if state.get("state") == "absent":
        return {"status": "absent"}
    if not state.get("stale"):
        raise SafetyError("compiler lock is not stale; recovery refused")
    nonce = state.get("nonce")
    required = nonce if nonce else INVALID_LOCK_CONFIRMATION
    if confirmation != required:
        label = "exact owner nonce" if nonce else INVALID_LOCK_CONFIRMATION
        raise SafetyError(f"stale lock recovery requires {label}")

    try:
        before = lock.stat(follow_symlinks=False)
        owner_before = (lock / "owner.json").read_bytes() if (lock / "owner.json").is_file() else None
        names = {item.name for item in lock.iterdir()}
    except OSError as exc:
        raise SafetyError("compiler lock changed during recovery inspection") from exc
    def owned_temporary(name: str) -> bool:
        if not name.endswith(".tmp"):
            return False
        if nonce:
            return name == f".owner-{nonce}.tmp" or name.startswith(f".owner-{nonce}-")
        prefix = name.removeprefix(".owner-").split("-", 1)[0]
        return len(prefix) == 32 and all(character in "0123456789abcdef" for character in prefix)

    allowed = {"owner.json"}
    allowed.update(name for name in names if owned_temporary(name))
    if names - allowed:
        raise SafetyError("compiler lock contains unowned residue; recovery refused")

    # Recheck immediately before claiming. In particular, a compiler owns the
    # directory from mkdir onward even though owner.json is written next.
    rechecked = compiler_lock_state(root)
    try:
        rechecked_stat = lock.stat(follow_symlinks=False)
    except OSError as exc:
        raise SafetyError("compiler lock changed before recovery claim") from exc
    if (
        not rechecked.get("stale")
        or rechecked.get("state") != state.get("state")
        or rechecked.get("nonce") != state.get("nonce")
        or (rechecked_stat.st_dev, rechecked_stat.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise SafetyError("compiler lock changed before recovery claim")

    claimed = root / f".compiler-lock-recovery-{uuid.uuid4().hex}"
    try:
        os.replace(lock, claimed)
    except OSError as exc:
        raise SafetyError("compiler lock changed before recovery claim") from exc
    try:
        secure_tree(claimed)
        after = claimed.stat(follow_symlinks=False)
        owner_after = (claimed / "owner.json").read_bytes() if (claimed / "owner.json").is_file() else None
        claimed_state = _compiler_lock_directory_state(claimed)
        if (
            not claimed_state.get("stale")
            or claimed_state.get("state") != state.get("state")
            or claimed_state.get("nonce") != state.get("nonce")
        ):
            raise SafetyError("compiler lock ownership changed during recovery claim")
        if (before.st_dev, before.st_ino, owner_before) != (after.st_dev, after.st_ino, owner_after):
            raise SafetyError("compiler lock changed during recovery claim")
        for item in tuple(claimed.iterdir()):
            if item.name == "owner.json" or owned_temporary(item.name):
                if item.is_symlink() or not item.is_file():
                    raise SafetyError("compiler lock residue is not a regular file")
                item.unlink()
            else:
                raise SafetyError("compiler lock contains unowned residue; recovery refused")
        claimed.rmdir()
    except Exception:
        if claimed.exists() and not lock.exists():
            try:
                os.replace(claimed, lock)
                secure_tree(lock)
            except OSError:
                pass
        raise
    if nonce:
        return {"status": "recovered", "nonce": nonce}
    return {"status": "recovered", "nonce": None, "recovery_mode": "invalid-explicit"}


def acknowledgement_committed(operator_root: Path, path: Path, envelope: dict[str, Any]) -> bool:
    """Verify exact durable commit evidence for one queued spool envelope."""
    target = _ack_path(Path(operator_root), envelope)
    try:
        if target.is_symlink() or not target.is_file():
            return False
        ack = json.loads(target.read_text(encoding="ascii"))
        required = {
            "ack_schema_version", "input_event_id", "node_id", "payload_sha256",
            "source_file_sha256", "source_path", "committed", "compiler_result",
            "acknowledged_at",
        }
        return (
            set(ack) == required
            and ack["ack_schema_version"] == "1.0.0"
            and ack["committed"] is True
            and ack["input_event_id"] == envelope["input_event_id"]
            and ack["node_id"] == envelope["node_id"]
            and ack["payload_sha256"] == payload_sha256(envelope)
            and ack["source_file_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
            and ack["source_path"] == path.relative_to(operator_root).as_posix()
            and ack["compiler_result"] in {"captured", "duplicate"}
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _quarantine_receipt(operator_root: Path, path: Path, error: Exception) -> None:
    """Record a content-free failure receipt without moving foreign input."""
    relative = path.relative_to(operator_root).as_posix()
    receipt_id = hashlib.sha256(relative.encode("utf-8")).hexdigest()
    directory = operator_root / "quarantine"
    secure_directory(directory)
    final = directory / f"{receipt_id}.json"
    body = json.dumps({
        "quarantine_schema_version": "1.0.0",
        "receipt_id": receipt_id,
        "error_type": type(error).__name__,
        "content_included": False,
        "recorded_at": _now(),
    }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if final.exists():
        secure_file(final)
        return
    try:
        publish_new_private(final, body)
    except SafetyError:
        if not final.exists():
            raise
    if final.exists():
        secure_file(final)


def _ack_path(operator_root: Path, envelope: dict[str, Any]) -> Path:
    node = envelope["node_id"]
    event = envelope["input_event_id"].rsplit(":", 1)[-1]
    return operator_root / "runtime" / "acknowledgements" / node / f"{event}.json"


def _write_acknowledgement(
    operator_root: Path, path: Path, envelope: dict[str, Any], result: str,
) -> None:
    """Persist content-free commit proof; never rewrite the source spool."""
    target = _ack_path(operator_root, envelope)
    secure_directory(target.parent)
    if target.parent.is_symlink():
        raise SafetyError("acknowledgement directory must not be a symlink")
    body = {
        "ack_schema_version": "1.0.0",
        "input_event_id": envelope["input_event_id"],
        "node_id": envelope["node_id"],
        "payload_sha256": payload_sha256(envelope),
        "source_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "source_path": path.relative_to(operator_root).as_posix(),
        "committed": True,
        "compiler_result": result,
        "acknowledged_at": _now(),
    }
    def matches_prior() -> bool:
        prior = json.loads(target.read_text(encoding="ascii"))
        stable = set(body) - {"acknowledged_at", "compiler_result"}
        return all(prior.get(key) == body[key] for key in stable)

    if target.exists():
        secure_file(target)
        if not matches_prior():
            raise ConflictError("acknowledgement identity conflicts with committed input")
        return
    try:
        publish_new_private(
            target,
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n",
        )
    except SafetyError:
        if not target.exists() or not matches_prior():
            raise ConflictError("acknowledgement identity conflicts with committed input")
    if target.exists():
        secure_file(target)


def prune_acknowledged_spools(
    operator_root: Path, *, source_node_id: str, retention_days: int,
    now: datetime | None = None,
) -> dict[str, int]:
    """Delete only this producer's old spool inputs after exact commit proof."""
    if retention_days < 1:
        raise SafetyError("spool retention must be at least one day")
    if not source_node_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in source_node_id):
        raise SafetyError("source node identity is unsafe")
    root = Path(operator_root)
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise SafetyError("retention clock must be timezone-aware")
    threshold = clock.astimezone(timezone.utc) - timedelta(days=retention_days)
    ack_root = root / "runtime" / "acknowledgements" / source_node_id
    counts = {
        "deleted": 0, "retained": 0, "already_pruned": 0,
        "acknowledgements_deleted": 0, "quarantine_deleted": 0,
        "invalid": 0,
    }
    for ack_path in sorted(ack_root.glob("*.json")) if ack_root.exists() else ():
        try:
            if ack_path.is_symlink() or not ack_path.is_file():
                raise SafetyError("acknowledgement is not a regular file")
            ack = json.loads(ack_path.read_text(encoding="ascii"))
            required = {
                "ack_schema_version", "input_event_id", "node_id", "payload_sha256",
                "source_file_sha256", "source_path", "committed", "compiler_result",
                "acknowledged_at",
            }
            if set(ack) != required or ack["ack_schema_version"] != "1.0.0" or ack["committed"] is not True:
                raise SafetyError("acknowledgement contract is invalid")
            if ack["node_id"] != source_node_id:
                raise SafetyError("acknowledgement belongs to another producer")
            acknowledged = datetime.fromisoformat(ack["acknowledged_at"].replace("Z", "+00:00"))
            relative = Path(ack["source_path"])
            event = ack["input_event_id"].rsplit(":", 1)[-1]
            if (
                relative.is_absolute()
                or relative.parts != ("spool", source_node_id, f"{event}.json")
            ):
                raise SafetyError("acknowledgement source escapes its producer spool")
            source = root / relative
            if not source.exists():
                # Legacy releases left the acknowledgement after deleting its
                # exact source. That is a completed prune, not corruption.
                ack_path.unlink()
                counts["already_pruned"] += 1
                counts["acknowledgements_deleted"] += 1
                continue
            expected_parent = (root / "spool" / source_node_id).resolve(strict=True)
            resolved_source = source.resolve(strict=True)
            if resolved_source.parent != expected_parent or source.is_symlink() or not source.is_file():
                raise SafetyError("acknowledgement source escapes its producer spool")
            raw = source.read_bytes()
            value = validate_capture_envelope(json.loads(raw))
            if value["input_event_id"] != ack["input_event_id"]:
                raise SafetyError("acknowledgement event does not match source")
            if payload_sha256(value) != ack["payload_sha256"] or hashlib.sha256(raw).hexdigest() != ack["source_file_sha256"]:
                raise SafetyError("acknowledgement hash does not match source")
            if acknowledged.astimezone(timezone.utc) > threshold:
                counts["retained"] += 1
                continue
            source.unlink()
            ack_path.unlink()
            counts["deleted"] += 1
            counts["acknowledgements_deleted"] += 1
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, SafetyError):
            counts["invalid"] += 1
    quarantine = root / "quarantine"
    for receipt in sorted(quarantine.glob("*.json")) if quarantine.exists() else ():
        try:
            if receipt.is_symlink() or not receipt.is_file():
                raise SafetyError("quarantine receipt is not a regular file")
            value = json.loads(receipt.read_text(encoding="ascii"))
            expected = {"quarantine_schema_version", "receipt_id", "error_type", "content_included"}
            if "recorded_at" in value:
                expected.add("recorded_at")
            if (
                set(value) != expected
                or value["quarantine_schema_version"] != "1.0.0"
                or value["content_included"] is not False
            ):
                raise SafetyError("quarantine receipt contract is invalid")
            recorded = (
                datetime.fromisoformat(value["recorded_at"].replace("Z", "+00:00"))
                if "recorded_at" in value
                else datetime.fromtimestamp(receipt.stat().st_mtime, tz=timezone.utc)
            )
            if recorded.astimezone(timezone.utc) <= threshold:
                receipt.unlink()
                counts["quarantine_deleted"] += 1
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, SafetyError):
            counts["invalid"] += 1
    return counts


def write_envelope(operator_root: Path, envelope: dict[str, Any]) -> Path:
    validate_capture_envelope(envelope)
    node_id = envelope["node_id"]
    event_id = envelope["input_event_id"].rsplit(":", 1)[-1]
    spool = operator_root / "spool" / node_id
    secure_directory(spool)
    final = spool / f"{event_id}.json"
    data = canonical_bytes(envelope) + b"\n"
    if final.exists():
        secure_file(final)
        if final.read_bytes() == data:
            return final
        raise ConflictError("same spool event path contains different bytes")
    try:
        publish_new_private(final, data)
    except SafetyError:
        if final.exists() and final.read_bytes() == data:
            return final
        raise
    return final


def compile_spools(
    operator_root: Path, store: ImprintStore, *, compiler_authorized: bool,
    retention_days: int = 30, batch_size: int = CAPTURE_BATCH_SIZE,
) -> dict[str, int]:
    if not compiler_authorized:
        raise SafetyError("canonical mutation requires explicit compiler authority")
    lock = operator_root / "compiler.lock"
    secure_directory(operator_root)
    nonce = uuid.uuid4().hex
    try:
        lock.mkdir()
    except FileExistsError as exc:
        state = compiler_lock_state(operator_root)
        raise SafetyError(f"compiler lock already held; refusing a second writer; state={state['state']} nonce={state.get('nonce','unknown')}") from exc
    secure_directory(lock)
    try:
        owner = {
            "lock_schema_version": "1.0.0", "nonce": nonce, "pid": os.getpid(),
            "host": socket.gethostname(), "created_at": _now(), "heartbeat_at": _now(),
        }
        _write_lock_owner(_lock_owner_path(operator_root), owner)
        store.initialize()
        inputs = []
        producer_nodes: set[str] = set()
        counts = {"captured": 0, "duplicate": 0, "quarantined": 0}
        for path in sorted((operator_root / "spool").glob("*/*.json")):
            try:
                raw = path.read_text(encoding="utf-8")
            except UnicodeError as exc:
                _quarantine_receipt(operator_root, path, exc)
                counts["quarantined"] += 1
                continue
            except OSError:
                # Filesystem failure is infrastructure failure. Quarantine is
                # reserved for content that was successfully read and rejected.
                raise
            try:
                envelope = json.loads(raw)
                if not isinstance(envelope, dict):
                    raise ValueError("spool payload must be an object")
                envelope = validate_capture_envelope(envelope)
            except (UnicodeError, json.JSONDecodeError, ValueError, ValidationError) as exc:
                _quarantine_receipt(operator_root, path, exc)
                counts["quarantined"] += 1
                continue
            if acknowledgement_committed(operator_root, path, envelope):
                producer_nodes.add(envelope["node_id"])
                continue
            producer_nodes.add(envelope["node_id"])
            inputs.append((envelope.get("captured_at", ""), envelope.get("input_event_id", ""), path, envelope))
        ordered = sorted(inputs)
        batch_results = store.apply_capture_batch(
            [
                (envelope, path.relative_to(operator_root).as_posix())
                for _, _, path, envelope in ordered
            ],
            batch_size=batch_size,
        )
        for (_, _, path, envelope), result in zip(ordered, batch_results, strict=True):
            if isinstance(result, (ValidationError, ConflictError)):
                exc = result
                _quarantine_receipt(operator_root, path, exc)
                counts["quarantined"] += 1
            else:
                # Acknowledgement failures are infrastructure failures. They must
                # propagate so callers never claim canonical success without proof.
                _write_acknowledgement(operator_root, path, envelope, result)
                counts[result] += 1
            owner["heartbeat_at"] = _now()
            _write_lock_owner(_lock_owner_path(operator_root), owner)
        for source_node_id in sorted(producer_nodes):
            prune_acknowledged_spools(
                operator_root, source_node_id=source_node_id,
                retention_days=retention_days,
            )
        return counts
    finally:
        try:
            owner_path = _lock_owner_path(operator_root)
            current = json.loads(owner_path.read_text(encoding="ascii"))
            if current.get("nonce") == nonce:
                owner_path.unlink()
                lock.rmdir()
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            pass
        secure_tree(operator_root)
