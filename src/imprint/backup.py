"""Verified SQLite backups and guarded restore operations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .constants import ONTOLOGY_SCHEMA_VERSION, STORE_SCHEMA_VERSION
from .errors import SafetyError, ValidationError
from .durable_io import publish_new_private, publish_staged_private
from .paths import validate_data_root
from .permissions import secure_directory, secure_file, secure_files
from .store import ImprintStore


_RECEIPT_FIELDS_V1 = {
    "backup_schema_version", "store_schema_version", "file", "sha256",
    "bytes", "integrity",
}
_RECEIPT_FIELDS = _RECEIPT_FIELDS_V1 | {
    "ontology_schema_version", "authenticity",
    "signing_key_id", "signature_b64",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BACKUP_DOMAIN = b"imprint-backup-receipt-v1\x00"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sidecars(path: Path) -> tuple[Path, Path, Path]:
    return (
        Path(str(path) + "-wal"),
        Path(str(path) + "-shm"),
        Path(str(path) + "-journal"),
    )


def _secure_sqlite_state(path: Path) -> None:
    """Tighten an SQLite file and any private-state sidecars that exist."""
    secure_files(candidate for candidate in (path, *_sidecars(path)) if candidate.exists())


def _write_atomic_private(path: Path, payload: str) -> None:
    """Publish UTF-8 text from a pre-secured same-directory temporary file."""
    if path.exists() or path.is_symlink():
        raise SafetyError("refusing to overwrite an existing backup receipt")
    publish_new_private(path, payload.encode("utf-8"))


def _inspect_database(path: Path) -> dict[str, str]:
    """Validate a closed standalone database without creating sidecars."""
    if any(sidecar.exists() for sidecar in _sidecars(path)):
        raise ValidationError("database has WAL/SHM/journal sidecars and is not a closed backup")
    try:
        resolved = path.resolve(strict=True)
        if path.is_symlink() or not resolved.is_file():
            raise ValidationError("database must be a regular non-symlink file")
        connection = sqlite3.connect(
            f"{resolved.as_uri()}?mode=ro&immutable=1", uri=True, timeout=5,
        )
        try:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            store_row = connection.execute(
                "SELECT value FROM meta WHERE key='store_schema_version'"
            ).fetchone()
            ontology_row = connection.execute(
                "SELECT value FROM meta WHERE key='ontology_schema_version'"
            ).fetchone()
        finally:
            connection.close()
    except ValidationError:
        raise
    except (OSError, sqlite3.DatabaseError, TypeError) as exc:
        raise ValidationError("database is corrupt or missing schema metadata") from exc
    if integrity != "ok":
        raise ValidationError(f"backup integrity failed: {integrity}")
    if not store_row or store_row[0] != STORE_SCHEMA_VERSION:
        raise ValidationError("backup store schema is incompatible")
    if not ontology_row or ontology_row[0] not in {"3.0.0", "3.0.1", ONTOLOGY_SCHEMA_VERSION}:
        raise ValidationError("backup ontology schema is incompatible")
    return {
        "integrity": integrity,
        "store_schema_version": str(store_row[0]),
        "ontology_schema_version": str(ontology_row[0]),
    }


def _validate_receipt(receipt: Any, target: Path) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ValidationError("backup receipt has unknown or missing fields")
    version = receipt.get("backup_schema_version")
    if version not in {"1.0.0", "1.1.0"}:
        raise ValidationError("unsupported backup receipt schema")
    expected_fields = _RECEIPT_FIELDS_V1 if version == "1.0.0" else _RECEIPT_FIELDS
    if set(receipt) != expected_fields:
        raise ValidationError("backup receipt has unknown or missing fields")
    if receipt["store_schema_version"] != STORE_SCHEMA_VERSION:
        raise ValidationError("backup schema does not match supported store schema")
    if version == "1.1.0":
        if receipt["ontology_schema_version"] not in {"3.0.0", "3.0.1", ONTOLOGY_SCHEMA_VERSION}:
            raise ValidationError("backup ontology schema is incompatible")
        if receipt["authenticity"] not in {"corruption-detection-only", "signed-authority-snapshot"}:
            raise ValidationError("backup authenticity label is invalid")
        if receipt["authenticity"] == "corruption-detection-only" and (
            receipt["signing_key_id"] is not None or receipt["signature_b64"] is not None
        ):
            raise ValidationError("unsigned backup has contradictory signing fields")
    if receipt["file"] != target.name or receipt["integrity"] != "ok":
        raise ValidationError("backup receipt identity or integrity claim is invalid")
    if not isinstance(receipt["sha256"], str) or not _SHA256.fullmatch(receipt["sha256"]):
        raise ValidationError("backup receipt hash is invalid")
    if (
        not isinstance(receipt["bytes"], int) or isinstance(receipt["bytes"], bool)
        or receipt["bytes"] <= 0
    ):
        raise ValidationError("backup receipt byte count is invalid")
    return receipt


def _safe_backup_path(root: Path, output: Path | None) -> Path:
    root = validate_data_root(root)
    backups = root / "backups"
    target = output or backups / f"imprint-{_stamp()}.sqlite3"
    target = target.expanduser().resolve(strict=False)
    if target == root or target == Path(target.anchor) or target == Path.home().resolve():
        raise SafetyError("backup target must be a file below a safe directory")
    if target.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise SafetyError("backup target must end in .db, .sqlite, or .sqlite3")
    validate_data_root(target.parent)
    return target


def create_backup(
    store: ImprintStore, root: Path, output: Path | None = None, *,
    signing_key: Ed25519PrivateKey | None = None, signing_key_id: str | None = None,  # gitleaks:allow -- a type annotation
    authority_service: Any | None = None, signing_console: Any | None = None,
) -> dict[str, Any]:
    if not store.path.exists():
        raise ValidationError("canonical database does not exist")
    target = _safe_backup_path(root, output)
    secure_directory(target.parent)
    if target.exists():
        raise SafetyError("refusing to overwrite an existing backup")
    if authority_service is not None and (signing_key is not None or signing_key_id is not None):
        raise ValidationError("raw and authority-service backup signing are mutually exclusive")
    if authority_service is not None:
        if authority_service.store.path.resolve() != store.path.resolve():
            raise ValidationError("backup authority service is bound to another store")

    def snapshot_payload(active_signing_key_id: str | None) -> dict[str, Any]:
        fd, temporary_name = tempfile.mkstemp(
            prefix=".backup-", suffix=".sqlite3", dir=target.parent,
        )
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            secure_file(temporary)
            source = sqlite3.connect(store.path)
            destination = sqlite3.connect(temporary)
            try:
                _secure_sqlite_state(store.path)
                _secure_sqlite_state(temporary)
                source.backup(destination)
            finally:
                destination.close()
                source.close()
                _secure_sqlite_state(store.path)
                _secure_sqlite_state(temporary)
            inspected = _inspect_database(temporary)
            secure_file(temporary)
            publish_staged_private(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        secure_file(target)
        return {
            "backup_schema_version": "1.1.0",
            "store_schema_version": STORE_SCHEMA_VERSION,
            "ontology_schema_version": inspected["ontology_schema_version"],
            "file": target.name,
            "sha256": _sha256(target),
            "bytes": target.stat().st_size,
            "integrity": inspected["integrity"],
            "authenticity": "signed-authority-snapshot" if active_signing_key_id else "corruption-detection-only",
            "signing_key_id": active_signing_key_id,
            "signature_b64": None,
        }

    checkpoint = None
    if authority_service is not None:
        try:
            signed = authority_service.sign_backup_snapshot(
                snapshot_payload, console=signing_console,
            )
        except Exception:
            target.unlink(missing_ok=True)
            raise
        receipt = signed["payload"]
        if signed["signer_key_id"] != receipt["signing_key_id"]:
            target.unlink(missing_ok=True)
            raise ValidationError("backup signer changed during snapshot approval")
        receipt["signature_b64"] = signed["signature_b64"]
        checkpoint = signed["checkpoint"]
    else:
        receipt = snapshot_payload(signing_key_id if signing_key else None)
    if authority_service is None and (signing_key is None) != (signing_key_id is None):
        target.unlink(missing_ok=True)
        raise ValidationError("backup signing key and key ID must be supplied together")
    if signing_key is not None:
        unsigned = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
        receipt["signature_b64"] = base64.b64encode(
            signing_key.sign(_BACKUP_DOMAIN + unsigned)
        ).decode("ascii")
    receipt_path = target.with_suffix(target.suffix + ".receipt.json")
    checkpoint_path = None
    checkpoint_file = target.with_suffix(
        target.suffix + ".authority-checkpoint.json"
    )
    try:
        _write_atomic_private(receipt_path, json.dumps(receipt, sort_keys=True) + "\n")
        if checkpoint is not None:
            _write_atomic_private(
                checkpoint_file, json.dumps(checkpoint, sort_keys=True) + "\n",
            )
            checkpoint_path = str(checkpoint_file)
    except Exception:
        checkpoint_file.unlink(missing_ok=True)
        receipt_path.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        raise
    return {
        **receipt, "path": str(target), "receipt_path": str(receipt_path),
        "authority_checkpoint": checkpoint,
        "authority_checkpoint_path": checkpoint_path,
    }


def verify_backup(path: Path, *, trusted_public_key: Ed25519PublicKey | None = None) -> dict[str, Any]:
    supplied = path.expanduser()
    if supplied.is_symlink():
        raise ValidationError("backup must be a regular non-symlink file")
    target = supplied.resolve(strict=True)
    receipt_path = target.with_suffix(target.suffix + ".receipt.json")
    if not receipt_path.exists() or receipt_path.is_symlink():
        raise ValidationError("backup receipt is missing")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError("backup receipt is corrupt") from exc
    receipt = _validate_receipt(receipt, target)
    actual_hash = _sha256(target)
    if actual_hash != receipt["sha256"]:
        raise ValidationError("backup hash does not match receipt")
    if receipt["bytes"] != target.stat().st_size:
        raise ValidationError("backup receipt byte count is invalid")
    inspected = _inspect_database(target)
    if (
        receipt["backup_schema_version"] == "1.1.0"
        and inspected["ontology_schema_version"] != receipt["ontology_schema_version"]
    ):
        raise ValidationError("backup receipt ontology version does not match database")
    authority_preserved = False
    authenticity = receipt.get("authenticity", "corruption-detection-only")
    if authenticity == "signed-authority-snapshot":
        if trusted_public_key is None:
            raise ValidationError("signed backup requires a trusted Ed25519 public key")
        unsigned = {**receipt, "signature_b64": None}
        try:
            signature = base64.b64decode(receipt["signature_b64"], validate=True)
            payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
            trusted_public_key.verify(signature, _BACKUP_DOMAIN + payload)
        except (TypeError, ValueError, base64.binascii.Error, InvalidSignature) as exc:
            raise ValidationError("backup signature is invalid") from exc
        authority_preserved = True
    return {
        "status": "verified", "path": str(target), "sha256": actual_hash,
        "bytes": receipt["bytes"],
        **inspected, "backup_schema_version": receipt["backup_schema_version"],
        "authenticity": authenticity,
        "signing_key_id": receipt.get("signing_key_id"),
        "authority_preserved": authority_preserved,
    }


def _receipt_for(path: Path) -> dict[str, Any]:
    receipt_path = path.with_suffix(path.suffix + ".receipt.json")
    if not receipt_path.exists() or receipt_path.is_symlink():
        raise ValidationError("backup receipt is missing")
    try:
        return _validate_receipt(
            json.loads(receipt_path.read_text(encoding="utf-8")), path,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError("backup receipt is corrupt") from exc


def _backup_authority_rows(path: Path) -> int:
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
    try:
        return int(connection.execute("SELECT COUNT(*) FROM authority_ledger").fetchone()[0])
    finally:
        connection.close()


def _verify_backup_authority(
    path: Path, receipt: Mapping[str, Any], *, expected_operator_id: str | None,
    expected_store_identity: str | None, checkpoint: Mapping[str, Any] | None,
    pinned_head: Mapping[str, Any] | None, now: datetime | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not expected_operator_id:
        raise ValidationError("destination operator identity is required")
    if checkpoint is None:
        raise ValidationError("a physically supplied fresh authority checkpoint is required")
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        from imprint.authority.keys import public_key_from_b64
        from imprint.authority.ledger import verify_authority_chain
        chain = verify_authority_chain(
            connection, expected_operator_id=expected_operator_id,
            expected_store_identity=expected_store_identity,
            checkpoint=checkpoint, pinned_head=pinned_head,
            now=now or datetime.now(timezone.utc),
        )
    finally:
        connection.close()
    signer = chain["keys"].get(receipt.get("signing_key_id"))
    if (
        not isinstance(signer, Mapping)
        or signer.get("kind") != "installation"
        or signer.get("status") != "active"
        or signer.get("paired") is not True
    ):
        raise ValidationError("backup signer is not an active paired installation key")
    verified = verify_backup(
        path, trusted_public_key=public_key_from_b64(signer["public_key_b64"]),
    )
    if verified["authority_preserved"] is not True or chain["checkpoint"] is None:
        raise ValidationError("backup authority was not preserved")
    return verified, chain


def _quarantine_backup(
    source: Path, directory: Path, *, receipt: Mapping[str, Any], reason: str,
) -> Path:
    """Atomically publish exact backup bytes plus a closed imported-floor envelope."""
    digest = _sha256(source)
    directory = secure_directory(directory)
    target = directory / f"foreign-backup-{digest}.quarantine"
    if target.exists():
        artifact = target / "artifact.sqlite3"
        metadata = target / "metadata.json"
        if not target.is_dir() or _sha256(artifact) != digest:
            raise SafetyError("backup quarantine digest collision")
        value = json.loads(metadata.read_text(encoding="utf-8"))
        if value.get("original_sha256") != digest:
            raise SafetyError("backup quarantine metadata collision")
        return target
    staging = Path(tempfile.mkdtemp(prefix=".backup-quarantine-", dir=directory))
    try:
        os.chmod(staging, 0o700)
        artifact = staging / "artifact.sqlite3"
        shutil.copyfile(source, artifact)
        secure_file(artifact)
        descriptor = os.open(artifact, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata = {
            "schema_version": "imprint.backup.quarantine/1.0.0",
            "authority_tier": "imported_floor",
            "disposition": "noncanonical_private_quarantine",
            "original_sha256": digest,
            "original_bytes": source.stat().st_size,
            "original_signing_key_id": receipt.get("signing_key_id"),
            "original_signature_b64": receipt.get("signature_b64"),
            "rejection_reason": reason,
            "artifact_file": "artifact.sqlite3",
        }
        publish_new_private(
            staging / "metadata.json",
            json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        os.replace(staging, target)
        if os.name != "nt":
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return target
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _require_staged_identity(path: Path, verified: dict[str, Any]) -> None:
    """Bind a staged restore candidate to the exact previously verified bytes."""
    if path.stat().st_size != verified["bytes"] or _sha256(path) != verified["sha256"]:
        raise ValidationError("staged backup bytes do not match verified source")


def restore_backup(
    store: ImprintStore, root: Path, source: Path, *, confirmation: str,
    expected_operator_id: str | None = None,
    expected_store_identity: str | None = None,
    authority_checkpoint: Mapping[str, Any] | None = None,
    pinned_authority_head: Mapping[str, Any] | None = None,
    authority_now: datetime | None = None,
    quarantine_dir: Path | None = None, dry_run: bool = False,
) -> dict[str, Any]:
    supplied_source = source.expanduser()
    if supplied_source.is_symlink():
        raise ValidationError("backup must be a regular non-symlink file")
    source = supplied_source
    source = source.resolve(strict=True)
    root = validate_data_root(root)
    receipt = _receipt_for(source)
    authority_rows = _backup_authority_rows(source)
    if authority_rows:
        try:
            if receipt.get("authenticity") != "signed-authority-snapshot":
                raise ValidationError("authority-bearing backup is unsigned")
            expected_operator_id = expected_operator_id or getattr(
                store, "expected_operator_id", None,
            )
            if (
                store.path.exists() and expected_operator_id
                and (expected_store_identity is None or pinned_authority_head is None)
            ):
                with store.connect() as local_conn:
                    local_rows = int(local_conn.execute(
                        "SELECT COUNT(*) FROM authority_ledger"
                    ).fetchone()[0])
                    if local_rows:
                        from imprint.authority.ledger import verify_authority_chain
                        local_chain = verify_authority_chain(
                            local_conn, expected_operator_id=expected_operator_id,
                        )
                        if expected_store_identity is None:
                            expected_store_identity = local_chain["store_identity"]
                        if pinned_authority_head is None:
                            pinned_authority_head = {
                                "sequence": local_chain["head_sequence"],
                                "event_sha256": local_chain["head_sha256"],
                            }
            verified, _chain = _verify_backup_authority(
                source, receipt, expected_operator_id=expected_operator_id,
                expected_store_identity=expected_store_identity,
                checkpoint=authority_checkpoint, pinned_head=pinned_authority_head,
                now=authority_now,
            )
        except ValidationError as exc:
            if not dry_run:
                _quarantine_backup(
                    source, quarantine_dir or root / "quarantine" / "imports",
                    receipt=receipt, reason=str(exc),
                )
            raise ValidationError(
                "E_BACKUP_AUTHORITY_QUARANTINED: " + str(exc)
            ) from exc
    else:
        if receipt.get("authenticity") == "signed-authority-snapshot":
            raise ValidationError("signed backup has no authority chain")
        verified = verify_backup(source)
    if dry_run:
        return {
            **verified, "status": "verified-dry-run", "source": str(source),
        }
    if confirmation != source.name:
        raise SafetyError("restore confirmation must exactly name the backup file")
    secure_directory(store.path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=".restore-", suffix=".db", dir=store.path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    rollback: Path | None = None
    live_existed = store.path.exists()
    safety = None
    try:
        secure_file(temporary)
        shutil.copyfile(source, temporary)
        secure_file(temporary)
        _inspect_database(temporary)
        _require_staged_identity(temporary, verified)
        if live_existed and any(sidecar.exists() for sidecar in _sidecars(store.path)):
            raise ValidationError("live database has WAL/SHM sidecars; close it before restore")
        if live_existed:
            safety = create_backup(store, root)
            rollback = store.path.with_name(f".restore-rollback-{os.getpid()}-{_stamp()}.db")
            try:
                os.link(store.path, rollback)
            except OSError:
                if rollback.exists() or rollback.is_symlink():
                    raise SafetyError("refusing an existing restore rollback path")
                rollback.touch(exist_ok=False)
                secure_file(rollback)
                shutil.copyfile(store.path, rollback)
            secure_file(rollback)
        # Recheck immediately before replacement so neither source substitution
        # nor staged-file replacement can cross the verified restore boundary.
        _require_staged_identity(temporary, verified)
        os.replace(temporary, store.path)
        try:
            secure_file(store.path)
            _inspect_database(store.path)
        except Exception:
            if rollback is not None:
                os.replace(rollback, store.path)
                secure_file(store.path)
            else:
                store.path.unlink(missing_ok=True)
            raise
    finally:
        temporary.unlink(missing_ok=True)
        if rollback is not None:
            rollback.unlink(missing_ok=True)
        store._compatibility_verified = False
    return {
        "status": "restored",
        "source": str(source),
        "safety_backup": safety["path"] if safety else None,
        "authenticity": verified["authenticity"],
        "authority_preserved": verified["authority_preserved"],
    }


def verify_backup_for_store(
    store: ImprintStore, path: Path, *,
    authority_checkpoint: Mapping[str, Any] | None = None,
    expected_operator_id: str | None = None,
    expected_store_identity: str | None = None,
    pinned_authority_head: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify a local backup for migration/health without permitting mutation."""
    source = Path(path)
    if authority_checkpoint is None:
        sibling = Path(str(source) + ".authority-checkpoint.json")
        if sibling.exists() and not sibling.is_symlink():
            try:
                authority_checkpoint = json.loads(sibling.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ValidationError("authority checkpoint is corrupt") from exc
    return restore_backup(
        store, store.path.parent, source, confirmation="unused", dry_run=True,
        authority_checkpoint=authority_checkpoint,
        expected_operator_id=expected_operator_id,
        expected_store_identity=expected_store_identity,
        pinned_authority_head=pinned_authority_head,
    )
