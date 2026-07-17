"""Append-only authority ledger and transaction-bound token consumption."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from imprint.errors import ConflictError, ValidationError
from .challenge import (
    ApprovalToken, ChallengeRequest, build_challenge, canonical_bytes,
    parse_timestamp, sha256_hex, signature_message, validate_challenge_shape,
)
from .keys import public_key_from_b64


LEDGER_DOMAIN = b"imprint-authority-ledger-v1\x00"
CHECKPOINT_DOMAIN = b"imprint-authority-checkpoint-v1\x00"
PREPARED_TTL_SECONDS = 24 * 60 * 60
MAX_CHECKPOINT_AGE_SECONDS = 24 * 60 * 60


def utc_now(clock: Callable[[], datetime] | None = None) -> datetime:
    value = (clock or (lambda: datetime.now(timezone.utc)))()
    if value.tzinfo is None:
        raise ValidationError("authority clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def active_binding(conn: sqlite3.Connection, *, expected_operator_id: str | None = None) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT * FROM authority_keys WHERE status='active' ORDER BY ledger_sequence DESC"
    ).fetchall()
    if len(rows) != 1:
        raise ValidationError("authority requires exactly one active local key")
    binding = dict(rows[0])
    if expected_operator_id is not None and binding["operator_id"] != expected_operator_id:
        raise ValidationError("authority key does not match configured operator")
    head = conn.execute("SELECT MAX(sequence) FROM authority_ledger").fetchone()[0]
    if head is None or int(head) < int(binding["ledger_sequence"]):
        raise ValidationError("authority ledger is missing its active key binding")
    return binding


def genesis_event(
    metadata: Mapping[str, Any], *, blob_rel_path: str, blob_sha256: str,
    blob_size: int, recovery_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    event = {
        "contract_version": "imprint.authority.ledger-event/1.0.0",
        "domain_separator": "imprint-authority-ledger-v1",
        "sequence": 1,
        "event_id": f"urn:imprint:authority-event:{uuid.uuid4()}",
        "event_type": "enrollment",
        "operator_id": metadata["operator_id"],
        "install_id": metadata["install_id"],
        "store_identity": metadata["store_identity"],
        "key_id": metadata["key_id"],
        "public_key_b64": metadata["public_key_b64"],
        "public_key_fingerprint": metadata["public_key_fingerprint"],
        "algorithm_suite": metadata["algorithm_suite"],
        "enrollment_nonce": metadata["enrollment_nonce"],
        "blob_rel_path": blob_rel_path,
        "blob_sha256": blob_sha256,
        "blob_size": blob_size,
        "status": "active",
        "created_at": metadata["created_at"],
        "previous_event_sha256": None,
    }
    if recovery_binding is not None:
        required = {
            "key_id", "public_key_b64", "public_key_fingerprint", "install_id",
        }
        if set(recovery_binding) != required:
            raise ValidationError("genesis recovery binding is incomplete")
        event["recovery_binding"] = dict(recovery_binding)
    return event


def insert_genesis(
    conn: sqlite3.Connection, *, metadata: Mapping[str, Any], blob_rel_path: str,
    blob_sha256: str, blob_size: int, private_key: Ed25519PrivateKey,
    recovery_binding: Mapping[str, Any] | None = None,
    approve: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if conn.execute("SELECT 1 FROM authority_ledger LIMIT 1").fetchone() is not None:
        raise ConflictError("authority is already enrolled")
    event = genesis_event(
        metadata, blob_rel_path=blob_rel_path, blob_sha256=blob_sha256,
        blob_size=blob_size, recovery_binding=recovery_binding,
    )
    encoded = canonical_bytes(event)
    if approve is not None:
        approve(event)
    event_sha = sha256_hex(encoded)
    signature = base64.b64encode(private_key.sign(LEDGER_DOMAIN + encoded)).decode("ascii")
    conn.execute(
        """INSERT INTO authority_ledger(
          sequence,event_id,event_type,operator_id,install_id,key_id,event_json,
          event_sha256,signature_b64,previous_event_sha256,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (1, event["event_id"], "enrollment", event["operator_id"], event["install_id"],
         event["key_id"], encoded.decode("utf-8"), event_sha, signature, None, event["created_at"]),
    )
    conn.execute(
        """INSERT INTO authority_keys(
          key_id,operator_id,install_id,store_identity,public_key_b64,
          public_key_fingerprint,status,ledger_sequence,blob_rel_path,blob_sha256,
          blob_size,algorithm_suite,enrollment_nonce,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (metadata["key_id"], metadata["operator_id"], metadata["install_id"],
         metadata["store_identity"], metadata["public_key_b64"],
         metadata["public_key_fingerprint"], "active", 1, blob_rel_path,
         blob_sha256, blob_size, metadata["algorithm_suite"],
         metadata["enrollment_nonce"], metadata["created_at"]),
    )
    return {"event": event, "event_sha256": event_sha, "signature_b64": signature}


def verify_genesis(binding: Mapping[str, Any], ledger_row: Mapping[str, Any]) -> None:
    try:
        event = json.loads(ledger_row["event_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValidationError("authority ledger event is malformed") from exc
    encoded = canonical_bytes(event)
    if sha256_hex(encoded) != ledger_row["event_sha256"]:
        raise ValidationError("authority ledger event digest mismatch")
    for name in ("operator_id", "install_id", "key_id", "public_key_b64", "public_key_fingerprint", "store_identity"):
        if event.get(name) != binding[name]:
            raise ValidationError("authority ledger binding mismatch")
    try:
        signature = base64.b64decode(ledger_row["signature_b64"], validate=True)
        public_key_from_b64(binding["public_key_b64"]).verify(signature, LEDGER_DOMAIN + encoded)
    except (ValueError, base64.binascii.Error, InvalidSignature) as exc:
        raise ValidationError("authority ledger signature is invalid") from exc


def append_ledger_event(
    conn: sqlite3.Connection, *, event_type: str, operator_id: str,
    install_id: str, key_id: str, details: Mapping[str, Any],
    signer_key_id: str, signer_private_key: Ed25519PrivateKey,
    clock: Callable[[], datetime] | None = None,
    approve: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Append one signed chain event; callers materialize local key state atomically."""
    head = conn.execute(
        "SELECT sequence,event_sha256 FROM authority_ledger ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    if head is None:
        raise ValidationError("authority lifecycle event requires an enrolled ledger")
    sequence = int(head["sequence"]) + 1
    event = {
        "contract_version": "imprint.authority.ledger-event/1.1.0",
        "domain_separator": "imprint-authority-ledger-v1",
        "sequence": sequence,
        "event_id": f"urn:imprint:authority-event:{uuid.uuid4()}",
        "event_type": event_type,
        "operator_id": operator_id,
        "install_id": install_id,
        "key_id": key_id,
        "signed_by_key_id": signer_key_id,
        "details": dict(details),
        "created_at": utc_text(utc_now(clock)),
        "previous_event_sha256": head["event_sha256"],
    }
    encoded = canonical_bytes(event)
    if approve is not None:
        approve(event)
    digest = sha256_hex(encoded)
    signature = base64.b64encode(
        signer_private_key.sign(LEDGER_DOMAIN + encoded)
    ).decode("ascii")
    conn.execute(
        """INSERT INTO authority_ledger(
          sequence,event_id,event_type,operator_id,install_id,key_id,event_json,
          event_sha256,signature_b64,previous_event_sha256,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (sequence, event["event_id"], event_type, operator_id, install_id,
         key_id, encoded.decode("utf-8"), digest, signature,
         event["previous_event_sha256"], event["created_at"]),
    )
    return {"event": event, "event_sha256": digest, "signature_b64": signature}


def _new_chain_key(details: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    required = {
        "key_id", "public_key_b64", "public_key_fingerprint", "install_id",
    }
    if not required.issubset(details):
        raise ValidationError("authority ledger key certificate is incomplete")
    try:
        public_raw = base64.b64decode(details["public_key_b64"], validate=True)
    except (TypeError, ValueError, base64.binascii.Error) as exc:
        raise ValidationError("authority ledger public key is invalid") from exc
    if len(public_raw) != 32 or details["public_key_fingerprint"] != "sha256:" + sha256_hex(public_raw):
        raise ValidationError("authority ledger public key fingerprint mismatch")
    result = {
        "key_id": details["key_id"], "public_key_b64": details["public_key_b64"],
        "public_key_fingerprint": details["public_key_fingerprint"],
        "install_id": details["install_id"], "kind": kind, "status": "active",
        "paired": kind == "installation",
    }
    blob_fields = {"blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite"}
    present = blob_fields & set(details)
    if present and present != blob_fields:
        raise ValidationError("authority ledger blob binding is incomplete")
    if present:
        if (
            not isinstance(details["blob_rel_path"], str)
            or not isinstance(details["blob_sha256"], str)
            or len(details["blob_sha256"]) != 64
            or not isinstance(details["blob_size"], int)
            or details["blob_size"] <= 0
            or not isinstance(details["algorithm_suite"], str)
        ):
            raise ValidationError("authority ledger blob binding is invalid")
        result.update({name: details[name] for name in blob_fields})
    return result


def _key_state_value(keys: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    fields = (
        "key_id", "public_key_b64", "public_key_fingerprint", "install_id",
        "kind", "status", "paired", "certificate_sequence",
        "certificate_event_sha256", "effective_at", "compromised_at",
        "replacement_key_id",
    )
    return {
        "key_state_version": "imprint.authority.key-state/1.0.0",
        "keys": [
            {name: value.get(name) for name in fields}
            for _, value in sorted(keys.items())
        ],
    }


def key_state_sha256(keys: Mapping[str, Mapping[str, Any]]) -> str:
    return sha256_hex(canonical_bytes(_key_state_value(keys)))


def _signer_certificate(key: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "certificate_version": "imprint.authority.installation-certificate/1.0.0",
        "key_id": key["key_id"], "install_id": key["install_id"],
        "public_key_b64": key["public_key_b64"],
        "public_key_fingerprint": key["public_key_fingerprint"],
        "kind": key["kind"], "paired": bool(key["paired"]),
        "authorization_sequence": key["certificate_sequence"],
        "authorization_event_sha256": key["certificate_event_sha256"],
        "status_at_checkpoint": "active",
    }


def verify_authority_chain(
    conn: sqlite3.Connection, *, expected_operator_id: str,
    expected_store_identity: str | None = None,
    checkpoint: Mapping[str, Any] | None = None,
    pinned_head: Mapping[str, Any] | None = None,
    now: datetime | None = None,
    max_checkpoint_age_seconds: int = MAX_CHECKPOINT_AGE_SECONDS,
    enforce_checkpoint_freshness: bool = True,
) -> dict[str, Any]:
    """Verify the entire authority chain and optional physically supplied checkpoint."""
    rows = [dict(row) for row in conn.execute(
        "SELECT * FROM authority_ledger ORDER BY sequence,event_sha256"
    )]
    if not rows:
        raise ValidationError("authority ledger is absent")
    if [int(row["sequence"]) for row in rows] != list(range(1, len(rows) + 1)):
        raise ValidationError("authority ledger sequence is broken or forked")
    try:
        genesis = json.loads(rows[0]["event_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValidationError("authority ledger genesis is malformed") from exc
    if genesis.get("operator_id") != expected_operator_id:
        raise ValidationError("authority ledger operator mismatch")
    store_identity = genesis.get("store_identity")
    if expected_store_identity is not None and store_identity != expected_store_identity:
        raise ValidationError("authority ledger store identity mismatch")
    keys = {
        genesis["key_id"]: {
            "key_id": genesis["key_id"], "public_key_b64": genesis["public_key_b64"],
            "public_key_fingerprint": genesis["public_key_fingerprint"],
            "install_id": genesis["install_id"], "kind": "installation",
            "status": "active", "paired": True,
            "certificate_sequence": 1, "certificate_event_sha256": None,
            "effective_at": genesis.get("created_at"), "compromised_at": None,
            "replacement_key_id": None,
        }
    }
    recovery_binding = genesis.get("recovery_binding")
    if recovery_binding is not None:
        if not isinstance(recovery_binding, dict) or set(recovery_binding) != {
            "key_id", "public_key_b64", "public_key_fingerprint", "install_id",
        }:
            raise ValidationError("authority genesis recovery binding is invalid")
        recovery = _new_chain_key(recovery_binding, kind="recovery")
        if recovery["key_id"] in keys:
            raise ValidationError("authority genesis key identities collide")
        recovery.update({
            "certificate_sequence": 1, "certificate_event_sha256": None,
            "effective_at": genesis.get("created_at"), "compromised_at": None,
            "replacement_key_id": None,
        })
        keys[recovery["key_id"]] = recovery
    head_hash = None
    hashes: dict[int, str] = {}
    states_by_sequence: dict[int, dict[str, str]] = {}
    key_snapshots_by_sequence: dict[int, dict[str, dict[str, Any]]] = {}
    key_state_hashes: dict[int, str] = {}
    for index, row in enumerate(rows):
        try:
            event = json.loads(row["event_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValidationError("authority ledger event is malformed") from exc
        encoded = canonical_bytes(event)
        digest = sha256_hex(encoded)
        if digest != row["event_sha256"] or int(event.get("sequence", -1)) != index + 1:
            raise ValidationError("authority ledger event digest or sequence mismatch")
        if any(event.get(name) != row[name] for name in (
            "event_id", "event_type", "operator_id", "install_id", "key_id",
            "previous_event_sha256", "created_at",
        )):
            raise ValidationError("authority ledger row and signed event disagree")
        if event.get("operator_id") != expected_operator_id:
            raise ValidationError("authority ledger operator equivocation")
        if event.get("previous_event_sha256") != head_hash:
            raise ValidationError("authority ledger rollback, fork, or missing intermediate")
        signer_id = event.get("signed_by_key_id", event.get("key_id"))
        signer = keys.get(signer_id)
        if signer is None or signer["status"] != "active":
            raise ValidationError("authority ledger event signer is unknown or inactive")
        try:
            signature = base64.b64decode(row["signature_b64"], validate=True)
            public_key_from_b64(signer["public_key_b64"]).verify(
                signature, LEDGER_DOMAIN + encoded,
            )
        except (TypeError, ValueError, base64.binascii.Error, InvalidSignature) as exc:
            raise ValidationError("authority ledger signature is invalid") from exc
        if index == 0:
            for key in keys.values():
                key["certificate_event_sha256"] = digest
        if index:
            lifecycle_fields = {
                "contract_version", "domain_separator", "sequence", "event_id",
                "event_type", "operator_id", "install_id", "key_id",
                "signed_by_key_id", "details", "created_at", "previous_event_sha256",
            }
            if (
                set(event) != lifecycle_fields
                or event.get("contract_version") != "imprint.authority.ledger-event/1.1.0"
                or event.get("domain_separator") != "imprint-authority-ledger-v1"
            ):
                raise ValidationError("authority lifecycle event has unknown fields or version")
            details = event.get("details")
            if not isinstance(details, dict):
                raise ValidationError("authority ledger lifecycle details are invalid")
            event_type = event.get("event_type")
            key_fields = {
                "key_id", "public_key_b64", "public_key_fingerprint", "install_id",
            }
            blob_fields = {"blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite"}
            if event_type in {"recovery_created", "installation_paired"}:
                kind = "recovery" if event_type == "recovery_created" else "installation"
                expected_details = (
                    key_fields if kind == "recovery"
                    else key_fields | blob_fields | {"authorization"}
                )
                if set(details) != expected_details:
                    raise ValidationError("authority key certificate has unknown or missing fields")
                certified = _new_chain_key(details, kind=kind)
                if event["key_id"] != certified["key_id"] or event["install_id"] != certified["install_id"]:
                    raise ValidationError("authority key certificate subject mismatch")
                if certified["key_id"] in keys:
                    raise ValidationError("authority key identity was certified twice")
                if kind == "installation" and any(
                    key["kind"] == "installation" and key["install_id"] == certified["install_id"]
                    and key["status"] == "active" for key in keys.values()
                ):
                    raise ValidationError("authority installation already has an active key")
                if kind == "installation":
                    authorization = details["authorization"]
                    authorization_fields = {
                        "certificate_version", "operator_id", "store_identity",
                        "new_install_id", "new_key_id", "new_public_key_b64",
                        "pairing_nonce", "pairing_request_sha256",
                        "preceding_authority_head_sha256", "expires_at",
                    }
                    if (
                        not isinstance(authorization, Mapping)
                        or set(authorization) != authorization_fields
                        or authorization["certificate_version"] != "imprint.authority.authorize-installation/1.0.0"
                        or authorization["operator_id"] != expected_operator_id
                        or authorization["store_identity"] != store_identity
                        or authorization["new_install_id"] != certified["install_id"]
                        or authorization["new_key_id"] != certified["key_id"]
                        or authorization["new_public_key_b64"] != certified["public_key_b64"]
                        or authorization["preceding_authority_head_sha256"] != event["previous_event_sha256"]
                    ):
                        raise ValidationError("installation authorization certificate is invalid")
                    parse_timestamp(authorization["expires_at"])
                keys[certified["key_id"]] = certified
                certified.update({
                    "certificate_sequence": index + 1,
                    "certificate_event_sha256": digest,
                    "effective_at": event["created_at"], "compromised_at": None,
                    "replacement_key_id": None,
                })
            elif event_type == "key_rotated":
                if set(details) != key_fields | blob_fields | {"old_key_id"}:
                    raise ValidationError("authority rotation has unknown or missing fields")
                old_id = details.get("old_key_id")
                if signer_id != old_id or old_id not in keys or keys[old_id]["status"] != "active":
                    raise ValidationError("authority rotation does not continue the active key")
                certified = _new_chain_key(details, kind="installation")
                if certified["key_id"] in keys:
                    raise ValidationError("authority rotation key already exists")
                if certified["install_id"] != keys[old_id]["install_id"]:
                    raise ValidationError("authority rotation changed installation identity")
                keys[old_id]["status"] = "retired"
                keys[old_id]["effective_at"] = event["created_at"]
                keys[certified["key_id"]] = certified
                certified.update({
                    "certificate_sequence": index + 1,
                    "certificate_event_sha256": digest,
                    "effective_at": event["created_at"], "compromised_at": None,
                    "replacement_key_id": None,
                })
            elif event_type in {"key_revoked", "key_compromised", "recovery_revoked"}:
                current_fields = {
                    "target_key_id", "effective_at", "compromised_at", "reason",
                    "replacement_key_id", "affected_installation_ids",
                    "evidence_sha256s", "required_revocation_key_ids",
                }
                if (
                    set(details) != current_fields
                ) or not isinstance(details.get("reason"), str) or not details["reason"].strip():
                    raise ValidationError("authority key-state event has unknown or missing fields")
                target = details.get("target_key_id")
                if event["key_id"] != target:
                    raise ValidationError("authority key-state subject mismatch")
                if target not in keys or keys[target]["status"] != "active":
                    raise ValidationError("authority key-state equivocation")
                if event_type == "key_compromised" and signer_id == target:
                    raise ValidationError("a compromised key cannot revoke itself")
                if event_type == "recovery_revoked" and keys[target]["kind"] != "recovery":
                    raise ValidationError("recovery revocation targets a non-recovery key")
                if (
                    details["affected_installation_ids"] != [keys[target]["install_id"]]
                    or details["required_revocation_key_ids"] != [target]
                    or not isinstance(details["evidence_sha256s"], list)
                    or any(
                        not isinstance(item, str) or len(item) != 64
                        or any(char not in "0123456789abcdef" for char in item)
                        for item in details["evidence_sha256s"]
                    )
                ):
                    raise ValidationError("authority compromise scope or evidence is invalid")
                keys[target]["status"] = {
                    "key_revoked": "revoked", "key_compromised": "compromised",
                    "recovery_revoked": "revoked",
                }[event_type]
                effective_at = details["effective_at"]
                parse_timestamp(effective_at)
                compromised_at = details.get("compromised_at")
                if compromised_at is not None:
                    parse_timestamp(compromised_at)
                if event_type == "key_compromised" and compromised_at is None:
                    compromised_at = effective_at
                if compromised_at is not None and parse_timestamp(compromised_at) > parse_timestamp(effective_at):
                    raise ValidationError("authority compromise boundary follows its effective time")
                replacement = details["replacement_key_id"]
                if replacement is not None and replacement not in keys:
                    raise ValidationError("authority key-state replacement is unknown")
                keys[target]["effective_at"] = effective_at
                keys[target]["compromised_at"] = compromised_at
                keys[target]["replacement_key_id"] = replacement
            elif event_type == "installation_rebound":
                if set(details) != key_fields | blob_fields | {"old_install_id", "authorization"}:
                    raise ValidationError("authority rebind has unknown or missing fields")
                old_install = details.get("old_install_id")
                active_old = [key for key in keys.values() if key["install_id"] == old_install and key["status"] == "active"]
                if len(active_old) != 1:
                    raise ValidationError("authority rebind source installation is ambiguous")
                active_old[0]["status"] = "retired"
                active_old[0]["effective_at"] = event["created_at"]
                certified = _new_chain_key(details, kind="installation")
                if certified["key_id"] in keys:
                    raise ValidationError("authority rebind key already exists")
                if any(
                    key["kind"] == "installation" and key["install_id"] == certified["install_id"]
                    and key["status"] == "active" for key in keys.values()
                ):
                    raise ValidationError("authority rebind target installation is already active")
                authorization = details["authorization"]
                authorization_fields = {
                    "certificate_version", "operator_id", "store_identity",
                    "new_install_id", "new_key_id", "new_public_key_b64",
                    "pairing_nonce", "pairing_request_sha256",
                    "preceding_authority_head_sha256", "expires_at",
                }
                if (
                    not isinstance(authorization, Mapping)
                    or set(authorization) != authorization_fields
                    or authorization["certificate_version"] != "imprint.authority.authorize-installation/1.0.0"
                    or authorization["operator_id"] != expected_operator_id
                    or authorization["store_identity"] != store_identity
                    or authorization["new_install_id"] != certified["install_id"]
                    or authorization["new_key_id"] != certified["key_id"]
                    or authorization["new_public_key_b64"] != certified["public_key_b64"]
                    or authorization["preceding_authority_head_sha256"] != event["previous_event_sha256"]
                ):
                    raise ValidationError("installation rebind authorization is invalid")
                parse_timestamp(authorization["expires_at"])
                keys[certified["key_id"]] = certified
                certified.update({
                    "certificate_sequence": index + 1,
                    "certificate_event_sha256": digest,
                    "effective_at": event["created_at"], "compromised_at": None,
                    "replacement_key_id": None,
                })
            elif event_type == "authority_conflict_adjudicated":
                adjudication_fields = {
                    "proof_id", "chosen_checkpoint_sha256", "rejected_proof_sha256",
                    "reason", "effective_at",
                }
                if (
                    set(details) != adjudication_fields
                    or not isinstance(details["reason"], str) or not details["reason"].strip()
                    or signer["kind"] != "recovery"
                ):
                    raise ValidationError("authority conflict adjudication is invalid")
                for name in ("chosen_checkpoint_sha256", "rejected_proof_sha256"):
                    if (
                        not isinstance(details[name], str) or len(details[name]) != 64
                        or any(char not in "0123456789abcdef" for char in details[name])
                    ):
                        raise ValidationError("authority conflict adjudication digest is invalid")
                parse_timestamp(details["effective_at"])
            else:
                raise ValidationError("authority ledger event type is unsupported")
        head_hash = digest
        hashes[index + 1] = digest
        states_by_sequence[index + 1] = {
            key_id: value["status"] for key_id, value in keys.items()
        }
        key_snapshots_by_sequence[index + 1] = copy.deepcopy(keys)
        key_state_hashes[index + 1] = key_state_sha256(keys)
    if pinned_head is not None:
        if set(pinned_head) != {"sequence", "event_sha256"}:
            raise ValidationError("authority pinned head is malformed")
        sequence = pinned_head["sequence"]
        if not isinstance(sequence, int) or sequence < 1 or sequence > len(rows):
            raise ValidationError("authority source ledger is older than the pinned head")
        if hashes[sequence] != pinned_head["event_sha256"]:
            raise ValidationError("authority ledger fork or equivocation against pinned head")
    checkpoint_result = None
    if checkpoint is not None:
        fields = {
            "checkpoint_version", "domain_separator", "operator_id", "store_identity", "sequence",
            "event_sha256", "genesis_event_sha256", "key_state_sha256",
            "prior_checkpoint_sha256", "signer_key_id", "signer_certificate",
            "issued_at", "expires_at", "signature_b64",
        }
        if not isinstance(checkpoint, Mapping) or set(checkpoint) != fields:
            raise ValidationError("authority checkpoint is malformed")
        if (
            checkpoint["checkpoint_version"] != "imprint.authority.checkpoint/1.1.0"
            or checkpoint["domain_separator"] != "imprint-authority-checkpoint-v1"
        ):
            raise ValidationError("authority checkpoint version is unsupported")
        sequence = checkpoint["sequence"]
        signer = keys.get(checkpoint["signer_key_id"])
        if checkpoint["operator_id"] != expected_operator_id or checkpoint["store_identity"] != store_identity:
            raise ValidationError("authority checkpoint identity mismatch")
        if checkpoint["genesis_event_sha256"] != hashes[1]:
            raise ValidationError("authority checkpoint trust genesis mismatch")
        if not isinstance(sequence, int) or sequence not in hashes or hashes[sequence] != checkpoint["event_sha256"]:
            raise ValidationError("authority checkpoint names an absent, rolled-back, or forked head")
        if checkpoint["key_state_sha256"] != key_state_hashes[sequence]:
            raise ValidationError("authority checkpoint key-state digest mismatch")
        prior_checkpoint = checkpoint["prior_checkpoint_sha256"]
        if prior_checkpoint is not None and (
            not isinstance(prior_checkpoint, str) or len(prior_checkpoint) != 64
            or any(char not in "0123456789abcdef" for char in prior_checkpoint)
        ):
            raise ValidationError("authority checkpoint prior hash is invalid")
        checkpoint_signer_status = states_by_sequence[sequence].get(checkpoint["signer_key_id"])
        signer_at_checkpoint = key_snapshots_by_sequence[sequence].get(checkpoint["signer_key_id"])
        if signer is None or signer_at_checkpoint is None or checkpoint_signer_status != "active":
            raise ValidationError("authority checkpoint signer is inactive")
        certificate = checkpoint["signer_certificate"]
        if not isinstance(certificate, Mapping) or dict(certificate) != _signer_certificate(signer_at_checkpoint):
            raise ValidationError("authority checkpoint signer certificate mismatch")
        issued = parse_timestamp(checkpoint["issued_at"])
        expires = parse_timestamp(checkpoint["expires_at"])
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if expires <= issued or (expires - issued).total_seconds() > max_checkpoint_age_seconds:
            raise ValidationError("authority checkpoint freshness window is invalid")
        if enforce_checkpoint_freshness and (current < issued or current >= expires):
            raise ValidationError("authority checkpoint is absent or stale")
        unsigned = {name: checkpoint[name] for name in fields - {"signature_b64"}}
        try:
            signature = base64.b64decode(checkpoint["signature_b64"], validate=True)
            public_key_from_b64(signer["public_key_b64"]).verify(
                signature, CHECKPOINT_DOMAIN + canonical_bytes(unsigned),
            )
        except (TypeError, ValueError, base64.binascii.Error, InvalidSignature) as exc:
            raise ValidationError("authority checkpoint signature is invalid") from exc
        checkpoint_result = {
            "sequence": sequence, "event_sha256": checkpoint["event_sha256"],
            "issued_at": checkpoint["issued_at"], "expires_at": checkpoint["expires_at"],
            "signer_key_id": checkpoint["signer_key_id"],
            "signer_current_status": signer["status"],
            "key_state_sha256": checkpoint["key_state_sha256"],
            "prior_checkpoint_sha256": checkpoint["prior_checkpoint_sha256"],
            "signer_certificate": dict(certificate),
            "checkpoint_sha256": sha256_hex(canonical_bytes(dict(checkpoint))),
        }
    active_installations = [
        key for key in keys.values() if key["kind"] == "installation" and key["status"] == "active"
    ]
    return {
        "operator_id": expected_operator_id, "store_identity": store_identity,
        "genesis_event_sha256": hashes[1],
        "head_sequence": len(rows), "head_sha256": head_hash,
        "key_state_sha256": key_state_hashes[len(rows)],
        "key_state_sha256_at_checkpoint": (
            key_state_hashes[checkpoint_result["sequence"]] if checkpoint_result else None
        ),
        "pinned_head": dict(pinned_head) if pinned_head is not None else None,
        "checkpoint": checkpoint_result,
        "snapshot_valid_as_of": checkpoint_result["issued_at"] if checkpoint_result else rows[-1]["created_at"],
        "unseen_newer_events": bool(checkpoint_result and checkpoint_result["sequence"] < len(rows)),
        "keys": keys, "active_installations": active_installations,
    }


def create_checkpoint(
    conn: sqlite3.Connection, *, expected_operator_id: str,
    signer_binding: Mapping[str, Any], signer_private_key: Ed25519PrivateKey,
    clock: Callable[[], datetime] | None = None, ttl_seconds: int = MAX_CHECKPOINT_AGE_SECONDS,
    prior_checkpoint_sha256: str | None = None,
    approve: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if not 1 <= ttl_seconds <= MAX_CHECKPOINT_AGE_SECONDS:
        raise ValidationError("authority checkpoint TTL must be within 24 hours")
    verified = verify_authority_chain(conn, expected_operator_id=expected_operator_id)
    signer = verified["keys"].get(signer_binding["key_id"])
    if signer is None or signer["status"] != "active":
        raise ValidationError("authority checkpoint signer is not active")
    issued = utc_now(clock)
    unsigned = {
        "checkpoint_version": "imprint.authority.checkpoint/1.1.0",
        "domain_separator": "imprint-authority-checkpoint-v1",
        "operator_id": expected_operator_id,
        "store_identity": verified["store_identity"],
        "sequence": verified["head_sequence"],
        "event_sha256": verified["head_sha256"],
        "genesis_event_sha256": verified["genesis_event_sha256"],
        "key_state_sha256": verified["key_state_sha256"],
        "prior_checkpoint_sha256": prior_checkpoint_sha256,
        "signer_certificate": _signer_certificate(signer),
        "issued_at": utc_text(issued),
        "expires_at": utc_text(issued + timedelta(seconds=ttl_seconds)),
        "signer_key_id": signer_binding["key_id"],
    }
    if approve is not None:
        approve(unsigned)
    signature = signer_private_key.sign(CHECKPOINT_DOMAIN + canonical_bytes(unsigned))
    return {**unsigned, "signature_b64": base64.b64encode(signature).decode("ascii")}


def issue_challenge(
    conn: sqlite3.Connection, request: ChallengeRequest, *,
    expected_operator_id: str | None = None, ttl_seconds: int = 120,
    clock: Callable[[], datetime] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    binding = active_binding(conn, expected_operator_id=expected_operator_id)
    challenge = build_challenge(
        request, operator_id=binding["operator_id"], install_id=binding["install_id"],
        key_id=binding["key_id"], store_identity=binding["store_identity"],
        ledger_sequence=int(conn.execute("SELECT MAX(sequence) FROM authority_ledger").fetchone()[0]),
        ttl_seconds=ttl_seconds, clock=clock,
    )
    challenge_sha = sha256_hex(canonical_bytes(challenge))
    nonce_sha = hashlib.sha256(challenge["nonce"].encode("ascii")).hexdigest()
    try:
        conn.execute(
            "INSERT INTO authority_challenges VALUES(?,?,?,?,?,NULL,NULL)",
            (nonce_sha, challenge["operation_id"], challenge_sha,
             challenge["issued_at"], challenge["expires_at"]),
        )
    except sqlite3.IntegrityError as exc:
        raise ConflictError("authority nonce or operation collision") from exc
    return challenge, binding


def prepare_mutation(
    conn: sqlite3.Connection, *, command_name: str, request: ChallengeRequest,
    intent: Mapping[str, Any], prior_state: Mapping[str, Any],
    execution_fields: Mapping[str, Any], operator_id: str,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Durably freeze one mutation before any authority challenge is issued."""
    request.validate()
    if not command_name or not isinstance(command_name, str):
        raise ValidationError("prepared mutation command is required")
    created = utc_now(clock)
    expires = created.timestamp() + PREPARED_TTL_SECONDS
    expires_at = datetime.fromtimestamp(expires, tz=timezone.utc)
    execution_json = canonical_bytes(execution_fields).decode("utf-8")
    execution_sha256 = sha256_hex(execution_json.encode())
    if request.execution_fields_sha256 != execution_sha256:
        raise ValidationError("prepared mutation execution-fields digest mismatch")
    request_json = canonical_bytes({
        "operation_id": request.operation_id, "purpose": request.purpose,
        "payload_sha256": request.payload_sha256,
        "prior_state_sha256": request.prior_state_sha256,
        "execution_fields_sha256": request.execution_fields_sha256,
        "authority_transition": request.authority_transition,
        "subject_ids": list(request.subject_ids), "source_ids": list(request.source_ids),
        "target_ids": list(request.target_ids), "proposal_ids": list(request.proposal_ids),
        "result_version_ids": list(request.result_version_ids), "scope": list(request.scope),
        "field_paths": list(request.field_paths),
    }).decode("utf-8")
    intent_json = canonical_bytes(intent).decode("utf-8")
    prior_json = canonical_bytes(prior_state).decode("utf-8")
    try:
        conn.execute(
            """INSERT INTO authority_prepared_mutations(
              operation_id,command_name,operator_id,request_json,request_sha256,
              intent_json,intent_sha256,prior_state_json,prior_state_sha256,
              execution_fields_json,execution_fields_sha256,created_at,expires_at,status,executed_at,
              provenance_id
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending',NULL,NULL)""",
            (request.operation_id, command_name, operator_id, request_json,
             sha256_hex(request_json.encode()), intent_json, sha256_hex(intent_json.encode()),
             prior_json, sha256_hex(prior_json.encode()), execution_json,
             execution_sha256, utc_text(created), utc_text(expires_at)),
        )
    except sqlite3.IntegrityError as exc:
        raise ConflictError("prepared mutation operation already exists") from exc
    return {
        "request": json.loads(request_json), "command_name": command_name,
        "created_at": utc_text(created), "expires_at": utc_text(expires_at),
        "status": "pending",
    }


def load_prepared_mutation(
    conn: sqlite3.Connection, *, operation_id: str, command_name: str,
    intent: Mapping[str, Any], prior_state: Mapping[str, Any], operator_id: str,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM authority_prepared_mutations WHERE operation_id=?", (operation_id,),
    ).fetchone()
    if row is None:
        raise ValidationError("authority token does not name a stored prepared mutation")
    value = dict(row)
    if value["status"] != "pending":
        raise ConflictError("prepared mutation is not pending")
    if value["command_name"] != command_name or value["operator_id"] != operator_id:
        raise ValidationError("authority token is for another command or operator")
    if utc_now(clock) >= parse_timestamp(value["expires_at"]):
        conn.execute(
            "UPDATE authority_prepared_mutations SET status='expired' WHERE operation_id=? AND status='pending'",
            (operation_id,),
        )
        raise ValidationError("prepared mutation has expired")
    intent_json = canonical_bytes(intent).decode("utf-8")
    prior_json = canonical_bytes(prior_state).decode("utf-8")
    if intent_json != value["intent_json"] or prior_json != value["prior_state_json"]:
        raise ValidationError("prepared mutation intent or prior state changed")
    if sha256_hex(value["request_json"].encode()) != value["request_sha256"]:
        raise ValidationError("prepared mutation request digest mismatch")
    if sha256_hex(value["intent_json"].encode()) != value["intent_sha256"]:
        raise ValidationError("prepared mutation intent digest mismatch")
    if sha256_hex(value["prior_state_json"].encode()) != value["prior_state_sha256"]:
        raise ValidationError("prepared mutation prior-state digest mismatch")
    execution_sha256 = sha256_hex(value["execution_fields_json"].encode())
    if execution_sha256 != value["execution_fields_sha256"]:
        raise ValidationError("prepared mutation execution-fields digest mismatch")
    try:
        value["request"] = json.loads(value["request_json"])
        value["execution_fields"] = json.loads(value["execution_fields_json"])
    except json.JSONDecodeError as exc:
        raise ValidationError("prepared mutation storage is corrupt") from exc
    if value["request"].get("execution_fields_sha256") != execution_sha256:
        raise ValidationError("signed request does not bind prepared execution fields")
    return value


def mark_prepared_executed(
    conn: sqlite3.Connection, *, operation_id: str, provenance_id: str,
    clock: Callable[[], datetime] | None = None,
) -> None:
    changed = conn.execute(
        """UPDATE authority_prepared_mutations
           SET status='executed',executed_at=?,provenance_id=?
           WHERE operation_id=? AND status='pending'""",
        (utc_text(utc_now(clock)), provenance_id, operation_id),
    ).rowcount
    if changed != 1:
        raise ConflictError("prepared mutation was already executed or expired")


def _assert_request_exact(challenge: Mapping[str, Any], expected: ChallengeRequest) -> None:
    expected.validate()
    fields = {
        "operation_id": expected.operation_id,
        "purpose": expected.purpose,
        "payload_sha256": expected.payload_sha256,
        "prior_state_sha256": expected.prior_state_sha256,
        "execution_fields_sha256": expected.execution_fields_sha256,
        "authority_transition": expected.authority_transition,
        "subject_ids": list(expected.subject_ids),
        "source_ids": list(expected.source_ids),
        "target_ids": list(expected.target_ids),
        "proposal_ids": list(expected.proposal_ids),
        "result_version_ids": list(expected.result_version_ids),
        "scope": list(expected.scope),
        "field_paths": list(expected.field_paths),
    }
    if any(challenge[name] != value for name, value in fields.items()):
        raise ValidationError("authority token does not match the exact mutation")


def verify_and_consume(
    conn: sqlite3.Connection, token: ApprovalToken | Mapping[str, Any], *,
    expected: ChallengeRequest, expected_operator_id: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> str:
    """Verify and consume inside the caller's mutation transaction.

    The caller must begin ``BEGIN IMMEDIATE`` first and perform its authorized
    mutation before committing.  Any later exception rolls nonce consumption
    and provenance back with the mutation.
    """
    if not conn.in_transaction:
        raise ValidationError("authority verification requires an active mutation transaction")
    approval = token if isinstance(token, ApprovalToken) else ApprovalToken.from_dict(token)
    challenge = approval.challenge
    validate_challenge_shape(challenge)
    _assert_request_exact(challenge, expected)
    binding = active_binding(conn, expected_operator_id=expected_operator_id)
    for name in ("operator_id", "install_id", "key_id", "store_identity"):
        if challenge[name] != binding[name]:
            raise ValidationError("authority token is bound to another operator or installation")
    head = int(conn.execute("SELECT MAX(sequence) FROM authority_ledger").fetchone()[0])
    if challenge["ledger_sequence"] != head:
        raise ValidationError("authority token is stale relative to the ledger")
    encoded = canonical_bytes(challenge)
    challenge_sha = sha256_hex(encoded)
    nonce_sha = hashlib.sha256(challenge["nonce"].encode("ascii")).hexdigest()
    nonce = conn.execute(
        "SELECT * FROM authority_challenges WHERE nonce_sha256=?", (nonce_sha,),
    ).fetchone()
    if nonce is None or nonce["challenge_sha256"] != challenge_sha or nonce["operation_id"] != challenge["operation_id"]:
        raise ValidationError("authority nonce was not issued by this store")
    if nonce["consumed_at"] is not None:
        raise ConflictError("authority nonce has already been consumed")
    now = utc_now(clock)
    issued = parse_timestamp(challenge["issued_at"])
    expires = parse_timestamp(challenge["expires_at"])
    if now < issued or now >= expires:
        raise ValidationError("authority token is not currently valid")
    try:
        signature = base64.b64decode(approval.signature_b64, validate=True)
        public_key_from_b64(binding["public_key_b64"]).verify(signature, signature_message(challenge))
    except (ValueError, base64.binascii.Error, InvalidSignature) as exc:
        raise ValidationError("authority signature is invalid") from exc
    provenance_id = f"urn:imprint:authority-provenance:{uuid.uuid4()}"
    committed_at = utc_text(now)
    try:
        conn.execute(
            """INSERT INTO authority_provenance VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (provenance_id, challenge["operation_id"], binding["operator_id"],
             binding["install_id"], binding["key_id"], head, encoded.decode("utf-8"),
             challenge_sha, approval.signature_b64, challenge["authority_transition"], committed_at),
        )
        updated = conn.execute(
            """UPDATE authority_challenges
               SET consumed_at=?, consumed_provenance_id=?
               WHERE nonce_sha256=? AND consumed_at IS NULL""",
            (committed_at, provenance_id, nonce_sha),
        ).rowcount
    except sqlite3.IntegrityError as exc:
        raise ConflictError("authority operation or provenance already exists") from exc
    if updated != 1:
        raise ConflictError("authority nonce was consumed concurrently")
    return provenance_id
