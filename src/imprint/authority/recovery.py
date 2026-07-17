"""Signed, encrypted, offline-verifiable authority recovery bundles."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from imprint.durable_io import publish_new_private
from imprint.errors import ConflictError, ValidationError
from .challenge import canonical_bytes, sha256_hex
from .keys import GeneratedKey, public_key_from_b64
from .ledger import verify_authority_chain


RECOVERY_DOMAIN = b"imprint-authority-recovery-manifest-v1\x00"
RECOVERY_WRAP_DOMAIN = b"imprint-authority-recovery-wrap-v1\x00"
RECOVERY_ALGORITHM = "Ed25519+PKCS8-DER+AES-256-GCM+scrypt-N262144-r8-p1+recovery-v1"
_ROW_FIELDS = {
    "sequence", "event_id", "event_type", "operator_id", "install_id", "key_id",
    "event_json", "event_sha256", "signature_b64", "previous_event_sha256", "created_at",
}
_MANIFEST_FIELDS = {
    "manifest_version", "operator_id", "store_identity", "created_at",
    "recovery_key_id", "recovery_public_key_b64", "recovery_public_key_fingerprint",
    "recovery_install_id", "ledger_sequence", "ledger_head_sha256", "ledger_sha256",
    "authority_ledger_genesis_sha256", "encrypted_recovery_key_sha256",
    "signer_key_id", "signer_install_id", "checkpoint_history", "creation_checkpoint",
}
_BUNDLE_FIELDS = {
    "bundle_version", "manifest", "ledger", "encrypted_recovery_key_b64", "signature_b64",  # gitleaks:allow -- schema field names
}
_TRANSPORT_FIELDS = {
    "transport_version", "operator_id", "store_identity",
    "authority_ledger_genesis_sha256", "ledger", "ledger_sha256",
    "checkpoint_history", "checkpoint",
}


def _derive(passphrase: str, salt: bytes) -> bytearray:
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValidationError("recovery passphrase must contain at least 12 characters")
    try:
        return bytearray(Scrypt(salt=salt, length=32, n=2**18, r=8, p=1).derive(passphrase.encode()))
    except (MemoryError, ValueError) as exc:
        raise ValidationError("recovery key derivation failed") from exc


def recovery_aad(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "domain": "imprint-authority-recovery-wrap-v1",
        "operator_id": metadata["operator_id"],
        "store_identity": metadata["store_identity"],
        "recovery_key_id": metadata["recovery_key_id"],
        "recovery_public_key_b64": metadata["recovery_public_key_b64"],
        "recovery_public_key_fingerprint": metadata["recovery_public_key_fingerprint"],
        "recovery_install_id": metadata["recovery_install_id"],
        "created_at": metadata["created_at"],
        "algorithm": RECOVERY_ALGORITHM,
    }


def encrypt_recovery_key(key: GeneratedKey, passphrase: str, *, metadata: Mapping[str, Any]) -> bytes:
    salt, nonce = os.urandom(32), os.urandom(12)
    aad = canonical_bytes(recovery_aad(metadata))
    wrapping = _derive(passphrase, salt)
    private = bytearray(key.private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    try:
        ciphertext = AESGCM(bytes(wrapping)).encrypt(nonce, bytes(private), RECOVERY_WRAP_DOMAIN + aad)
    finally:
        private[:] = b"\x00" * len(private)
        wrapping[:] = b"\x00" * len(wrapping)
    return canonical_bytes({
        "recovery_blob_version": "imprint.authority.recovery-key/1.0.0",
        "algorithm": RECOVERY_ALGORITHM,
        "salt_b64": base64.b64encode(salt).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "aad_sha256": sha256_hex(aad),
    }) + b"\n"


def decrypt_recovery_key(blob_bytes: bytes, passphrase: str, *, metadata: Mapping[str, Any]) -> Ed25519PrivateKey:
    try:
        blob = json.loads(blob_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("recovery key blob is malformed") from exc
    fields = {"recovery_blob_version", "algorithm", "salt_b64", "nonce_b64", "ciphertext_b64", "aad_sha256"}
    if not isinstance(blob, dict) or set(blob) != fields or canonical_bytes(blob) + b"\n" != blob_bytes:
        raise ValidationError("recovery key blob is malformed or non-canonical")
    if blob["recovery_blob_version"] != "imprint.authority.recovery-key/1.0.0" or blob["algorithm"] != RECOVERY_ALGORITHM:
        raise ValidationError("recovery key algorithm is unsupported")
    aad = canonical_bytes(recovery_aad(metadata))
    if blob["aad_sha256"] != sha256_hex(aad):
        raise ValidationError("recovery key binding is invalid")
    try:
        salt = base64.b64decode(blob["salt_b64"], validate=True)
        nonce = base64.b64decode(blob["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(blob["ciphertext_b64"], validate=True)
    except (TypeError, ValueError, base64.binascii.Error) as exc:
        raise ValidationError("recovery key encoding is invalid") from exc
    if len(salt) != 32 or len(nonce) != 12 or len(ciphertext) < 17:
        raise ValidationError("recovery key lengths are invalid")
    wrapping = _derive(passphrase, salt)
    try:
        try:
            private_der = bytearray(AESGCM(bytes(wrapping)).decrypt(
                nonce, ciphertext, RECOVERY_WRAP_DOMAIN + aad,
            ))
        except InvalidTag as exc:
            raise ValidationError("recovery passphrase or bundle is invalid") from exc
    finally:
        wrapping[:] = b"\x00" * len(wrapping)
    try:
        key = serialization.load_der_private_key(bytes(private_der), password=None)
    except (TypeError, ValueError) as exc:
        raise ValidationError("recovery private key is invalid") from exc
    finally:
        private_der[:] = b"\x00" * len(private_der)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValidationError("recovery private key is not Ed25519")
    expected = base64.b64decode(metadata["recovery_public_key_b64"], validate=True)
    actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if actual != expected:
        raise ValidationError("recovery private key does not match the manifest")
    return key


def _ledger_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    return sha256_hex(canonical_bytes({"ledger": [dict(row) for row in rows]}))


def _chain_connection(rows: Sequence[Mapping[str, Any]]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE authority_ledger(
      sequence INTEGER,event_id TEXT,event_type TEXT,operator_id TEXT,install_id TEXT,key_id TEXT,
      event_json TEXT,event_sha256 TEXT,signature_b64 TEXT,previous_event_sha256 TEXT,created_at TEXT)""")
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != _ROW_FIELDS:
            conn.close()
            raise ValidationError("recovery ledger row has unknown or missing fields")
        conn.execute(
            "INSERT INTO authority_ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            tuple(row[name] for name in (
                "sequence", "event_id", "event_type", "operator_id", "install_id", "key_id",
                "event_json", "event_sha256", "signature_b64", "previous_event_sha256", "created_at",
            )),
        )
    return conn


def write_recovery_bundle(
    destination: Path, *, manifest_base: Mapping[str, Any], ledger_rows: Sequence[Mapping[str, Any]],
    encrypted_recovery_key: bytes, signer_private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ConflictError("recovery bundle destination already exists")
    rows = [dict(row) for row in ledger_rows]
    manifest = {
        **dict(manifest_base),
        "manifest_version": "imprint.authority.recovery-manifest/1.1.0",
        "ledger_sha256": _ledger_digest(rows),
        "encrypted_recovery_key_sha256": sha256_hex(encrypted_recovery_key),
    }
    if set(manifest) != _MANIFEST_FIELDS:
        raise ValidationError("recovery manifest has unknown or missing fields")
    signature = signer_private_key.sign(RECOVERY_DOMAIN + canonical_bytes(manifest))
    bundle = {
        "bundle_version": "imprint.authority.recovery-bundle/1.0.0",
        "manifest": manifest, "ledger": rows,
        "encrypted_recovery_key_b64": base64.b64encode(encrypted_recovery_key).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
    }
    publish_new_private(destination, canonical_bytes(bundle) + b"\n")
    return {"path": str(destination), "manifest": manifest, "bundle_sha256": sha256_hex(canonical_bytes(bundle) + b"\n")}


def verify_recovery_bundle(
    source: Path | Mapping[str, Any], *, now=None, require_fresh_checkpoint: bool = False,
) -> dict[str, Any]:
    if isinstance(source, Mapping):
        bundle = dict(source)
    else:
        path = Path(source)
        if path.is_symlink() or not path.is_file():
            raise ValidationError("recovery bundle must be a regular non-symlink file")
        raw = path.read_bytes()
        try:
            bundle = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("recovery bundle is malformed") from exc
        if canonical_bytes(bundle) + b"\n" != raw:
            raise ValidationError("recovery bundle is not canonical")
    if set(bundle) != _BUNDLE_FIELDS or bundle.get("bundle_version") != "imprint.authority.recovery-bundle/1.0.0":
        raise ValidationError("recovery bundle has unknown fields or version")
    manifest = bundle["manifest"]
    rows = bundle["ledger"]
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS or not isinstance(rows, list):
        raise ValidationError("recovery manifest or ledger is malformed")
    if manifest["manifest_version"] != "imprint.authority.recovery-manifest/1.1.0" or _ledger_digest(rows) != manifest["ledger_sha256"]:
        raise ValidationError("recovery manifest ledger digest mismatch")
    history = manifest["checkpoint_history"]
    if not isinstance(history, list) or not history or dict(history[-1]) != manifest["creation_checkpoint"]:
        raise ValidationError("recovery manifest checkpoint history is absent or inconsistent")
    prior_sha = None
    for checkpoint in history:
        if not isinstance(checkpoint, Mapping) or checkpoint.get("prior_checkpoint_sha256") != prior_sha:
            raise ValidationError("recovery manifest checkpoint history is not closed")
        prior_sha = sha256_hex(canonical_bytes(dict(checkpoint)))
    try:
        encrypted = base64.b64decode(bundle["encrypted_recovery_key_b64"], validate=True)
    except (TypeError, ValueError, base64.binascii.Error) as exc:
        raise ValidationError("recovery key encoding is invalid") from exc
    if sha256_hex(encrypted) != manifest["encrypted_recovery_key_sha256"]:
        raise ValidationError("recovery encrypted-key digest mismatch")
    conn = _chain_connection(rows)
    try:
        for checkpoint in history:
            verify_authority_chain(
                conn, expected_operator_id=manifest["operator_id"],
                expected_store_identity=manifest["store_identity"], checkpoint=checkpoint,
                enforce_checkpoint_freshness=False,
            )
        chain = verify_authority_chain(
            conn, expected_operator_id=manifest["operator_id"],
            expected_store_identity=manifest["store_identity"],
            checkpoint=manifest["creation_checkpoint"] if require_fresh_checkpoint else None,
            now=now,
        )
    finally:
        conn.close()
    if chain["head_sequence"] != manifest["ledger_sequence"] or chain["head_sha256"] != manifest["ledger_head_sha256"]:
        raise ValidationError("recovery manifest names another ledger head")
    if chain["genesis_event_sha256"] != manifest["authority_ledger_genesis_sha256"]:
        raise ValidationError("recovery manifest genesis binding mismatch")
    signer = chain["keys"].get(manifest["signer_key_id"])
    recovery = chain["keys"].get(manifest["recovery_key_id"])
    if signer is None or signer["status"] != "active" or signer["kind"] != "installation" or signer["install_id"] != manifest["signer_install_id"]:
        raise ValidationError("recovery manifest signer is not active and paired")
    if recovery is None or recovery["status"] != "active" or recovery["kind"] != "recovery":
        raise ValidationError("recovery key is absent or inactive")
    try:
        signature = base64.b64decode(bundle["signature_b64"], validate=True)
        public_key_from_b64(signer["public_key_b64"]).verify(
            signature, RECOVERY_DOMAIN + canonical_bytes(manifest),
        )
    except (TypeError, ValueError, base64.binascii.Error, InvalidSignature) as exc:
        raise ValidationError("recovery manifest signature is invalid") from exc
    return {"bundle": bundle, "manifest": manifest, "ledger": rows, "encrypted_recovery_key": encrypted, "chain": chain}


def write_authority_transport(
    destination: Path, *, operator_id: str, store_identity: str,
    genesis_event_sha256: str, ledger_rows: Sequence[Mapping[str, Any]],
    checkpoint_history: Sequence[Mapping[str, Any]], checkpoint: Mapping[str, Any],
) -> dict[str, Any]:
    """Publish the fresh public chain/checkpoint separately from recovery secrets."""
    rows = [dict(row) for row in ledger_rows]
    value = {
        "transport_version": "imprint.authority.transport/1.0.0",
        "operator_id": operator_id,
        "store_identity": store_identity,
        "authority_ledger_genesis_sha256": genesis_event_sha256,
        "ledger": rows,
        "ledger_sha256": _ledger_digest(rows),
        "checkpoint_history": [dict(item) for item in checkpoint_history],
        "checkpoint": dict(checkpoint),
    }
    if set(value) != _TRANSPORT_FIELDS:
        raise ValidationError("authority transport has unknown or missing fields")
    encoded = canonical_bytes(value) + b"\n"
    publish_new_private(Path(destination), encoded)
    return {"path": str(destination), "transport_sha256": sha256_hex(encoded), "checkpoint": dict(checkpoint)}


def verify_authority_transport(source: Path | Mapping[str, Any], *, now=None) -> dict[str, Any]:
    """Verify a physically supplied <=24-hour checkpoint and every chain event."""
    if isinstance(source, Mapping):
        value = dict(source)
    else:
        path = Path(source)
        if path.is_symlink() or not path.is_file():
            raise ValidationError("authority transport must be a regular non-symlink file")
        raw = path.read_bytes()
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("authority transport is malformed") from exc
        if canonical_bytes(value) + b"\n" != raw:
            raise ValidationError("authority transport is not canonical")
    if set(value) != _TRANSPORT_FIELDS or value.get("transport_version") != "imprint.authority.transport/1.0.0":
        raise ValidationError("authority transport has unknown fields or version")
    rows = value["ledger"]
    if not isinstance(rows, list) or _ledger_digest(rows) != value["ledger_sha256"]:
        raise ValidationError("authority transport ledger digest mismatch")
    conn = _chain_connection(rows)
    try:
        prior_sha = None
        history = value["checkpoint_history"]
        if not isinstance(history, list) or not history:
            raise ValidationError("authority transport checkpoint history is absent")
        for item in history:
            if not isinstance(item, Mapping) or item.get("prior_checkpoint_sha256") != prior_sha:
                raise ValidationError("authority transport checkpoint history is not closed")
            verify_authority_chain(
                conn, expected_operator_id=value["operator_id"],
                expected_store_identity=value["store_identity"],
                checkpoint=item, now=now if item == history[-1] else None,
                enforce_checkpoint_freshness=(item == history[-1]),
            )
            prior_sha = sha256_hex(canonical_bytes(dict(item)))
        if dict(history[-1]) != value["checkpoint"]:
            raise ValidationError("authority transport latest checkpoint is inconsistent")
        chain = verify_authority_chain(
            conn, expected_operator_id=value["operator_id"],
            expected_store_identity=value["store_identity"],
            checkpoint=value["checkpoint"], now=now,
        )
    finally:
        conn.close()
    if chain["genesis_event_sha256"] != value["authority_ledger_genesis_sha256"]:
        raise ValidationError("authority transport genesis binding mismatch")
    return {"transport": value, "ledger": rows, "checkpoint": value["checkpoint"], "chain": chain}


__all__ = [
    "decrypt_recovery_key", "encrypt_recovery_key", "recovery_aad",
    "verify_authority_transport", "verify_recovery_bundle",
    "write_authority_transport", "write_recovery_bundle",
]
