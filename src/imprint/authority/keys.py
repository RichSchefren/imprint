"""Ed25519 key generation and passphrase-protected private-key blobs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from imprint.errors import ValidationError
from imprint.permissions import assert_private_file, secure_directory
from .challenge import canonical_bytes, sha256_hex


ALGORITHM_SUITE = "Ed25519+PKCS8-DER+AES-256-GCM+scrypt-N262144-r8-p1"
SCRYPT_N = 2**18
SCRYPT_R = 8
SCRYPT_P = 1
_BLOB_FIELDS = frozenset({
    "blob_version", "algorithm_suite", "salt_b64", "nonce_b64",
    "ciphertext_b64", "aad_sha256",
})


@dataclass(frozen=True)
class GeneratedKey:
    private_key: Ed25519PrivateKey  # gitleaks:allow -- a type annotation, not key material
    public_key_raw: bytes
    key_id: str
    fingerprint: str


def generate_key() -> GeneratedKey:
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    fingerprint = sha256_hex(public_raw)
    return GeneratedKey(
        private_key=private_key,
        public_key_raw=public_raw,
        key_id=f"urn:imprint:authority-key:{fingerprint[:32]}",
        fingerprint=f"sha256:{fingerprint}",
    )


def _derive_key(passphrase: str, salt: bytes) -> bytearray:
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValidationError("authority passphrase must contain at least 12 characters")
    try:
        derived = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
            passphrase.encode("utf-8")
        )
    except (MemoryError, ValueError) as exc:
        raise ValidationError("authority key derivation failed") from exc
    return bytearray(derived)


def encrypt_private_key(
    private_key: Ed25519PrivateKey, passphrase: str, *, aad: Mapping[str, Any],
) -> bytes:
    salt = os.urandom(32)
    nonce = os.urandom(12)
    aad_bytes = canonical_bytes(aad)
    wrapping_key = _derive_key(passphrase, salt)
    private_bytes = bytearray(private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    try:
        ciphertext = AESGCM(bytes(wrapping_key)).encrypt(nonce, bytes(private_bytes), aad_bytes)
    finally:
        private_bytes[:] = b"\x00" * len(private_bytes)
        wrapping_key[:] = b"\x00" * len(wrapping_key)
    blob = {
        "blob_version": "imprint.authority.key-blob/1.0.0",
        "algorithm_suite": ALGORITHM_SUITE,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "aad_sha256": sha256_hex(aad_bytes),
    }
    return canonical_bytes(blob) + b"\n"


def validate_encrypted_key_blob(blob_bytes: bytes) -> dict[str, Any]:
    """Validate the closed encrypted-blob schema without decrypting or repairing it."""
    try:
        blob = json.loads(blob_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("authority key blob is malformed") from exc
    if not isinstance(blob, dict) or set(blob) != _BLOB_FIELDS:
        raise ValidationError("authority key blob is malformed")
    if blob["blob_version"] != "imprint.authority.key-blob/1.0.0" or blob["algorithm_suite"] != ALGORITHM_SUITE:
        raise ValidationError("authority key blob algorithm is unsupported")
    if not isinstance(blob["aad_sha256"], str) or len(blob["aad_sha256"]) != 64 or any(
        char not in "0123456789abcdef" for char in blob["aad_sha256"]
    ):
        raise ValidationError("authority key blob binding digest is invalid")
    try:
        salt = base64.b64decode(blob["salt_b64"], validate=True)
        nonce = base64.b64decode(blob["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(blob["ciphertext_b64"], validate=True)
    except (TypeError, ValueError, base64.binascii.Error) as exc:
        raise ValidationError("authority key blob encoding is invalid") from exc
    if len(salt) != 32 or len(nonce) != 12 or len(ciphertext) < 17:
        raise ValidationError("authority key blob lengths are invalid")
    if canonical_bytes(blob) + b"\n" != blob_bytes:
        raise ValidationError("authority key blob is not canonical")
    return blob


def decrypt_private_key(blob_bytes: bytes, passphrase: str, *, aad: Mapping[str, Any]) -> Ed25519PrivateKey:
    blob = validate_encrypted_key_blob(blob_bytes)
    aad_bytes = canonical_bytes(aad)
    if blob["aad_sha256"] != sha256_hex(aad_bytes):
        raise ValidationError("authority key blob binding is invalid")
    salt = base64.b64decode(blob["salt_b64"], validate=True)
    nonce = base64.b64decode(blob["nonce_b64"], validate=True)
    ciphertext = base64.b64decode(blob["ciphertext_b64"], validate=True)
    wrapping_key = _derive_key(passphrase, salt)
    try:
        try:
            private_der = bytearray(AESGCM(bytes(wrapping_key)).decrypt(nonce, ciphertext, aad_bytes))
        except InvalidTag as exc:
            raise ValidationError("authority passphrase or key blob is invalid") from exc
    finally:
        wrapping_key[:] = b"\x00" * len(wrapping_key)
    try:
        key = serialization.load_der_private_key(bytes(private_der), password=None)
    except (TypeError, ValueError) as exc:
        raise ValidationError("authority private key is invalid") from exc
    finally:
        private_der[:] = b"\x00" * len(private_der)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValidationError("authority private key is not Ed25519")
    return key


def key_aad(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        name: metadata[name] for name in (
            "operator_id", "install_id", "store_identity", "key_id",
            "public_key_b64", "public_key_fingerprint", "created_at",
            "algorithm_suite", "ledger_sequence", "enrollment_nonce",
        )
    }


def read_verified_blob(data_root: Path, binding: Mapping[str, Any]) -> bytes:
    relative = binding["blob_rel_path"]
    if not isinstance(relative, str) or relative.startswith(("/", "\\")) or ".." in Path(relative).parts:
        raise ValidationError("authority key blob path is invalid")
    target = data_root / relative
    try:
        assert_private_file(target)
    except OSError as exc:
        raise ValidationError("authority key blob is missing or has unsafe permissions") from exc
    content = target.read_bytes()
    if len(content) != binding["blob_size"] or hashlib.sha256(content).hexdigest() != binding["blob_sha256"]:
        raise ValidationError("authority key blob digest mismatch")
    return content


def prepare_key_directory(data_root: Path) -> Path:
    authority = secure_directory(data_root / "authority")
    return secure_directory(authority / "keys")


def verify_public_binding(private_key: Ed25519PrivateKey, public_key_b64: str) -> None:
    try:
        expected = base64.b64decode(public_key_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidationError("authority public key is invalid") from exc
    actual = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    if actual != expected:
        raise ValidationError("authority private key does not match public binding")


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(value, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidationError("authority public key is invalid") from exc
