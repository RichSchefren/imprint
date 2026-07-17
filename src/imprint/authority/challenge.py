"""RFC 8785 canonical, single-use command challenges."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

import rfc8785

from imprint.errors import ValidationError


CONTRACT_VERSION = "imprint.authority.approval/1.1.0"
DOMAIN_SEPARATOR = "imprint-authority-approval-v1"
MAX_TTL_SECONDS = 120
_REQUIRED_FIELDS = frozenset({
    "contract_version", "domain_separator", "operator_id", "install_id",
    "key_id", "store_identity", "ledger_sequence", "operation_id", "purpose",
    "subject_ids", "source_ids", "target_ids", "proposal_ids", "result_version_ids",
    "payload_sha256", "prior_state_sha256", "execution_fields_sha256", "scope", "field_paths",
    "authority_transition", "nonce", "issued_at", "expires_at",
})


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Return RFC 8785 bytes; never fall back to ordinary JSON."""
    try:
        encoded = rfc8785.dumps(dict(value))
    except (TypeError, ValueError, rfc8785.CanonicalizationError) as exc:
        raise ValidationError("E_AUTH_CANONICALIZATION") from exc
    if not isinstance(encoded, bytes):
        raise ValidationError("E_AUTH_CANONICALIZATION")
    return encoded


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def signature_message(challenge: Mapping[str, Any]) -> bytes:
    """Domain-separate signatures independently of the visible JSON field."""
    return DOMAIN_SEPARATOR.encode("ascii") + b"\x00" + canonical_bytes(challenge)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValidationError("authority time must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError("authority time must be RFC 3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValidationError("authority time must be RFC 3339 UTC") from exc
    return parsed.astimezone(timezone.utc)


def _string_list(name: str, values: tuple[str, ...]) -> list[str]:
    if any(not isinstance(item, str) or not item for item in values):
        raise ValidationError(f"{name} must contain non-empty strings")
    if len(set(values)) != len(values):
        raise ValidationError(f"{name} must not contain duplicates")
    return list(values)


@dataclass(frozen=True)
class ChallengeRequest:
    operation_id: str
    purpose: str
    payload_sha256: str
    prior_state_sha256: str
    execution_fields_sha256: str
    authority_transition: str
    subject_ids: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    target_ids: tuple[str, ...] = ()
    proposal_ids: tuple[str, ...] = ()
    result_version_ids: tuple[str, ...] = ()
    scope: tuple[str, ...] = ()
    field_paths: tuple[str, ...] = ()

    def validate(self) -> None:
        for name in ("operation_id", "purpose", "authority_transition"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValidationError(f"{name} must be a non-empty string")
        for name in ("payload_sha256", "prior_state_sha256", "execution_fields_sha256"):
            value = getattr(self, name)
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValidationError(f"{name} must be lowercase SHA-256")
        for name in (
            "subject_ids", "source_ids", "target_ids", "proposal_ids",
            "result_version_ids", "scope", "field_paths",
        ):
            _string_list(name, getattr(self, name))


@dataclass(frozen=True)
class ApprovalToken:
    challenge: dict[str, Any]
    signature_b64: str

    def as_dict(self) -> dict[str, Any]:
        return {"challenge": self.challenge, "signature_b64": self.signature_b64}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ApprovalToken":
        if set(value) != {"challenge", "signature_b64"}:
            raise ValidationError("approval token has unknown or missing fields")
        challenge = value.get("challenge")
        signature = value.get("signature_b64")
        if not isinstance(challenge, dict) or not isinstance(signature, str):
            raise ValidationError("approval token is malformed")
        validate_challenge_shape(challenge)
        try:
            decoded = base64.b64decode(signature, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValidationError("approval signature is not canonical base64") from exc
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != signature:
            raise ValidationError("approval signature is not canonical Ed25519 bytes")
        return cls(dict(challenge), signature)


def validate_challenge_shape(challenge: Mapping[str, Any]) -> None:
    if set(challenge) != _REQUIRED_FIELDS:
        raise ValidationError("authority challenge has unknown or missing fields")
    if challenge["contract_version"] != CONTRACT_VERSION or challenge["domain_separator"] != DOMAIN_SEPARATOR:
        raise ValidationError("authority challenge contract is unsupported")
    if not isinstance(challenge["ledger_sequence"], int) or isinstance(challenge["ledger_sequence"], bool) or challenge["ledger_sequence"] < 1:
        raise ValidationError("authority ledger sequence is invalid")
    for name in _REQUIRED_FIELDS - {"ledger_sequence", "subject_ids", "source_ids", "target_ids", "proposal_ids", "result_version_ids", "scope", "field_paths"}:
        if not isinstance(challenge[name], str) or not challenge[name]:
            raise ValidationError(f"authority challenge field {name} is invalid")
    for name in ("subject_ids", "source_ids", "target_ids", "proposal_ids", "result_version_ids", "scope", "field_paths"):
        value = challenge[name]
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value) or len(set(value)) != len(value):
            raise ValidationError(f"authority challenge field {name} is invalid")
    nonce = challenge["nonce"]
    try:
        raw_nonce = base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidationError("authority nonce is invalid") from exc
    if len(raw_nonce) != 32 or base64.urlsafe_b64encode(raw_nonce).rstrip(b"=").decode("ascii") != nonce:
        raise ValidationError("authority nonce is invalid")
    issued = parse_timestamp(challenge["issued_at"])
    expires = parse_timestamp(challenge["expires_at"])
    ttl = (expires - issued).total_seconds()
    if ttl <= 0 or ttl > MAX_TTL_SECONDS:
        raise ValidationError("authority challenge expiry is invalid")


def build_challenge(
    request: ChallengeRequest, *, operator_id: str, install_id: str, key_id: str,
    store_identity: str, ledger_sequence: int, ttl_seconds: int = MAX_TTL_SECONDS,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    request.validate()
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValidationError("authority challenge TTL must be 1..120 seconds")
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    value: dict[str, Any] = {
        "contract_version": CONTRACT_VERSION,
        "domain_separator": DOMAIN_SEPARATOR,
        "operator_id": operator_id,
        "install_id": install_id,
        "key_id": key_id,
        "store_identity": store_identity,
        "ledger_sequence": ledger_sequence,
        "operation_id": request.operation_id,
        "purpose": request.purpose,
        "subject_ids": _string_list("subject_ids", request.subject_ids),
        "source_ids": _string_list("source_ids", request.source_ids),
        "target_ids": _string_list("target_ids", request.target_ids),
        "proposal_ids": _string_list("proposal_ids", request.proposal_ids),
        "result_version_ids": _string_list("result_version_ids", request.result_version_ids),
        "payload_sha256": request.payload_sha256,
        "prior_state_sha256": request.prior_state_sha256,
        "execution_fields_sha256": request.execution_fields_sha256,
        "scope": _string_list("scope", request.scope),
        "field_paths": _string_list("field_paths", request.field_paths),
        "authority_transition": request.authority_transition,
        "nonce": nonce,
        "issued_at": _timestamp(now),
        "expires_at": _timestamp(now + timedelta(seconds=ttl_seconds)),
    }
    validate_challenge_shape(value)
    canonical_bytes(value)
    return value
