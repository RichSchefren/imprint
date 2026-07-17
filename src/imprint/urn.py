"""Canonical typed UUIDv4 URNs shared by every Imprint boundary."""

from __future__ import annotations

import re
import uuid
from typing import Any

from .errors import ValidationError

_KIND = re.compile(r"^[a-z][a-z0-9_-]*$")


def make_urn(kind: str) -> str:
    """Mint a canonical typed UUIDv4 URN."""
    if not isinstance(kind, str) or _KIND.fullmatch(kind) is None:
        raise ValidationError(f"invalid URN kind: {kind}")
    return f"urn:imprint:{kind}:{uuid.uuid4()}"


def require_urn(value: Any, kind: str | None = None, field: str = "URN") -> str:
    """Validate the one public Imprint URN grammar without accepting aliases."""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an Imprint URN")
    parts = value.split(":")
    if len(parts) != 4 or parts[:2] != ["urn", "imprint"]:
        raise ValidationError(f"{field} must be an Imprint URN")
    actual_kind, uuid_text = parts[2], parts[3]
    if _KIND.fullmatch(actual_kind) is None or (kind is not None and actual_kind != kind):
        raise ValidationError(f"{field} must be a {kind or 'typed'} URN")
    try:
        parsed = uuid.UUID(uuid_text)
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"{field} has an invalid UUID") from exc
    if parsed.version != 4 or str(parsed) != uuid_text:
        raise ValidationError(f"{field} must contain canonical UUIDv4")
    return value
