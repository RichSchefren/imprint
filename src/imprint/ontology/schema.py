"""Closed capture schemas with a namespaced extension escape hatch."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from imprint.constants import AUTHORITY_TIERS, PROVENANCE
from imprint.errors import ValidationError
from imprint.urn import make_urn, require_urn

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def payload_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_provenance(value: Any, *, raw_capture: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("provenance must be an object")
    status = value.get("status")
    if status not in PROVENANCE:
        raise ValidationError("unknown provenance status")
    if raw_capture and status != "captured":
        raise ValidationError("raw operator capture must be captured")
    if raw_capture and value.get("actor_class") != "operator":
        raise ValidationError("raw captured authority requires operator actor_class")
    return value


# Compatibility import only. Raw capture has one canonical validator.
from imprint.capture.schema import validate_capture_envelope as validate_capture_envelope
