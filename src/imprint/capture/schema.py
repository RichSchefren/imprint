"""Closed, versioned raw-capture envelopes.

This module performs no storage and no model work.  It intentionally keeps the
raw operator words, case, alternatives, and evidence intact.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from imprint.constants import CALL_TYPES, MAX_EVENT_BYTES, REASON_STATUSES, RECORD_SCHEMA_VERSION
from imprint.errors import ValidationError
from imprint.urn import make_urn, require_urn

_NODE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL = {
    "record_schema_version", "input_event_id", "operator_id", "session_id",
    "node_id", "captured_at", "capture_mechanism", "case", "verdict",
    "alternatives", "evidence", "provenance", "extensions",
}
_CAPTURE_MECHANISMS = {"claude_code_stop_hook", "explicit_cli", "approved_import"}
_EVIDENCE_KINDS = {"operator_verbatim", "artifact", "context"}
_DISPOSITIONS = {"chosen", "rejected"}
_MAX_TEXT = 256 * 1024


def new_urn(kind: str) -> str:
    """Return an opaque UUIDv4 typed URN."""
    return make_urn(kind)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    if len(value.encode("utf-8")) > _MAX_TEXT:
        raise ValidationError(f"{field} is oversized")
    return value


def _alternative(value: str | Mapping[str, Any], disposition: str) -> dict[str, Any]:
    if isinstance(value, str):
        description, alternative_id = value, new_urn("alternative")
    elif isinstance(value, Mapping):
        description = _text(value.get("description"), "alternative.description")
        alternative_id = value.get("alternative_id") or new_urn("alternative")
    else:
        raise ValidationError("alternative must be a string or object")
    return {
        "alternative_id": alternative_id,
        "description": description,
        "disposition": disposition,
    }


def build_capture_envelope(
    *,
    operator_id: str,
    session_id: str,
    node_id: str,
    case_description: str,
    raw_operator_text: str,
    call_type: str,
    capture_mechanism: str,
    captured_by: str,
    reason: str | None = None,
    reason_status: str | None = None,
    chosen_alternatives: Sequence[str | Mapping[str, Any]] = (),
    rejected_alternatives: Sequence[str | Mapping[str, Any]] = (),
    artifact_refs: Sequence[str] = (),
    contextual_evidence: Sequence[Mapping[str, Any]] = (),
    input_event_id: str | None = None,
    captured_at: str | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and validate a complete raw envelope without inferring a reason."""
    raw_operator_text = _text(raw_operator_text, "raw_operator_text")  # type: ignore[assignment]
    if reason_status is None:
        reason_status = "supplied" if reason is not None else "absent"
    if reason is None and reason_status in {"supplied", "later_added"}:
        raise ValidationError("a supplied/later_added reason cannot be null")
    if reason is not None and reason_status not in {"supplied", "later_added"}:
        raise ValidationError("reason text requires supplied or later_added status")

    chosen = [_alternative(item, "chosen") for item in chosen_alternatives]
    rejected = [_alternative(item, "rejected") for item in rejected_alternatives]
    evidence_id = new_urn("evidence")
    evidence = [{
        "evidence_id": evidence_id,
        "kind": "operator_verbatim",
        "content": raw_operator_text,
        "content_sha256": hashlib.sha256(raw_operator_text.encode("utf-8")).hexdigest(),
        "source_locator": f"capture:{session_id}",
    }]
    for item in contextual_evidence:
        content = _text(item.get("content"), "evidence.content")
        evidence.append({
            "evidence_id": item.get("evidence_id") or new_urn("evidence"),
            "kind": item.get("kind", "context"),
            "content": content,
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "source_locator": _text(item.get("source_locator"), "evidence.source_locator"),
        })

    envelope = {
        "record_schema_version": RECORD_SCHEMA_VERSION,
        "input_event_id": input_event_id or new_urn("event"),
        "operator_id": operator_id,
        "session_id": session_id,
        "node_id": node_id,
        "captured_at": captured_at or _utc_now(),
        "capture_mechanism": capture_mechanism,
        "case": {
            "case_id": new_urn("case"),
            "description": _text(case_description, "case.description"),
            "artifact_refs": list(artifact_refs),
            "source_refs": [item["evidence_id"] for item in evidence],
        },
        "verdict": {
            "verdict_id": new_urn("verdict"),
            "raw_operator_text": raw_operator_text,
            "call": {"call_id": new_urn("call"), "call_type": call_type},
            "chosen_alternative_ids": [item["alternative_id"] for item in chosen],
            "rejected_alternative_ids": [item["alternative_id"] for item in rejected],
            "reason": reason,
            "reason_status": reason_status,
        },
        "alternatives": chosen + rejected,
        "evidence": evidence,
        "provenance": {
            "status": "captured", "authority_tier": "observed_candidate",
            "actor_class": "software", "actor_id": _text(captured_by, "captured_by"),
            "captured_by": _text(captured_by, "captured_by"), "model": None,
            "evidence_ids": [item["evidence_id"] for item in evidence],
        },
        "extensions": deepcopy(dict(extensions or {})),
    }
    return validate_capture_envelope(envelope)


def _require_keys(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown:
        raise ValidationError(f"unknown {field} fields: {sorted(unknown)}")
    if missing:
        raise ValidationError(f"missing {field} fields: {sorted(missing)}")


def _urn(value: Any, kind: str, field: str) -> None:
    require_urn(value, kind, field)


def validate_capture_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed on unknown fields, bad references, hashes, provenance, or size."""
    if not isinstance(value, Mapping):
        raise ValidationError("capture envelope must be an object")
    _require_keys(value, _TOP_LEVEL, "top-level")
    version = value["record_schema_version"]
    if version != RECORD_SCHEMA_VERSION:
        raise ValidationError("unsupported record schema version")
    _urn(value["input_event_id"], "event", "input_event_id")
    _urn(value["operator_id"], "operator", "operator_id")
    _urn(value["session_id"], "session", "session_id")
    if not isinstance(value["node_id"], str) or not _NODE_ID.fullmatch(value["node_id"]):
        raise ValidationError("unsafe node_id")
    if value["capture_mechanism"] not in _CAPTURE_MECHANISMS:
        raise ValidationError("invalid capture_mechanism")
    try:
        instant = datetime.fromisoformat(str(value["captured_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("captured_at must be RFC3339") from exc
    if instant.tzinfo is None or instant.utcoffset() != timezone.utc.utcoffset(instant):
        raise ValidationError("captured_at must be UTC")

    case, verdict = value["case"], value["verdict"]
    if not isinstance(case, Mapping) or not isinstance(verdict, Mapping):
        raise ValidationError("case and verdict must be objects")
    _require_keys(case, {"case_id", "description", "artifact_refs", "source_refs"}, "case")
    _require_keys(verdict, {"verdict_id", "raw_operator_text", "call", "chosen_alternative_ids", "rejected_alternative_ids", "reason", "reason_status"}, "verdict")
    _urn(case["case_id"], "case", "case.case_id")
    _urn(verdict["verdict_id"], "verdict", "verdict.verdict_id")
    _text(case["description"], "case.description")
    _text(verdict["raw_operator_text"], "verdict.raw_operator_text")
    if not isinstance(case["artifact_refs"], list) or not all(isinstance(x, str) for x in case["artifact_refs"]):
        raise ValidationError("case.artifact_refs must be strings")

    call = verdict["call"]
    if not isinstance(call, Mapping):
        raise ValidationError("verdict.call must be an object")
    _require_keys(call, {"call_id", "call_type"}, "call")
    _urn(call["call_id"], "call", "call.call_id")
    if call["call_type"] not in CALL_TYPES:
        raise ValidationError("invalid call_type")
    if verdict["reason_status"] not in REASON_STATUSES:
        raise ValidationError("invalid reason_status")
    reason = verdict["reason"]
    if reason is None and verdict["reason_status"] in {"supplied", "later_added"}:
        raise ValidationError("reason status fabricates a missing reason")
    if reason is not None:
        _text(reason, "verdict.reason")
        if verdict["reason_status"] not in {"supplied", "later_added"}:
            raise ValidationError("reason and reason_status disagree")

    alternatives = value["alternatives"]
    if not isinstance(alternatives, list):
        raise ValidationError("alternatives must be a list")
    by_id: dict[str, str] = {}
    for item in alternatives:
        if not isinstance(item, Mapping):
            raise ValidationError("alternative must be an object")
        _require_keys(item, {"alternative_id", "description", "disposition"}, "alternative")
        _urn(item["alternative_id"], "alternative", "alternative.alternative_id")
        _text(item["description"], "alternative.description")
        if item["disposition"] not in _DISPOSITIONS or item["alternative_id"] in by_id:
            raise ValidationError("invalid or duplicate alternative")
        by_id[item["alternative_id"]] = item["disposition"]
    for key, disposition in (("chosen_alternative_ids", "chosen"), ("rejected_alternative_ids", "rejected")):
        ids = verdict[key]
        if not isinstance(ids, list) or len(ids) != len(set(ids)):
            raise ValidationError(f"verdict.{key} must be a unique list")
        if any(by_id.get(item) != disposition for item in ids):
            raise ValidationError(f"verdict.{key} does not match alternatives")
    if set(by_id) != set(verdict["chosen_alternative_ids"] + verdict["rejected_alternative_ids"]):
        raise ValidationError("unreferenced alternative")

    evidence = value["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ValidationError("evidence must be a non-empty list")
    evidence_ids: set[str] = set()
    for item in evidence:
        if not isinstance(item, Mapping):
            raise ValidationError("evidence item must be an object")
        _require_keys(item, {"evidence_id", "kind", "content", "content_sha256", "source_locator"}, "evidence")
        _urn(item["evidence_id"], "evidence", "evidence.evidence_id")
        content = _text(item["content"], "evidence.content")
        if item["kind"] not in _EVIDENCE_KINDS or item["evidence_id"] in evidence_ids:
            raise ValidationError("invalid or duplicate evidence")
        if not isinstance(item["content_sha256"], str) or not _SHA256.fullmatch(item["content_sha256"]):
            raise ValidationError("invalid evidence hash")
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != item["content_sha256"]:
            raise ValidationError("evidence hash mismatch")
        _text(item["source_locator"], "evidence.source_locator")
        evidence_ids.add(item["evidence_id"])
    if not isinstance(case["source_refs"], list) or not set(case["source_refs"]).issubset(evidence_ids):
        raise ValidationError("case.source_refs contains an unknown evidence ID")
    if not any(item["kind"] == "operator_verbatim" and item["content"] == verdict["raw_operator_text"] for item in evidence):
        raise ValidationError("verbatim operator evidence is missing")

    provenance = value["provenance"]
    if not isinstance(provenance, Mapping):
        raise ValidationError("provenance must be an object")
    _require_keys(provenance, {"status", "authority_tier", "actor_class", "actor_id", "captured_by", "model", "evidence_ids"}, "provenance")
    if provenance["status"] != "captured" or provenance["authority_tier"] != "observed_candidate" or provenance["actor_class"] != "software" or provenance["model"] is not None:
        raise ValidationError("raw recorder capture must remain a non-authoritative candidate")
    if provenance["actor_id"] != provenance["captured_by"] or set(provenance["evidence_ids"]) != evidence_ids:
        raise ValidationError("provenance references are incomplete")
    _text(provenance["captured_by"], "provenance.captured_by")

    extensions = value["extensions"]
    if not isinstance(extensions, Mapping):
        raise ValidationError("extensions must be an object")
    for namespace, extension in extensions.items():
        if not isinstance(namespace, str) or "." not in namespace or not isinstance(extension, Mapping):
            raise ValidationError("invalid extension namespace")
        if set(extension) != {"schema_version", "payload"}:
            raise ValidationError("extension must contain schema_version and payload only")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(canonical) > MAX_EVENT_BYTES:
        raise ValidationError("capture envelope is oversized")
    return deepcopy(dict(value))
