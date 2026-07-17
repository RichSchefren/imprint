"""Closed proposal schema and deterministic capture routing."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Mapping

from imprint.constants import MAX_EVENT_BYTES, RECORD_SCHEMA_VERSION
from imprint.errors import ValidationError
from imprint.capture.detector import FeedbackDetection
from imprint.urn import make_urn, require_urn

PROPOSAL_TYPES = frozenset({
    "correction_with_reason", "correction_without_reason", "preference",
    "standard", "approval", "refusal", "reason_addition", "non_feedback",
})
ALLOWED_TRANSITIONS = frozenset({"extract", "infer", "route"})
_FORBIDDEN_TRANSITIONS = {"captured", "ratified", "purged", "purge", "migrated", "migration", "tombstoned"}
_FORBIDDEN_KEYS = re.compile(r"(?:^|_)(?:sql|query|path|database|db|command|writer|purge|migration)(?:$|_)", re.I)
_TOP = {"record_schema_version", "proposal_id", "source_input_event_id", "proposal_type", "proposed_transition", "references", "payload", "provenance", "extensions"}


def _urn(value: Any, kind: str) -> None:
    require_urn(value, kind, kind)


def _scan_authority(value: Any, path: str = "proposal") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _FORBIDDEN_KEYS.search(str(key)):
                raise ValidationError(f"proposal contains forbidden authority field at {path}.{key}")
            _scan_authority(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_authority(child, f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _FORBIDDEN_TRANSITIONS or re.search(r"\b(?:insert|update|delete|drop|alter)\s+(?:into|table|from|\w+)", lowered):
            raise ValidationError(f"proposal contains forbidden transition or SQL at {path}")
        if value.startswith(("/", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", value) or "../" in value or "..\\" in value:
            raise ValidationError(f"proposal contains an arbitrary path at {path}")


def validate_proposal(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate model output without granting canonical mutation authority."""
    if not isinstance(value, Mapping) or set(value) != _TOP:
        raise ValidationError("proposal has missing or unknown top-level fields")
    if value["record_schema_version"] != RECORD_SCHEMA_VERSION:
        raise ValidationError("unsupported proposal schema version")
    _urn(value["proposal_id"], "proposal")
    _urn(value["source_input_event_id"], "event")
    if value["proposal_type"] not in PROPOSAL_TYPES:
        raise ValidationError("unknown proposal type")
    if value["proposed_transition"] not in ALLOWED_TRANSITIONS:
        raise ValidationError("unknown or forbidden proposal transition")
    if value["proposal_type"] == "non_feedback" and value["proposed_transition"] != "route":
        raise ValidationError("non_feedback may only route")
    if value["proposal_type"] != "non_feedback" and value["proposed_transition"] == "route":
        raise ValidationError("feedback proposals cannot route as non-feedback")
    references = value["references"]
    if not isinstance(references, Mapping) or set(references) != {"case_id", "verdict_id", "evidence_ids"}:
        raise ValidationError("proposal references are incomplete")
    _urn(references["case_id"], "case")
    _urn(references["verdict_id"], "verdict")
    if not isinstance(references["evidence_ids"], list) or not references["evidence_ids"]:
        raise ValidationError("proposal requires evidence references")
    for evidence_id in references["evidence_ids"]:
        _urn(evidence_id, "evidence")
    payload = value["payload"]
    if not isinstance(payload, Mapping):
        raise ValidationError("proposal payload must be an object")
    reason, status = payload.get("reason"), payload.get("reason_status")
    if reason is None and status in {"supplied", "later_added"}:
        raise ValidationError("proposal fabricates WHY status")
    if reason is not None and (not isinstance(reason, str) or not reason.strip() or status not in {"supplied", "later_added"}):
        raise ValidationError("proposal reason and status disagree")
    if value["proposal_type"] == "correction_with_reason" and reason is None:
        raise ValidationError("correction_with_reason requires source reason")
    if value["proposal_type"] == "correction_without_reason" and reason is not None:
        raise ValidationError("correction_without_reason cannot invent a reason")
    provenance = value["provenance"]
    if not isinstance(provenance, Mapping) or set(provenance) != {"status", "authority_tier", "proposer", "model", "prompt_recipe_hash"}:
        raise ValidationError("proposal provenance is incomplete")
    if provenance["status"] not in {"extracted", "inferred"} or provenance["authority_tier"] not in {"inferred_candidate", "observed_candidate"}:
        raise ValidationError("proposal provenance escalates authority")
    if not isinstance(provenance["proposer"], str) or not provenance["proposer"]:
        raise ValidationError("proposal proposer is required")
    model, recipe_hash = provenance["model"], provenance["prompt_recipe_hash"]
    if model is None and recipe_hash is not None:
        raise ValidationError("prompt hash without a model is invalid")
    if model is not None:
        if not isinstance(model, str) or not model.strip():
            raise ValidationError("model identity must be a non-empty string")
        if not isinstance(recipe_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", recipe_hash):
            raise ValidationError("model proposal requires a prompt recipe SHA-256")
    extensions = value["extensions"]
    if not isinstance(extensions, Mapping):
        raise ValidationError("extensions must be an object")
    _scan_authority(value)
    if len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_EVENT_BYTES:
        raise ValidationError("proposal is oversized")
    return deepcopy(dict(value))


def route_capture_to_proposal(envelope: Mapping[str, Any], detection: FeedbackDetection, *, proposer: str = "deterministic-router") -> dict[str, Any]:
    """Create a proposal from captured facts only; never infer a missing WHY."""
    verdict = envelope["verdict"]
    reason, status = verdict["reason"], verdict["reason_status"]
    route = detection.route
    if route == "correction":
        proposal_type = "correction_with_reason" if reason is not None else "correction_without_reason"
    elif route in {"preference", "standard", "approval", "refusal"}:
        proposal_type = route
    else:
        proposal_type = "non_feedback"
    proposal = {
        "record_schema_version": RECORD_SCHEMA_VERSION,
        "proposal_id": make_urn("proposal"),
        "source_input_event_id": envelope["input_event_id"],
        "proposal_type": proposal_type,
        "proposed_transition": "route" if proposal_type == "non_feedback" else "extract",
        "references": {
            "case_id": envelope["case"]["case_id"],
            "verdict_id": verdict["verdict_id"],
            "evidence_ids": list(envelope["provenance"]["evidence_ids"]),
        },
        "payload": {
            "call_type": verdict["call"]["call_type"],
            "reason": reason,
            "reason_status": status,
            "chosen_alternative_ids": list(verdict["chosen_alternative_ids"]),
            "rejected_alternative_ids": list(verdict["rejected_alternative_ids"]),
        },
        "provenance": {
            "status": "extracted", "authority_tier": "observed_candidate",
            "proposer": proposer, "model": None, "prompt_recipe_hash": None,
        },
        "extensions": {},
    }
    return validate_proposal(proposal)


def build_reason_addition_proposal(original: Mapping[str, Any], later_capture: Mapping[str, Any]) -> dict[str, Any]:
    """Link a later supplied reason without altering the original null verdict."""
    if original["verdict"]["reason"] is not None:
        raise ValidationError("original verdict already has a reason")
    reason = later_capture["verdict"]["reason"]
    if reason is None or later_capture["verdict"]["reason_status"] != "later_added":
        raise ValidationError("later capture must explicitly supply a later_added reason")
    proposal = route_capture_to_proposal(
        later_capture,
        FeedbackDetection(True, "correction", "correct", "reason_addition", 1.0),
    )
    proposal["proposal_type"] = "reason_addition"
    proposal["payload"]["original_verdict_id"] = original["verdict"]["verdict_id"]
    return validate_proposal(proposal)
