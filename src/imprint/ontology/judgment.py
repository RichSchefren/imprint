"""Typed Level 3 judgment and calibration payload contracts."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Callable, Mapping

from imprint.constants import CALL_TYPES
from imprint.errors import ValidationError
from imprint.ontology.contracts import (
    require_confidence,
    require_exact_fields,
    require_text,
    require_time,
    require_urn,
    validate_reason,
)


_CASE_FIELDS = frozenset({"description", "source_refs", "artifact_refs"})
_CALL_FIELDS = frozenset({"call_type"})
_ALTERNATIVE_FIELDS = frozenset({"description", "disposition"})
_VERDICT_FIELDS = frozenset({
    "raw_operator_text", "call_id", "chosen_alternative_ids", "rejected_alternative_ids",
    "reason", "reason_status",
})
_PATTERN_FIELDS = frozenset({"statement", "case_ids", "reason", "reason_status"})
_CALIBRATION_FIELDS = frozenset({
    "prediction", "predicted_at", "confidence", "outcome_id", "resolved_at",
    "assessment", "reason", "reason_status",
})
_STATEMENT_FIELDS = frozenset({"statement"})
_ENRICHED_STATEMENT_FIELDS = frozenset({"statement", "reason", "reason_status"})
_DOMAIN_STATEMENT_FIELDS = frozenset({"statement", "domain_id"})
_DOMAIN_ENRICHED_STATEMENT_FIELDS = frozenset({
    "statement", "reason", "reason_status", "domain_id",
})
_DOMAIN_FIELDS = frozenset({"domain_id", "public_label", "description", "selected", "frozen"})
_DOMAIN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_DISPOSITIONS = frozenset({"chosen", "rejected"})
_ASSESSMENTS = frozenset({"pending", "confirmed", "disconfirmed", "mixed"})


def _urn_list(value: Any, *, kind: str, field: str, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) != len(set(value)):
        raise ValidationError(f"{field} must be a unique list")
    if nonempty and not value:
        raise ValidationError(f"{field} must not be empty")
    for item in value:
        require_urn(item, kind, field)
    return list(value)


def _case(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_fields(value, _CASE_FIELDS, "Case payload")
    require_text(value["description"], "Case.description")
    _urn_list(value["source_refs"], kind="evidence", field="Case.source_refs", nonempty=True)
    if not isinstance(value["artifact_refs"], list) or not all(isinstance(item, str) and item for item in value["artifact_refs"]):
        raise ValidationError("Case.artifact_refs must be strings")
    return deepcopy(dict(value))


def _call(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_fields(value, _CALL_FIELDS, "Call payload")
    if value["call_type"] not in CALL_TYPES:
        raise ValidationError("Call.call_type is invalid")
    return deepcopy(dict(value))


def _alternative(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_fields(value, _ALTERNATIVE_FIELDS, "Alternative payload")
    require_text(value["description"], "Alternative.description")
    if value["disposition"] not in _DISPOSITIONS:
        raise ValidationError("Alternative.disposition is invalid")
    return deepcopy(dict(value))


def _verdict(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_fields(value, _VERDICT_FIELDS, "Verdict payload")
    require_text(value["raw_operator_text"], "Verdict.raw_operator_text")
    require_urn(value["call_id"], "call", "Verdict.call_id")
    chosen = _urn_list(value["chosen_alternative_ids"], kind="alternative", field="Verdict.chosen_alternative_ids")
    rejected = _urn_list(value["rejected_alternative_ids"], kind="alternative", field="Verdict.rejected_alternative_ids")
    if set(chosen) & set(rejected):
        raise ValidationError("a Verdict cannot both choose and reject an Alternative")
    validate_reason(value["reason"], value["reason_status"], prefix="reason")
    if provenance["status"] == "captured" and provenance["actor_id"] is None:
        raise ValidationError("captured Verdict requires an operator actor")
    return deepcopy(dict(value))


def _pattern(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_fields(value, _PATTERN_FIELDS, "Pattern payload")
    require_text(value["statement"], "Pattern.statement")
    case_ids = _urn_list(value["case_ids"], kind="case", field="Pattern.case_ids", nonempty=True)
    if len(case_ids) < 2:
        raise ValidationError("Pattern requires at least two distinct Case inputs")
    validate_reason(value["reason"], value["reason_status"], prefix="reason")
    if provenance["status"] not in {"inferred", "ratified"}:
        raise ValidationError("Pattern must be inferred or ratified, never raw captured truth")
    return deepcopy(dict(value))


def _knowledge_statement(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    """Validate legacy statement payloads and the additive rationale form."""
    fields = frozenset(value)
    allowed = {
        _STATEMENT_FIELDS, _ENRICHED_STATEMENT_FIELDS,
        _DOMAIN_STATEMENT_FIELDS, _DOMAIN_ENRICHED_STATEMENT_FIELDS,
    }
    if fields not in allowed:
        # Use the standard diagnostic while retaining two explicitly closed,
        # compatibility-preserving shapes.
        require_exact_fields(value, _ENRICHED_STATEMENT_FIELDS, "knowledge payload")
    require_text(value["statement"], "knowledge.statement")
    if "domain_id" in value:
        require_text(value["domain_id"], "knowledge.domain_id")
        if _DOMAIN_ID.fullmatch(value["domain_id"]) is None:
            raise ValidationError("knowledge.domain_id must be a safe lowercase identifier")
    if "reason" in value:
        validate_reason(value["reason"], value["reason_status"], prefix="reason")
    if provenance["status"] == "captured":
        raise ValidationError("derived knowledge must be extracted, inferred, or ratified")
    return deepcopy(dict(value))


def _domain(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_fields(value, _DOMAIN_FIELDS, "Domain payload")
    require_text(value["domain_id"], "Domain.domain_id")
    require_text(value["public_label"], "Domain.public_label")
    require_text(value["description"], "Domain.description")
    if not isinstance(value["selected"], bool) or not isinstance(value["frozen"], bool):
        raise ValidationError("Domain.selected and Domain.frozen must be booleans")
    # Domains may be explicitly operator-declared, unlike derived knowledge.
    return deepcopy(dict(value))


def _calibration(value: Mapping[str, Any], provenance: Mapping[str, Any]) -> dict[str, Any]:
    require_exact_fields(value, _CALIBRATION_FIELDS, "CalibrationTrial payload")
    require_text(value["prediction"], "CalibrationTrial.prediction")
    require_time(value["predicted_at"], "CalibrationTrial.predicted_at")
    require_confidence(value["confidence"], "CalibrationTrial.confidence")
    if value["assessment"] not in _ASSESSMENTS:
        raise ValidationError("CalibrationTrial.assessment is invalid")
    validate_reason(value["reason"], value["reason_status"], prefix="reason")
    if value["assessment"] == "pending":
        if value["outcome_id"] is not None or value["resolved_at"] is not None:
            raise ValidationError("pending CalibrationTrial cannot have a resolution")
    else:
        require_urn(value["outcome_id"], "outcome", "CalibrationTrial.outcome_id")
        require_time(value["resolved_at"], "CalibrationTrial.resolved_at")
    return deepcopy(dict(value))


PAYLOAD_VALIDATORS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]]] = {
    "Case": _case,
    "Verdict": _verdict,
    "Call": _call,
    "Alternative": _alternative,
    "Pattern": _pattern,
    "CalibrationTrial": _calibration,
    "Principle": _knowledge_statement,
    "Belief": _knowledge_statement,
    "Value": _knowledge_statement,
    "Rule": _knowledge_statement,
    "Domain": _domain,
}


def validate_payload(node_type: str, value: Any, provenance: Mapping[str, Any]) -> dict[str, Any]:
    """Dispatch a payload through the closed node-type registry."""
    validator = PAYLOAD_VALIDATORS.get(node_type)
    if validator is None:
        raise ValidationError("unsupported ontology node_type")
    if not isinstance(value, Mapping):
        raise ValidationError(f"{node_type} payload must be an object")
    return validator(value, provenance)
