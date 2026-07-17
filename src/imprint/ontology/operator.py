"""Generic semantic contracts for operator-controlled self-model records.

The storage layer deliberately remains a generic versioned graph.  This module
is the fail-closed boundary for portable self-model assertions without embedding
any product-specific taxonomy. It performs no storage and grants no authority.
"""

from __future__ import annotations

import math
import re
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.errors import ValidationError
from imprint.urn import require_urn


OPERATOR_ONTOLOGY_VERSION = ONTOLOGY_SCHEMA_VERSION

OPERATOR_NODE_TYPES = frozenset({
    "SelfModelAssertion", "Observation", "Cue", "LexiconTerm",
    "InterventionRule", "ConsentGrant", "DerivationTrace",
})

OBSERVATION_SOURCE_CLASSES = frozenset({
    "operator_explicit", "conversation", "transcript", "screenpipe",
    "financial_record", "behavioral_telemetry", "business_system",
    "customer_result", "external_connector", "approved_import",
})
CONSENT_EXEMPT_SOURCE_CLASSES = frozenset()
CONSENT_PURPOSES = frozenset({
    "self_modeling", "behavioral_observation", "outcome_learning",
    "business_analysis", "retrieval", "export",
})
CONSENT_OPERATIONS = frozenset({"ingest", "store", "derive", "retrieve", "export"})

PROVENANCE_STATUSES = frozenset({"captured", "extracted", "inferred", "ratified"})
REVIEW_STATES = frozenset({"proposed", "deferred", "confirmed", "corrected", "rejected"})
POLARITIES = frozenset({"asset", "constraint", "mixed", "neutral"})

_NAMESPACE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)+$")


def _object(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field} must be an object")
    return value


def _keys(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown:
        raise ValidationError(f"unknown {field} fields: {sorted(unknown)}")
    if missing:
        raise ValidationError(f"missing {field} fields: {sorted(missing)}")


def _text(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def _urn(value: Any, field: str, kind: str | None = None) -> str:
    return require_urn(value, kind, field)


def _urns(value: Any, field: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ValidationError(f"{field} must be {'a non-empty' if nonempty else 'a'} list")
    result = [_urn(item, f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        raise ValidationError(f"{field} must not contain duplicates")
    return result


def _time(value: Any, field: str, *, nullable: bool = False) -> datetime | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a timezone")
    return parsed


def _extensions(value: Any) -> None:
    obj = _object(value, "extensions")
    if any(not isinstance(key, str) or not _NAMESPACE.fullmatch(key) or not isinstance(body, Mapping)
           for key, body in obj.items()):
        raise ValidationError("extensions require namespaced object keys")


def _extension_value(value: Any, field: str) -> str:
    """Require a portable, vendor-namespaced taxonomy value.

    The public contract deliberately does not enumerate private ontology terms.
    Integrations own their vocabulary under stable namespaced identifiers.
    """
    if not isinstance(value, str) or not _NAMESPACE.fullmatch(value):
        raise ValidationError(f"{field} must be a namespaced extension value")
    return value


def _json_value(value: Any, field: str) -> None:
    """Validate generic extension structure as finite JSON data."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError(f"{field} must contain finite JSON values")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_value(item, f"{field}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ValidationError(f"{field} JSON object keys must be non-empty strings")
            _json_value(item, f"{field}.{key}")
        return
    raise ValidationError(f"{field} must contain JSON-compatible values")


def _confidence(value: Any) -> None:
    obj = _object(value, "confidence")
    _keys(obj, {
        "score", "assessor_id", "method", "basis_evidence_ids", "assessed_at",
        "calibration_trial_id", "uncertainty_note",
    }, "confidence")
    score = obj["score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 1:
        raise ValidationError("confidence.score must be between 0 and 1")
    _text(obj["assessor_id"], "confidence.assessor_id")
    if obj["method"] not in {"operator_assessment", "model_estimate", "calibrated_model", "statistical", "approved_import"}:
        raise ValidationError("invalid confidence.method")
    _urns(obj["basis_evidence_ids"], "confidence.basis_evidence_ids", nonempty=True)
    _time(obj["assessed_at"], "confidence.assessed_at")
    if obj["calibration_trial_id"] is not None:
        _urn(obj["calibration_trial_id"], "confidence.calibration_trial_id")
    _text(obj["uncertainty_note"], "confidence.uncertainty_note", nullable=True)


def _freshness(value: Any) -> None:
    obj = _object(value, "freshness")
    _keys(obj, {
        "valid_from", "valid_to", "last_reviewed_at", "revalidate_after",
        "evidence_window_start", "evidence_window_end", "status",
    }, "freshness")
    valid_from = _time(obj["valid_from"], "freshness.valid_from")
    valid_to = _time(obj["valid_to"], "freshness.valid_to", nullable=True)
    reviewed = _time(obj["last_reviewed_at"], "freshness.last_reviewed_at", nullable=True)
    revalidate = _time(obj["revalidate_after"], "freshness.revalidate_after", nullable=True)
    window_start = _time(obj["evidence_window_start"], "freshness.evidence_window_start")
    window_end = _time(obj["evidence_window_end"], "freshness.evidence_window_end")
    if valid_to is not None and valid_to < valid_from:
        raise ValidationError("freshness.valid_to precedes valid_from")
    if window_end < window_start:
        raise ValidationError("freshness evidence window is reversed")
    if reviewed is not None and revalidate is not None and revalidate < reviewed:
        raise ValidationError("freshness.revalidate_after precedes last review")
    if obj["status"] not in {"current", "review_due", "stale", "superseded"}:
        raise ValidationError("invalid freshness.status")


def _review_rule(review_state: Any, provenance: Mapping[str, Any]) -> None:
    if review_state not in REVIEW_STATES:
        raise ValidationError("invalid review_state")
    _keys(provenance, {"status", "actor_class", "actor_id", "model_id", "prompt_id"}, "provenance")
    status = provenance["status"]
    if status not in PROVENANCE_STATUSES:
        raise ValidationError("invalid provenance.status")
    _text(provenance["actor_class"], "provenance.actor_class")
    _text(provenance["actor_id"], "provenance.actor_id")
    _text(provenance["model_id"], "provenance.model_id", nullable=True)
    _text(provenance["prompt_id"], "provenance.prompt_id", nullable=True)
    if status in {"captured", "extracted"}:
        raise ValidationError("self-model readings must enter as inferred proposals")
    if status == "inferred" and review_state not in {"proposed", "deferred", "rejected"}:
        raise ValidationError("an inferred reading cannot be confirmed")
    if status == "inferred" and (provenance["model_id"] is None or provenance["prompt_id"] is None):
        raise ValidationError("inferred readings require model_id and prompt_id")
    if status == "ratified":
        if review_state not in {"confirmed", "corrected"}:
            raise ValidationError("ratified readings must be confirmed or corrected")
        if provenance["actor_class"] != "operator":
            raise ValidationError("only the operator can ratify a self-model reading")


def validate_self_model_assertion(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, "SelfModelAssertion")
    _keys(value, {
        "ontology_schema_version", "operator_id", "function_class", "dimension", "subtype",
        "statement", "polarity", "scope", "source_phase", "derivation_trace_id",
        "evidence_ids", "confidence", "freshness", "review_state", "structure",
        "provenance", "extensions",
    }, "SelfModelAssertion")
    if value["ontology_schema_version"] != OPERATOR_ONTOLOGY_VERSION:
        raise ValidationError("unsupported operator ontology version")
    _urn(value["operator_id"], "operator_id", "operator")
    _extension_value(value["function_class"], "function_class")
    _extension_value(value["dimension"], "dimension")
    _extension_value(value["subtype"], "subtype")
    _text(value["statement"], "statement")
    if value["polarity"] not in POLARITIES:
        raise ValidationError("invalid polarity")
    _text(value["scope"], "scope")
    _extension_value(value["source_phase"], "source_phase")
    _urn(value["derivation_trace_id"], "derivation_trace_id")
    _urns(value["evidence_ids"], "evidence_ids", nonempty=True)
    _confidence(value["confidence"])
    _freshness(value["freshness"])
    _review_rule(value["review_state"], _object(value["provenance"], "provenance"))
    _object(value["structure"], "structure")
    _json_value(value["structure"], "structure")
    _extensions(value["extensions"])
    return deepcopy(dict(value))


def _validate_observation(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, "Observation")
    _keys(value, {
        "ontology_schema_version", "operator_id", "source_class", "observation_kind",
        "subject_id", "description", "observed_at", "window_start", "window_end", "evidence_ids",
        "confidence", "consent_grant_id", "attributes", "extensions",
    }, "Observation")
    if value["ontology_schema_version"] != OPERATOR_ONTOLOGY_VERSION:
        raise ValidationError("unsupported operator ontology version")
    _urn(value["operator_id"], "operator_id", "operator")
    if value["source_class"] not in OBSERVATION_SOURCE_CLASSES:
        raise ValidationError("invalid observation source_class")
    if value["observation_kind"] not in {"behavior", "outcome", "communication", "state", "business_event"}:
        raise ValidationError("invalid observation_kind")
    _urn(value["subject_id"], "subject_id")
    _text(value["description"], "description")
    observed = _time(value["observed_at"], "observed_at")
    start = _time(value["window_start"], "window_start")
    end = _time(value["window_end"], "window_end")
    if end < start or not start <= observed <= end:
        raise ValidationError("observation times are inconsistent")
    _urns(value["evidence_ids"], "evidence_ids", nonempty=True)
    _confidence(value["confidence"])
    _urn(value["consent_grant_id"], "consent_grant_id", "consentgrant")
    _object(value["attributes"], "attributes")
    _extensions(value["extensions"])
    return deepcopy(dict(value))


def _validate_cue(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, "Cue")
    _keys(value, {
        "ontology_schema_version", "operator_id", "cue_kind", "description", "context",
        "interpretation", "observation_id", "evidence_ids", "confidence", "extensions",
    }, "Cue")
    if value["ontology_schema_version"] != OPERATOR_ONTOLOGY_VERSION:
        raise ValidationError("unsupported operator ontology version")
    _urn(value["operator_id"], "operator_id", "operator")
    if value["cue_kind"] not in {"perceptual", "anomaly", "relational", "emotional", "environmental", "temporal", "business"}:
        raise ValidationError("invalid cue_kind")
    _text(value["description"], "description")
    _text(value["context"], "context")
    _text(value["interpretation"], "interpretation", nullable=True)
    _urn(value["observation_id"], "observation_id")
    _urns(value["evidence_ids"], "evidence_ids", nonempty=True)
    _confidence(value["confidence"])
    _extensions(value["extensions"])
    return deepcopy(dict(value))


def _validate_lexicon(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, "LexiconTerm")
    _keys(value, {
        "ontology_schema_version", "operator_id", "term", "definition", "term_kind",
        "aliases", "scope", "evidence_ids", "provenance_status", "extensions",
    }, "LexiconTerm")
    if value["ontology_schema_version"] != OPERATOR_ONTOLOGY_VERSION:
        raise ValidationError("unsupported operator ontology version")
    _urn(value["operator_id"], "operator_id", "operator")
    _text(value["term"], "term")
    _text(value["definition"], "definition")
    if value["term_kind"] not in {"private_vocabulary", "distinction", "metaphor", "shorthand", "label"}:
        raise ValidationError("invalid term_kind")
    if not isinstance(value["aliases"], list) or any(not isinstance(x, str) or not x.strip() for x in value["aliases"]):
        raise ValidationError("aliases must be non-empty strings")
    _text(value["scope"], "scope")
    _urns(value["evidence_ids"], "evidence_ids", nonempty=True)
    if value["provenance_status"] not in PROVENANCE_STATUSES:
        raise ValidationError("invalid provenance_status")
    _extensions(value["extensions"])
    return deepcopy(dict(value))


def _validate_intervention(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, "InterventionRule")
    _keys(value, {
        "ontology_schema_version", "operator_id", "instruction", "trigger_ids",
        "protects_standard_ids", "action_steps", "contraindications", "review_state",
        "evidence_ids", "freshness", "provenance", "extensions",
    }, "InterventionRule")
    if value["ontology_schema_version"] != OPERATOR_ONTOLOGY_VERSION:
        raise ValidationError("unsupported operator ontology version")
    _urn(value["operator_id"], "operator_id", "operator")
    _text(value["instruction"], "instruction")
    _urns(value["trigger_ids"], "trigger_ids", nonempty=True)
    _urns(value["protects_standard_ids"], "protects_standard_ids", nonempty=True)
    if not isinstance(value["action_steps"], list) or not value["action_steps"]:
        raise ValidationError("action_steps must be a non-empty list")
    for index, step in enumerate(value["action_steps"]):
        obj = _object(step, f"action_steps[{index}]")
        _keys(obj, {"order", "instruction", "success_criterion"}, f"action_steps[{index}]")
        if obj["order"] != index + 1:
            raise ValidationError("action_steps order must be contiguous from one")
        _text(obj["instruction"], "action step instruction")
        _text(obj["success_criterion"], "action step success_criterion")
    if not isinstance(value["contraindications"], list) or any(not isinstance(x, str) or not x.strip() for x in value["contraindications"]):
        raise ValidationError("contraindications must be strings")
    _urns(value["evidence_ids"], "evidence_ids", nonempty=True)
    _freshness(value["freshness"])
    _review_rule(value["review_state"], _object(value["provenance"], "provenance"))
    _extensions(value["extensions"])
    return deepcopy(dict(value))


def _validate_consent(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, "ConsentGrant")
    _keys(value, {
        "ontology_schema_version", "operator_id", "source_class", "purposes",
        "sensitivity", "allowed_operations", "retention", "effective_from", "effective_to",
        "granted_by", "granted_at", "revoked_at", "revocation_reason", "extensions",
    }, "ConsentGrant")
    if value["ontology_schema_version"] != OPERATOR_ONTOLOGY_VERSION:
        raise ValidationError("unsupported operator ontology version")
    operator_id = _urn(value["operator_id"], "operator_id", "operator")
    if value["source_class"] not in OBSERVATION_SOURCE_CLASSES:
        raise ValidationError("invalid consent source_class")
    if not isinstance(value["purposes"], list) or not value["purposes"] or set(value["purposes"]) - CONSENT_PURPOSES:
        raise ValidationError("invalid consent purposes")
    if len(value["purposes"]) != len(set(value["purposes"])):
        raise ValidationError("consent purposes must not contain duplicates")
    if value["sensitivity"] not in {"standard", "sensitive", "highly_sensitive"}:
        raise ValidationError("invalid consent sensitivity")
    if not isinstance(value["allowed_operations"], list) or not value["allowed_operations"] or set(value["allowed_operations"]) - CONSENT_OPERATIONS:
        raise ValidationError("invalid allowed_operations")
    retention = _object(value["retention"], "retention")
    _keys(retention, {"mode", "days", "delete_on_revoke"}, "retention")
    if retention["mode"] not in {"session", "days", "until_revoked", "indefinite"}:
        raise ValidationError("invalid retention.mode")
    if retention["mode"] == "days":
        if isinstance(retention["days"], bool) or not isinstance(retention["days"], int) or retention["days"] < 1:
            raise ValidationError("day retention requires a positive day count")
    elif retention["days"] is not None:
        raise ValidationError("retention.days is only valid for day retention")
    if not isinstance(retention["delete_on_revoke"], bool):
        raise ValidationError("retention.delete_on_revoke must be boolean")
    effective_from = _time(value["effective_from"], "effective_from")
    effective_to = _time(value["effective_to"], "effective_to", nullable=True)
    granted_at = _time(value["granted_at"], "granted_at")
    revoked_at = _time(value["revoked_at"], "revoked_at", nullable=True)
    if effective_to is not None and effective_to < effective_from:
        raise ValidationError("consent effective interval is reversed")
    if revoked_at is not None and revoked_at < granted_at:
        raise ValidationError("consent cannot be revoked before it was granted")
    granted_by = _urn(value["granted_by"], "granted_by", "operator")
    if granted_by != operator_id:
        raise ValidationError("only the operator can grant capture consent")
    reason = _text(value["revocation_reason"], "revocation_reason", nullable=True)
    if (revoked_at is None) != (reason is None):
        raise ValidationError("revoked_at and revocation_reason must be supplied together")
    _extensions(value["extensions"])
    return deepcopy(dict(value))


def _validate_trace(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, "DerivationTrace")
    _keys(value, {
        "ontology_schema_version", "operator_id", "element_version_id", "source_phase",
        "derived_from_rule", "computed_at", "input_ids", "input_snapshot_sha256",
        "model_id", "prompt_id", "extensions",
    }, "DerivationTrace")
    if value["ontology_schema_version"] != OPERATOR_ONTOLOGY_VERSION:
        raise ValidationError("unsupported operator ontology version")
    _urn(value["operator_id"], "operator_id", "operator")
    _urn(value["element_version_id"], "element_version_id")
    _extension_value(value["source_phase"], "source_phase")
    _text(value["derived_from_rule"], "derived_from_rule")
    _time(value["computed_at"], "computed_at")
    _urns(value["input_ids"], "input_ids", nonempty=True)
    if not isinstance(value["input_snapshot_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["input_snapshot_sha256"]):
        raise ValidationError("input_snapshot_sha256 must be lowercase SHA-256")
    _text(value["model_id"], "model_id")
    _text(value["prompt_id"], "prompt_id")
    _extensions(value["extensions"])
    return deepcopy(dict(value))


OPERATOR_PAYLOAD_VALIDATORS: Mapping[str, Callable[[Mapping[str, Any]], dict[str, Any]]] = {
    "SelfModelAssertion": validate_self_model_assertion,
    "Observation": _validate_observation,
    "Cue": _validate_cue,
    "LexiconTerm": _validate_lexicon,
    "InterventionRule": _validate_intervention,
    "ConsentGrant": _validate_consent,
    "DerivationTrace": _validate_trace,
}


def validate_operator_payload(node_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and detach one operator-ontology payload."""
    try:
        validator = OPERATOR_PAYLOAD_VALIDATORS[node_type]
    except KeyError as exc:
        raise ValidationError("unsupported operator ontology node type") from exc
    return validator(payload)


def consent_authorizes(
    grant: Mapping[str, Any] | None,
    *,
    source_class: str,
    purpose: str,
    operation: str,
    at: str,
) -> bool:
    """Return valid-time authorization for an explicit ConsentGrant.

    Invalid, absent, expired, or revoked grants deny access.  This helper is
    intentionally fail-closed. Operator-explicit capture has no exemption;
    persistence callers must also enforce the store-created system interval.
    """
    if source_class not in OBSERVATION_SOURCE_CLASSES or purpose not in CONSENT_PURPOSES or operation not in CONSENT_OPERATIONS:
        return False
    if grant is None:
        return False
    try:
        checked = _validate_consent(grant)
        instant = _time(at, "at")
        start = _time(checked["effective_from"], "effective_from")
        end = _time(checked["effective_to"], "effective_to", nullable=True)
        revoked = _time(checked["revoked_at"], "revoked_at", nullable=True)
        retention = checked["retention"]
        retention_end = None
        if retention["mode"] == "days":
            retention_end = start + timedelta(days=retention["days"])
        return (
            checked["source_class"] == source_class
            and purpose in checked["purposes"]
            and operation in checked["allowed_operations"]
            and instant >= start
            and (end is None or instant < end)
            and (retention_end is None or instant < retention_end)
            and (revoked is None or instant < revoked)
        )
    except (ValidationError, TypeError):
        return False
