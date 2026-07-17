"""Typed declared-versus-observed contracts for the business/world model."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any

from imprint.errors import ValidationError
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.ontology.operator import OBSERVATION_SOURCE_CLASSES, validate_operator_payload
from imprint.ontology.schema import require_urn


DECLARED_BUSINESS_TYPES = frozenset({
    "Customer", "Segment", "Problem", "Desire", "Situation", "Claim", "Promise",
    "Expectation", "Mechanism", "RequiredBehavior", "Offer", "Price", "Channel",
    "Objection", "Proof", "Intervention",
})
OBSERVED_BUSINESS_TYPES = frozenset({
    "SupportAction", "Purchase", "Usage", "Result", "Refund", "Retention", "Referral",
})
GENERAL_EVIDENCE_TYPES = frozenset({"Observation", "Outcome"})
WORLD_NODE_TYPES = DECLARED_BUSINESS_TYPES | OBSERVED_BUSINESS_TYPES | GENERAL_EVIDENCE_TYPES

ATTRIBUTION_STATUSES = frozenset({"unknown", "associated", "contributory", "causal", "contested"})

_PRIMARY_FIELDS = {
    "Customer": ("name",), "Segment": ("name", "definition"), "Problem": ("description",),
    "Desire": ("description",), "Situation": ("description",), "Claim": ("statement",),
    "Promise": ("statement",), "Expectation": ("statement",), "Mechanism": ("description",),
    "RequiredBehavior": ("description",), "Offer": ("name",), "Price": ("amount", "currency"),
    "Channel": ("name",), "Objection": ("statement",), "Proof": ("description",),
    "Intervention": ("description",), "SupportAction": ("action",),
    "Purchase": ("amount", "currency"), "Usage": ("action",),
    "Result": ("metric", "value", "unit"), "Refund": ("amount", "currency", "reason"),
    "Retention": ("status",), "Referral": ("referred_party",),
}
_BUSINESS_COMMON = frozenset({"evidence_mode", "effective_at", "source_refs", "attributes"})


def _time(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include timezone")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def _sources(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValidationError("source_refs must be a non-empty list")
    for item in value:
        require_urn(item)
    if len(value) != len(set(value)):
        raise ValidationError("source_refs cannot contain duplicates")
    return value


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be numeric")
    return float(value)


def _assert_closed(payload: dict[str, Any], expected: set[str] | frozenset[str]) -> None:
    unknown = set(payload) - set(expected)
    missing = set(expected) - set(payload)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing fields: {sorted(missing)}")
        if unknown:
            details.append(f"unknown fields: {sorted(unknown)}")
        raise ValidationError("; ".join(details))


def validate_world_payload(node_type: str, payload: Any, provenance: Any) -> dict[str, Any]:
    """Validate a business assertion, general observation, or general outcome."""
    if node_type not in WORLD_NODE_TYPES:
        raise ValidationError("unsupported world node type")
    if not isinstance(payload, dict) or not isinstance(provenance, dict):
        raise ValidationError("world payload and provenance must be objects")
    if node_type == "Observation":
        _validate_world_provenance("observed", provenance)
        return validate_operator_payload("Observation", payload)
    if node_type == "Outcome":
        return _validate_outcome(payload, provenance)

    expected = _BUSINESS_COMMON | frozenset(_PRIMARY_FIELDS[node_type])
    _assert_closed(payload, expected)
    declared = node_type in DECLARED_BUSINESS_TYPES
    required_mode = "declared" if declared else "observed"
    if payload["evidence_mode"] != required_mode:
        raise ValidationError(f"{node_type} must use evidence_mode={required_mode}")
    _time(payload["effective_at"], "effective_at")
    _sources(payload["source_refs"])
    if not isinstance(payload["attributes"], dict):
        raise ValidationError("attributes must be an object")
    _validate_primary_fields(node_type, payload)
    _validate_world_provenance(required_mode, provenance)
    return deepcopy(payload)


def _validate_primary_fields(node_type: str, payload: dict[str, Any]) -> None:
    for field in _PRIMARY_FIELDS[node_type]:
        value = payload[field]
        if field in {"amount", "value"}:
            if field == "value" and isinstance(value, (str, bool)):
                _text(value, field)
            else:
                _number(value, field)
        else:
            _text(value, field)


def _validate_world_provenance(mode: str, provenance: dict[str, Any]) -> None:
    if mode == "declared":
        if provenance.get("actor_class") != "operator":
            raise ValidationError("declared business theory requires an operator actor")
        if provenance.get("status") not in {"captured", "ratified"}:
            raise ValidationError("declared business theory must be captured or ratified")
    else:
        if provenance.get("status") not in {"extracted", "inferred", "ratified"}:
            raise ValidationError("observed business evidence has incompatible provenance")
        if provenance.get("status") == "inferred" and provenance.get("authority_tier") != "observed_candidate":
            raise ValidationError("inferred observations require observed_candidate authority")


def _validate_observation(payload: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any]:
    expected = frozenset({
        "evidence_mode", "subject_id", "source_class", "observed_at", "window_start",
        "window_end", "metric", "value", "unit", "source_refs", "consent_grant_id",
        "attributes",
    })
    _assert_closed(payload, expected)
    if payload["evidence_mode"] != "observed":
        raise ValidationError("Observation must use evidence_mode=observed")
    require_urn(payload["subject_id"])
    if payload["source_class"] not in OBSERVATION_SOURCE_CLASSES:
        raise ValidationError("unsupported observation source_class")
    _time(payload["observed_at"], "observed_at")
    start = _time(payload["window_start"], "window_start")
    end = _time(payload["window_end"], "window_end")
    if datetime.fromisoformat(end.replace("Z", "+00:00")) < datetime.fromisoformat(start.replace("Z", "+00:00")):
        raise ValidationError("observation window_end precedes window_start")
    _text(payload["metric"], "metric")
    if payload["value"] is None:
        raise ValidationError("value cannot be null")
    _text(payload["unit"], "unit")
    _sources(payload["source_refs"])
    require_urn(payload["consent_grant_id"], "consentgrant")
    if not isinstance(payload["attributes"], dict):
        raise ValidationError("attributes must be an object")
    _validate_world_provenance("observed", provenance)
    return deepcopy(payload)


def _validate_outcome(payload: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any]:
    expected = frozenset({
        "ontology_schema_version", "operator_id", "evidence_mode", "subject_id", "description",
        "metric", "value", "unit", "window_start",
        "window_end", "source_class", "attribution_status", "observed_at", "source_refs",
        "consent_grant_id", "attributes",
    })
    _assert_closed(payload, expected)
    if payload["ontology_schema_version"] != ONTOLOGY_SCHEMA_VERSION:
        raise ValidationError("unsupported ontology_schema_version")
    require_urn(payload["operator_id"], "operator")
    # Outcome is an observation about what happened, never a declared expectation.
    if payload["evidence_mode"] != "observed":
        raise ValidationError("Outcome must use evidence_mode=observed")
    require_urn(payload["subject_id"])
    _text(payload["description"], "description")
    _text(payload["metric"], "metric")
    if payload["value"] is None:
        raise ValidationError("value cannot be null")
    _text(payload["unit"], "unit")
    start = _time(payload["window_start"], "window_start")
    end = _time(payload["window_end"], "window_end")
    if datetime.fromisoformat(end.replace("Z", "+00:00")) < datetime.fromisoformat(start.replace("Z", "+00:00")):
        raise ValidationError("outcome window_end precedes window_start")
    if payload["source_class"] not in OBSERVATION_SOURCE_CLASSES:
        raise ValidationError("unsupported outcome source_class")
    if payload["attribution_status"] not in ATTRIBUTION_STATUSES:
        raise ValidationError("unsupported attribution_status")
    _time(payload["observed_at"], "observed_at")
    _sources(payload["source_refs"])
    require_urn(payload["consent_grant_id"], "consentgrant")
    if not isinstance(payload["attributes"], dict):
        raise ValidationError("attributes must be an object")
    _validate_world_provenance("observed", provenance)
    return deepcopy(payload)


# Exact endpoint signatures.  Sets intentionally use semantic types rather
# than storage tables, allowing the central graph validator to compose this
# module with judgment and operator contracts later.
RELATION_SIGNATURES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "targets": (frozenset({"Offer", "Claim", "Intervention"}), frozenset({"Customer", "Segment"})),
    "experiences": (frozenset({"Customer", "Segment"}), frozenset({"Problem"})),
    "desires": (frozenset({"Customer", "Segment"}), frozenset({"Desire"})),
    "occurs_in": (frozenset({"Problem", "Desire"}), frozenset({"Situation"})),
    "promises": (frozenset({"Claim", "Offer"}), frozenset({"Promise"})),
    "expects": (frozenset({"Promise", "Offer"}), frozenset({"Expectation"})),
    "requires": (frozenset({"Expectation", "Mechanism", "Offer"}), frozenset({"RequiredBehavior"})),
    "supported_by": (frozenset({"Claim", "Promise", "Mechanism"}), frozenset({"Proof"})),
    "delivered_through": (frozenset({"Offer", "Intervention"}), frozenset({"Channel"})),
    "priced_as": (frozenset({"Offer"}), frozenset({"Price"})),
    "purchased_via": (frozenset({"Purchase"}), frozenset({"Offer", "Channel"})),
    "used": (frozenset({"Usage"}), frozenset({"Offer", "Mechanism", "Intervention"})),
    "produced": (frozenset({"Usage", "SupportAction", "Intervention"}), frozenset({"Result", "Outcome"})),
    "refunded_because": (frozenset({"Refund"}), frozenset({"Problem", "Objection", "Outcome"})),
    "retained_by": (frozenset({"Retention"}), frozenset({"Offer", "SupportAction", "Result", "Outcome"})),
    "referred_by": (frozenset({"Referral"}), frozenset({"Customer", "Retention", "Result", "Outcome"})),
    "observes": (frozenset({"Observation"}), WORLD_NODE_TYPES - frozenset({"Observation"})),
    "tested_by": (DECLARED_BUSINESS_TYPES, frozenset({"Observation", "Outcome"}) | OBSERVED_BUSINESS_TYPES),
    "confirms": (frozenset({"Observation", "Outcome"}) | OBSERVED_BUSINESS_TYPES, DECLARED_BUSINESS_TYPES),
    "weakens": (frozenset({"Observation", "Outcome"}) | OBSERVED_BUSINESS_TYPES, DECLARED_BUSINESS_TYPES),
    "contradicts": (frozenset({"Observation", "Outcome"}) | OBSERVED_BUSINESS_TYPES, DECLARED_BUSINESS_TYPES),
    "extends": (frozenset({"Observation", "Outcome"}) | OBSERVED_BUSINESS_TYPES, DECLARED_BUSINESS_TYPES),
}


def validate_world_relation(
    source_type: str,
    relation: str,
    target_type: str,
    payload: Any,
    provenance: Any,
) -> dict[str, Any]:
    """Validate endpoint types, evidence channel, and evidence-linked WHY."""
    signature = RELATION_SIGNATURES.get(relation)
    if signature is None:
        raise ValidationError("unsupported world relation")
    if source_type not in signature[0] or target_type not in signature[1]:
        raise ValidationError(f"invalid endpoint signature for {relation}")
    if not isinstance(payload, dict) or not isinstance(provenance, dict):
        raise ValidationError("relation payload and provenance must be objects")
    expected = frozenset({"evidence_mode", "why", "evidence_ids", "attributes"})
    _assert_closed(payload, expected)
    mode = payload["evidence_mode"]
    source_observed = source_type in OBSERVED_BUSINESS_TYPES | GENERAL_EVIDENCE_TYPES
    required_mode = "observed" if source_observed else "declared"
    if mode != required_mode:
        raise ValidationError(f"{relation} from {source_type} requires evidence_mode={required_mode}")
    _text(payload["why"], "why")
    _sources(payload["evidence_ids"])
    if not isinstance(payload["attributes"], dict):
        raise ValidationError("attributes must be an object")
    _validate_world_provenance(mode, provenance)
    return deepcopy(payload)
