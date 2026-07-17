"""Closed, typed ontology envelopes shared by Imprint knowledge levels.

The raw-capture envelope remains owned by :mod:`imprint.capture.schema`.  These
contracts describe graph nodes and relations after capture without weakening
that persist-first boundary.
"""

from __future__ import annotations

import math
from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping

from imprint.constants import AUTHORITY_TIERS, ONTOLOGY_SCHEMA_VERSION, PROVENANCE
from imprint.errors import ValidationError
from imprint.urn import require_urn as require_canonical_urn


KNOWLEDGE_NODE_TYPES = frozenset({"Principle", "Belief", "Value", "Rule", "Domain"})
JUDGMENT_NODE_TYPES = frozenset({"Case", "Verdict", "Call", "Alternative", "Pattern"}) | KNOWLEDGE_NODE_TYPES
GENERAL_NODE_TYPES = frozenset({"Outcome", "CalibrationTrial"})

# Imported lazily by validators as well; importing the type sets here is safe
# because the leaf modules do not import this registry.
from imprint.ontology.operator import OPERATOR_NODE_TYPES
from imprint.ontology.world import WORLD_NODE_TYPES, RELATION_SIGNATURES as WORLD_RELATIONS

NODE_TYPES = (
    JUDGMENT_NODE_TYPES | GENERAL_NODE_TYPES | OPERATOR_NODE_TYPES |
    WORLD_NODE_TYPES
)

# Endpoint declarations are part of the public contract.  ``None`` means any
# registered node type, while a frozenset closes an endpoint to named types.
RELATION_REGISTRY: dict[str, tuple[frozenset[str] | None, frozenset[str] | None]] = {
    # Raw recorder relations are retained as their immutable v3.0 names.  They
    # are explicitly registered so the canonical writer and typed ontology do
    # not operate with two hidden vocabularies.
    "verdict_about_case": (frozenset({"Verdict"}), frozenset({"Case"})),
    "made_call": (frozenset({"Verdict"}), frozenset({"Call"})),
    "supported_by": (frozenset({"Verdict"}), frozenset({"Evidence"})),
    "chose_alternative": (frozenset({"Verdict"}), frozenset({"Alternative"})),
    "rejected_alternative": (frozenset({"Verdict"}), frozenset({"Alternative"})),
    "rendered_in": (frozenset({"Verdict"}), frozenset({"Case"})),
    "makes_call": (frozenset({"Verdict"}), frozenset({"Call"})),
    "chose": (frozenset({"Verdict"}), frozenset({"Alternative"})),
    "rejected": (frozenset({"Verdict"}), frozenset({"Alternative"})),
    "derived_from": (frozenset({"Pattern"}), frozenset({"Case"})),
    "expressed": (frozenset({"Verdict"}), KNOWLEDGE_NODE_TYPES - {"Domain"}),
    "protects": (frozenset({"Principle", "Rule"}), frozenset({"Value"})),
    "depends_on": (KNOWLEDGE_NODE_TYPES - {"Domain"}, KNOWLEDGE_NODE_TYPES),
    "extracted_from": (KNOWLEDGE_NODE_TYPES - {"Domain"}, frozenset({"Case", "Verdict"})),
    "inferred_from": (KNOWLEDGE_NODE_TYPES - {"Domain"}, frozenset({"Case", "Verdict", "Pattern"})),
    "similar_to": (KNOWLEDGE_NODE_TYPES, KNOWLEDGE_NODE_TYPES),
    "led_to": (frozenset({"Verdict", "Case"}), frozenset({"Outcome"})),
    "tested_by": (frozenset({"Pattern"}), frozenset({"CalibrationTrial"})),
    "resolved_by": (frozenset({"CalibrationTrial"}), frozenset({"Outcome"})),
    "supports": (None, None),
    "weakens": (None, None),
    "contradicts": (None, None),
    "supersedes": (None, None),
    "authorized_by": (frozenset({"Observation", "Outcome"}), frozenset({"ConsentGrant"})),
    # Lifecycle-only: Proposal is intentionally not a semantic node type and
    # cannot be written through ontology add-node. The atomic successor writer
    # is the sole producer of this typed audit relation.
    "proposal_succeeded_by": (frozenset({"Proposal"}), NODE_TYPES),
}
for _relation, _signature in WORLD_RELATIONS.items():
    if _relation not in RELATION_REGISTRY:
        RELATION_REGISTRY[_relation] = _signature
        continue
    _old_sources, _old_targets = RELATION_REGISTRY[_relation]
    _new_sources, _new_targets = _signature
    RELATION_REGISTRY[_relation] = (
        None if _old_sources is None or _new_sources is None else _old_sources | _new_sources,
        None if _old_targets is None or _new_targets is None else _old_targets | _new_targets,
    )

_NODE_FIELDS = frozenset({
    "record_schema_version", "node_id", "node_type", "operator_id", "payload", "provenance",
})
_RELATION_FIELDS = frozenset({
    "record_schema_version", "relation_id", "relation_type", "source_id", "source_type",
    "target_id", "target_type", "operator_id", "evidence_mode", "why", "provenance",
})
_EVIDENCE_MODES = frozenset({"captured", "extracted", "declared", "observed", "inferred", "ratified"})
_PROVENANCE_FIELDS = frozenset({
    "status", "authority_tier", "actor_class", "actor_id", "mechanism",
    "evidence_ids", "model", "ratifier_id",
})
_ACTOR_CLASSES = frozenset({"operator", "software", "model", "importer"})


def require_exact_fields(value: Mapping[str, Any], expected: frozenset[str], field: str) -> None:
    """Fail closed when a contract gains, loses, or misspells a field."""
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown:
        raise ValidationError(f"unknown {field} fields: {sorted(unknown)}")
    if missing:
        raise ValidationError(f"missing {field} fields: {sorted(missing)}")


def require_text(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def require_urn(value: Any, kind: str | None, field: str) -> str:
    return require_canonical_urn(value, kind, field)


def require_time(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a timezone")
    return value


def require_confidence(value: Any, field: str = "confidence") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a number between 0 and 1")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 1:
        raise ValidationError(f"{field} must be a number between 0 and 1")
    return result


def validate_reason(reason: Any, status: Any, *, prefix: str = "reason") -> None:
    """Preserve honest nullable rationale semantics used by raw capture."""
    allowed = {"absent", "pending", "supplied", "later_added"}
    if status not in allowed:
        raise ValidationError(f"{prefix}_status is invalid")
    if reason is None:
        if status in {"supplied", "later_added"}:
            raise ValidationError(f"{prefix} cannot be null when {prefix}_status is {status}")
        return
    require_text(reason, prefix)
    if status not in {"supplied", "later_added"}:
        raise ValidationError(f"{prefix} and {prefix}_status disagree")


def validate_provenance_contract(value: Any) -> dict[str, Any]:
    """Validate origin and prevent inferred material from gaining authority."""
    if not isinstance(value, Mapping):
        raise ValidationError("provenance must be an object")
    require_exact_fields(value, _PROVENANCE_FIELDS, "provenance")
    status = value["status"]
    tier = value["authority_tier"]
    actor_class = value["actor_class"]
    if status not in PROVENANCE or tier not in AUTHORITY_TIERS:
        raise ValidationError("unsupported provenance status or authority tier")
    if actor_class not in _ACTOR_CLASSES:
        raise ValidationError("unsupported provenance actor_class")
    require_urn(value["actor_id"], None, "provenance.actor_id")
    require_text(value["mechanism"], "provenance.mechanism")
    evidence_ids = value["evidence_ids"]
    if not isinstance(evidence_ids, list) or len(evidence_ids) != len(set(evidence_ids)):
        raise ValidationError("provenance.evidence_ids must be a unique list")
    for item in evidence_ids:
        require_urn(item, None, "provenance.evidence_ids")

    model, ratifier = value["model"], value["ratifier_id"]
    if model is not None:
        require_text(model, "provenance.model")
    if ratifier is not None:
        require_urn(ratifier, None, "provenance.ratifier_id")

    if status == "captured":
        if tier != "captured_judgment" or actor_class != "operator" or model is not None or ratifier is not None:
            raise ValidationError("captured provenance must remain operator-authored captured judgment")
    elif status == "extracted":
        if tier not in {"imported_floor", "observed_candidate"} or ratifier is not None or not evidence_ids:
            raise ValidationError("extracted provenance requires evidence and non-ratified authority")
    elif status == "inferred":
        if tier != "inferred_candidate" or actor_class not in {"model", "software"} or not evidence_ids or ratifier is not None:
            raise ValidationError("inferred provenance must remain an evidenced candidate")
        if actor_class == "model" and model is None:
            raise ValidationError("model inference must identify its model")
    elif status == "ratified":
        if tier != "ratified_knowledge" or ratifier is None or actor_class != "operator" or not evidence_ids:
            raise ValidationError("ratified provenance requires operator ratification and evidence")
        if ratifier != value["actor_id"]:
            raise ValidationError("ratified provenance actor and ratifier must be the same operator")
    return deepcopy(dict(value))


def validate_node_contract(value: Any) -> dict[str, Any]:
    """Validate one registered ontology node and its type-specific payload."""
    if not isinstance(value, Mapping):
        raise ValidationError("node contract must be an object")
    require_exact_fields(value, _NODE_FIELDS, "node")
    if value["record_schema_version"] != ONTOLOGY_SCHEMA_VERSION:
        raise ValidationError("unsupported ontology schema version")
    node_type = value["node_type"]
    if node_type not in NODE_TYPES:
        raise ValidationError("unsupported ontology node_type")
    require_urn(value["node_id"], node_type.lower().replace("trial", "_trial"), "node_id")
    require_urn(value["operator_id"], "operator", "operator_id")
    provenance = validate_provenance_contract(value["provenance"])
    if provenance["status"] in {"captured", "ratified"} and provenance["actor_id"] != value["operator_id"]:
        raise ValidationError("captured or ratified semantic authority must belong to the contract operator")
    if not isinstance(value["payload"], Mapping):
        raise ValidationError("payload must be an object")

    payload = validate_node_payload(node_type, value["payload"], provenance)
    if isinstance(payload, Mapping) and "operator_id" in payload and payload["operator_id"] != value["operator_id"]:
        raise ValidationError("payload operator_id must match the semantic node operator_id")
    if node_type in {"SelfModelAssertion", "InterventionRule"}:
        inner_status = payload["provenance"]["status"]
        if inner_status != provenance["status"]:
            raise ValidationError("self-model payload provenance must match outer semantic provenance")
        allowed_reviews = {
            "inferred": {"proposed", "deferred", "rejected"},
            "ratified": {"confirmed", "corrected"},
        }
        if (
            provenance["status"] not in allowed_reviews
            or payload["review_state"] not in allowed_reviews[provenance["status"]]
        ):
            raise ValidationError("self-model review state conflicts with semantic authority")
    result = dict(value)
    result["payload"] = payload
    result["provenance"] = provenance
    return deepcopy(result)


def validate_relation_contract(value: Any) -> dict[str, Any]:
    """Validate a typed, evidence-linked relation without touching storage."""
    if not isinstance(value, Mapping):
        raise ValidationError("relation contract must be an object")
    require_exact_fields(value, _RELATION_FIELDS, "relation")
    if value["record_schema_version"] != ONTOLOGY_SCHEMA_VERSION:
        raise ValidationError("unsupported ontology schema version")
    relation_type = value["relation_type"]
    if relation_type not in RELATION_REGISTRY:
        raise ValidationError("unsupported ontology relation_type")
    source_type, target_type = value["source_type"], value["target_type"]
    if source_type not in NODE_TYPES or target_type not in NODE_TYPES:
        raise ValidationError("relation endpoints must use registered node types")
    allowed_sources, allowed_targets = RELATION_REGISTRY[relation_type]
    if allowed_sources is not None and source_type not in allowed_sources:
        raise ValidationError("relation source_type is invalid")
    if allowed_targets is not None and target_type not in allowed_targets:
        raise ValidationError("relation target_type is invalid")
    require_urn(value["relation_id"], "relation", "relation_id")
    require_urn(value["source_id"], source_type.lower().replace("trial", "_trial"), "source_id")
    require_urn(value["target_id"], target_type.lower().replace("trial", "_trial"), "target_id")
    require_urn(value["operator_id"], "operator", "operator_id")
    evidence_mode = value["evidence_mode"]
    if evidence_mode not in _EVIDENCE_MODES:
        raise ValidationError("unsupported relation evidence_mode")
    require_text(value["why"], "why")
    provenance = validate_provenance_contract(value["provenance"])
    if provenance["status"] in {"captured", "ratified"} and provenance["actor_id"] != value["operator_id"]:
        raise ValidationError("captured or ratified relation authority must belong to the contract operator")
    if not provenance["evidence_ids"]:
        raise ValidationError("relations require provenance evidence")
    if relation_type == "extracted_from" and provenance["status"] != "extracted":
        raise ValidationError("extracted_from requires extracted provenance")
    if relation_type == "inferred_from" and provenance["status"] not in {"inferred", "ratified"}:
        raise ValidationError("inferred_from requires inferred or operator-ratified provenance")
    if relation_type == "similar_to":
        if source_type != target_type:
            raise ValidationError("similar_to endpoints must have the same node type")
        if value["source_id"] == value["target_id"]:
            raise ValidationError("similar_to cannot relate a node to itself")
    allowed_statuses = {
        "captured": {"captured"}, "extracted": {"extracted"},
        "declared": {"captured", "ratified"},
        "observed": {"extracted", "inferred", "ratified"},
        "inferred": {"inferred", "ratified"}, "ratified": {"ratified"},
    }
    if provenance["status"] not in allowed_statuses[evidence_mode]:
        raise ValidationError("relation evidence_mode conflicts with provenance status")
    world_signature = WORLD_RELATIONS.get(relation_type)
    if world_signature and source_type in world_signature[0] and target_type in world_signature[1]:
        from imprint.ontology.world import validate_world_relation
        validate_world_relation(
            source_type, relation_type, target_type,
            {
                "evidence_mode": evidence_mode, "why": value["why"],
                "evidence_ids": provenance["evidence_ids"], "attributes": {},
            },
            provenance,
        )
    result = dict(value)
    result["provenance"] = provenance
    return deepcopy(result)


def validate_node_payload(
    node_type: str, payload: Any, provenance: Mapping[str, Any]
) -> dict[str, Any]:
    """Dispatch every public semantic type through one closed registry."""
    if node_type in JUDGMENT_NODE_TYPES | {"CalibrationTrial"}:
        from imprint.ontology.judgment import validate_payload
        return validate_payload(node_type, payload, provenance)
    if node_type == "Outcome":
        from imprint.ontology.world import validate_world_payload
        return validate_world_payload(node_type, payload, provenance)
    if node_type == "Observation":
        from imprint.ontology.operator import validate_operator_payload
        return validate_operator_payload(node_type, payload)
    if node_type in OPERATOR_NODE_TYPES:
        from imprint.ontology.operator import validate_operator_payload
        return validate_operator_payload(node_type, payload)
    if node_type in WORLD_NODE_TYPES:
        from imprint.ontology.world import validate_world_payload
        return validate_world_payload(node_type, payload, provenance)
    raise ValidationError("unsupported ontology node_type")
