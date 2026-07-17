"""Declared-versus-observed business ontology relationships."""

from __future__ import annotations

import json
import math
import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping

from imprint.errors import ValidationError
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256
from imprint.store import ImprintStore
from imprint.store.service import insert_edge_version, utc_now, version_provenance


BUSINESS_NODE_TYPES = frozenset({
    "Customer", "Segment", "Problem", "Desire", "Situation", "Claim",
    "Promise", "Expectation", "Mechanism", "RequiredBehavior", "Offer",
    "Price", "Channel", "Objection", "Proof", "Intervention",
    "SupportAction", "Purchase", "Usage", "Result", "Refund", "Retention",
    "Referral",
    "Market", "Positioning", "TermSet", "Asset", "Campaign", "BusinessEvent",
    "ExpectedOutcome", "CampaignPerformanceMeasurement", "PerformanceDisposition",
    "Outcome", "Actor",
})
EVIDENCE_MODES = frozenset({"declared", "observed", "inferred", "ratified"})
RELATION_TYPES = frozenset({
    "declares", "observes", "supported_by", "confirms", "weakens",
    "contradicts", "extends",
})

BUSINESS_NODE_SCHEMA_IDS = (
    "imprint.node.market/1.0.0", "imprint.node.positioning/1.0.0",
    "imprint.node.term-set/1.0.0", "imprint.node.asset/1.0.0",
    "imprint.node.campaign/1.0.0", "imprint.node.business-event/1.1.0",
    "imprint.node.segment/1.0.0", "imprint.node.situation/1.0.0",
    "imprint.node.required-behavior/1.0.0",
    "imprint.node.campaign-performance-measurement/1.1.0",
    "imprint.node.performance-disposition/1.1.0",
)
BUSINESS_RELATION_SPECS = {
    "defines_segment": ("Market", {"Segment"}, "link", "O", "J"),
    "bounds_situation": ("Market", {"Situation"}, "link", "O", "J"),
    "positioned_in": ("Positioning", {"Market"}, "link", "O", "R"),
    "positions_for_segment": ("Positioning", {"Segment"}, "link", "O", "R"),
    "positions_for_situation": ("Positioning", {"Situation"}, "link", "O", "R"),
    "uses_terms": ({"Positioning", "Offer", "Asset", "Campaign"}, {"TermSet"}, "link", "O", "J"),
    "promotes_offer": ("Campaign", {"Offer"}, "link", "O", "R"),
    "uses_asset": ("Campaign", {"Asset"}, "link", "O", "J"),
    "targets_market": ({"Campaign", "Offer"}, {"Market"}, "link", "O", "R"),
    "targets_segment": ({"Campaign", "Offer"}, {"Segment"}, "link", "O", "R"),
    "targets_situation": ({"Campaign", "Offer"}, {"Situation"}, "link", "O", "R"),
    "requires_behavior": ({"Positioning", "Offer", "Campaign"}, {"RequiredBehavior"}, "link", "O", "R"),
    "event_for_campaign": ("BusinessEvent", {"Campaign"}, "evidence-link", "B", "I"),
    "event_for_asset": ("BusinessEvent", {"Asset"}, "evidence-link", "B", "I"),
    "event_for_offer": ("BusinessEvent", {"Offer"}, "evidence-link", "B", "I"),
    "measures_campaign": ("CampaignPerformanceMeasurement", {"Campaign"}, "attribution", "B", "I"),
    "measures_event": ("CampaignPerformanceMeasurement", {"BusinessEvent"}, "attribution", "C", "I"),
    "expected_performance": ("Campaign", {"ExpectedOutcome"}, "link", "O", "J"),
    "observed_performance": ("CampaignPerformanceMeasurement", {"Outcome"}, "attribution", "B", "I"),
    "performance_supports": ("CampaignPerformanceMeasurement", {"Claim", "Promise"}, "attribution", "B", "I"),
    "performance_weakens": ("CampaignPerformanceMeasurement", {"Claim", "Promise"}, "attribution", "B", "I"),
    "claims_mechanism": ({"Positioning", "Offer", "Campaign"}, {"Mechanism"}, "causation", "C", "I"),
    "disposition_of": ("PerformanceDisposition", {"CampaignPerformanceMeasurement", "Outcome"}, "evidence-link", "B", "J"),
}
BUSINESS_QUALIFIER_SCHEMA_IDS = {
    "link": "imprint.business.qualifier.link/1.1.0",
    "attribution": "imprint.business.qualifier.attribution/1.2.0",
    "causation": "imprint.business.qualifier.causation/1.2.0",
    "evidence-link": "imprint.business.qualifier.evidence-link/1.0.0",
}


class BusinessValidationError(ValidationError):
    def __init__(self, code: str, pointer: str, message: str):
        self.code = code
        self.pointer = pointer
        self.mutation_outcome = "none"
        super().__init__(f"{code} at {pointer}: {message}")


def _bfail(code: str, pointer: str, message: str) -> None:
    raise BusinessValidationError(code, pointer, message)


def _bclosed(payload: Any, required: set[str], optional: set[str]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        _bfail("E_BUSINESS_FIELD_TYPE", "/payload", "object required")
    unknown = set(payload) - required - optional
    if unknown:
        _bfail("E_BUSINESS_FIELD_UNKNOWN", f"/payload/{sorted(unknown)[0]}", "unknown field")
    missing = required - set(payload)
    if missing:
        _bfail("E_BUSINESS_FIELD_REQUIRED", f"/payload/{sorted(missing)[0]}", "required field")
    return payload


def _btime(value: Any, pointer: str) -> datetime:
    if not isinstance(value, str):
        _bfail("E_BUSINESS_FIELD_TYPE", pointer, "RFC3339 string required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _bfail("E_BUSINESS_FIELD_VALUE", pointer, "invalid RFC3339")
    if result.tzinfo is None:
        _bfail("E_BUSINESS_FIELD_VALUE", pointer, "timezone required")
    return result


def _btext(value: Any, pointer: str, maximum: int = 4000) -> None:
    if not isinstance(value, str):
        _bfail("E_BUSINESS_FIELD_TYPE", pointer, "string required")
    if not 1 <= len(value) <= maximum:
        _bfail("E_BUSINESS_FIELD_VALUE", pointer, "string length")


_NODE_SHAPES = {
    BUSINESS_NODE_SCHEMA_IDS[0]: ({"name", "category", "definition"}, {"geography_ids", "channel_ids", "confidence_assessment_version_id"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[1]: ({"frame", "category_claim", "differentiator_claims", "ratification_event_version_id"}, {"alternative_version_ids", "proof_version_ids", "confidence_assessment_version_id"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[2]: ({"name", "terms", "language", "ratification_event_version_id"}, {"confidence_assessment_version_id"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[3]: ({"name", "asset_type", "artifact_version_id", "purpose", "lifecycle_state"}, {"approved_by_role_assignment_version_id", "confidence_assessment_version_id"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[4]: ({"name", "objective", "status", "owner_role_assignment_version_id"}, {"start_at", "end_at", "budget", "confidence_assessment_version_id"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[5]: ({"event_type", "occurred_at", "observer_actor_version_id", "source_artifact_version_id", "quantity", "deduplication_key", "confidence_assessment_version_id"}, {"subject_version_id", "value"}, "business_observed"),
    BUSINESS_NODE_SCHEMA_IDS[6]: ({"name", "definition", "criteria", "confidence_assessment_version_id"}, {"population_estimate"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[7]: ({"name", "trigger_conditions", "context_statement", "confidence_assessment_version_id"}, {"valid_from", "valid_to"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[8]: ({"actor_class", "action", "observable_criterion", "required", "ratification_event_version_id"}, {"preconditions", "deadline_or_horizon", "confidence_assessment_version_id"}, "business_declared"),
    BUSINESS_NODE_SCHEMA_IDS[9]: ({"metric_id", "value", "unit_id", "window_start", "window_end", "method_id", "method_version", "observer_actor_version_id", "source_artifact_version_ids", "attribution_status", "attribution_rationale", "confidence_assessment_version_id"}, {"baseline_measurement_version_id", "comparator_measurement_version_id"}, "business_observed"),
    BUSINESS_NODE_SCHEMA_IDS[10]: ({"disposition", "measurement_version_id", "outcome_version_id", "decided_by_actor_version_id", "decided_by_role_assignment_version_id", "decided_at", "reason", "evidence_version_ids", "confidence_assessment_version_id"}, set(), "business_declared"),
}


def validate_business_payload(schema_id: str, payload: Any, *, partition: str, reference_types: dict[str, str] | None = None) -> dict[str, Any]:
    """Validate one of the exact eleven business payload schemas."""
    if schema_id not in _NODE_SHAPES:
        _bfail("E_BUSINESS_SCHEMA_UNKNOWN", "/payload_schema_id", "unknown schema")
    required, optional, expected_partition = _NODE_SHAPES[schema_id]
    value = _bclosed(payload, required, optional)
    if partition != expected_partition:
        _bfail("E_BUSINESS_PARTITION_MISMATCH", "/partition", expected_partition)
    if schema_id.endswith("asset/1.0.0"):
        if value["asset_type"] not in {"copy", "image", "video", "audio", "page", "email", "document", "offer_component", "other"}:
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/asset_type", "invalid asset type")
        if value["lifecycle_state"] in {"approved", "active"} and not value.get("approved_by_role_assignment_version_id"):
            _bfail("E_BUSINESS_CONDITIONAL_RULE", "/payload/approved_by_role_assignment_version_id", "approval required")
    elif schema_id.endswith("campaign/1.0.0"):
        if value["status"] not in {"planned", "active", "paused", "completed", "cancelled"}:
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/status", "invalid status")
        if value["status"] == "active" and not value.get("start_at"):
            _bfail("E_BUSINESS_CONDITIONAL_RULE", "/payload/start_at", "active campaign requires start")
        if value.get("start_at") and value.get("end_at") and _btime(value["end_at"], "/payload/end_at") < _btime(value["start_at"], "/payload/start_at"):
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/end_at", "end before start")
    elif schema_id.endswith("business-event/1.1.0"):
        if value["event_type"] not in {"impression", "click", "lead", "purchase", "usage", "refund", "retention", "referral", "support", "other"}:
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/event_type", "invalid event")
        _btime(value["occurred_at"], "/payload/occurred_at")
        if isinstance(value["quantity"], bool) or not isinstance(value["quantity"], (int, float)) or value["quantity"] < 0:
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/quantity", "nonnegative number required")
        subject = value.get("subject_version_id")
        if subject is not None:
            kind = (reference_types or {}).get(subject)
            if kind not in {"Customer", "Actor:external_subject"}:
                _bfail("E_BUSINESS_REFERENCE_TYPE", "/payload/subject_version_id", "Customer or external_subject Actor required")
    elif schema_id.endswith("campaign-performance-measurement/1.1.0"):
        start, end = _btime(value["window_start"], "/payload/window_start"), _btime(value["window_end"], "/payload/window_end")
        if end <= start:
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/window_end", "exclusive end after start required")
        if value["attribution_status"] not in {"unattributed", "correlated", "modeled", "experimental_estimate"}:
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/attribution_status", "invalid attribution")
        if value["attribution_status"] in {"modeled", "experimental_estimate"} and (not value.get("baseline_measurement_version_id") or not value.get("comparator_measurement_version_id")):
            _bfail("E_BUSINESS_ATTRIBUTION_INCOMPLETE", "/payload/attribution_status", "baseline and comparator required")
    elif schema_id.endswith("performance-disposition/1.1.0"):
        if value["disposition"] not in {"confirm", "correct", "reject", "defer"}:
            _bfail("E_BUSINESS_FIELD_VALUE", "/payload/disposition", "invalid disposition")
        if (value["measurement_version_id"] is None) == (value["outcome_version_id"] is None):
            _bfail("E_BUSINESS_DISPOSITION_TARGET_MISMATCH", "/payload", "exactly one target reference required")
        if not value["evidence_version_ids"]:
            _bfail("E_BUSINESS_FIELD_CARDINALITY", "/payload/evidence_version_ids", "evidence required")
    return deepcopy(value)


def _qtime(value: Any, pointer: str) -> datetime:
    if not isinstance(value, str):
        _bfail("E_RELATION_QUALIFIER_TYPE", pointer, "RFC3339 string required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _bfail("E_RELATION_QUALIFIER_TYPE", pointer, "invalid RFC3339")
    if result.tzinfo is None:
        _bfail("E_RELATION_QUALIFIER_TYPE", pointer, "timezone required")
    return result


def validate_business_qualifier(kind: str, value: Any) -> dict[str, Any]:
    """Validate the four closed/default-free business qualifier schemas."""
    common = {"attribution_rationale", "baseline_version_id", "comparator_version_id", "window_start", "window_end", "method_id", "method_version", "observer_actor_version_id", "source_artifact_version_ids", "status"}
    shapes = {
        "link": {"rationale", "evidence_version_ids"},
        "evidence-link": {"rationale", "evidence_version_ids", "window_start", "window_end", "confidence_assessment_version_id", "observer_actor_version_id", "source_artifact_version_ids"},
        "attribution": common,
        "causation": common | {"claim_text", "mechanism_version_id", "design", "causal_status", "confidence_assessment_version_id"},
    }
    if kind not in shapes:
        _bfail("E_RELATION_QUALIFIER_SCHEMA_UNKNOWN", "/qualifier/schema_id", "unknown schema")
    if not isinstance(value, dict):
        _bfail("E_RELATION_QUALIFIER_TYPE", "/qualifier", "object required")
    unknown = set(value) - shapes[kind]
    if unknown:
        _bfail("E_RELATION_QUALIFIER_UNKNOWN", f"/qualifier/{sorted(unknown)[0]}", "unknown field")
    missing = shapes[kind] - set(value)
    if missing:
        _bfail("E_RELATION_QUALIFIER_CARDINALITY", f"/qualifier/{sorted(missing)[0]}", "required field")
    nullable = {"baseline_version_id", "comparator_version_id"}
    for field, item in value.items():
        if item is None and field not in nullable:
            _bfail("E_RELATION_QUALIFIER_NULL", f"/qualifier/{field}", "null forbidden")
    for field in ("evidence_version_ids", "source_artifact_version_ids"):
        if field in value and (not isinstance(value[field], list) or not value[field] or len(value[field]) != len(set(value[field]))):
            _bfail("E_RELATION_QUALIFIER_CARDINALITY", f"/qualifier/{field}", "nonempty unique array")
    if "window_start" in value:
        if _qtime(value["window_end"], "/qualifier/window_end") <= _qtime(value["window_start"], "/qualifier/window_start"):
            _bfail("E_RELATION_QUALIFIER_VALUE", "/qualifier/window_end", "exclusive end must follow start")
    if kind in {"attribution", "causation"}:
        if value["status"] not in {"unattributed", "correlated", "modeled", "experimental_estimate"}:
            _bfail("E_RELATION_QUALIFIER_VALUE", "/qualifier/status", "invalid status")
        if value["status"] in {"modeled", "experimental_estimate"} and (value["baseline_version_id"] is None or value["comparator_version_id"] is None):
            _bfail("E_RELATION_QUALIFIER_CONDITIONAL", "/qualifier/status", "baseline and comparator required")
    if kind == "causation":
        if value["causal_status"] not in {"unproven", "bounded_estimate"}:
            _bfail("E_BUSINESS_CAUSATION_OVERCLAIM", "/qualifier/causal_status", "proven is forbidden")
        if value["causal_status"] == "bounded_estimate" and value["design"] not in {"quasi_experimental", "randomized"}:
            _bfail("E_BUSINESS_CAUSATION_OVERCLAIM", "/qualifier/design", "bounded estimate requires strong design")
    return deepcopy(value)


def validate_business_relation(predicate: str, source_type: str, target_type: str, qualifier: Any, *, source_payload: dict[str, Any] | None = None, target_version_id: str | None = None, source_partition: str | None = None, target_partition: str | None = None) -> dict[str, Any]:
    if predicate not in BUSINESS_RELATION_SPECS:
        _bfail("E_BUSINESS_RELATION_UNKNOWN", "/predicate_id", "unknown predicate")
    sources, targets, kind, policy, authority = BUSINESS_RELATION_SPECS[predicate]
    sources = {sources} if isinstance(sources, str) else sources
    if source_type not in sources or target_type not in targets:
        _bfail("E_BUSINESS_RELATION_ENDPOINT_TYPE", "/target_version_id", "invalid endpoint pair")
    if predicate in {"event_for_campaign", "event_for_asset", "event_for_offer"} and (source_partition, target_partition) != ("business_observed", "business_declared"):
        _bfail("E_RELATION_PARTITION_CROSSING", "/partition", "exclusive observed-to-declared Policy B pair required")
    checked = validate_business_qualifier(kind, qualifier)
    if predicate == "disposition_of" and source_payload is not None:
        field = "measurement_version_id" if target_type == "CampaignPerformanceMeasurement" else "outcome_version_id"
        other = "outcome_version_id" if field == "measurement_version_id" else "measurement_version_id"
        if source_payload.get(field) != target_version_id or source_payload.get(other) is not None:
            _bfail("E_BUSINESS_DISPOSITION_TARGET_MISMATCH", "/target_version_id", "target must equal active payload reference")
    return {"predicate": predicate, "qualifier": checked, "policy": policy, "authority_minimum": authority}


def append_business_relationship(
    store: ImprintStore,
    *,
    source_id: str,
    target_id: str,
    relation_type: str,
    evidence_mode: str,
    evidence_ids: list[str],
    why: str,
    actor_id: str,
    qualifier: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    approval_token: Mapping[str, Any] | None = None,
) -> str:
    """Append one evidence-linked relation without merging other evidence modes.

    Internal writer helper: not wired to the CLI or hooks. It constructs
    provenance directly, so it enforces the operator-identity pin and refuses to
    mint ``ratified`` authority for anyone other than the endpoint operator, to
    match the guarantees the strict semantic relation writer provides.
    """
    locked_relation = relation_type in BUSINESS_RELATION_SPECS
    if relation_type not in RELATION_TYPES and not locked_relation:
        raise ValidationError("unsupported business relation type")
    if evidence_mode not in EVIDENCE_MODES:
        raise ValidationError("unsupported evidence_mode")
    if not evidence_ids:
        raise ValidationError("business relationships require evidence")
    if not isinstance(why, str) or not why.strip():
        raise ValidationError("relationship WHY is required")
    if not isinstance(metadata or {}, dict):
        raise ValidationError("metadata must be an object")
    generated = {
        "system_time": utc_now(), "event_id": make_urn("event"),
        "edge_id": make_urn("edge"), "edge_version_id": make_urn("edge-version"),
    }
    provenance = "inferred" if evidence_mode == "inferred" else "ratified" if evidence_mode == "ratified" else "extracted"
    authority = "inferred_candidate" if evidence_mode == "inferred" else "ratified_knowledge" if evidence_mode == "ratified" else "imported_floor"
    payload = {
        "relation": relation_type,
        "evidence_mode": evidence_mode,
        "why": why,
        "metadata": metadata or {},
    }
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        endpoints = conn.execute(
            """SELECT n.node_id,n.node_type,n.operator_id,nv.version_id,nv.payload_json,
                      sv.payload_schema_id
               FROM nodes n JOIN node_versions nv USING(node_id)
               LEFT JOIN semantic_node_versions sv USING(version_id)
               WHERE n.node_id IN (?,?) AND nv.system_to IS NULL""",
            (source_id, target_id),
        ).fetchall()
        if len(endpoints) != 2:
            raise ValidationError("business relationship endpoints must exist")
        if any(row["node_type"] not in BUSINESS_NODE_TYPES for row in endpoints):
            raise ValidationError("business relationship endpoint has a non-business node type")
        by_id = {row["node_id"]: row for row in endpoints}
        if evidence_mode == "ratified" and not locked_relation:
            _bfail("E_BUSINESS_RELATION_UNKNOWN", "/predicate_id", "ratified relation requires locked predicate")
        checked_relation = None
        if locked_relation:
            def partition(row: Mapping[str, Any]) -> str | None:
                schema_id = row["payload_schema_id"]
                if schema_id in _NODE_SHAPES:
                    return _NODE_SHAPES[schema_id][2]
                if row["node_type"] in {"BusinessEvent", "CampaignPerformanceMeasurement"}:
                    return "business_observed"
                return "business_declared"

            source = by_id[source_id]
            target = by_id[target_id]
            checked_relation = validate_business_relation(
                relation_type, source["node_type"], target["node_type"], qualifier,
                source_payload=json.loads(source["payload_json"]),
                target_version_id=target["version_id"],
                source_partition=partition(source), target_partition=partition(target),
            )
            payload.update({
                "qualifier_schema_id": BUSINESS_QUALIFIER_SCHEMA_IDS[
                    BUSINESS_RELATION_SPECS[relation_type][2]
                ],
                "qualifier": checked_relation["qualifier"],
                "policy": checked_relation["policy"],
                "authority_minimum": checked_relation["authority_minimum"],
            })
        known_evidence = 0
        for evidence_id in set(evidence_ids):
            if conn.execute("SELECT 1 FROM source_receipts WHERE source_id=?", (evidence_id,)).fetchone():
                known_evidence += 1
            elif conn.execute("SELECT 1 FROM nodes WHERE node_id=? AND node_type='Evidence'", (evidence_id,)).fetchone():
                known_evidence += 1
        if known_evidence != len(set(evidence_ids)):
            raise ValidationError("relationship evidence must reference Evidence nodes or source receipts")
        operator_ids = {row["operator_id"] for row in endpoints}
        if len(operator_ids) != 1:
            raise ValidationError("cross-operator relationship is forbidden")
        operator_id = operator_ids.pop()
        store._require_configured_operator(operator_id)
        if evidence_mode == "ratified" and actor_id != operator_id:
            raise ValidationError("ratified business relationship must be authored by the endpoint operator")
        if evidence_mode == "ratified":
            execution = store._consume_authority(
                conn, approval_token, command_name="business.relationship.ratify",
                purpose="append ratified business relationship",
                intent={
                    "source_id": source_id, "target_id": target_id,
                    "relation_type": relation_type, "evidence_mode": evidence_mode,
                    "evidence_ids": evidence_ids, "why": why,
                    "actor_id": actor_id, "qualifier": checked_relation["qualifier"],
                    "metadata": metadata or {},
                },
                execution_fields=generated,
                prior_state={"source_id": source_id, "target_id": target_id},
                authority_transition="none_to_ratified_knowledge",
                source_ids=(source_id,), target_ids=(target_id,),
                scope=("business_relationship",), field_paths=("/authority_tier",),
            )
        else:
            if approval_token is not None:
                raise ValidationError("approval token is only valid for ratified business relationships")
            execution = generated
        now = execution["system_time"]
        event_id = execution["event_id"]
        edge_id = execution["edge_id"]
        event_payload = {
            "edge_id": edge_id, "source_id": source_id, "target_id": target_id,
            "payload": payload, "evidence_ids": evidence_ids, "actor_id": actor_id,
        }
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            (event_id, "derived", operator_id, now, now,
             canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None, provenance),
        )
        conn.execute(
            "INSERT INTO edges VALUES(?,?,?,?,?,?)",
            (edge_id, relation_type, source_id, target_id, operator_id, event_id),
        )
        insert_edge_version(
            conn,
            (execution["edge_version_id"], edge_id, canonical_bytes(payload).decode(), payload_sha256(payload),
             provenance, authority, canonical_bytes(version_provenance(
                 status=provenance, authority_tier=authority,
                 actor_class="operator" if evidence_mode in {"declared", "ratified"} else "software",
                 actor_id=actor_id, mechanism=f"business_{evidence_mode}", event_id=event_id,
                 ratifier=actor_id if evidence_mode == "ratified" else None, relation=relation_type,
             )).decode(), json.dumps(evidence_ids), now, None, now, None, event_id, None),
        )
    return edge_id
