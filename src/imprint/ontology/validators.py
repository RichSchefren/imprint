"""Fail-closed validators for the Imprint ontology binding contract 3.6.1."""
from __future__ import annotations

import math
import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping

from imprint.errors import ValidationError
from imprint.ontology.registries import CORE_NODE_SCHEMA_IDS, PREDICATE_IDS


class OntologyValidationError(ValidationError):
    """A stable contract failure with a machine-readable JSON Pointer."""

    def __init__(self, code: str, pointer: str, message: str, *, schema_id: str | None = None):
        self.code = code
        self.pointer = pointer
        self.schema_id = schema_id
        self.mutation_outcome = "none"
        super().__init__(f"{code} at {pointer}: {message}")


def _fail(code: str, pointer: str, message: str, schema_id: str | None = None) -> None:
    raise OntologyValidationError(code, pointer, message, schema_id=schema_id)


def _closed(value: Any, required: set[str], optional: set[str], schema_id: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("E_NODE_FIELD_TYPE", "/payload", "payload must be an object", schema_id)
    unknown = set(value) - required - optional
    if unknown:
        name = sorted(unknown)[0]
        _fail("E_NODE_FIELD_UNKNOWN", f"/payload/{name}", "unknown field", schema_id)
    missing = required - set(value)
    if missing:
        name = sorted(missing)[0]
        _fail("E_NODE_FIELD_REQUIRED", f"/payload/{name}", "required field missing", schema_id)
    return value


def _text(value: Any, pointer: str, *, maximum: int = 4000) -> str:
    if not isinstance(value, str):
        _fail("E_NODE_FIELD_TYPE", pointer, "expected string")
    if not 1 <= len(value) <= maximum:
        _fail("E_NODE_FIELD_VALUE", pointer, "string length out of range")
    return value


def _uri(value: Any, pointer: str) -> str:
    if not isinstance(value, str) or not value or ":" not in value:
        _fail("E_NODE_REFERENCE_VERSION_REQUIRED", pointer, "exact version URI required")
    return value


def _time(value: Any, pointer: str) -> str:
    if not isinstance(value, str):
        _fail("E_NODE_FIELD_TYPE", pointer, "RFC3339 timestamp required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("E_NODE_FIELD_VALUE", pointer, "invalid RFC3339 timestamp")
    if parsed.tzinfo is None:
        _fail("E_NODE_FIELD_VALUE", pointer, "timezone required")
    return value


def _uris(value: Any, pointer: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        _fail("E_NODE_FIELD_TYPE", pointer, "expected array")
    if nonempty and not value:
        _fail("E_NODE_FIELD_CARDINALITY", pointer, "array cannot be empty")
    if len(value) != len(set(value)):
        _fail("E_NODE_FIELD_CARDINALITY", pointer, "array members must be unique")
    for index, item in enumerate(value):
        _uri(item, f"{pointer}/{index}")
    return value


_CORE_FIELDS = {
    "imprint.node.decision-episode/1.0.0": ({"case_version_id", "verdict_version_id", "operator_role_assignment_version_id", "captured_at"}, {"participant_role_assignment_version_ids", "session_id", "conversation_id", "project_id", "artifact_version_ids", "domain_ids", "situation_type", "expected_outcome_version_ids"}),
    "imprint.node.actor/1.0.0": ({"actor_type", "display_label"}, {"external_id", "organization_id"}),
    "imprint.node.role-assignment/1.0.0": ({"actor_version_id", "role_type", "scope_ids", "authority_basis", "allowed_operations", "valid_from", "valid_to", "granted_by_role_assignment_version_id"}, set()),
    "imprint.node.expected-outcome/1.0.0": ({"statement", "observable_criterion", "horizon"}, {"metric", "target_value", "unit", "uncertainty_note", "confidence_assessment_version_id"}),
    "imprint.node.confidence-assessment/1.0.0": ({"subject_version_id", "score", "scale", "assessor_actor_version_id", "method", "assessed_at"}, {"basis_evidence_version_ids", "dissent_note"}),
    "imprint.node.evidence-artifact/1.0.0": ({"original_sha256", "byte_count", "media_type", "media_type_source", "source_class", "source_locator", "source_system", "captured_at", "custody_actor_version_id", "consent_version_id", "access_policy_version_id", "storage_locator", "derived_from_version_ids", "content_state"}, {"declared_encoding", "source_event_id", "encryption_key_ref", "transform_event_version_id", "purged_at", "purge_event_version_id"}),
    "imprint.node.access-policy/1.0.0": ({"principal_role_assignment_version_ids", "operations", "purposes", "field_paths", "valid_from", "valid_to", "system_from", "system_to"}, set()),
    "imprint.node.deletion-event/1.0.0": ({"target_version_ids", "mode", "scope", "actor_version_id", "role_assignment_version_id", "reason", "invalidated_version_ids", "purge_receipts", "completed"}, set()),
}
_ACTORS = {"operator", "human_delegate", "software", "model", "importer", "external_subject", "organization"}
_OPERATIONS = {"ingest", "store", "derive", "retrieve", "export", "delete"}


def validate_provenance_v2_1(value: Any) -> dict[str, Any]:
    required = {"origin_status", "lifecycle_status", "authority_tier", "authority_source", "mechanism", "actor_id", "actor_class", "role_assignment_version_id", "evidence_version_ids", "source_phase_ids", "primary_source_phase_id"}
    optional = {"model_id", "prompt_version_id", "derivation_trace_version_id", "proposal_version_id", "ratification_event_version_id"}
    if not isinstance(value, Mapping):
        _fail("E_NODE_FIELD_TYPE", "/provenance", "provenance must be object", "imprint.provenance/2.1.0")
    unknown = set(value) - required - optional
    missing = required - set(value)
    if unknown:
        _fail("E_NODE_FIELD_UNKNOWN", f"/provenance/{sorted(unknown)[0]}", "unknown provenance field")
    if missing:
        _fail("E_NODE_FIELD_REQUIRED", f"/provenance/{sorted(missing)[0]}", "missing provenance field")
    if value["origin_status"] not in {"captured", "extracted", "inferred"}:
        _fail("E_NODE_FIELD_VALUE", "/provenance/origin_status", "invalid immutable origin")
    if value["lifecycle_status"] not in {"proposed", "active", "superseded", "disputed", "retracted", "purged"}:
        _fail("E_NODE_FIELD_VALUE", "/provenance/lifecycle_status", "invalid lifecycle")
    _uris(value["evidence_version_ids"], "/provenance/evidence_version_ids", nonempty=True)
    phases = value["source_phase_ids"]
    from imprint.ontology.registries import is_public_source_phase_id
    if (not isinstance(phases, list) or not phases or
            len(phases) != len(set(phases)) or
            any(not is_public_source_phase_id(phase) for phase in phases)):
        _fail(
            "E_NODE_FIELD_VALUE", "/provenance/source_phase_ids",
            "built-in or namespaced extension phases required",
        )
    if value["primary_source_phase_id"] not in phases:
        _fail("E_NODE_CONDITIONAL_RULE", "/provenance/primary_source_phase_id", "primary must be a listed phase")
    if value["authority_tier"] == "ratified_knowledge" and not value.get("ratification_event_version_id"):
        _fail("E_RATIFICATION_PROOF_REQUIRED", "/provenance/ratification_event_version_id", "ratification event required")
    if value["origin_status"] == "inferred" and not value.get("derivation_trace_version_id"):
        _fail("E_NODE_CONDITIONAL_RULE", "/provenance/derivation_trace_version_id", "inference requires trace")
    return deepcopy(dict(value))


def validate_core_payload(schema_id: str, payload: Any) -> dict[str, Any]:
    if schema_id not in _CORE_FIELDS:
        _fail("E_NODE_SCHEMA_UNKNOWN", "/payload_schema_id", "unknown node schema", schema_id)
    required, optional = _CORE_FIELDS[schema_id]
    value = _closed(payload, required, optional, schema_id)
    if schema_id.endswith("actor/1.0.0"):
        if value["actor_type"] not in _ACTORS:
            _fail("E_NODE_FIELD_VALUE", "/payload/actor_type", "invalid actor type", schema_id)
        _text(value["display_label"], "/payload/display_label", maximum=300)
    elif schema_id.endswith("decision-episode/1.0.0"):
        for field in ("case_version_id", "verdict_version_id", "operator_role_assignment_version_id"):
            _uri(value[field], f"/payload/{field}")
        _time(value["captured_at"], "/payload/captured_at")
    elif schema_id.endswith("role-assignment/1.0.0"):
        _uris(value["scope_ids"], "/payload/scope_ids", nonempty=True)
        operations = value["allowed_operations"]
        if not isinstance(operations, list) or not operations or len(operations) != len(set(operations)) or not set(operations) <= _OPERATIONS:
            _fail("E_NODE_FIELD_VALUE", "/payload/allowed_operations", "invalid canonical operations", schema_id)
    elif schema_id.endswith("expected-outcome/1.0.0"):
        trio = [value.get(name) for name in ("metric", "target_value", "unit")]
        if any(item is not None for item in trio) and not all(item is not None for item in trio):
            _fail("E_NODE_CONDITIONAL_RULE", "/payload/metric", "metric, target and unit are jointly present", schema_id)
    elif schema_id.endswith("confidence-assessment/1.0.0"):
        score = value["score"]
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
            _fail("E_NODE_FIELD_VALUE", "/payload/score", "score outside [0,1]", schema_id)
        if not value.get("basis_evidence_version_ids") and value["method"] != "operator_intuition":
            _fail("E_NODE_CONDITIONAL_RULE", "/payload/basis_evidence_version_ids", "basis required", schema_id)
    elif schema_id.endswith("evidence-artifact/1.0.0"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(value["original_sha256"])):
            _fail("E_NODE_FIELD_VALUE", "/payload/original_sha256", "lowercase sha256 required", schema_id)
        if value["media_type"] == "application/octet-stream" and value["media_type_source"] != "unknown_sentinel":
            _fail("E_MEDIA_TYPE_SENTINEL_RULE", "/payload/media_type_source", "unknown sentinel source required", schema_id)
        derived = bool(value["derived_from_version_ids"])
        if derived != bool(value.get("transform_event_version_id")):
            _fail("E_NODE_CONDITIONAL_RULE", "/payload/transform_event_version_id", "transform iff derived", schema_id)
    elif schema_id.endswith("access-policy/1.0.0"):
        _uris(value["principal_role_assignment_version_ids"], "/payload/principal_role_assignment_version_ids", nonempty=True)
        if not set(value["operations"]) <= _OPERATIONS:
            _fail("E_NODE_FIELD_VALUE", "/payload/operations", "unknown operation", schema_id)
    elif schema_id.endswith("deletion-event/1.0.0"):
        if value["mode"] not in {"hard_delete", "cryptographic_erase", "content_purge_with_tombstone", "projection_only"}:
            _fail("E_NODE_FIELD_VALUE", "/payload/mode", "invalid deletion mode", schema_id)
        if value["scope"] not in {"target_only", "target_and_derivatives", "subgraph", "projection"}:
            _fail("E_DELETION_SCOPE_REQUIRED", "/payload/scope", "canonical scope required", schema_id)
        if value["completed"] and not value["purge_receipts"]:
            _fail("E_NODE_CONDITIONAL_RULE", "/payload/purge_receipts", "completed deletion requires receipts", schema_id)
    return deepcopy(dict(value))


def validate_relation_identity(predicate_id: str, qualifier_schema_id: str) -> None:
    if predicate_id not in PREDICATE_IDS:
        _fail("E_RELATION_PREDICATE_UNKNOWN", "/predicate_id", "unknown predicate")
    from imprint.ontology.registries import QUALIFIER_SCHEMA_IDS
    if qualifier_schema_id not in QUALIFIER_SCHEMA_IDS:
        _fail("E_RELATION_QUALIFIER_SCHEMA_UNKNOWN", "/qualifier/schema_id", "unknown qualifier")
