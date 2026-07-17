from copy import deepcopy

import pytest

from imprint.capture.schema import new_urn
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.errors import ValidationError
from imprint.ontology.contracts import (
    RELATION_REGISTRY,
    GENERAL_NODE_TYPES,
    JUDGMENT_NODE_TYPES,
    KNOWLEDGE_NODE_TYPES,
    NODE_TYPES,
    validate_node_contract,
    validate_relation_contract,
)


def test_raw_capture_writer_relations_are_in_the_canonical_registry():
    assert {
        "verdict_about_case", "made_call", "supported_by",
        "chose_alternative", "rejected_alternative",
    }.issubset(RELATION_REGISTRY)


def provenance(status="captured", *, evidence_ids=None, actor_id=None):
    tiers = {
        "captured": "captured_judgment", "extracted": "observed_candidate",
        "inferred": "inferred_candidate", "ratified": "ratified_knowledge",
    }
    actor_id = actor_id or new_urn("operator")
    return {
        "status": status,
        "authority_tier": tiers[status],
        "actor_class": "model" if status == "inferred" else "operator",
        "actor_id": actor_id,
        "mechanism": "unit-test",
        "evidence_ids": list(evidence_ids if evidence_ids is not None else [new_urn("evidence")]),
        "model": "synthetic-model" if status == "inferred" else None,
        "ratifier_id": actor_id if status == "ratified" else None,
    }


def node(node_type, payload, *, status="captured"):
    kind = node_type.lower().replace("trial", "_trial")
    operator_id = new_urn("operator")
    return {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": new_urn(kind),
        "node_type": node_type,
        "operator_id": operator_id,
        "payload": payload,
        "provenance": provenance(
            status, actor_id=operator_id if status in {"captured", "ratified"} else None,
        ),
    }


def test_registries_are_explicit_and_relation_endpoints_are_typed():
    assert KNOWLEDGE_NODE_TYPES == {"Principle", "Belief", "Value", "Rule", "Domain"}
    assert {"Case", "Verdict", "Call", "Alternative", "Pattern"}.issubset(JUDGMENT_NODE_TYPES)
    assert GENERAL_NODE_TYPES == {"Outcome", "CalibrationTrial"}
    assert (JUDGMENT_NODE_TYPES | GENERAL_NODE_TYPES).issubset(NODE_TYPES)
    assert RELATION_REGISTRY["derived_from"] == (frozenset({"Pattern"}), frozenset({"Case"}))


@pytest.mark.parametrize("node_type", ["Principle", "Belief", "Value", "Rule"])
def test_knowledge_nodes_accept_legacy_statement_and_additive_nullable_rationale(node_type):
    legacy = node(node_type, {"statement": f"Synthetic {node_type}"}, status="inferred")
    assert validate_node_contract(legacy)["payload"] == legacy["payload"]

    enriched = node(node_type, {
        "statement": f"Synthetic {node_type}", "reason": None, "reason_status": "pending",
    }, status="inferred")
    assert validate_node_contract(enriched)["payload"]["reason"] is None

    captured = deepcopy(legacy)
    captured["provenance"] = provenance("captured", actor_id=captured["operator_id"])
    with pytest.raises(ValidationError, match="derived knowledge"):
        validate_node_contract(captured)


def test_domain_contract_matches_existing_canonical_store_payload():
    value = node("Domain", {
        "domain_id": "research",
        "public_label": "Research",
        "description": "Source-grounded research work",
        "selected": True,
        "frozen": False,
    })
    assert validate_node_contract(value)["payload"] == value["payload"]


def test_captured_or_ratified_authority_is_bound_to_contract_operator():
    value = node("Domain", {
        "domain_id": "research", "public_label": "Research",
        "description": "Source-grounded research work", "selected": False, "frozen": False,
    })
    value["provenance"]["actor_id"] = new_urn("operator")
    with pytest.raises(ValidationError, match="must belong to the contract operator"):
        validate_node_contract(value)


@pytest.mark.parametrize("relation_type,source_type,target_type,status", [
    ("expressed", "Verdict", "Principle", "extracted"),
    ("protects", "Rule", "Value", "ratified"),
    ("depends_on", "Belief", "Domain", "ratified"),
    ("extracted_from", "Value", "Verdict", "extracted"),
    ("inferred_from", "Rule", "Pattern", "inferred"),
    ("similar_to", "Principle", "Principle", "inferred"),
])
def test_level_three_relation_signatures(relation_type, source_type, target_type, status):
    source_kind = source_type.lower().replace("trial", "_trial")
    target_kind = target_type.lower().replace("trial", "_trial")
    operator_id = new_urn("operator")
    value = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "relation_id": new_urn("relation"),
        "relation_type": relation_type,
        "source_id": new_urn(source_kind),
        "source_type": source_type,
        "target_id": new_urn(target_kind),
        "target_type": target_type,
        "operator_id": operator_id,
        "evidence_mode": status,
        "why": "Evidence-backed Level 3 relationship.",
        "provenance": provenance(
            status, actor_id=operator_id if status in {"captured", "ratified"} else None,
        ),
    }
    assert validate_relation_contract(value) == value


def test_relation_semantics_reject_wrong_provenance_and_cross_type_similarity():
    value = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "relation_id": new_urn("relation"),
        "relation_type": "extracted_from",
        "source_id": new_urn("value"),
        "source_type": "Value",
        "target_id": new_urn("verdict"),
        "target_type": "Verdict",
        "operator_id": new_urn("operator"),
        "evidence_mode": "inferred",
        "why": "The value was extracted from this verdict.",
        "provenance": provenance("inferred"),
    }
    with pytest.raises(ValidationError, match="extracted provenance"):
        validate_relation_contract(value)

    value.update(
        relation_type="similar_to",
        target_id=new_urn("belief"),
        target_type="Belief",
    )
    with pytest.raises(ValidationError, match="same node type"):
        validate_relation_contract(value)


def test_pattern_requires_two_distinct_case_nodes_and_inferred_candidate_provenance():
    cases = [new_urn("case"), new_urn("case")]
    value = node("Pattern", {
        "statement": "The operator rejects layouts that hide the decision.",
        "case_ids": cases,
        "reason": None,
        "reason_status": "pending",
    }, status="inferred")
    checked = validate_node_contract(value)
    assert checked == value and checked is not value
    assert checked["payload"]["case_ids"] == cases

    for bad_cases in ([cases[0]], [cases[0], cases[0]]):
        broken = deepcopy(value)
        broken["payload"]["case_ids"] = bad_cases
        with pytest.raises(ValidationError, match="distinct Case|unique list"):
            validate_node_contract(broken)

    captured = deepcopy(value)
    captured["provenance"] = provenance("captured", actor_id=captured["operator_id"])
    with pytest.raises(ValidationError, match="inferred or ratified"):
        validate_node_contract(captured)


def test_verdict_retains_nullable_reason_without_fabrication():
    value = node("Verdict", {
        "raw_operator_text": "Use option B.",
        "call_id": new_urn("call"),
        "chosen_alternative_ids": [new_urn("alternative")],
        "rejected_alternative_ids": [],
        "reason": None,
        "reason_status": "absent",
    })
    assert validate_node_contract(value)["payload"]["reason"] is None
    value["payload"]["reason_status"] = "supplied"
    with pytest.raises(ValidationError, match="cannot be null"):
        validate_node_contract(value)


@pytest.mark.parametrize("mutation, message", [
    (lambda x: x.update(extra="open"), "unknown node fields"),
    (lambda x: x["payload"].update(extra="open"), "unknown Case payload fields"),
    (lambda x: x["provenance"].update(authority_tier="ratified_knowledge"), "captured provenance"),
    (lambda x: x["provenance"].update(actor_class="model", model="synthetic"), "captured provenance"),
])
def test_contracts_fail_closed_and_cannot_escalate_provenance(mutation, message):
    value = node("Case", {
        "description": "A concrete decision context.",
        "source_refs": [new_urn("evidence")],
        "artifact_refs": [],
    })
    mutation(value)
    with pytest.raises(ValidationError, match=message):
        validate_node_contract(value)


def test_general_outcome_and_resolved_calibration_trial_validate():
    outcome_id = new_urn("outcome")
    outcome = node("Outcome", {
        "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "operator_id": new_urn("operator"),
        "evidence_mode": "observed",
        "subject_id": new_urn("verdict"),
        "description": "Conversion increased after the decision.",
        "metric": "conversion_rate",
        "value": 0.31,
        "unit": "ratio",
        "window_start": "2026-07-01T00:00:00Z",
        "window_end": "2026-07-14T20:00:00Z",
        "source_class": "financial_record",
        "attribution_status": "contributory",
        "observed_at": "2026-07-14T20:00:00Z",
        "source_refs": [new_urn("evidence")],
        "consent_grant_id": new_urn("consentgrant"),
        "attributes": {"qualified": True, "note": "audited"},
    }, status="extracted")
    outcome["payload"]["operator_id"] = outcome["operator_id"]
    assert validate_node_contract(outcome)["payload"]["value"] == 0.31

    trial = node("CalibrationTrial", {
        "prediction": "Option B will increase conversion.",
        "predicted_at": "2026-07-01T12:00:00Z",
        "confidence": 0.8,
        "outcome_id": outcome_id,
        "resolved_at": "2026-07-14T20:00:00Z",
        "assessment": "confirmed",
        "reason": "The measured outcome exceeded baseline.",
        "reason_status": "later_added",
    })
    assert validate_node_contract(trial)["payload"]["assessment"] == "confirmed"

    invalid = deepcopy(trial)
    invalid["payload"].update(assessment="pending", outcome_id=outcome_id, resolved_at=None)
    with pytest.raises(ValidationError, match="pending.*resolution"):
        validate_node_contract(invalid)


def test_typed_evidence_linked_relations_fail_closed():
    value = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "relation_id": new_urn("relation"),
        "relation_type": "derived_from",
        "source_id": new_urn("pattern"),
        "source_type": "Pattern",
        "target_id": new_urn("case"),
        "target_type": "Case",
        "operator_id": new_urn("operator"),
        "evidence_mode": "inferred",
        "why": "This case is one distinct input to the pattern.",
        "provenance": provenance("inferred"),
    }
    assert validate_relation_contract(value) == value

    reversed_relation = deepcopy(value)
    reversed_relation.update(
        source_id=new_urn("case"), source_type="Case",
        target_id=new_urn("pattern"), target_type="Pattern",
    )
    with pytest.raises(ValidationError, match="source_type"):
        validate_relation_contract(reversed_relation)

    no_evidence = deepcopy(value)
    no_evidence["provenance"]["evidence_ids"] = []
    with pytest.raises(ValidationError, match="evidenced candidate|relations require"):
        validate_relation_contract(no_evidence)
