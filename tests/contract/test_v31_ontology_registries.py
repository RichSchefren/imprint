from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from imprint.ontology import registries
from imprint.ontology.business import (
    BUSINESS_NODE_SCHEMA_IDS, BUSINESS_QUALIFIER_SCHEMA_IDS,
    BUSINESS_RELATION_SPECS, BusinessValidationError,
    validate_business_payload, validate_business_qualifier,
    validate_business_relation,
)
from imprint.ontology.validators import (
    OntologyValidationError, validate_core_payload, validate_provenance_v2_1,
)


FIXTURE = Path(__file__).parents[1] / "fixtures/v3_1/ontology/registry-identities-v1.json"


def test_exact_registry_identities_and_atomic_bundle():
    expected = json.loads(FIXTURE.read_text())
    bundle = registries.compile_registry_bundle()
    assert bundle["contract_id"] == expected["binding_contract"]
    assert len(bundle["nodes"]) == expected["core_node_count"]
    assert len(bundle["predicates"]) == expected["core_predicate_count"]
    assert len(bundle["qualifiers"]) == expected["core_qualifier_count"]
    assert len(bundle["unions"]) == expected["endpoint_union_count"]
    assert all(registries.ENDPOINT_UNIONS[name] for name in bundle["unions"])
    assert set(bundle) == {"contract_id", "nodes", "predicates", "qualifiers", "unions"}
    assert len(BUSINESS_NODE_SCHEMA_IDS) == expected["business_node_count"]
    assert len(BUSINESS_RELATION_SPECS) == expected["business_predicate_count"]
    assert len(BUSINESS_QUALIFIER_SCHEMA_IDS) == expected["business_qualifier_count"]

CORE_MINIMUM = {
    "imprint.node.decision-episode/1.0.0": {"case_version_id":"urn:x:case:v1","verdict_version_id":"urn:x:verdict:v1","operator_role_assignment_version_id":"urn:x:role:v1","captured_at":"2026-07-16T12:00:00Z"},
    "imprint.node.actor/1.0.0": {"actor_type":"operator","display_label":"Operator"},
    "imprint.node.role-assignment/1.0.0": {"actor_version_id":"urn:x:actor:v1","role_type":"operator_of_record","scope_ids":["urn:x:scope:v1"],"authority_basis":"operator_self","allowed_operations":["ingest"],"valid_from":"2026-01-01T00:00:00Z","valid_to":None,"granted_by_role_assignment_version_id":"urn:x:role:v0"},
    "imprint.node.expected-outcome/1.0.0": {"statement":"Increase conversion","observable_criterion":"A measured increase","horizon":"P30D"},
    "imprint.node.confidence-assessment/1.0.0": {"subject_version_id":"urn:x:subject:v1","score":0.5,"scale":"unit_interval","assessor_actor_version_id":"urn:x:actor:v1","method":"operator_intuition","assessed_at":"2026-07-16T12:00:00Z"},
    "imprint.node.evidence-artifact/1.0.0": {"original_sha256":"0"*64,"byte_count":0,"media_type":"application/octet-stream","media_type_source":"unknown_sentinel","source_class":"file","source_locator":"local","source_system":"test","captured_at":"2026-07-16T12:00:00Z","custody_actor_version_id":"urn:x:actor:v1","consent_version_id":"urn:x:consent:v1","access_policy_version_id":"urn:x:policy:v1","storage_locator":"blob:1","derived_from_version_ids":[],"content_state":"active"},
    "imprint.node.access-policy/1.0.0": {"principal_role_assignment_version_ids":["urn:x:role:v1"],"operations":["retrieve"],"purposes":["retrieval"],"field_paths":[],"valid_from":"2026-01-01T00:00:00Z","valid_to":None,"system_from":"2026-01-01T00:00:00Z","system_to":None},
    "imprint.node.deletion-event/1.0.0": {"target_version_ids":["urn:x:target:v1"],"mode":"hard_delete","scope":"target_only","actor_version_id":"urn:x:actor:v1","role_assignment_version_id":"urn:x:role:v1","reason":"requested","invalidated_version_ids":[],"purge_receipts":[],"completed":False},
}


@pytest.mark.parametrize("schema_id", tuple(CORE_MINIMUM))
def test_all_eight_core_payload_schemas_are_closed(schema_id):
    assert validate_core_payload(schema_id, CORE_MINIMUM[schema_id]) == CORE_MINIMUM[schema_id]
    invalid = deepcopy(CORE_MINIMUM[schema_id]); invalid["opaque_core"] = True
    with pytest.raises(OntologyValidationError) as caught:
        validate_core_payload(schema_id, invalid)
    assert caught.value.code == "E_NODE_FIELD_UNKNOWN"
    assert caught.value.mutation_outcome == "none"


def test_provenance_v21_keeps_inferred_origin_and_requires_trace():
    value = {"origin_status":"inferred","lifecycle_status":"proposed","authority_tier":"inferred_candidate","authority_source":"system_inference","mechanism":"model","actor_id":"urn:x:actor:v1","actor_class":"model","role_assignment_version_id":"urn:x:role:v1","evidence_version_ids":["urn:x:evidence:v1"],"source_phase_ids":["operator_authored"],"primary_source_phase_id":"operator_authored","derivation_trace_version_id":"urn:x:trace:v1"}
    assert validate_provenance_v2_1(value)["origin_status"] == "inferred"
    del value["derivation_trace_version_id"]
    with pytest.raises(OntologyValidationError) as caught:
        validate_provenance_v2_1(value)
    assert caught.value.code == "E_NODE_CONDITIONAL_RULE"


def _event_payload(subject="urn:x:customer:v1"):
    return {"event_type":"purchase","occurred_at":"2026-07-16T12:00:00Z","observer_actor_version_id":"urn:x:actor:v1","source_artifact_version_id":"urn:x:evidence:v1","subject_version_id":subject,"quantity":1,"deduplication_key":"purchase-1","confidence_assessment_version_id":"urn:x:confidence:v1"}


def test_business_event_subject_is_finite_customer_or_external_subject_actor():
    customer = _event_payload()
    assert validate_business_payload(BUSINESS_NODE_SCHEMA_IDS[5], customer, partition="business_observed", reference_types={customer["subject_version_id"]:"Customer"})
    actor = _event_payload("urn:x:actor:v2")
    assert validate_business_payload(BUSINESS_NODE_SCHEMA_IDS[5], actor, partition="business_observed", reference_types={actor["subject_version_id"]:"Actor:external_subject"})
    for wrong in ("Actor:operator", "Market"):
        with pytest.raises(BusinessValidationError) as caught:
            validate_business_payload(BUSINESS_NODE_SCHEMA_IDS[5], actor, partition="business_observed", reference_types={actor["subject_version_id"]:wrong})
        assert caught.value.code == "E_BUSINESS_REFERENCE_TYPE"


def _evidence_link():
    return {"rationale":"Observed event","evidence_version_ids":["urn:x:evidence:v1"],"window_start":"2026-07-01T00:00:00Z","window_end":"2026-07-02T00:00:00Z","confidence_assessment_version_id":"urn:x:confidence:v1","observer_actor_version_id":"urn:x:actor:v1","source_artifact_version_ids":["urn:x:evidence:v1"]}


def test_business_qualifiers_are_closed_default_free_and_windows_are_ordered():
    assert validate_business_qualifier("evidence-link", _evidence_link())
    bad = _evidence_link(); bad["window_end"] = bad["window_start"]
    with pytest.raises(BusinessValidationError) as caught:
        validate_business_qualifier("evidence-link", bad)
    assert caught.value.code == "E_RELATION_QUALIFIER_VALUE"
    bad = _evidence_link(); bad["window_start"] = None
    with pytest.raises(BusinessValidationError) as caught:
        validate_business_qualifier("evidence-link", bad)
    assert caught.value.code == "E_RELATION_QUALIFIER_NULL"


def test_exact_23_business_relations_and_disposition_target_equality():
    assert len(BUSINESS_RELATION_SPECS) == 23
    payload = {"measurement_version_id":"urn:x:measurement:v1","outcome_version_id":None}
    result = validate_business_relation("disposition_of", "PerformanceDisposition", "CampaignPerformanceMeasurement", _evidence_link(), source_payload=payload, target_version_id=payload["measurement_version_id"])
    assert result["policy"] == "B" and result["authority_minimum"] == "J"
    with pytest.raises(BusinessValidationError) as caught:
        validate_business_relation("disposition_of", "PerformanceDisposition", "CampaignPerformanceMeasurement", _evidence_link(), source_payload=payload, target_version_id="urn:x:measurement:v2")
    assert caught.value.code == "E_BUSINESS_DISPOSITION_TARGET_MISMATCH"


@pytest.mark.parametrize(("predicate", "target"), [("event_for_campaign", "Campaign"), ("event_for_asset", "Asset"), ("event_for_offer", "Offer")])
def test_event_relations_have_exclusive_policy_b_crossing(predicate, target):
    result = validate_business_relation(predicate, "BusinessEvent", target, _evidence_link(), source_partition="business_observed", target_partition="business_declared")
    assert result["policy"] == "B" and result["authority_minimum"] == "I"
    with pytest.raises(BusinessValidationError) as caught:
        validate_business_relation(predicate, "BusinessEvent", target, _evidence_link(), source_partition="business_observed", target_partition="business_observed")
    assert caught.value.code == "E_RELATION_PARTITION_CROSSING"
