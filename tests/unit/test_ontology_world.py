import pytest

from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.errors import ValidationError
from imprint.ontology.schema import make_urn
from imprint.ontology.world import validate_world_payload, validate_world_relation


DECLARED = {"status": "captured", "authority_tier": "captured_judgment", "actor_class": "operator"}
OBSERVED = {"status": "extracted", "authority_tier": "observed_candidate", "actor_class": "software"}


def declared_promise():
    return {
        "evidence_mode": "declared", "effective_at": "2026-07-14T20:00:00Z",
        "source_refs": [make_urn("evidence")], "attributes": {},
        "statement": "The system preserves judgment.",
    }


def observation():
    operator_id = make_urn("operator")
    evidence_id = make_urn("evidence")
    return {
        "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION, "operator_id": operator_id,
        "subject_id": make_urn("promise"), "observation_kind": "business_event",
        "description": "Customers retained twenty-five verdicts.",
        "source_class": "customer_result", "observed_at": "2026-07-14T20:00:00Z",
        "window_start": "2026-07-01T00:00:00Z", "window_end": "2026-07-14T20:00:00Z",
        "evidence_ids": [evidence_id],
        "confidence": {
            "score": 0.9, "assessor_id": "test", "method": "statistical",
            "basis_evidence_ids": [evidence_id], "assessed_at": "2026-07-14T20:00:00Z",
            "calibration_trial_id": None, "uncertainty_note": None,
        },
        "consent_grant_id": make_urn("consentgrant"), "attributes": {}, "extensions": {},
    }


def test_declared_business_payload_is_closed_and_operator_authored():
    value = declared_promise()
    assert validate_world_payload("Promise", value, DECLARED) == value
    with pytest.raises(ValidationError, match="evidence_mode=declared"):
        validate_world_payload("Promise", dict(value, evidence_mode="observed"), OBSERVED)
    with pytest.raises(ValidationError, match="unknown fields"):
        validate_world_payload("Promise", dict(value, synthetic=True), DECLARED)


def test_general_observation_is_typed_consent_linked_and_observed_only():
    value = observation()
    assert validate_world_payload("Observation", value, OBSERVED) == value
    with pytest.raises(ValidationError, match="incompatible provenance"):
        validate_world_payload("Observation", value, {"status": "captured", "authority_tier": "captured_judgment", "actor_class": "operator"})
    with pytest.raises(ValidationError, match="consentgrant"):
        validate_world_payload("Observation", dict(value, consent_grant_id=make_urn("evidence")), OBSERVED)


def test_general_outcome_supports_world_and_decision_feedback():
    value = {
        "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION, "operator_id": make_urn("operator"),
        "evidence_mode": "observed", "subject_id": make_urn("verdict"),
        "description": "Conversion increased after the decision.",
        "metric": "conversion", "value": 0.14, "unit": "ratio",
        "window_start": "2026-07-01T00:00:00Z", "window_end": "2026-07-14T20:00:00Z",
        "source_class": "financial_record", "attribution_status": "contributory",
        "observed_at": "2026-07-14T20:00:00Z", "source_refs": [make_urn("evidence")],
        "consent_grant_id": make_urn("consentgrant"), "attributes": {},
    }
    assert validate_world_payload("Outcome", value, OBSERVED) == value


def test_relation_signatures_reject_reversed_or_channel_spoofed_edges():
    relation = {
        "evidence_mode": "observed", "why": "The measured result matched the promise.",
        "evidence_ids": [make_urn("evidence")], "attributes": {},
    }
    assert validate_world_relation("Outcome", "confirms", "Promise", relation, OBSERVED) == relation
    with pytest.raises(ValidationError, match="endpoint signature"):
        validate_world_relation("Promise", "confirms", "Outcome", relation, OBSERVED)
    with pytest.raises(ValidationError, match="evidence_mode=observed"):
        validate_world_relation("Outcome", "confirms", "Promise", dict(relation, evidence_mode="declared"), DECLARED)


def test_typed_purchase_and_causal_relation():
    purchase = {
        "evidence_mode": "observed", "effective_at": "2026-07-14T20:00:00Z",
        "source_refs": [make_urn("evidence")], "attributes": {}, "amount": 499.0, "currency": "USD",
    }
    assert validate_world_payload("Purchase", purchase, OBSERVED) == purchase
    relation = {
        "evidence_mode": "observed", "why": "Checkout recorded the offer identifier.",
        "evidence_ids": [make_urn("evidence")], "attributes": {},
    }
    assert validate_world_relation("Purchase", "purchased_via", "Offer", relation, OBSERVED) == relation
