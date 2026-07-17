from copy import deepcopy
from datetime import datetime, timezone

import pytest

from imprint.capture.schema import new_urn
from imprint.errors import ValidationError
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.ontology.contracts import validate_node_contract
from imprint.ontology.operator import (
    OPERATOR_ONTOLOGY_VERSION,
    consent_authorizes,
    validate_operator_payload,
)


NOW = "2026-07-14T20:00:00Z"


def confidence(evidence_id):
    return {
        "score": 0.72, "assessor_id": "model:test/1", "method": "model_estimate",
        "basis_evidence_ids": [evidence_id], "assessed_at": NOW,
        "calibration_trial_id": None, "uncertainty_note": "Limited sample.",
    }


def freshness():
    return {
        "valid_from": NOW, "valid_to": None, "last_reviewed_at": None,
        "revalidate_after": "2026-08-14T20:00:00Z",
        "evidence_window_start": "2026-07-01T00:00:00Z",
        "evidence_window_end": NOW, "status": "current",
    }


def provenance(status="inferred", review_state="proposed"):
    return review_state, {
        "status": status, "actor_class": "software" if status == "inferred" else "operator",
        "actor_id": "model:test/1" if status == "inferred" else "operator:test",
        "model_id": "model:test/1" if status == "inferred" else None,
        "prompt_id": "prompt:test/1" if status == "inferred" else None,
    }


def assertion(
    subtype="example.profile-element",
    function_class="example.self-model",
    structure=None,
):
    evidence_id = new_urn("evidence")
    review_state, prov = provenance()
    return {
        "ontology_schema_version": OPERATOR_ONTOLOGY_VERSION,
        "operator_id": new_urn("operator"), "function_class": function_class,
        "dimension": "example.hidden-narrative", "subtype": subtype,
        "statement": "Achievement is used to restore safety.", "polarity": "mixed",
        "scope": "high-stakes launches", "source_phase": "example.analysis-pass",
        "derivation_trace_id": new_urn("derivation_trace"), "evidence_ids": [evidence_id],
        "confidence": confidence(evidence_id), "freshness": freshness(),
        "review_state": review_state, "structure": {} if structure is None else structure,
        "provenance": prov, "extensions": {},
    }


def test_proposal_first_assertion_is_closed_and_detached():
    value = assertion()
    checked = validate_operator_payload("SelfModelAssertion", value)
    assert checked == value and checked is not value
    value["statement"] = "mutated"
    assert checked["statement"] != value["statement"]


@pytest.mark.parametrize("mutation, message", [
    (lambda x: x.update(extra=True), "unknown SelfModelAssertion"),
    (lambda x: x.update(function_class="unscoped"), "namespaced extension"),
    (lambda x: x.update(dimension="hidden_narrative"), "namespaced extension"),
    (lambda x: x.update(source_phase="Unscoped Phase"), "namespaced extension"),
    (lambda x: x["confidence"].update(score=1.2), "between 0 and 1"),
    (lambda x: x["freshness"].update(evidence_window_start="2026-08-01T00:00:00Z"), "window is reversed"),
])
def test_assertion_fails_closed(mutation, message):
    value = assertion()
    mutation(value)
    with pytest.raises(ValidationError, match=message):
        validate_operator_payload("SelfModelAssertion", value)


def test_model_read_cannot_masquerade_as_captured_or_self_ratify():
    value = assertion()
    value["provenance"]["status"] = "captured"
    with pytest.raises(ValidationError, match="must enter as inferred"):
        validate_operator_payload("SelfModelAssertion", value)

    value = assertion()
    value["provenance"]["status"] = "ratified"
    value["review_state"] = "confirmed"
    with pytest.raises(ValidationError, match="only the operator"):
        validate_operator_payload("SelfModelAssertion", value)


def test_operator_ratification_is_explicit_and_valid():
    value = assertion()
    value["review_state"], value["provenance"] = provenance("ratified", "confirmed")
    assert validate_operator_payload("SelfModelAssertion", value)["review_state"] == "confirmed"


def test_outer_authority_cannot_disagree_with_inner_self_model_review():
    value = assertion()
    operator_id = value["operator_id"]
    with pytest.raises(ValidationError, match="payload provenance must match"):
        validate_node_contract({
            "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "node_id": new_urn("selfmodelassertion"),
            "node_type": "SelfModelAssertion", "operator_id": operator_id,
            "payload": value,
            "provenance": {
                "status": "ratified", "authority_tier": "ratified_knowledge",
                "actor_class": "operator", "actor_id": operator_id,
                "mechanism": "adversarial-test", "evidence_ids": value["evidence_ids"],
                "model": None, "ratifier_id": operator_id,
            },
        })


def test_assertion_accepts_extension_owned_taxonomy_and_generic_json_structure():
    structure = {
        "steps": [
            {"name": "first", "enabled": True, "weight": 0.75},
            {"name": "second", "enabled": False, "weight": None},
        ],
        "metadata": {"revision": 2},
    }
    value = assertion("vendor.custom-type", "vendor.any-function", structure)
    value["dimension"] = "vendor.any-dimension"
    value["source_phase"] = "partner.pipeline-step"
    checked = validate_operator_payload("SelfModelAssertion", value)
    assert checked["subtype"] == "vendor.custom-type"
    assert checked["structure"] == structure


def test_assertion_rejects_non_json_extension_structure():
    value = assertion(structure={"not_json": {"a", "set"}})
    with pytest.raises(ValidationError, match="JSON-compatible"):
        validate_operator_payload("SelfModelAssertion", value)


def observation(source_class="transcript", consent_grant_id=None):
    evidence_id = new_urn("evidence")
    return {
        "ontology_schema_version": OPERATOR_ONTOLOGY_VERSION,
        "operator_id": new_urn("operator"), "source_class": source_class,
        "observation_kind": "communication", "subject_id": new_urn("operator"),
        "description": "The operator rejected vague language.",
        "observed_at": NOW, "window_start": "2026-07-14T19:00:00Z", "window_end": NOW,
        "evidence_ids": [evidence_id], "confidence": confidence(evidence_id),
        "consent_grant_id": consent_grant_id, "attributes": {}, "extensions": {},
    }


def test_every_observation_requires_an_exact_consent_reference():
    with pytest.raises(ValidationError, match="consent_grant_id"):
        validate_operator_payload("Observation", observation())
    checked = validate_operator_payload("Observation", observation(consent_grant_id=new_urn("consentgrant")))
    assert checked["source_class"] == "transcript"
    with pytest.raises(ValidationError, match="consent_grant_id"):
        validate_operator_payload("Observation", observation("operator_explicit"))
    explicit = validate_operator_payload(
        "Observation", observation("operator_explicit", new_urn("consentgrant"))
    )
    assert explicit["consent_grant_id"] is not None


def consent(operator_id=None):
    operator_id = operator_id or new_urn("operator")
    return {
        "ontology_schema_version": OPERATOR_ONTOLOGY_VERSION, "operator_id": operator_id,
        "source_class": "transcript", "purposes": ["self_modeling"], "sensitivity": "sensitive",
        "allowed_operations": ["ingest", "store"],
        "retention": {"mode": "days", "days": 30, "delete_on_revoke": False},
        "effective_from": "2026-07-01T00:00:00Z", "effective_to": "2026-08-01T00:00:00Z",
        "granted_by": operator_id, "granted_at": "2026-07-01T00:00:00Z",
        "revoked_at": None, "revocation_reason": None, "extensions": {},
    }


def test_consent_is_default_deny_scoped_and_time_bounded():
    grant = consent()
    assert not consent_authorizes(None, source_class="transcript", purpose="self_modeling", operation="ingest", at=NOW)
    assert consent_authorizes(grant, source_class="transcript", purpose="self_modeling", operation="ingest", at=NOW)
    assert not consent_authorizes(grant, source_class="screenpipe", purpose="self_modeling", operation="ingest", at=NOW)
    assert not consent_authorizes(grant, source_class="transcript", purpose="export", operation="export", at=NOW)
    assert not consent_authorizes(grant, source_class="transcript", purpose="self_modeling", operation="ingest", at="2026-09-01T00:00:00Z")
    assert not consent_authorizes(None, source_class="operator_explicit", purpose="self_modeling", operation="store", at=NOW)
    short = deepcopy(grant)
    short["retention"] = {"mode": "days", "days": 2, "delete_on_revoke": False}
    assert not consent_authorizes(
        short, source_class="transcript", purpose="self_modeling",
        operation="ingest", at="2026-07-10T00:00:00Z",
    )


def test_revoked_consent_denies_from_revocation_forward():
    grant = consent()
    grant["revoked_at"] = "2026-07-10T00:00:00Z"
    grant["revocation_reason"] = "Operator withdrew access."
    validate_operator_payload("ConsentGrant", grant)
    assert not consent_authorizes(grant, source_class="transcript", purpose="self_modeling", operation="ingest", at=NOW)
    assert consent_authorizes(grant, source_class="transcript", purpose="self_modeling", operation="ingest", at="2026-07-09T00:00:00Z")


def test_consent_cannot_be_granted_by_someone_else():
    grant = consent()
    grant["granted_by"] = new_urn("operator")
    with pytest.raises(ValidationError, match="only the operator"):
        validate_operator_payload("ConsentGrant", grant)


def test_derivation_trace_preserves_recomputable_source_phase_and_inputs():
    trace = {
        "ontology_schema_version": OPERATOR_ONTOLOGY_VERSION,
        "operator_id": new_urn("operator"), "element_version_id": new_urn("node_version"),
        "source_phase": "example.analysis-pass", "derived_from_rule": "generic-analysis-v2",
        "computed_at": NOW, "input_ids": [new_urn("verdict"), new_urn("case")],
        "input_snapshot_sha256": "a" * 64, "model_id": "model:test/1",
        "prompt_id": "prompt:self-model/2", "extensions": {},
    }
    checked = validate_operator_payload("DerivationTrace", trace)
    assert checked["source_phase"] == "example.analysis-pass"
    trace["input_snapshot_sha256"] = "A" * 64
    with pytest.raises(ValidationError, match="lowercase SHA-256"):
        validate_operator_payload("DerivationTrace", trace)


def test_intervention_rule_has_triggers_standards_and_ordered_actions():
    evidence_id = new_urn("evidence")
    review_state, prov = provenance("ratified", "confirmed")
    value = {
        "ontology_schema_version": OPERATOR_ONTOLOGY_VERSION,
        "operator_id": new_urn("operator"), "instruction": "Return to the ratified standard.",
        "trigger_ids": [new_urn("cue")], "protects_standard_ids": [new_urn("assertion")],
        "action_steps": [{"order": 1, "instruction": "Name the trigger.", "success_criterion": "Trigger is explicit."}],
        "contraindications": [], "review_state": review_state, "evidence_ids": [evidence_id],
        "freshness": freshness(), "provenance": prov, "extensions": {},
    }
    assert validate_operator_payload("InterventionRule", value)["review_state"] == "confirmed"
    value["action_steps"][0]["order"] = 2
    with pytest.raises(ValidationError, match="contiguous"):
        validate_operator_payload("InterventionRule", value)


def test_cue_and_lexicon_are_typed_not_profile_fields():
    evidence_id = new_urn("evidence")
    cue = {
        "ontology_schema_version": OPERATOR_ONTOLOGY_VERSION, "operator_id": new_urn("operator"),
        "cue_kind": "anomaly", "description": "The exception was more revealing than the rule.",
        "context": "Offer review", "interpretation": None, "observation_id": new_urn("observation"),
        "evidence_ids": [evidence_id], "confidence": confidence(evidence_id), "extensions": {},
    }
    term = {
        "ontology_schema_version": OPERATOR_ONTOLOGY_VERSION, "operator_id": cue["operator_id"],
        "term": "fossil", "definition": "A once-valid model left active past its evidence.",
        "term_kind": "private_vocabulary", "aliases": [], "scope": "self model",
        "evidence_ids": [evidence_id], "provenance_status": "captured", "extensions": {},
    }
    assert validate_operator_payload("Cue", cue)["cue_kind"] == "anomaly"
    assert validate_operator_payload("LexiconTerm", term)["term"] == "fossil"
