from __future__ import annotations

import hashlib
import json

import pytest

from imprint.capture.schema import build_capture_envelope
from imprint.errors import ValidationError
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256
from imprint.store import ImprintStore


NOW = "2026-07-16T12:00:00Z"
SCOPE = "urn:imprint:scope:00000000-0000-4000-8000-000000000001"


def _provenance(actor_id, role_version, evidence_version, *, tier="captured_judgment"):
    return {
        "origin_status": "captured", "lifecycle_status": "active",
        "authority_tier": tier, "authority_source": "operator",
        "mechanism": "operator_authored", "actor_id": actor_id,
        "actor_class": "operator", "role_assignment_version_id": role_version,
        "evidence_version_ids": [evidence_version],
        "source_phase_ids": ["operator_authored"],
        "primary_source_phase_id": "operator_authored",
    }


def _envelope(schema_id, record_id, version_id, payload, *, operator_id, actor_id,
              role_version, policy_version, consent_version, evidence_version,
              tier="captured_judgment"):
    return {
        "record_id": record_id, "version_id": version_id,
        "payload_schema_id": schema_id, "record_schema_version": "3.1.0",
        "ontology_schema_version": "3.6.1", "operator_id": operator_id,
        "payload": payload,
        "provenance": _provenance(actor_id, role_version, evidence_version, tier=tier),
        "sensitivity": "standard", "access_policy_version_id": policy_version,
        "consent_version_id": consent_version, "actor_id": actor_id,
        "role_assignment_version_id": role_version, "valid_from": NOW,
        "valid_to": None, "scope_id": SCOPE, "extensions": {},
    }


def _seed_consent(store: ImprintStore, operator_id: str) -> tuple[str, str]:
    record_id, version_id, event_id = make_urn("consentgrant"), make_urn("node-version"), make_urn("event")
    payload = {"valid_from": "2026-01-01T00:00:00Z", "valid_to": None, "system_from": "2026-01-01T00:00:00Z", "system_to": None}
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            (event_id, "test_consent", operator_id, NOW, NOW, canonical_bytes(payload).decode(), payload_sha256(payload), None, "captured"),
        )
        conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (record_id, "ConsentGrant", operator_id, event_id))
        conn.execute(
            "INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (version_id, record_id, canonical_bytes(payload).decode(), payload_sha256(payload), "captured",
             "captured_judgment", canonical_bytes({"lifecycle_status": "active"}).decode(), "[]",
             "2026-01-01T00:00:00Z", None, "2026-01-01T00:00:00Z", None, event_id, None),
        )
    return record_id, version_id


def _governed_store(tmp_path, signed_store):
    operator_id = make_urn("operator")
    harness = signed_store(tmp_path / "imprint.db", operator_id)
    store = harness.store
    _, consent_version = _seed_consent(store, operator_id)
    actor_id, actor_version = make_urn("actor"), make_urn("node-version")
    role_id, role_version = make_urn("roleassignment"), make_urn("node-version")
    policy_id, policy_version = make_urn("accesspolicy"), make_urn("node-version")
    artifact_id, artifact_version = make_urn("evidenceartifact"), make_urn("node-version")
    content = b"exact first-write evidence bytes\x00\xff"
    envelopes = [
        _envelope("imprint.node.actor/1.0.0", actor_id, actor_version,
                  {"actor_type": "operator", "display_label": "Operator"},
                  operator_id=operator_id, actor_id=actor_id, role_version=role_version,
                  policy_version=policy_version, consent_version=consent_version,
                  evidence_version=artifact_version),
        _envelope("imprint.node.role-assignment/1.0.0", role_id, role_version,
                  {"actor_version_id": actor_version, "role_type": "operator_of_record",
                   "scope_ids": [SCOPE], "authority_basis": "operator_self",
                   "allowed_operations": ["store"], "valid_from": "2026-01-01T00:00:00Z",
                   "valid_to": None, "granted_by_role_assignment_version_id": role_version},
                  operator_id=operator_id, actor_id=actor_id, role_version=role_version,
                  policy_version=policy_version, consent_version=consent_version,
                  evidence_version=artifact_version),
        _envelope("imprint.node.access-policy/1.0.0", policy_id, policy_version,
                  {"principal_role_assignment_version_ids": [role_version], "operations": ["store"],
                   "purposes": ["self_modeling"], "field_paths": [],
                   "valid_from": "2026-01-01T00:00:00Z", "valid_to": None,
                   "system_from": "2026-01-01T00:00:00Z", "system_to": None},
                  operator_id=operator_id, actor_id=actor_id, role_version=role_version,
                  policy_version=policy_version, consent_version=consent_version,
                  evidence_version=artifact_version),
        _envelope("imprint.node.evidence-artifact/1.0.0", artifact_id, artifact_version,
                  {"original_sha256": hashlib.sha256(content).hexdigest(), "byte_count": len(content),
                   "media_type": "application/octet-stream", "media_type_source": "unknown_sentinel",
                   "source_class": "explicit_test", "source_locator": "memory:test", "source_system": "pytest",
                   "captured_at": NOW, "custody_actor_version_id": actor_version,
                   "consent_version_id": consent_version, "access_policy_version_id": policy_version,
                   "storage_locator": "sqlite:semantic_artifact_bytes", "derived_from_version_ids": [],
                   "content_state": "active"},
                  operator_id=operator_id, actor_id=actor_id, role_version=role_version,
                  policy_version=policy_version, consent_version=consent_version,
                  evidence_version=artifact_version),
    ]
    versions = harness.call(store.append_ontology_bundle, envelopes, artifact_bytes={artifact_version: content})
    assert versions == (actor_version, role_version, policy_version, artifact_version)
    return harness, {
        "operator": operator_id, "actor_id": actor_id, "actor_version": actor_version,
        "role_version": role_version, "policy_version": policy_version,
        "consent_version": consent_version, "artifact_version": artifact_version,
    }


def _capture_case_and_verdict(store, operator_id):
    capture = build_capture_envelope(
        operator_id=operator_id, session_id=make_urn("session"), node_id="semantic-test",
        case_description="Choose the public ontology boundary", raw_operator_text="Preserve exact versions.",
        call_type="prefer", capture_mechanism="explicit_cli", captured_by="pytest",
        reason=None, captured_at=NOW,
    )
    store.apply_capture(capture)
    nodes = {item["node_type"]: item for item in store.current_nodes(["Case", "Verdict"])}
    with store.connect() as conn:
        return tuple(conn.execute("SELECT version_id FROM node_versions WHERE node_id=?", (nodes[k]["node_id"],)).fetchone()[0] for k in ("Case", "Verdict"))


def test_decision_episode_expected_outcome_and_confidence_commit_atomically(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    case_version, verdict_version = _capture_case_and_verdict(store, ids["operator"])
    outcome_id, outcome_version = make_urn("expectedoutcome"), make_urn("node-version")
    confidence_id, confidence_version = make_urn("confidenceassessment"), make_urn("node-version")
    episode_id, episode_version = make_urn("decisionepisode"), make_urn("node-version")
    expected = _envelope(
        "imprint.node.expected-outcome/1.0.0", outcome_id, outcome_version,
        {"statement": "A stable public release", "observable_criterion": "All semantic gates pass",
         "horizon": "P30D", "confidence_assessment_version_id": confidence_version}, **ids_for(ids),
    )
    confidence = _envelope(
        "imprint.node.confidence-assessment/1.0.0", confidence_id, confidence_version,
        {"subject_version_id": outcome_version, "score": 0.7, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition",
         "assessed_at": NOW}, **ids_for(ids),
    )
    episode = _envelope(
        "imprint.node.decision-episode/1.0.0", episode_id, episode_version,
        {"case_version_id": case_version, "verdict_version_id": verdict_version,
         "operator_role_assignment_version_id": ids["role_version"], "captured_at": NOW,
         "session_id": "session-1", "project_id": "imprint-v3.1",
         "artifact_version_ids": [ids["artifact_version"]],
         "expected_outcome_version_ids": [outcome_version]}, **ids_for(ids),
    )
    assert harness.call(store.append_ontology_bundle, [episode, expected, confidence]) == (
        episode_version, outcome_version, confidence_version,
    )
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM semantic_node_versions").fetchone()[0] == 7
        assert conn.execute("SELECT assessment_version_id FROM semantic_confidence_heads WHERE subject_version_id=?", (outcome_version,)).fetchone()[0] == confidence_version


def ids_for(ids):
    return {
        "operator_id": ids["operator"], "actor_id": ids["actor_id"],
        "role_version": ids["role_version"], "policy_version": ids["policy_version"],
        "consent_version": ids["consent_version"], "evidence_version": ids["artifact_version"],
    }


def test_missing_required_assessment_and_artifact_digest_fail_without_mutation(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    before = store.snapshot()
    expected = _envelope(
        "imprint.node.expected-outcome/1.0.0", make_urn("expectedoutcome"), make_urn("node-version"),
        {"statement": "No fabricated score", "observable_criterion": "Atomic rejection", "horizon": "P7D"},
        **ids_for(ids), tier="observed_candidate",
    )
    with pytest.raises(ValidationError, match="required initial assessment"):
        store.append_ontology_node(expected)
    bad_artifact = next(
        json.loads(row["envelope_json"]) for row in _semantic_rows(store)
        if row["payload_schema_id"] == "imprint.node.evidence-artifact/1.0.0"
    )
    bad_artifact.pop("system_from"); bad_artifact.pop("system_to")
    bad_artifact["record_id"], bad_artifact["version_id"] = make_urn("evidenceartifact"), make_urn("node-version")
    bad_artifact["provenance"]["evidence_version_ids"] = [bad_artifact["version_id"]]
    with pytest.raises(ValidationError, match="E_ARTIFACT_DIGEST_MISMATCH"):
        store.append_ontology_node(bad_artifact, artifact_bytes=b"wrong")
    assert store.snapshot() == before


def _semantic_rows(store):
    with store.connect() as conn:
        return conn.execute("SELECT * FROM semantic_node_versions ORDER BY version_id").fetchall()


def test_bitemporal_late_correction_preserves_history_and_renews_confidence(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    original_id, original_version = make_urn("expectedoutcome"), make_urn("node-version")
    initial_conf_id, initial_conf_version = make_urn("confidenceassessment"), make_urn("node-version")
    original = _envelope(
        "imprint.node.expected-outcome/1.0.0", original_id, original_version,
        {"statement": "Payload A", "observable_criterion": "A observed", "horizon": "P30D",
         "confidence_assessment_version_id": initial_conf_version}, **ids_for(ids),
    )
    initial_conf = _envelope(
        "imprint.node.confidence-assessment/1.0.0", initial_conf_id, initial_conf_version,
        {"subject_version_id": original_version, "score": 0.4, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        **ids_for(ids),
    )
    harness.call(store.append_ontology_bundle, [original, initial_conf])
    with store.connect() as conn:
        original_system = conn.execute("SELECT system_from FROM node_versions WHERE version_id=?", (original_version,)).fetchone()[0]
    carry, corrected = make_urn("node-version"), make_urn("node-version")
    renewed_id, renewed_version = make_urn("confidenceassessment"), make_urn("node-version")
    renewed = _envelope(
        "imprint.node.confidence-assessment/1.0.0", renewed_id, renewed_version,
        {"subject_version_id": corrected, "score": 0.8, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        **ids_for(ids),
    )
    result = harness.call(
        store.correct_ontology_version, record_id=original_id, scope_id=SCOPE,
        effective_from="2026-07-20T00:00:00Z",
        corrected_payload={"statement": "Payload B", "observable_criterion": "B observed", "horizon": "P30D",
                           "confidence_assessment_version_id": renewed_version},
        correction_event_id=make_urn("correctionevent"), carry_forward_version_id=carry,
        corrected_version_id=corrected, evidence_version_ids=[ids["artifact_version"]],
        actor_id=ids["actor_id"], role_assignment_version_id=ids["role_version"],
        confidence_assessment=renewed,
    )
    assert result == (carry, corrected)
    old = store.ontology_as_of(original_id, SCOPE, valid_at="2026-07-21T00:00:00Z", system_at=original_system)
    assert old["versions"][0]["payload"]["statement"] == "Payload A"
    with store.connect() as conn:
        new_system = conn.execute("SELECT system_from FROM node_versions WHERE version_id=?", (corrected,)).fetchone()[0]
    assert store.ontology_as_of(original_id, SCOPE, valid_at="2026-07-17T00:00:00Z", system_at=new_system)["winner"] == carry
    latest = store.ontology_as_of(original_id, SCOPE, valid_at="2026-07-21T00:00:00Z", system_at=new_system)
    assert latest["winner"] == corrected and latest["versions"][0]["payload"]["statement"] == "Payload B"


def test_contradiction_uses_exact_versions_and_atomic_confidence(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    verdict_versions = []
    for index in range(2):
        capture = build_capture_envelope(
            operator_id=ids["operator"], session_id=make_urn("session"), node_id=f"semantic-{index}",
            case_description=f"Contradiction case {index}", raw_operator_text=f"Verdict {index}",
            call_type="prefer", capture_mechanism="explicit_cli", captured_by="pytest",
            reason="Exact disagreement.", captured_at=NOW,
        )
        store.apply_capture(capture)
        with store.connect() as conn:
            verdict_versions.append(conn.execute(
                "SELECT version_id FROM node_versions WHERE node_id=?", (capture["verdict"]["verdict_id"],),
            ).fetchone()[0])
    relation_id, relation_version = make_urn("relation"), make_urn("relation-version")
    relation = {
        "relation_id": relation_id, "relation_version_id": relation_version,
        "predicate_id": "contradicts", "predicate_version": 1,
        "source_version_id": verdict_versions[0], "target_version_id": verdict_versions[1],
        "operator_id": ids["operator"], "actor_id": ids["actor_id"],
        "role_assignment_version_id": ids["role_version"],
        "provenance": _provenance(ids["actor_id"], ids["role_version"], ids["artifact_version"]),
        "evidence_version_ids": [ids["artifact_version"]], "why": "The calls disagree.",
        "sensitivity": "standard", "access_policy_version_id": ids["policy_version"],
        "consent_version_id": ids["consent_version"], "valid_from": NOW, "valid_to": None,
        "qualifier_schema_id": "q.contradiction@1",
        "qualifier": {"resolution_state": "open", "scope_ids": [SCOPE],
                      "detected_by": ids["actor_version"], "resolution_event_version_id": None},
        "extensions": {},
    }
    assessment = _envelope(
        "imprint.node.confidence-assessment/1.0.0", make_urn("confidenceassessment"), make_urn("node-version"),
        {"subject_version_id": relation_version, "score": 0.9, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        **ids_for(ids), tier="observed_candidate",
    )
    with pytest.raises(ValidationError, match="requires an atomic assessment"):
        store.append_ontology_contradiction(relation)
    assert harness.call(
        store.append_ontology_contradiction, relation, confidence_assessment=assessment,
    ) == relation_version
    with store.connect() as conn:
        stored = conn.execute(
            "SELECT source_version_id,target_version_id FROM semantic_relation_versions WHERE relation_version_id=?",
            (relation_version,),
        ).fetchone()
        assert tuple(stored) == tuple(verdict_versions)
        assert conn.execute(
            "SELECT assessment_version_id FROM semantic_confidence_heads WHERE subject_version_id=?",
            (relation_version,),
        ).fetchone()[0] == assessment["version_id"]


def test_evidence_transform_appends_new_bytes_and_complete_custody(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    original_row = next(
        row for row in _semantic_rows(store)
        if row["payload_schema_id"] == "imprint.node.evidence-artifact/1.0.0"
    )
    derived = json.loads(original_row["envelope_json"])
    derived.pop("system_from"); derived.pop("system_to")
    derived["record_id"], derived["version_id"] = make_urn("evidenceartifact"), make_urn("node-version")
    derived_bytes = b"redacted derivative with independent bytes"
    derived["payload"].update({
        "original_sha256": hashlib.sha256(derived_bytes).hexdigest(),
        "byte_count": len(derived_bytes), "media_type": "text/plain",
        "media_type_source": "declared", "storage_locator": "sqlite:semantic_artifact_bytes",
        "derived_from_version_ids": [ids["artifact_version"]],
        "transform_event_version_id": make_urn("transformevent"),
    })
    derived["provenance"]["evidence_version_ids"] = [ids["artifact_version"]]
    assert harness.call(
        store.append_ontology_node, derived, artifact_bytes=derived_bytes,
    ) == derived["version_id"]
    with store.connect() as conn:
        original = conn.execute(
            "SELECT content FROM semantic_artifact_bytes WHERE version_id=?", (ids["artifact_version"],),
        ).fetchone()[0]
        stored = conn.execute(
            "SELECT content,content_sha256,byte_count FROM semantic_artifact_bytes WHERE version_id=?",
            (derived["version_id"],),
        ).fetchone()
    assert bytes(original) != derived_bytes
    assert bytes(stored[0]) == derived_bytes
    assert stored[1:] == (hashlib.sha256(derived_bytes).hexdigest(), len(derived_bytes))


def test_contested_versions_return_both_members_and_no_winner(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    record_id, original_version = make_urn("expectedoutcome"), make_urn("node-version")
    initial_assessment = _envelope(
        "imprint.node.confidence-assessment/1.0.0", make_urn("confidenceassessment"), make_urn("node-version"),
        {"subject_version_id": original_version, "score": 0.5, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        **ids_for(ids),
    )
    original = _envelope(
        "imprint.node.expected-outcome/1.0.0", record_id, original_version,
        {"statement": "Original projection", "observable_criterion": "Original observed", "horizon": "P30D",
         "confidence_assessment_version_id": initial_assessment["version_id"]}, **ids_for(ids),
    )
    harness.call(store.append_ontology_bundle, [original, initial_assessment])
    preserved_version, competing_version = make_urn("node-version"), make_urn("node-version")
    preserved_assessment = _envelope(
        "imprint.node.confidence-assessment/1.0.0", make_urn("confidenceassessment"), make_urn("node-version"),
        {"subject_version_id": preserved_version, "score": 0.45, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        **ids_for(ids),
    )
    competing_assessment = _envelope(
        "imprint.node.confidence-assessment/1.0.0", make_urn("confidenceassessment"), make_urn("node-version"),
        {"subject_version_id": competing_version, "score": 0.55, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        **ids_for(ids),
    )
    assert harness.call(
        store.contest_ontology_version, record_id=record_id, scope_id=SCOPE,
        contested_set_id=make_urn("contested-set"), contest_event_id=make_urn("contestevent"),
        preserved_version_id=preserved_version, competing_version_id=competing_version,
        competing_payload={"statement": "Competing projection", "observable_criterion": "Competing observed",
                           "horizon": "P30D", "confidence_assessment_version_id": competing_assessment["version_id"]},
        evidence_version_ids=[ids["artifact_version"]], actor_id=ids["actor_id"],
        role_assignment_version_id=ids["role_version"],
        confidence_assessments=[preserved_assessment, competing_assessment],
    ) == (preserved_version, competing_version)
    with store.connect() as conn:
        system_at = conn.execute("SELECT system_from FROM node_versions WHERE version_id=?", (competing_version,)).fetchone()[0]
    result = store.ontology_as_of(record_id, SCOPE, valid_at="2026-07-17T00:00:00Z", system_at=system_at)
    assert result["state"] == "contested" and result["winner"] is None
    assert {item["version_id"] for item in result["versions"]} == {preserved_version, competing_version}


def _seed_exact_test_version(store, operator_id, node_type, payload):
    record_id, version_id, event_id = make_urn(node_type.lower()), make_urn("node-version"), make_urn("event")
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", (event_id, "test_reference", operator_id, NOW, NOW, canonical_bytes(payload).decode(), payload_sha256(payload), None, "captured"))
        conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (record_id, node_type, operator_id, event_id))
        conn.execute("INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (version_id, record_id, canonical_bytes(payload).decode(), payload_sha256(payload), "captured", "captured_judgment", canonical_bytes({"lifecycle_status": "active"}).decode(), "[]", NOW, None, NOW, None, event_id, None))
    return version_id


def _business_confidence(subject_version, ids):
    return _envelope(
        "imprint.node.confidence-assessment/1.0.0", make_urn("confidenceassessment"), make_urn("node-version"),
        {"subject_version_id": subject_version, "score": 0.61, "scale": "unit_interval",
         "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        **ids_for(ids),
    )


def test_all_eleven_business_schemas_persist_exactly_with_locked_partitions(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    proof_version = _seed_exact_test_version(store, ids["operator"], "Proof", {"claim": "Observed"})
    _seed_exact_test_version(store, ids["operator"], "Offer", {"name": "Advisory"})
    _seed_exact_test_version(store, ids["operator"], "Outcome", {"result": "Growth"})
    ratification_event = make_urn("event")
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", (ratification_event, "ratification", ids["operator"], NOW, NOW, "{}", payload_sha256({}), None, "captured"))
    measurement_version = make_urn("node-version")
    cases = [
        ("imprint.node.market/1.0.0", {"name": "Founder market", "category": "urn:market:founders", "definition": "Founder-led firms"}),
        ("imprint.node.positioning/1.0.0", {"frame": "Evidence first", "category_claim": "Auditable intelligence", "differentiator_claims": ["Exact provenance"], "ratification_event_version_id": ratification_event, "proof_version_ids": [proof_version]}),
        ("imprint.node.term-set/1.0.0", {"name": "Canonical terms", "terms": [{"term_id": "urn:term:imprint", "label": "Imprint", "definition": "Durable judgment", "status": "preferred", "replaced_by_term_id": None}], "language": "en-US", "ratification_event_version_id": ratification_event}),
        ("imprint.node.asset/1.0.0", {"name": "Manifesto", "asset_type": "document", "artifact_version_id": ids["artifact_version"], "purpose": "Public explanation", "lifecycle_state": "active", "approved_by_role_assignment_version_id": ids["role_version"]}),
        ("imprint.node.campaign/1.0.0", {"name": "Launch", "objective": "Qualified adoption", "status": "active", "start_at": NOW, "owner_role_assignment_version_id": ids["role_version"]}),
        ("imprint.node.business-event/1.1.0", {"event_type": "purchase", "occurred_at": NOW, "observer_actor_version_id": ids["actor_version"], "source_artifact_version_id": ids["artifact_version"], "quantity": 1, "deduplication_key": "purchase-1"}),
        ("imprint.node.segment/1.0.0", {"name": "Operators", "definition": "Founder operators", "criteria": [{"criterion_id": "urn:criterion:one", "field_id": "urn:field:role", "operator": "eq", "value": "founder"}]}),
        ("imprint.node.situation/1.0.0", {"name": "AI transition", "trigger_conditions": [{"criterion_id": "urn:criterion:two", "field_id": "urn:field:state", "operator": "eq", "value": "transition"}], "context_statement": "Business is adopting AI"}),
        ("imprint.node.required-behavior/1.0.0", {"actor_class": "operator", "action": "Review the evidence", "observable_criterion": "Signed disposition exists", "required": True, "ratification_event_version_id": ratification_event}),
        ("imprint.node.campaign-performance-measurement/1.1.0", {"metric_id": "urn:metric:conversion", "value": 0.2, "unit_id": "urn:unit:ratio", "window_start": "2026-07-15T00:00:00Z", "window_end": NOW, "method_id": "urn:method:observational", "method_version": "1.0.0", "observer_actor_version_id": ids["actor_version"], "source_artifact_version_ids": [ids["artifact_version"]], "attribution_status": "correlated", "attribution_rationale": "Correlation only"}),
        ("imprint.node.performance-disposition/1.1.0", {"disposition": "confirm", "measurement_version_id": measurement_version, "outcome_version_id": None, "decided_by_actor_version_id": ids["actor_version"], "decided_by_role_assignment_version_id": ids["role_version"], "decided_at": NOW, "reason": "Evidence supports the bounded result", "evidence_version_ids": [ids["artifact_version"]]}),
    ]
    written = []
    for schema_id, payload in cases:
        version_id = measurement_version if schema_id.endswith("campaign-performance-measurement/1.1.0") else make_urn("node-version")
        required_confidence = schema_id.endswith(("business-event/1.1.0", "segment/1.0.0", "situation/1.0.0", "campaign-performance-measurement/1.1.0", "performance-disposition/1.1.0"))
        confidence = _business_confidence(version_id, ids) if required_confidence else None
        if confidence:
            payload["confidence_assessment_version_id"] = confidence["version_id"]
        envelope = _envelope(schema_id, make_urn("business"), version_id, payload, **ids_for(ids))
        if schema_id.endswith(("positioning/1.0.0", "term-set/1.0.0", "required-behavior/1.0.0")):
            envelope["provenance"].update(authority_tier="ratified_knowledge", ratification_event_version_id=ratification_event)
        harness.call(store.append_ontology_bundle, [envelope, confidence] if confidence else [envelope])
        stored = store.read_business_node(version_id)
        assert {key: stored["envelope"][key] for key in envelope} == envelope
        assert stored["partition"] == ("business_observed" if schema_id in {"imprint.node.business-event/1.1.0", "imprint.node.campaign-performance-measurement/1.1.0"} else "business_declared")
        written.append(version_id)
    assert {item["envelope"]["version_id"] for item in store.iter_business_nodes()} == set(written)


def test_business_candidate_ceiling_fails_before_mutation(tmp_path, signed_store):
    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    envelope = _envelope("imprint.node.market/1.0.0", make_urn("market"), make_urn("node-version"), {"name": "Imported market", "category": "urn:market:test", "definition": "Imported"}, **ids_for(ids), tier="observed_candidate")
    envelope["provenance"]["origin_status"] = "extracted"
    before = store.snapshot()
    with pytest.raises(ValidationError, match="E_BUSINESS_AUTHORITY_CEILING"):
        store.append_ontology_node(envelope)
    assert store.snapshot() == before


def test_all_twenty_three_business_relations_persist_with_exact_qualifiers(tmp_path, signed_store):
    from imprint.ontology.business import BUSINESS_QUALIFIER_SCHEMA_IDS, BUSINESS_RELATION_SPECS

    harness, ids = _governed_store(tmp_path, signed_store)
    store = harness.store
    ratification_event = make_urn("event")
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)", (ratification_event, "ratification", ids["operator"], NOW, NOW, "{}", payload_sha256({}), None, "captured"))

    written = []
    for predicate, (source_spec, target_spec, kind, policy_code, authority_minimum) in BUSINESS_RELATION_SPECS.items():
        source_type = source_spec if isinstance(source_spec, str) else sorted(source_spec)[0]
        target_type = sorted(target_spec)[0]
        source_payload = {"name": source_type}
        target_payload = {"name": target_type}
        target_version = _seed_exact_test_version(store, ids["operator"], target_type, target_payload)
        if predicate == "disposition_of":
            source_payload = {"measurement_version_id": target_version, "outcome_version_id": None}
        source_version = _seed_exact_test_version(store, ids["operator"], source_type, source_payload)
        relation_version = make_urn("relation-version")
        confidence_version = _seed_exact_test_version(
            store, ids["operator"], "ConfidenceAssessment",
            {"subject_version_id": relation_version, "score": 0.5, "scale": "unit_interval",
             "assessor_actor_version_id": ids["actor_version"], "method": "operator_intuition", "assessed_at": NOW},
        )
        link = {"rationale": "Exact governed link", "evidence_version_ids": [ids["artifact_version"]]}
        evidence_link = {
            "rationale": "Observed evidence", "evidence_version_ids": [ids["artifact_version"]],
            "window_start": "2026-07-15T00:00:00Z", "window_end": NOW,
            "confidence_assessment_version_id": confidence_version,
            "observer_actor_version_id": ids["actor_version"],
            "source_artifact_version_ids": [ids["artifact_version"]],
        }
        attribution = {
            "attribution_rationale": "Correlated only", "baseline_version_id": None,
            "comparator_version_id": None, "window_start": "2026-07-15T00:00:00Z",
            "window_end": NOW, "method_id": "urn:method:observational", "method_version": "1.0.0",
            "observer_actor_version_id": ids["actor_version"],
            "source_artifact_version_ids": [ids["artifact_version"]], "status": "correlated",
        }
        mechanism_version = _seed_exact_test_version(store, ids["operator"], "Mechanism", {"name": "Mechanism"})
        causation = {
            **attribution, "claim_text": "Mechanism may contribute", "mechanism_version_id": mechanism_version,
            "design": "observational", "causal_status": "unproven",
            "confidence_assessment_version_id": confidence_version,
        }
        qualifier = {"link": link, "evidence-link": evidence_link, "attribution": attribution, "causation": causation}[kind]
        tier = "ratified_knowledge" if authority_minimum == "R" else "captured_judgment" if authority_minimum == "J" else "observed_candidate"
        provenance = _provenance(ids["actor_id"], ids["role_version"], ids["artifact_version"], tier=tier)
        if tier == "ratified_knowledge":
            provenance["ratification_event_version_id"] = ratification_event
        envelope = {
            "relation_id": make_urn("relation"), "relation_version_id": relation_version,
            "predicate_id": predicate, "predicate_version": 1,
            "source_version_id": source_version, "target_version_id": target_version,
            "operator_id": ids["operator"], "actor_id": ids["actor_id"],
            "role_assignment_version_id": ids["role_version"], "provenance": provenance,
            "evidence_version_ids": [ids["artifact_version"]], "why": "Exact business assertion",
            "sensitivity": "standard", "access_policy_version_id": ids["policy_version"],
            "consent_version_id": ids["consent_version"], "valid_from": NOW, "valid_to": None,
            "qualifier_schema_id": BUSINESS_QUALIFIER_SCHEMA_IDS[kind], "qualifier": qualifier,
            "extensions": {},
        }
        result = harness.call(store.append_business_relation, envelope) if tier in {"captured_judgment", "ratified_knowledge"} else store.append_business_relation(envelope)
        assert result == relation_version
        readback = store.read_business_relation(relation_version)
        expected_envelope = {**envelope, "provenance": provenance, "qualifier": qualifier}
        assert {key: readback["envelope"][key] for key in expected_envelope} == expected_envelope
        assert readback["policy"] == policy_code and readback["authority_minimum"] == authority_minimum
        written.append(relation_version)
    assert {item["envelope"]["relation_version_id"] for item in store.iter_business_relations()} == set(written)
