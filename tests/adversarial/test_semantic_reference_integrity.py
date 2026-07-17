from __future__ import annotations

from copy import deepcopy
import json

import pytest

from imprint.capture.schema import build_capture_envelope, new_urn
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.errors import ValidationError
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256
from imprint.portability import export_jsonld, import_jsonld
from imprint.portability.jsonld import semantic_digest
from imprint.store import ImprintStore


NOW = "2026-07-14T18:00:00Z"


def _provenance(evidence_id: str) -> dict:
    return {
        "status": "inferred", "authority_tier": "inferred_candidate",
        "actor_class": "model", "actor_id": make_urn("model"),
        "mechanism": "adversarial_reference_test", "evidence_ids": [evidence_id],
        "model": "synthetic-model", "ratifier_id": None,
    }


def _contract(node_type: str, operator_id: str, payload: dict, evidence_id: str) -> dict:
    return {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": make_urn(node_type.lower().replace("trial", "_trial")),
        "node_type": node_type, "operator_id": operator_id, "payload": payload,
        "provenance": _provenance(evidence_id),
    }


def _other_capture() -> dict:
    return build_capture_envelope(
        operator_id=new_urn("operator"), session_id=new_urn("session"),
        node_id="foreign-workstation", case_description="Foreign operator decision",
        raw_operator_text="Keep operators isolated.", call_type="correct",
        capture_mechanism="explicit_cli", captured_by="imprint-test",
        reason="Operator boundaries are authoritative.", captured_at=NOW,
    )


def test_append_rejects_missing_nodes_versions_and_consent_without_mutation(
    tmp_path, capture_envelope,
):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    operator_id = capture_envelope["operator_id"]
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    with store.connect() as conn:
        baseline = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    attacks = [
        _contract("Pattern", operator_id, {
            "statement": "A fabricated pattern.",
            "case_ids": [make_urn("case"), make_urn("case")],
            "reason": "Synthetic", "reason_status": "supplied",
        }, evidence_id),
        _contract("DerivationTrace", operator_id, {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "operator_id": operator_id, "element_version_id": make_urn("node-version"),
                "source_phase": "example.approved-import", "derived_from_rule": "attack-v1",
            "computed_at": NOW, "input_ids": [evidence_id],
            "input_snapshot_sha256": "a" * 64, "model_id": "synthetic-model",
            "prompt_id": "synthetic-prompt", "extensions": {},
        }, evidence_id),
        _contract("Observation", operator_id, {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "operator_id": operator_id, "source_class": "transcript",
            "observation_kind": "behavior", "subject_id": operator_id,
            "description": "A consent-laundered observation.", "observed_at": NOW,
            "window_start": NOW, "window_end": NOW, "evidence_ids": [evidence_id],
            "confidence": {
                "score": 0.5, "assessor_id": "synthetic-model", "method": "model_estimate",
                "basis_evidence_ids": [evidence_id], "assessed_at": NOW,
                "calibration_trial_id": None, "uncertainty_note": "Adversarial fixture.",
            },
            "consent_grant_id": make_urn("consentgrant"), "attributes": {}, "extensions": {},
        }, evidence_id),
    ]

    messages = ("missing canonical node", "element_version_id is missing", "missing canonical node")
    for attack, message in zip(attacks, messages, strict=True):
        with pytest.raises(ValidationError, match=message):
            store.append_semantic_node(attack, valid_from=NOW)

    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == baseline


def test_append_rejects_foreign_operator_evidence(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    foreign = _other_capture()
    store.apply_capture(foreign)
    foreign_evidence = next(
        node["node_id"] for node in store.current_nodes(["Evidence"])
        if node["operator_id"] == foreign["operator_id"]
    )
    attack = _contract(
        "Principle", capture_envelope["operator_id"],
        {"statement": "Foreign evidence grants local authority."}, foreign_evidence,
    )
    with pytest.raises(ValidationError, match="another operator"):
        store.append_semantic_node(attack, valid_from=NOW)
    assert all(
        node["node_id"] != attack["node_id"] for node in store.current_nodes()
    )


@pytest.mark.parametrize("foreign", [False, True], ids=["missing", "foreign-operator"])
def test_jsonld_reference_attack_fails_before_store_creation(
    tmp_path, capture_envelope, foreign,
):
    source = ImprintStore(tmp_path / "source.db")
    source.initialize()
    source.apply_capture(capture_envelope)
    local_evidence = source.current_nodes(["Evidence"])[0]["node_id"]
    principle = _contract(
        "Principle", capture_envelope["operator_id"],
        {"statement": "Evidence boundaries survive transport."}, local_evidence,
    )
    source.append_semantic_node(principle, valid_from=NOW)
    if foreign:
        other = _other_capture()
        source.apply_capture(other)
        replacement = next(
            node["node_id"] for node in source.current_nodes(["Evidence"])
            if node["operator_id"] == other["operator_id"]
        )
    else:
        replacement = make_urn("evidence")

    document = export_jsonld(source)
    attacked = deepcopy(document)
    version = next(
        row for row in attacked["imprint:ledger"]["node_versions"]
        if row["node_id"] == principle["node_id"]
    )
    version["evidence_json"] = json.dumps([replacement])
    graph_item = next(item for item in attacked["@graph"] if item["@id"] == version["version_id"])
    graph_item["imprint:evidence"] = [replacement]
    node = next(
        row for row in attacked["imprint:ledger"]["nodes"]
        if row["node_id"] == principle["node_id"]
    )
    event = next(
        row for row in attacked["imprint:ledger"]["events"]
        if row["event_id"] == node["created_event_id"]
    )
    event_payload = json.loads(event["payload_json"])
    event_payload["provenance"]["evidence_ids"] = [replacement]
    event["payload_json"] = canonical_bytes(event_payload).decode()
    event["payload_sha256"] = payload_sha256(event_payload)
    attacked["imprint:semanticSha256"] = semantic_digest(attacked)

    target = ImprintStore(tmp_path / f"target-{foreign}.db")
    with pytest.raises(ValidationError, match="missing canonical node|another operator"):
        import_jsonld(target, attacked)
    assert not target.path.exists()
