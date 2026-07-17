from __future__ import annotations

import copy
import json

import pytest

from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.cli import main
from imprint.errors import ValidationError
from imprint.ontology.schema import make_urn
from imprint.portability import export_jsonld, import_jsonld
from imprint.store import ImprintStore


def _self_model_contract(operator_id: str, evidence_id: str) -> dict:
    model_id = make_urn("model")
    return {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": make_urn("selfmodelassertion"),
        "node_type": "SelfModelAssertion",
        "operator_id": operator_id,
        "payload": {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "operator_id": operator_id,
            "function_class": "example.self-model",
            "dimension": "example.review-signal",
            "subtype": "example.profile-element",
            "statement": "Completion pressure can trigger unnecessary reframing.",
            "polarity": "constraint",
            "scope": "public release work",
            "source_phase": "example.approved-import",
            "derivation_trace_id": make_urn("derivation_trace"),
            "evidence_ids": [evidence_id],
            "confidence": {
                "score": 0.7,
                "assessor_id": "synthetic-model",
                "method": "model_estimate",
                "basis_evidence_ids": [evidence_id],
                "assessed_at": "2026-07-14T12:00:00Z",
                "calibration_trial_id": None,
                "uncertainty_note": "Requires operator review.",
            },
            "freshness": {
                "valid_from": "2026-07-14T12:00:00Z",
                "valid_to": None,
                "last_reviewed_at": None,
                "revalidate_after": "2026-08-14T12:00:00Z",
                "evidence_window_start": "2026-07-01T00:00:00Z",
                "evidence_window_end": "2026-07-14T12:00:00Z",
                "status": "current",
            },
            "review_state": "proposed",
            "structure": {},
            "provenance": {
                "status": "inferred",
                "actor_class": "model",
                "actor_id": model_id,
                "model_id": "synthetic-model",
                "prompt_id": "synthetic-prompt-v1",
            },
            "extensions": {},
        },
        "provenance": {
            "status": "inferred",
            "authority_tier": "inferred_candidate",
            "actor_class": "model",
            "actor_id": model_id,
            "mechanism": "self_model_proposal_import",
            "evidence_ids": [evidence_id],
            "model": "synthetic-model",
            "ratifier_id": None,
        },
    }


def _add_derivation_trace(store: ImprintStore, operator_id: str, evidence_id: str) -> str:
    with store.connect() as conn:
        version_id = conn.execute(
            "SELECT version_id FROM node_versions WHERE node_id=? AND system_to IS NULL",
            (evidence_id,),
        ).fetchone()[0]
    trace_id = make_urn("derivationtrace")
    model_id = make_urn("model")
    store.append_semantic_node({
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": trace_id, "node_type": "DerivationTrace", "operator_id": operator_id,
        "payload": {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "operator_id": operator_id, "element_version_id": version_id,
            "source_phase": "example.approved-import", "derived_from_rule": "synthetic-test-v1",
            "computed_at": "2026-07-14T12:00:00Z", "input_ids": [evidence_id],
            "input_snapshot_sha256": "a" * 64, "model_id": "synthetic-model",
            "prompt_id": "synthetic-prompt-v1", "extensions": {},
        },
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": model_id,
            "mechanism": "synthetic_derivation", "evidence_ids": [evidence_id],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }, valid_from="2026-07-14T12:00:00Z")
    return trace_id


def _setup(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    operator_id = capture_envelope["operator_id"]
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    contract = _self_model_contract(operator_id, evidence_id)
    contract["payload"]["derivation_trace_id"] = _add_derivation_trace(
        store, operator_id, evidence_id,
    )
    store.append_semantic_node(contract, valid_from="2026-07-14T12:00:00Z")
    return authority, operator_id, evidence_id, contract


def test_typed_correction_preserves_proposal_and_creates_validated_ratified_head(
    tmp_path, capture_envelope, signed_store,
):
    authority, operator_id, _, proposal = _setup(tmp_path, capture_envelope, signed_store)
    store = authority.store
    corrected = copy.deepcopy(proposal)
    corrected["payload"]["statement"] = "Completion pressure requires a scope check before reframing."
    corrected["payload"]["review_state"] = "corrected"
    corrected["payload"]["provenance"] = {
        "status": "ratified", "actor_class": "operator", "actor_id": operator_id,
        "model_id": None, "prompt_id": None,
    }
    corrected["provenance"] = {
        "status": "ratified", "authority_tier": "ratified_knowledge",
        "actor_class": "operator", "actor_id": operator_id,
        "mechanism": "explicit_operator_correction",
        "evidence_ids": proposal["provenance"]["evidence_ids"],
        "model": None, "ratifier_id": operator_id,
    }

    laundered = copy.deepcopy(corrected)
    laundered["provenance"].update({
        "actor_class": "model", "actor_id": make_urn("model"),
        "model": "synthetic-model",
    })
    with pytest.raises(ValidationError, match="ratified provenance"):
        store.correct_typed_node(
            proposal["node_id"], corrected_contract=laundered,
            corrector=operator_id, reason="Attempted model authority escalation.",
        )
    assert store.current_nodes(["SelfModelAssertion"])[0]["provenance_status"] == "inferred"

    broken_lineage = copy.deepcopy(corrected)
    broken_lineage["payload"]["derivation_trace_id"] = make_urn("derivationtrace")
    with store.connect() as conn:
        counts_before = tuple(conn.execute(
            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM node_versions)"
        ).fetchone())
    with pytest.raises(ValidationError, match="missing canonical node"):
        store.correct_typed_node(
            proposal["node_id"], corrected_contract=broken_lineage,
            corrector=operator_id, reason="Broken lineage must fail atomically.",
        )
    with store.connect() as conn:
        counts_after = tuple(conn.execute(
            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM node_versions)"
        ).fetchone())
    assert counts_after == counts_before
    assert store.current_nodes(["SelfModelAssertion"])[0]["provenance_status"] == "inferred"

    event_id = authority.call(store.correct_typed_node,
        proposal["node_id"], corrected_contract=corrected,
        corrector=operator_id, reason="The proposal was directionally right but overstated.",
    )

    current = store.current_nodes(["SelfModelAssertion"])[0]
    history = store.node_history(proposal["node_id"])
    assert current["provenance_status"] == "ratified"
    assert current["payload"]["review_state"] == "corrected"
    assert current["payload"]["statement"] == corrected["payload"]["statement"]
    assert len(history["versions"]) == 2
    assert history["dispositions"][0]["event_type"] == "corrected"
    assert history["versions"][0]["payload"]["statement"] == proposal["payload"]["statement"]
    assert history["versions"][1]["prior_version_id"] == history["versions"][0]["version_id"]
    with store.connect() as conn:
        event = conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
    assert event["event_type"] == "corrected" and event["prior_event_id"] is not None


def test_typed_correction_and_contest_require_exact_operator_urn(tmp_path, capture_envelope, signed_store):
    authority, operator_id, _, proposal = _setup(tmp_path, capture_envelope, signed_store)
    store = authority.store
    with pytest.raises(ValidationError, match="operator"):
        store.contest_typed_node(proposal["node_id"], contestor="operator", reason="No")
    with pytest.raises(ValidationError, match="only by its operator"):
        store.contest_typed_node(
            proposal["node_id"], contestor=make_urn("operator"), reason="No",
        )
    event_id = authority.call(store.contest_typed_node,
        proposal["node_id"], contestor=operator_id, reason="This inference is not true.",
    )
    assert store.current_nodes(["SelfModelAssertion"]) == []
    history = store.node_history(proposal["node_id"])
    assert history["versions"][0]["system_to"] is not None
    assert history["dispositions"][0]["event_type"] == "contested"
    with store.connect() as conn:
        event = conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
    assert event["event_type"] == "contested" and event["prior_event_id"] is not None


def _semantic_relation(store, operator_id: str, evidence_id: str) -> str:
    principle_id = make_urn("principle")
    store.append_semantic_node({
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": principle_id, "node_type": "Principle", "operator_id": operator_id,
        "payload": {"statement": "Explicit failures protect decision quality."},
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": make_urn("model"),
            "mechanism": "synthetic_test", "evidence_ids": [evidence_id],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }, valid_from="2026-07-14T12:00:00Z")
    verdict_id = store.current_nodes(["Verdict"])[0]["node_id"]
    relation_id = make_urn("relation")
    store.append_semantic_relation({
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "relation_id": relation_id, "relation_type": "inferred_from",
        "source_id": principle_id, "source_type": "Principle",
        "target_id": verdict_id, "target_type": "Verdict",
        "operator_id": operator_id, "evidence_mode": "inferred",
        "why": "The verdict supplies direct evidence for the candidate principle.",
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": make_urn("model"),
            "mechanism": "synthetic_test", "evidence_ids": [evidence_id],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }, valid_from="2026-07-14T12:00:00Z")
    return relation_id


def test_semantic_edge_review_is_operator_only_append_only_and_no_escalation(
    tmp_path, capture_envelope, signed_store,
):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    operator_id = capture_envelope["operator_id"]
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]

    deferred_id = _semantic_relation(store, operator_id, evidence_id)
    defer_event = authority.call(store.defer_edge,
        deferred_id, reviewer=operator_id, reason="Need another case",
        revisit_after="2026-08-01T00:00:00Z",
    )
    deferred = next(edge for edge in store.current_edges() if edge["edge_id"] == deferred_id)
    assert deferred["provenance_status"] == "inferred"

    ratified_id = _semantic_relation(store, operator_id, evidence_id)
    with pytest.raises(ValidationError, match="operator"):
        store.ratify_edge(ratified_id, ratifier="operator")
    ratify_event = authority.call(store.ratify_edge, ratified_id, ratifier=operator_id, note="Confirmed")
    ratified = next(edge for edge in store.current_edges() if edge["edge_id"] == ratified_id)
    assert ratified["provenance_status"] == "ratified"
    assert ratified["provenance"]["actor_class"] == "operator"
    assert ratified["payload"]["evidence_mode"] == "inferred"
    portable = export_jsonld(store)
    imported = ImprintStore(tmp_path / "ratified-edge-import.db")
    import_jsonld(imported, portable)
    imported_edge = next(edge for edge in imported.current_edges() if edge["edge_id"] == ratified_id)
    assert imported_edge["provenance_status"] == "ratified"
    assert imported_edge["payload"]["evidence_mode"] == "inferred"

    rejected_id = _semantic_relation(store, operator_id, evidence_id)
    reject_event = authority.call(store.reject_edge, rejected_id, rejector=operator_id, reason="Overgeneralized")
    assert rejected_id not in {edge["edge_id"] for edge in store.current_edges()}

    with store.connect() as conn:
        events = {
            row["event_id"]: row["event_type"] for row in conn.execute(
                "SELECT event_id,event_type FROM events WHERE event_id IN (?,?,?)",
                (defer_event, ratify_event, reject_event),
            )
        }
        original_versions = conn.execute(
            "SELECT COUNT(*) FROM edge_versions WHERE edge_id=?", (ratified_id,),
        ).fetchone()[0]
    assert events == {
        defer_event: "edge_deferred",
        ratify_event: "edge_ratified",
        reject_event: "edge_rejected",
    }
    assert original_versions == 2


def test_edge_review_rejects_raw_captured_edges(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    edge_id = store.current_edges()[0]["edge_id"]
    with pytest.raises(ValidationError, match="typed semantic"):
        store.defer_edge(
            edge_id, reviewer=capture_envelope["operator_id"], reason="Not applicable",
        )


def test_closed_review_cli_exposes_typed_node_and_edge_dispositions(
    tmp_path, capsys, capture_envelope, signed_store, signed_cli,
):
    data = tmp_path / "data"
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "operator_slug": "semantic-review-operator",
        "data_root": str(data),
        "compiler": True,
        "experimental": {"digest": False, "profile_learning": False},
    }))
    assert main(["--config", str(config_path), "health"]) in {0, 2}
    capsys.readouterr()
    root = data / "semantic-review-operator"
    operator_id = json.loads((root / "identity.json").read_text())["operator_id"]
    capture_envelope["operator_id"] = operator_id
    store = ImprintStore(root / "imprint.db", expected_operator_id=operator_id)
    store.initialize()
    store.apply_capture(capture_envelope)
    authority = signed_store(root / "imprint.db", operator_id)
    store = authority.store
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]

    proposal = _self_model_contract(operator_id, evidence_id)
    proposal["payload"]["derivation_trace_id"] = _add_derivation_trace(
        store, operator_id, evidence_id,
    )
    store.append_semantic_node(proposal, valid_from="2026-07-14T12:00:00Z")
    corrected = copy.deepcopy(proposal)
    corrected["payload"]["statement"] = "Use a scope check before reframing."
    corrected["payload"]["review_state"] = "corrected"
    corrected["payload"]["provenance"] = {
        "status": "ratified", "actor_class": "operator", "actor_id": operator_id,
        "model_id": None, "prompt_id": None,
    }
    corrected["provenance"] = {
        "status": "ratified", "authority_tier": "ratified_knowledge",
        "actor_class": "operator", "actor_id": operator_id,
        "mechanism": "explicit_operator_correction", "evidence_ids": [evidence_id],
        "model": None, "ratifier_id": operator_id,
    }
    corrected_path = tmp_path / "corrected.json"
    corrected_path.write_text(json.dumps(corrected))
    assert signed_cli(main, [
        "--config", str(config_path), "review", "correct", proposal["node_id"],
        "--by", operator_id, "--reason", "Narrow the scope", "--input", str(corrected_path),
    ], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "corrected"

    contested = _self_model_contract(operator_id, evidence_id)
    contested["payload"]["derivation_trace_id"] = _add_derivation_trace(
        store, operator_id, evidence_id,
    )
    store.append_semantic_node(contested, valid_from="2026-07-14T12:00:00Z")
    assert signed_cli(main, [
        "--config", str(config_path), "review", "contest", contested["node_id"],
        "--by", operator_id, "--reason", "The inference is false",
    ], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "contested"

    actions = (("edge-defer", "edge_deferred"), ("edge-ratify", "edge_ratified"),
               ("edge-reject", "edge_rejected"))
    for command, expected_status in actions:
        relation_id = _semantic_relation(store, operator_id, evidence_id)
        argv = ["--config", str(config_path), "review", command, relation_id, "--by", operator_id]
        argv += ["--note", "Confirmed"] if command == "edge-ratify" else ["--reason", "Reviewed"]
        assert signed_cli(main, argv, capsys, authority) == 0
        assert json.loads(capsys.readouterr().out)["status"] == expected_status
