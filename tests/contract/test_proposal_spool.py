from __future__ import annotations

import json
from copy import deepcopy

import pytest

from imprint.capture.detector import FeedbackDetection
from imprint.cli import main
from imprint.derive.proposals import route_capture_to_proposal
from imprint.derive.spool import ProposalSpoolWriter, compile_pending_proposals
from imprint.errors import ConflictError, ValidationError
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.ontology.schema import make_urn
from imprint.store import ImprintStore


def _proposal(envelope):
    return route_capture_to_proposal(
        envelope,
        FeedbackDetection(True, "correction", "correct", "explicit", 1.0),
    )


def _successor(envelope, proposal):
    operator_id = envelope["operator_id"]
    return {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": make_urn("principle"),
        "node_type": "Principle",
        "operator_id": operator_id,
        "payload": {"statement": "Report material source failures explicitly."},
        "provenance": {
            "status": "ratified", "authority_tier": "ratified_knowledge",
            "actor_class": "operator", "actor_id": operator_id,
            "mechanism": "explicit_proposal_successor",
            "evidence_ids": list(proposal["references"]["evidence_ids"]),
            "model": None, "ratifier_id": operator_id,
        },
    }


def _compiled_proposal(root, store, envelope):
    store.apply_capture(envelope)
    proposal = _proposal(envelope)
    ProposalSpoolWriter(root).submit_proposal(proposal)
    assert compile_pending_proposals(root, store)["applied"] == 1
    return proposal


def test_immutable_spool_and_canonical_writer_are_idempotent(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db", expected_operator_id=capture_envelope["operator_id"])
    store.initialize()
    store.apply_capture(capture_envelope)
    proposal = _proposal(capture_envelope)
    writer = ProposalSpoolWriter(root)

    assert writer.submit_proposal(proposal) == proposal["proposal_id"]
    assert writer.submit_proposal(proposal) == proposal["proposal_id"]
    pending = list((root / "proposal-spool" / "pending").glob("*.json"))
    assert len(pending) == 1
    altered = deepcopy(proposal)
    altered["payload"]["call_type"] = "prefer"
    with pytest.raises(ConflictError):
        writer.submit_proposal(altered)

    first = compile_pending_proposals(root, store)
    assert first == {"applied": 1, "duplicates": 0, "rejected": 0, "skipped": 0, "failures": []}
    second = compile_pending_proposals(root, store)
    assert second == {"applied": 0, "duplicates": 0, "rejected": 0, "skipped": 1, "failures": []}
    node = store.current_nodes(["Proposal"])[0]
    assert node["node_id"] == proposal["proposal_id"]
    assert node["provenance_status"] == "extracted"
    assert node["authority_tier"] == "observed_candidate"
    assert node["provenance"]["proposal_id"] == proposal["proposal_id"]
    assert node["evidence"] == proposal["references"]["evidence_ids"]
    with pytest.raises(ValidationError, match="cannot be ratified"):
        store.ratify_node(node["node_id"], ratifier=capture_envelope["operator_id"])


def test_writer_rejects_cross_event_references_and_records_content_free_failure(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    proposal = _proposal(capture_envelope)
    proposal["references"]["case_id"] = "urn:imprint:case:00000000-0000-4000-8000-000000000001"
    ProposalSpoolWriter(root).submit_proposal(proposal)

    result = compile_pending_proposals(root, store)
    assert result["rejected"] == 1
    assert result["failures"][0]["error_type"] == "ValidationError"
    assert store.current_nodes(["Proposal"]) == []
    receipt = json.loads(next((root / "proposal-spool" / "receipts").glob("*.json")).read_text())
    assert receipt["status"] == "rejected"
    assert "payload" not in receipt and "evidence" not in receipt


def test_cli_submit_and_derive_pending(tmp_path, capsys, capture_envelope):
    data = tmp_path / "data"
    root = data / "test-operator"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "operator_slug": "test-operator", "data_root": str(data),
        "node_id": capture_envelope["node_id"], "compiler": True,
    }))
    identity = root / "identity.json"
    identity.parent.mkdir(parents=True)
    identity.write_text(json.dumps({"identity_schema_version": "1.0.0", "operator_id": capture_envelope["operator_id"]}))
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(json.dumps(_proposal(capture_envelope)))

    assert main(["--config", str(config), "derive", "--submit", str(proposal_path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "queued"
    assert main(["--config", str(config), "derive", "--pending"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok" and result["applied"] == 1


def test_cli_reference_derives_from_a_capture_without_a_model(tmp_path, capsys, capture_envelope):
    data = tmp_path / "data"
    root = data / "test-operator"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "operator_slug": "test-operator", "data_root": str(data),
        "node_id": capture_envelope["node_id"], "compiler": True,
    }))
    root.mkdir(parents=True)
    (root / "identity.json").write_text(json.dumps({
        "identity_schema_version": "1.0.0",
        "operator_id": capture_envelope["operator_id"],
    }))
    capture_path = tmp_path / "capture.json"
    capture_path.write_text(json.dumps(capture_envelope))
    assert main(["--config", str(config), "derive", "--capture", str(capture_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "queued"
    assert result["producer"] == "imprint-reference-deriver"
    assert len(list((root / "proposal-spool" / "pending").glob("*.json"))) == 1


def test_proposal_successor_is_atomic_typed_evidenced_and_replay_safe(
    tmp_path, capture_envelope, signed_store,
):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    proposal = _compiled_proposal(root, store, capture_envelope)
    successor = _successor(capture_envelope, proposal)
    kwargs = {
        "successor_contract": successor,
        "operator_id": capture_envelope["operator_id"],
        "valid_from": "2026-07-16T12:00:00Z",
        "reason": "The operator accepts this exact evidenced principle.",
    }
    token = authority.token_for(
        store.authorize_proposal_successor, proposal["proposal_id"], **kwargs,
    )
    created = store.authorize_proposal_successor(
        proposal["proposal_id"], **kwargs, approval_token=token,
    )
    assert created["status"] == "authorized"
    replay = store.authorize_proposal_successor(
        proposal["proposal_id"], **kwargs, approval_token=token,
    )
    assert replay == {**created, "status": "duplicate"}
    proposal_node = next(node for node in store.current_nodes() if node["node_id"] == proposal["proposal_id"])
    successor_node = next(node for node in store.current_nodes() if node["node_id"] == successor["node_id"])
    assert proposal_node["node_type"] == "Proposal"
    assert proposal_node["provenance_status"] == "extracted"
    assert successor_node["node_type"] == "Principle"
    assert successor_node["provenance_status"] == "ratified"
    edge = next(edge for edge in store.current_edges() if edge["edge_type"] == "proposal_succeeded_by")
    assert (edge["source_id"], edge["target_id"]) == (
        proposal["proposal_id"], successor["node_id"],
    )
    assert edge["evidence"] == proposal["references"]["evidence_ids"]
    assert store.node_history(proposal["proposal_id"])["dispositions"][-1]["event_type"] == "proposal_succeeded"
    with pytest.raises(ConflictError, match="different authorized successor"):
        store.authorize_proposal_successor(
            proposal["proposal_id"], **{**kwargs, "reason": "Different reason"},
        )


def test_proposal_successor_rolls_back_node_relation_disposition_and_token(
    tmp_path, capture_envelope, signed_store, monkeypatch,
):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    proposal = _compiled_proposal(root, store, capture_envelope)
    successor = _successor(capture_envelope, proposal)
    kwargs = {
        "successor_contract": successor,
        "operator_id": capture_envelope["operator_id"],
        "valid_from": "2026-07-16T12:00:00Z",
        "reason": "Approve only if the entire successor transaction commits.",
    }
    token = authority.token_for(
        store.authorize_proposal_successor, proposal["proposal_id"], **kwargs,
    )
    with monkeypatch.context() as scoped:
        def fail_edge_version(cls, conn, values):
            raise RuntimeError("synthetic edge-version failure")
        scoped.setattr(ImprintStore, "_insert_edge_version", classmethod(fail_edge_version))
        with pytest.raises(RuntimeError, match="synthetic edge-version failure"):
            store.authorize_proposal_successor(
                proposal["proposal_id"], **kwargs, approval_token=token,
            )
    assert successor["node_id"] not in {node["node_id"] for node in store.current_nodes()}
    assert not any(edge["edge_type"] == "proposal_succeeded_by" for edge in store.current_edges())
    assert store.node_history(proposal["proposal_id"])["dispositions"] == []
    # Authority consumption rolled back too; the exact same token can commit.
    assert store.authorize_proposal_successor(
        proposal["proposal_id"], **kwargs, approval_token=token,
    )["status"] == "authorized"


def test_cli_authorizes_typed_successor_without_ratifying_proposal_in_place(
    tmp_path, capsys, capture_envelope, signed_store, signed_cli,
):
    data = tmp_path / "data"
    root = data / "test-operator"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "operator_slug": "test-operator", "data_root": str(data),
        "node_id": capture_envelope["node_id"], "compiler": True,
    }))
    root.mkdir(parents=True)
    (root / "identity.json").write_text(json.dumps({
        "identity_schema_version": "1.0.0",
        "operator_id": capture_envelope["operator_id"],
    }))
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    proposal = _compiled_proposal(root, authority.store, capture_envelope)
    successor = _successor(capture_envelope, proposal)
    successor_path = tmp_path / "successor.json"
    successor_path.write_text(json.dumps(successor))
    argv = [
        "--config", str(config), "review", "authorize-successor",
        proposal["proposal_id"], "--input", str(successor_path),
        "--valid-from", "2026-07-16T12:00:00Z",
        "--reason", "Operator authorizes this exact typed successor.",
        "--by", capture_envelope["operator_id"],
    ]
    assert signed_cli(main, argv, capsys, authority) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "authorized"
    assert authority.store.current_nodes(["Proposal"])[0]["provenance_status"] == "extracted"
