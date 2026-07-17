from __future__ import annotations

import json
from pathlib import Path

import pytest

from imprint.backup import create_backup, verify_backup
from imprint.errors import SafetyError, ValidationError
from imprint.lifecycle import review_show
from imprint.ontology.schema import make_urn
from imprint.purge import hard_purge, preview_purge
from imprint.store import ImprintStore


def test_captured_judgment_cannot_be_disposed_through_proposal_review(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    verdict_id = capture_envelope["verdict"]["verdict_id"]
    with pytest.raises(ValidationError, match="not awaiting review"):
        review_show(store, verdict_id)
    with pytest.raises(ValidationError, match="only inferred or extracted"):
        store.reject_node(verdict_id, rejector="model", reason="attempted authority laundering")
    assert store.current_nodes(["Verdict"])[0]["provenance_status"] == "captured"


def test_failed_later_reason_attempt_is_atomic(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db", expected_operator_id=capture_envelope["operator_id"])
    store.initialize()
    store.apply_capture(capture_envelope)
    verdict_id = capture_envelope["verdict"]["verdict_id"]
    with store.connect() as conn:
        before = {
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "nodes": conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
            "versions": conn.execute("SELECT COUNT(*) FROM node_versions").fetchone()[0],
        }
    with pytest.raises(ValidationError, match="already has a reason"):
        store.add_reason(verdict_id, reason="replace original", actor_id=capture_envelope["operator_id"])
    with store.connect() as conn:
        after = {
            "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "nodes": conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
            "versions": conn.execute("SELECT COUNT(*) FROM node_versions").fetchone()[0],
        }
    assert after == before


def test_backup_receipt_schema_tampering_is_detected(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    backup = create_backup(store, root)
    receipt_path = Path(backup["receipt_path"])
    receipt = json.loads(receipt_path.read_text())
    receipt["store_schema_version"] = "999.0.0"
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValidationError, match="schema does not match"):
        verify_backup(Path(backup["path"]))


def test_purge_unknown_scope_and_substring_scope_do_not_delete_anything(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    with pytest.raises(ValidationError, match="existing node, operator, session, or source"):
        preview_purge(store, root, "urn:imprint:verdict:%")
    with pytest.raises(SafetyError, match="exactly name"):
        hard_purge(store, root, capture_envelope["verdict"]["verdict_id"], confirmation="urn:imprint:verdict:%")
    assert len(store.current_nodes()) == 4


def test_postcommit_residue_is_reported_as_committed_failure(tmp_path, capture_envelope, monkeypatch, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    monkeypatch.setattr("imprint.purge._scan_active_root", lambda _root, _markers: ["projections/stuck.txt"])
    scope = capture_envelope["verdict"]["verdict_id"]
    result = authority.call(hard_purge, store, root, scope, confirmation=scope)
    assert result["status"] == "purged_with_residue"
    assert result["committed"] is True
    assert result["active_root_scan"] == "residue"
    assert result["residue_locations"] == ["projections/stuck.txt"]
    assert store.current_nodes() == []


def test_blank_review_and_evidence_actors_are_rejected(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    node_id = store.append_derived_node(
        node_type="Principle", payload={"statement": "x"}, provenance_status="inferred",
        authority_tier="inferred_candidate", evidence_ids=[evidence_id],
        operator_id=capture_envelope["operator_id"], valid_from="2026-07-14T18:00:00Z", proposed_by="agent",
    )
    with pytest.raises(ValidationError, match="rejector"):
        store.reject_node(node_id, rejector="", reason="no")
    with pytest.raises(ValidationError, match="reason and actor"):
        store.add_reason(node_id, reason="why", actor_id="")
