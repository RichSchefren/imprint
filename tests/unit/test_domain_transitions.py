from __future__ import annotations

import json

import pytest

from imprint.authority.challenge import canonical_bytes
from imprint.errors import ConflictError, ValidationError
from imprint.retrieve.store_source import StoreRetrievalSource
from imprint.store import ImprintStore


def _captured(store, capture_envelope):
    store.apply_capture(capture_envelope)
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    return evidence_id, capture_envelope["operator_id"]


def _principle(authority, evidence_id, operator_id, statement):
    store = authority.store
    node_id = store.append_derived_node(
        node_type="Principle", payload={"statement": statement},
        provenance_status="inferred", authority_tier="inferred_candidate",
        evidence_ids=[evidence_id], operator_id=operator_id,
        valid_from="2026-07-14T12:00:00Z", proposed_by="unit-test",
    )
    authority.call(store.ratify_node, node_id, ratifier=operator_id, note="explicitly confirmed")
    return node_id


def test_domain_lifecycle_is_canonical_provenanced_and_versioned(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    evidence_id, operator_id = _captured(store, capture_envelope)

    node_id = authority.call(store.add_domain,
        domain_id="research", public_label="Research", description="Source-grounded research work",
        evidence_ids=[evidence_id], operator_id=operator_id, actor_id=operator_id,
        valid_from="2026-07-14T12:30:00Z",
    )
    assert node_id == store._domain_node_id(operator_id, "research")
    with pytest.raises(ConflictError, match="already exists"):
        store.add_domain(
            domain_id="research", public_label="Research", description="duplicate",
            evidence_ids=[evidence_id], operator_id=operator_id, actor_id=operator_id,
        )

    authority.call(store.select_domain, "research", actor_id=operator_id)
    authority.call(store.freeze_domain, "research", actor_id=operator_id)
    domain = store.list_domains()[0]
    assert domain["node_type"] == "Domain"
    assert domain["payload"] == {
        "domain_id": "research", "public_label": "Research",
        "description": "Source-grounded research work", "selected": True, "frozen": True,
    }
    assert domain["evidence"] == [evidence_id]
    assert domain["provenance"]["actor_class"] == "operator"
    assert domain["provenance"]["mechanism"] == "explicit_domain_freeze"
    history = store.node_history(node_id)
    assert len(history["versions"]) == 3
    assert [item["payload"]["frozen"] for item in history["versions"]] == [False, False, True]


def test_nested_domain_version_ids_are_visible_and_tamper_bound(
    tmp_path, capture_envelope, signed_store,
):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    evidence_id, operator_id = _captured(store, capture_envelope)
    authority.call(
        store.add_domain,
        domain_id="research", public_label="Research", description="Exact nested IDs",
        evidence_ids=[evidence_id], operator_id=operator_id, actor_id=operator_id,
        valid_from="2026-07-14T12:30:00Z",
    )

    with pytest.raises(ValidationError, match="E_AUTH_APPROVAL_REQUIRED") as denied:
        store.select_domain("research", actor_id=operator_id)
    request = authority._request(denied.value)
    token = authority.approve_request(request)
    with store.connect() as conn:
        row = conn.execute(
            "SELECT execution_fields_json FROM authority_prepared_mutations WHERE operation_id=?",
            (request.operation_id,),
        ).fetchone()
        execution = json.loads(row["execution_fields_json"])
        generated_version_ids = tuple(execution["version_ids"].values())
        assert generated_version_ids
        assert request.result_version_ids == generated_version_ids

        conn.execute("DROP TRIGGER authority_prepared_content_immutable")
        first_node = next(iter(execution["version_ids"]))
        execution["version_ids"][first_node] = (
            "urn:imprint:node-version:00000000-0000-4000-8000-000000000000"
        )
        conn.execute(
            "UPDATE authority_prepared_mutations SET execution_fields_json=? WHERE operation_id=?",
            (canonical_bytes(execution).decode(), request.operation_id),
        )

    with pytest.raises(ValidationError, match="execution-fields digest"):
        store.select_domain(
            "research", actor_id=operator_id, approval_token=token,
        )
    assert store.list_domains()[0]["payload"]["selected"] is False
    with store.connect() as conn:
        assert conn.execute(
            "SELECT consumed_at FROM authority_challenges WHERE operation_id=?",
            (request.operation_id,),
        ).fetchone()[0] is None


def test_contradiction_preserves_heads_and_supersession_retires_only_prior_head(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    evidence_id, operator_id = _captured(store, capture_envelope)
    prior = _principle(authority, evidence_id, operator_id, "Always soften failure reports")
    replacement = _principle(authority, evidence_id, operator_id, "Report material failures explicitly")

    contradiction = authority.call(store.add_transition,
        "contradicts", prior, replacement, reason="The rules prescribe incompatible reporting",
        evidence_ids=[evidence_id], actor_id=operator_id,
    )
    assert {prior, replacement}.issubset({item["node_id"] for item in store.current_nodes(["Principle"])})
    edge = next(item for item in store.current_edges() if item["edge_id"] == contradiction)
    assert edge["payload"]["reason"] == "The rules prescribe incompatible reporting"
    assert edge["evidence"] == [evidence_id]
    assert edge["provenance"]["relation"] == "contradicts"

    supersession = authority.call(store.add_transition,
        "supersedes", replacement, prior, reason="The newer judgment replaces the older rule",
        evidence_ids=[evidence_id], actor_id=operator_id,
    )
    current_ids = {item["node_id"] for item in store.current_nodes(["Principle"])}
    assert prior not in current_ids and replacement in current_ids
    candidates = {item.record_id for item in StoreRetrievalSource(store).retrieval_candidates("snapshot")}
    assert prior not in candidates and replacement in candidates
    assert next(item for item in store.current_edges() if item["edge_id"] == supersession)["edge_type"] == "supersedes"
    history = store.node_history(prior)
    assert history["versions"][-1]["system_to"] is not None
    assert history["versions"][-1]["valid_to"] is not None
    assert history["dispositions"][-1]["event_type"] == "supersedes"
