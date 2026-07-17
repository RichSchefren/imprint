from __future__ import annotations

import pytest

from imprint.errors import ValidationError
from imprint.ontology.schema import make_urn
from imprint.store import ImprintStore


def test_domain_and_transition_inputs_fail_closed_without_partial_writes(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    operator_id = capture_envelope["operator_id"]

    with pytest.raises(ValidationError, match="safe lowercase"):
        store.add_domain(
            domain_id="../Research", public_label="Research", description="bad id",
            evidence_ids=[evidence_id], operator_id=operator_id, actor_id=operator_id,
        )
    with pytest.raises(ValidationError, match="evidence must exist"):
        store.add_domain(
            domain_id="research", public_label="Research", description="bad evidence",
            evidence_ids=[make_urn("evidence")], operator_id=operator_id, actor_id=operator_id,
        )
    assert store.current_nodes(["Domain"]) == []

    principle = store.append_derived_node(
        node_type="Principle", payload={"statement": "Principle"}, provenance_status="inferred",
        authority_tier="inferred_candidate", evidence_ids=[evidence_id], operator_id=operator_id,
        valid_from="2026-07-14T12:00:00Z", proposed_by="test",
    )
    verdict = store.current_nodes(["Verdict"])[0]["node_id"]
    before_nodes = store.current_nodes()
    before_edges = store.current_edges()
    with pytest.raises(ValidationError, match="same node type"):
        store.add_transition(
            "supersedes", principle, verdict, reason="invalid cross-type transition",
            evidence_ids=[evidence_id], actor_id=operator_id,
        )
    assert store.current_nodes() == before_nodes
    assert store.current_edges() == before_edges

    with pytest.raises(ValidationError, match="canonical evidence"):
        store.add_transition(
            "contradicts", principle, verdict, reason="missing evidence",
            evidence_ids=[], actor_id=operator_id,
        )
