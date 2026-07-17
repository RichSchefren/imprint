from __future__ import annotations

from contextlib import contextmanager

from imprint.retrieve import (
    BUSINESS_DECLARED_PARTITION,
    BUSINESS_OBSERVED_PARTITION,
    SELF_MODEL_PARTITION,
    RetrievalConfig,
    RetrievalEngine,
    StoreRetrievalSource,
)


EVIDENCE_ID = "urn:imprint:evidence:00000000-0000-4000-8000-000000000001"


def node(node_id, node_type, payload, status, authority):
    return {
        "node_id": node_id,
        "node_type": node_type,
        "payload": payload,
        "evidence": [EVIDENCE_ID],
        "provenance_status": status,
        "authority_tier": authority,
        "valid_from": "2026-07-14T20:00:00Z",
        "valid_to": None,
    }


class EmptyConnection:
    def execute(self, statement):
        assert "source_receipts" in statement
        return ()


class SemanticStore:
    def current_nodes(self):
        return [
            {"node_id": EVIDENCE_ID, "node_type": "Evidence"},
            node(
                "self", "SelfModelAssertion",
                {
                    "statement": "I protect quality under deadline pressure.",
                    "function_class": "example.self-model", "subtype": "example.profile-element",
                    "dimension": "example.standard", "confidence": {"score": 0.91},
                },
                "ratified", "ratified_knowledge",
            ),
            node(
                "promise", "Promise",
                {"evidence_mode": "declared", "statement": "Judgment remains inspectable."},
                "captured", "captured_judgment",
            ),
            node(
                "result", "Result",
                {"evidence_mode": "observed", "metric": "retained verdicts", "value": 25, "unit": "count"},
                "extracted", "observed_candidate",
            ),
        ]

    def current_edges(self):
        return []

    @contextmanager
    def connect(self):
        yield EmptyConnection()


def test_store_source_projects_semantic_partition_type_path_confidence_and_disclosure():
    records = {
        item.record_id: item
        for item in StoreRetrievalSource(SemanticStore()).retrieval_candidates("snapshot")
    }
    assert records["self"].ontology_partition == SELF_MODEL_PARTITION
    assert records["self"].ontology_path == (
        "operator", "self_model", "example.self-model", "example.profile-element", "example.standard",
    )
    assert records["self"].confidence == 0.91
    assert records["self"].disclosure == "operator_ratified"
    assert records["promise"].ontology_partition == BUSINESS_DECLARED_PARTITION
    assert records["result"].ontology_partition == BUSINESS_OBSERVED_PARTITION


def test_store_source_authority_modes_keep_theory_observation_and_prediction_distinct():
    source = StoreRetrievalSource(SemanticStore())
    authoritative = RetrievalEngine(source).retrieve(
        snapshot_id="snapshot",
        ontology_partitions=(
            SELF_MODEL_PARTITION,
            BUSINESS_DECLARED_PARTITION,
            BUSINESS_OBSERVED_PARTITION,
        ),
    )
    assert set(authoritative.selected_ids) == {"self", "promise"}
    assert "result" not in authoritative.selected_ids

    analytical = RetrievalEngine(
        source, RetrievalConfig(authority_mode="analytical")
    ).retrieve(
        snapshot_id="snapshot",
        ontology_partitions=(BUSINESS_OBSERVED_PARTITION,),
    )
    assert analytical.selected_ids == ("result",)
    assert analytical.selected_by_partition == {
        BUSINESS_OBSERVED_PARTITION: ("result",)
    }
