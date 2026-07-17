from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from imprint.retrieve import (
    BUSINESS_DECLARED_PARTITION,
    BUSINESS_OBSERVED_PARTITION,
    SELF_MODEL_PARTITION,
    DeliveryReceipts,
    RetrievalConfig,
    RetrievalEngine,
    RetrievalRecord,
    retrieve_payload,
    commit_payload_delivery,
)
from imprint.store import ImprintStore
from imprint.retrieve.tokenizer import lexical_score, tokenize


class Source:
    def __init__(self, records):
        self.records = records

    def retrieval_candidates(self, snapshot_id):
        assert snapshot_id
        return tuple(self.records)


def record(record_id, text="value", **changes):
    values = dict(
        record_id=record_id,
        text=text,
        section="general",
        provenance_status="captured",
        authority_tier="captured_judgment",
        evidence_ids=(f"e-{record_id}",),
        case_ids=(f"case-{record_id}",),
        provenance_complete=True,
    )
    values.update(changes)
    return RetrievalRecord(**values)


def test_default_and_lower_budget_never_split_records():
    records = [record(f"r-{i:03}", "x" * 5000) for i in range(20)]
    default = RetrievalEngine(Source(records)).retrieve(snapshot_id="s")
    lower = RetrievalEngine(Source(records), RetrievalConfig(total_budget_bytes=10 * 1024)).retrieve(snapshot_id="s")
    assert default.selected_bytes <= 32 * 1024
    assert lower.selected_bytes <= 10 * 1024
    assert all(line.endswith(b"}\n") for line in default.payload.splitlines(keepends=True))
    for line in lower.payload.splitlines():
        json.loads(line)


def test_higher_budget_requires_explicit_bounded_setting():
    with pytest.raises(ValueError, match="explicit"):
        RetrievalEngine(Source([]), RetrievalConfig(total_budget_bytes=40 * 1024))
    RetrievalEngine(Source([]), RetrievalConfig(total_budget_bytes=40 * 1024, allow_higher_budget=True))
    with pytest.raises(ValueError, match="hard bound"):
        RetrievalEngine(Source([]), RetrievalConfig(total_budget_bytes=129 * 1024, allow_higher_budget=True))


@pytest.mark.parametrize(
    "change",
    [
        {"provenance_status": "inferred", "authority_tier": "inferred_candidate"},
        {"provenance_status": "captured", "authority_tier": "observed_candidate"},
        {"rejected": True},
        {"tombstoned": True},
        {"valid_until": "2026-01-01T00:00:00Z"},
        {"provenance_complete": False},
        {"evidence_ids": ()},
        {"case_ids": ()},
        {"authority_tier": "imported_floor", "imported_selected": False},
    ],
)
def test_ineligible_provenance_is_excluded(change):
    result = RetrievalEngine(Source([record("bad", **change)])).retrieve(snapshot_id="s")
    assert result.payload == b""


def test_floor_is_labeled_and_cannot_outrank_binding_authority():
    floor = record(
        "a-floor",
        authority_tier="imported_floor",
        provenance_status="extracted",
        imported_selected=True,
        pinned=True,
    )
    binding = record("z-binding", pinned=True)
    result = RetrievalEngine(Source([floor, binding])).retrieve(snapshot_id="s")
    lines = [json.loads(line) for line in result.payload.splitlines()]
    assert [line["record_id"] for line in lines] == ["z-binding", "a-floor"]
    assert lines[1]["authority"] == "imported_floor"


def test_domain_bound_record_cannot_escape_or_cross_domains():
    records = [
        record("good", section="domain", domain_id="alpha"),
        record("wrong", section="domain", domain_id="beta"),
        record("escape", section="general", domain_id="alpha"),
    ]
    result = RetrievalEngine(Source(records)).retrieve(snapshot_id="s", selected_domain="alpha")
    assert result.selected_ids == ("good",)


def test_rank_and_tokenizer_are_repeatable_and_versioned():
    records = [
        record("b", "Cafe launch", recurrence_count=2, valid_from="2026-01-02T00:00:00Z"),
        record("a", "Café launch", recurrence_count=2, valid_from="2026-01-02T00:00:00Z"),
    ]
    engine = RetrievalEngine(Source(records))
    first = engine.retrieve(snapshot_id="s", query="CAFÉ")
    assert first.payload == engine.retrieve(snapshot_id="s", query="CAFÉ").payload
    assert first.selected_ids == ("a", "b")
    assert tokenize("Café") == ("cafe",)
    assert lexical_score("café", "CAFE") == 1
    with pytest.raises(ValueError, match="unsupported"):
        tokenize("x", version="lexical-v2")


def test_session_and_domain_receipts_are_once_under_race(tmp_path):
    receipts = DeliveryReceipts(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(lambda _: receipts.claim_session_start("session-1", "snapshot"), range(20)))
    assert claims.count(True) == 1
    assert receipts.claim_domain("session-1", "snapshot", "domain-a") is True
    assert receipts.claim_domain("session-1", "snapshot", "domain-a") is False
    assert receipts.claim_domain("session-1", "snapshot-2", "domain-a") is True


def test_invalid_retrieval_does_not_consume_once_receipt(tmp_path):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    with pytest.raises(ValueError, match="hard bound"):
        retrieve_payload(store, root=root, session_id="same", budget=200_000)
    assert not (root / "receipts").exists()
    assert retrieve_payload(store, root=root, session_id="same", budget=32_768)["status"] == "delivered"


def test_delivered_latch_short_circuits_before_canonical_node_materialization(
    tmp_path, monkeypatch,
):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    monkeypatch.setattr(
        store, "snapshot",
        lambda: (_ for _ in ()).throw(AssertionError("full snapshot must never be read")),
    )
    first = retrieve_payload(store, root=root, session_id="same")
    assert commit_payload_delivery(
        root=root, session_id="same", snapshot_id=str(first["snapshot_id"]),
    )
    monkeypatch.setattr(
        store, "current_nodes",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("delivered latch must precede node reads")
        ),
    )
    monkeypatch.setattr(
        store, "current_edges",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("delivered latch must precede edge reads")
        ),
    )

    repeated = retrieve_payload(store, root=root, session_id="same")
    assert repeated["status"] == "already_delivered"
    assert repeated["snapshot_id"] == first["snapshot_id"]


def test_retrieval_renders_explicit_ontology_metadata_with_compatible_defaults():
    result = RetrievalEngine(Source([record("legacy")])).retrieve(snapshot_id="s")
    value = json.loads(result.payload)
    assert value["ontology"] == {
        "confidence": None,
        "disclosure": "authority_unclassified",
        "partition": "judgment",
        "path": [],
        "type": "LegacyRecord",
    }
    assert result.selected_by_partition == {"judgment": ("legacy",)}


def test_compact_format_prioritizes_judgment_and_case_over_graph_boilerplate():
    item = record(
        "r-compact",
        "Never omit a failed source.",
        case_referents=("Reviewing a multi-source synthesis",),
        ontology_type="Verdict",
    )
    result = RetrievalEngine(
        Source([item]), RetrievalConfig(output_format="compact")
    ).retrieve(snapshot_id="s")

    assert result.payload.decode("utf-8") == (
        "- Verdict (captured): Never omit a failed source. | "
        "Case: Reviewing a multi-source synthesis\n"
    )
    assert b"urn:" not in result.payload
    assert result.selected_bytes == len(result.payload)


def test_invalid_output_format_is_rejected():
    with pytest.raises(ValueError, match="output format"):
        RetrievalEngine(Source([]), RetrievalConfig(output_format="xml"))


def test_authoritative_self_model_requires_operator_ratification():
    proposed = record(
        "proposed-self",
        provenance_status="inferred",
        authority_tier="inferred_candidate",
        case_ids=(),
        ontology_partition=SELF_MODEL_PARTITION,
        ontology_type="SelfModelAssertion",
        disclosure="model_inference_not_operator_authority",
    )
    ratified = record(
        "ratified-self",
        provenance_status="ratified",
        authority_tier="ratified_knowledge",
        case_ids=(),
        ontology_partition=SELF_MODEL_PARTITION,
        ontology_type="SelfModelAssertion",
        ontology_path=("operator", "self_model", "Identity"),
        confidence=0.84,
        disclosure="operator_ratified",
    )
    result = RetrievalEngine(Source([proposed, ratified])).retrieve(
        snapshot_id="s", ontology_partitions=(SELF_MODEL_PARTITION,)
    )
    assert result.selected_ids == ("ratified-self",)
    assert json.loads(result.payload)["ontology"]["confidence"] == 0.84


def test_inference_requires_analytical_mode_and_an_explicit_partition():
    candidate = record(
        "candidate",
        provenance_status="inferred",
        authority_tier="inferred_candidate",
        case_ids=(),
        ontology_partition=SELF_MODEL_PARTITION,
        ontology_type="SelfModelAssertion",
        ontology_path=("operator", "self_model", "extension:working_hypothesis"),
        disclosure="model_inference_not_operator_authority",
    )
    authoritative = RetrievalEngine(Source([candidate])).retrieve(
        snapshot_id="s", ontology_partitions=(SELF_MODEL_PARTITION,)
    )
    assert authoritative.selected_ids == ()
    analytical_engine = RetrievalEngine(
        Source([candidate]), RetrievalConfig(authority_mode="analytical")
    )
    with pytest.raises(ValueError, match="explicit ontology partitions"):
        analytical_engine.retrieve(snapshot_id="s")
    with pytest.raises(ValueError, match="explicit ontology partitions"):
        analytical_engine.retrieve(snapshot_id="s", ontology_partitions=())
    analytical = analytical_engine.retrieve(
        snapshot_id="s", ontology_partitions=(SELF_MODEL_PARTITION,)
    )
    assert analytical.selected_ids == ("candidate",)
    assert analytical.selected_by_partition == {SELF_MODEL_PARTITION: ("candidate",)}
    assert json.loads(analytical.payload)["ontology"]["disclosure"] == "model_inference_not_operator_authority"


def test_declared_and_observed_business_records_remain_labelled():
    declared = record(
        "promise",
        case_ids=(),
        ontology_partition=BUSINESS_DECLARED_PARTITION,
        ontology_type="Promise",
        ontology_path=("business_world", "declared", "Promise"),
        disclosure="operator_captured",
    )
    observed = record(
        "result",
        provenance_status="ratified",
        authority_tier="ratified_knowledge",
        case_ids=(),
        ontology_partition=BUSINESS_OBSERVED_PARTITION,
        ontology_type="Result",
        ontology_path=("business_world", "observed", "Result"),
        disclosure="operator_ratified",
    )
    result = RetrievalEngine(Source([declared, observed])).retrieve(
        snapshot_id="s",
        ontology_partitions=(BUSINESS_DECLARED_PARTITION, BUSINESS_OBSERVED_PARTITION),
    )
    rendered = [json.loads(line)["ontology"] for line in result.payload.splitlines()]
    assert {item["partition"] for item in rendered} == {
        BUSINESS_DECLARED_PARTITION, BUSINESS_OBSERVED_PARTITION,
    }
    assert result.selected_by_partition == {
        BUSINESS_DECLARED_PARTITION: ("promise",),
        BUSINESS_OBSERVED_PARTITION: ("result",),
    }
