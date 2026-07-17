from __future__ import annotations

import json

import pytest

from imprint.errors import ConflictError, ValidationError
from imprint.ingest import IngestCandidate, IngestService, import_legacy_principles
from imprint.retrieve import RetrievalEngine, StoreRetrievalSource
from imprint.store import ImprintStore


def candidate(**changes):
    values = {
        "source_kind": "memory_export",
        "source_locator": "synthetic://memory/1",
        "content": "Always disclose missing evidence.",
        "metadata": {"created": "2026-01-01"},
        "extensions": {"org.example.source": {"schema_version": "1.0.0", "payload": {"rank": 7}}},
    }
    values.update(changes)
    return IngestCandidate(**values)


def test_scan_is_idempotent_and_starts_unruled_without_authority(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    service = IngestService(store, capture_envelope["operator_id"])
    first = service.scan([candidate()])
    second = service.scan([candidate()])
    assert first == second
    assert first[0]["status"] == "unruled"
    assert store.current_nodes() == []
    assert service.list(status="unruled")[0]["payload"]["extensions"]["org.example.source"]["payload"]["rank"] == 7


def test_same_source_identity_with_changed_metadata_fails(tmp_path, capture_envelope):
    service = IngestService(ImprintStore(tmp_path / "imprint.db"), capture_envelope["operator_id"])
    service.scan([candidate()])
    with pytest.raises(ConflictError):
        service.scan([candidate(metadata={"created": "changed"})])


def test_keep_requires_why_and_never_creates_captured_authority(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    service = IngestService(store, capture_envelope["operator_id"])
    item_id = service.scan([candidate()])[0]["item_id"]
    with pytest.raises(ValidationError):
        service.keep(item_id, why="  ")
    ruling_id = service.keep(item_id, why="Useful historical context, not witnessed judgment")
    assert service.keep(item_id, why="Useful historical context, not witnessed judgment") == ruling_id
    nodes = store.current_nodes()
    assert [(node["node_type"], node["authority_tier"], node["provenance_status"]) for node in nodes] == [
        ("IngestedItem", "imported_floor", "extracted")
    ]
    assert not ({"Case", "Verdict", "Call"} & {node["node_type"] for node in nodes})
    with store.connect() as conn:
        ruling = dict(conn.execute("SELECT * FROM ingest_rulings").fetchone())
        source = dict(conn.execute("SELECT * FROM source_receipts").fetchone())
    assert ruling["verdict"] == "KEEP"
    assert ruling["why"] == "Useful historical context, not witnessed judgment"
    assert source["locator"] == "synthetic://memory/1"
    retrieved = RetrievalEngine(StoreRetrievalSource(store)).retrieve(snapshot_id="after-keep")
    lines = [json.loads(line) for line in retrieved.payload.splitlines()]
    assert len(lines) == 1
    assert lines[0]["authority"] == "imported_floor"
    assert lines[0]["text"] == "Always disclose missing evidence."
    assert lines[0]["source_receipt_ids"] == [source["source_id"]]


def test_ingested_item_cannot_be_ratified_as_ontology_authority(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    service = IngestService(store, capture_envelope["operator_id"])
    item_id = service.scan([candidate()])[0]["item_id"]
    service.keep(item_id, why="Useful historical context, not witnessed judgment")
    node_id = store.current_nodes(["IngestedItem"])[0]["node_id"]
    with pytest.raises(ValidationError, match="cannot be ratified"):
        store.ratify_node(node_id, ratifier=capture_envelope["operator_id"])
    assert store.current_nodes(["IngestedItem"])[0]["authority_tier"] == "imported_floor"


def test_kill_is_recorded_and_creates_no_node(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    service = IngestService(store, capture_envelope["operator_id"])
    item_id = service.scan([candidate()])[0]["item_id"]
    ruling_id = service.kill(item_id, why="Contradicted by current operating evidence")
    assert service.kill(item_id, why="Contradicted by current operating evidence") == ruling_id
    with pytest.raises(ConflictError):
        service.kill(item_id, why="different reason")
    assert store.current_nodes() == []
    assert service.list(status="killed")[0]["item_id"] == item_id
    with pytest.raises(ConflictError):
        service.keep(item_id, why="changed mind")


def test_legacy_principles_remain_principles_without_fabricated_ontology(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    ids = import_legacy_principles(
        store,
        [{"text": "Preserve the exact original sentence."}],
        operator_id=capture_envelope["operator_id"],
        source_version="2.0",
        source_locator="synthetic://v2/principles.json",
    )
    assert len(ids) == 1
    nodes = store.current_nodes()
    assert [node["node_type"] for node in nodes] == ["Principle"]
    assert nodes[0]["payload"]["text"] == "Preserve the exact original sentence."
    assert nodes[0]["payload"]["imported_selected"] is True
    assert nodes[0]["authority_tier"] == "imported_floor"
    with store.connect() as conn:
        receipt = dict(conn.execute("SELECT * FROM source_receipts").fetchone())
    assert receipt["locator"] == "synthetic://v2/principles.json"
    retrieved = RetrievalEngine(StoreRetrievalSource(store)).retrieve(snapshot_id="legacy-import")
    assert "Preserve the exact original sentence." in retrieved.payload.decode()
    assert '"authority":"imported_floor"' in retrieved.payload.decode()


def test_legacy_unknown_fields_fail_closed(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    with pytest.raises(ValidationError):
        import_legacy_principles(
            store, [{"text": "x", "invent_case": True}],
            operator_id=capture_envelope["operator_id"], source_version="2",
            source_locator="synthetic://legacy",
        )
    assert store.current_nodes() == []
