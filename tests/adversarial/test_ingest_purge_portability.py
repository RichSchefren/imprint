from __future__ import annotations

from copy import deepcopy

import pytest

from imprint.errors import ValidationError
from imprint.ingest import IngestCandidate, IngestService
from imprint.portability import export_jsonld, import_jsonld
from imprint.purge import hard_purge, preview_purge
from imprint.store import ImprintStore


def _candidate(sentinel, session_id=None, node_id=None, suffix="1"):
    scope = {}
    if session_id:
        scope["session_id"] = session_id
    if node_id:
        scope["node_id"] = node_id
    return IngestCandidate(
        source_kind="memory_export",
        source_locator=f"synthetic://purge/{suffix}",
        content=f"{sentinel} imported {suffix}",
        metadata={"imprint_scope": scope},
    )


@pytest.mark.parametrize("status", ["unruled", "killed", "kept"])
def test_source_scope_purges_ingest_item_in_every_ruling_state(tmp_path, capture_envelope, status, signed_store):
    sentinel = f"PRIVATE-INGEST-{status.upper()}"
    root = tmp_path / status
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    service = IngestService(store, capture_envelope["operator_id"])
    item_id = service.scan([_candidate(sentinel, suffix=status)])[0]["item_id"]
    source_id = service.list()[0]["source_id"]
    if status == "killed":
        service.kill(item_id, why="not authoritative")
    elif status == "kept":
        service.keep(item_id, why="research floor only")
    preview = preview_purge(store, root, source_id)
    assert preview["scope_class"] == "source"
    assert preview["counts"]["ingest_items"] == 1
    result = authority.call(hard_purge, store, root, source_id, confirmation=source_id, sentinel=sentinel)
    assert result["status"] == "purged"
    assert result["counts"]["ingest_items"] == 1
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ingest_items").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM ingest_rulings").fetchone()[0] == 0
        receipt = dict(conn.execute("SELECT * FROM purge_receipts").fetchone())
    assert sentinel not in str(receipt)
    assert sentinel.encode() not in store.path.read_bytes()


@pytest.mark.parametrize("scope_kind", ["operator", "session", "node"])
def test_operator_session_and_node_scopes_purge_all_matching_ingest_states(
    tmp_path, capture_envelope, scope_kind, signed_store
):
    sentinel = f"PRIVATE-MULTI-{scope_kind.upper()}"
    root = tmp_path / scope_kind
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    session_id = capture_envelope["session_id"]
    node_id = capture_envelope["verdict"]["verdict_id"]
    service = IngestService(store, capture_envelope["operator_id"])
    ids = [
        service.scan([_candidate(sentinel, session_id, node_id, str(index))])[0]["item_id"]
        for index in range(3)
    ]
    service.kill(ids[1], why="kill fixture")
    service.keep(ids[2], why="keep fixture")
    scope = {
        "operator": capture_envelope["operator_id"],
        "session": session_id,
        "node": node_id,
    }[scope_kind]
    result = authority.call(hard_purge, store, root, scope, confirmation=scope, sentinel=sentinel)
    assert result["status"] == "purged"
    assert result["counts"]["ingest_items"] == 3
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ingest_items").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM ingest_rulings").fetchone()[0] == 0
    assert sentinel.encode() not in store.path.read_bytes()


def test_ingest_purge_residue_is_committed_and_content_is_still_removed(
    tmp_path, capture_envelope, monkeypatch, signed_store
):
    sentinel = "PRIVATE-COMMITTED-INGEST"
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    service = IngestService(store, capture_envelope["operator_id"])
    service.scan([_candidate(sentinel)])
    monkeypatch.setattr("imprint.purge._scan_active_root", lambda _root, _markers: ["synthetic-residue"])
    scope = capture_envelope["operator_id"]
    result = authority.call(hard_purge, store, root, scope, confirmation=scope, sentinel=sentinel)
    assert result["status"] == "purged_with_residue"
    assert result["committed"] is True
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ingest_items").fetchone()[0] == 0


def test_jsonld_digest_authenticates_graph_and_purge_receipts_roundtrip(tmp_path, capture_envelope, signed_store):
    root = tmp_path / "source"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    source = authority.store
    source.apply_capture(capture_envelope)
    scope = capture_envelope["operator_id"]
    authority.call(hard_purge, source, root, scope, confirmation=scope)
    document = export_jsonld(source)
    assert len(document["imprint:ledger"]["purge_receipts"]) == 1

    tampered = deepcopy(document)
    tampered["@graph"].append({"@id": "urn:imprint:tamper:graph", "@type": "imprint:Tamper"})
    with pytest.raises(ValidationError, match="semantic digest"):
        import_jsonld(ImprintStore(tmp_path / "tampered.db"), tampered)

    target = ImprintStore(tmp_path / "target.db")
    import_jsonld(target, document)
    replay = export_jsonld(target)
    assert replay["imprint:ledger"]["purge_receipts"] == document["imprint:ledger"]["purge_receipts"]
    assert replay["imprint:semanticSha256"] == document["imprint:semanticSha256"]
