from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from imprint.backup import create_backup, restore_backup, verify_backup
from imprint.errors import SafetyError, ValidationError
from imprint.lifecycle import review_list, review_show
from imprint.ontology.schema import make_urn
from imprint.projections import jsonld_document, markdown_document
from imprint.purge import _scan_active_root, hard_purge, preview_purge
from imprint.store import ImprintStore


def _derived(store: ImprintStore, *, status: str = "inferred", node_type: str = "Principle") -> str:
    evidence_ids = [item["node_id"] for item in store.current_nodes(["Evidence"])]
    operator_id = store.current_nodes()[0]["operator_id"]
    return store.append_derived_node(
        node_type=node_type,
        payload={"statement": "Expose every material source failure"},
        provenance_status=status,
        authority_tier="inferred_candidate" if status == "inferred" else "observed_candidate",
        evidence_ids=evidence_ids,
        operator_id=operator_id,
        valid_from="2026-07-14T18:00:00Z",
        proposed_by="test-agent",
    )


def test_review_list_show_ratify_and_reject_preserve_history(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    ratified_id = _derived(store)
    rejected_id = _derived(store, status="extracted")
    assert {item["node_id"] for item in review_list(store)} == {ratified_id, rejected_id}
    assert review_show(store, ratified_id)["provenance_status"] == "inferred"

    authority.call(store.ratify_node, ratified_id, ratifier=capture_envelope["operator_id"], note="Confirmed")
    reject_event = authority.call(store.reject_node, rejected_id, rejector=capture_envelope["operator_id"], reason="Overgeneralized")

    assert review_list(store) == []
    assert store.current_nodes(["Principle"])[0]["node_id"] == ratified_id
    assert store.current_nodes(["Principle"])[0]["provenance_status"] == "ratified"
    history = store.node_history(rejected_id)
    assert history["versions"][0]["system_to"] is not None
    assert history["dispositions"][0]["event_id"] == reject_event
    assert history["dispositions"][0]["event_type"] == "rejected"
    with pytest.raises(ValidationError, match="not current"):
        review_show(store, rejected_id)


def test_later_why_appends_evidence_and_preserves_original_null(tmp_path, capture_envelope, signed_store):
    capture_envelope["verdict"]["reason"] = None
    capture_envelope["verdict"]["reason_status"] = "pending"
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    verdict_id = capture_envelope["verdict"]["verdict_id"]

    event_id = authority.call(store.add_reason, verdict_id, reason="Because omission changes the result", actor_id=capture_envelope["operator_id"])
    history = store.node_history(verdict_id)
    assert [version["payload"]["reason"] for version in history["versions"]] == [None, "Because omission changes the result"]
    assert history["versions"][0]["payload"]["reason_status"] == "pending"
    assert history["versions"][1]["payload"]["reason_status"] == "later_added"
    assert len(history["versions"][1]["evidence"]) == len(history["versions"][0]["evidence"]) + 1
    assert any(item["event_id"] == event_id and item["event_type"] == "reason_added" for item in history["dispositions"])
    with pytest.raises(ValidationError, match="already has a reason"):
        store.add_reason(verdict_id, reason="Rewrite it", actor_id=capture_envelope["operator_id"])


def test_reinforcement_appends_version_without_changing_call(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    verdict_id = capture_envelope["verdict"]["verdict_id"]
    before = store.current_nodes(["Verdict"])[0]
    authority.call(store.reinforce_verdict, verdict_id, evidence_text="The same failure happened again", actor_id=capture_envelope["operator_id"])
    after = store.current_nodes(["Verdict"])[0]
    assert after["payload"] == before["payload"]
    assert len(after["evidence"]) == len(before["evidence"]) + 1
    assert len(store.node_history(verdict_id)["versions"]) == 2


def test_backup_is_verified_tamper_evident_and_restore_is_separately_confirmed(tmp_path, capture_envelope, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    backup = authority.signed_backup(root)

    authority.call(store.tombstone_node, capture_envelope["verdict"]["verdict_id"], reason="test mutation")
    with pytest.raises(SafetyError, match="exactly name"):
        restore_backup(
            store, root, Path(backup["path"]), confirmation="YES",
            authority_checkpoint=backup["authority_checkpoint"],
        )
    restored = restore_backup(
        store, root, Path(backup["path"]), confirmation=Path(backup["path"]).name,
        authority_checkpoint=backup["authority_checkpoint"],
    )
    assert restored["status"] == "restored"
    assert capture_envelope["verdict"]["verdict_id"] in {node["node_id"] for node in store.current_nodes()}
    assert restored["safety_backup"] is not None

    tampered = Path(backup["path"])
    tampered.write_bytes(tampered.read_bytes() + b"tamper")
    with pytest.raises(ValidationError, match="hash"):
        verify_backup(tampered)


def test_hard_purge_requires_exact_confirmation_removes_dependency_content_and_keeps_noncontent_receipt(tmp_path, capture_envelope, signed_store):
    sentinel = "PRIVATE-SENTINEL-DO-NOT-SURVIVE"
    capture_envelope["case"]["description"] = sentinel
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    projection_dir = root / "projections"
    projection_dir.mkdir(parents=True)
    snapshot = store.snapshot()
    (projection_dir / "imprint.md").write_text(markdown_document(snapshot), encoding="utf-8")
    (projection_dir / "imprint.jsonld").write_text(json.dumps(jsonld_document(snapshot)), encoding="utf-8")
    backup = create_backup(store, root)
    scope = capture_envelope["verdict"]["verdict_id"]
    preview = preview_purge(store, root, scope)
    assert preview["counts"]["nodes"] >= 4
    assert preview["confirmation_required"] == scope
    with pytest.raises(SafetyError, match="exactly name"):
        hard_purge(store, root, scope, confirmation="PURGE", sentinel=sentinel)

    result = authority.call(hard_purge, store, root, scope, confirmation=scope, sentinel=sentinel)
    assert result["status"] == "purged"
    assert result["active_root_scan"] == "clear"
    assert store.current_nodes() == []
    assert store.current_edges() == []
    assert not Path(backup["path"]).exists()
    assert sentinel not in (projection_dir / "imprint.md").read_text(encoding="utf-8")
    assert sentinel.encode() not in (projection_dir / "imprint.jsonld").read_bytes()
    assert sentinel.encode() not in store.path.read_bytes()
    assert not Path(backup["receipt_path"]).exists()
    with store.connect() as conn:
        receipt = dict(conn.execute("SELECT * FROM purge_receipts").fetchone())
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert event_count == 0
    assert set(receipt) == {"operation_id", "purged_at", "schema_version", "scope_class", "counts_json"}
    assert sentinel not in json.dumps(receipt)
    assert scope not in json.dumps(receipt)


def test_purge_scan_never_exempts_authority_content_by_extension(tmp_path):
    marker = b"operator-private-content"
    keys = tmp_path / "authority" / "keys"
    keys.mkdir(parents=True)
    (keys / "fingerprint.blob").write_bytes(marker)
    hidden = tmp_path / "authority" / "notes.txt"
    hidden.write_bytes(marker)
    identity = (set(), {hashlib.sha256(marker).hexdigest()})
    assert _scan_active_root(tmp_path, identity) == [
        "untyped:authority/keys/fingerprint.blob",
        "untyped:authority/notes.txt",
    ]


def test_backup_rejects_unsafe_and_cloud_sync_targets(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    with pytest.raises(SafetyError):
        create_backup(store, root, Path.home() / "unsafe.sqlite3")
    with pytest.raises(SafetyError, match="Cloud-sync"):
        create_backup(store, root, tmp_path / "Dropbox" / "copy.sqlite3")


@pytest.mark.parametrize("scope_key,expected_class", [
    ("operator_id", "operator"),
    ("session_id", "session"),
    ("source_id", "source"),
])
def test_hard_purge_supports_exact_operator_session_and_source_scopes(
    tmp_path, capture_envelope, scope_key, expected_class, signed_store
):
    root = tmp_path / expected_class
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    scope = {
        "operator_id": capture_envelope["operator_id"],
        "session_id": capture_envelope["session_id"],
        "source_id": capture_envelope["evidence"][0]["evidence_id"],
    }[scope_key]
    preview = preview_purge(store, root, scope)
    assert preview["scope_class"] == expected_class
    result = authority.call(hard_purge, store, root, scope, confirmation=scope)
    assert result["status"] == "purged"
    assert result["scope_class"] == expected_class
    assert store.current_nodes() == []
