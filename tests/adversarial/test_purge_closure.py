from __future__ import annotations

import json
import os

from imprint.paths import CONTENT_LOCATION_REGISTRY
from imprint.purge import _scan_active_root, _trusted_authority_paths, hard_purge, preview_purge


def test_content_registry_covers_every_locked_surface():
    surfaces = {item.surface_id for item in CONTENT_LOCATION_REGISTRY}
    required = {
        "sqlite.canonical_rows", "sqlite.projections", "retrieval.receipts",
        "retrieval.prepared_payloads", "capture.spool", "derive.proposal_spool",
        "compiler.acknowledgements", "compiler.delivery_retry", "import.quarantine",
        "retrieval.indexes", "retrieval.caches", "lifecycle.temporary",
        "lifecycle.rollback", "backup.configured", "export.configured",
        "external.registered", "graphrag.projections",
    }
    assert required <= surfaces
    assert len(surfaces) == len(CONTENT_LOCATION_REGISTRY)


def test_interrupted_inventory_is_durably_incomplete(
    tmp_path, capture_envelope, signed_store, monkeypatch,
):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    authority.store.apply_capture(capture_envelope)
    scope = capture_envelope["verdict"]["verdict_id"]
    preview = preview_purge(authority.store, root, scope)
    assert any(item["surface_id"] == "sqlite.canonical_rows" for item in preview["active_locations"])
    monkeypatch.setattr("imprint.purge._scan_active_root", lambda _root, _identity: ["registered:unreadable"])
    result = authority.call(hard_purge, authority.store, root, scope, confirmation=scope)
    assert result["status"] == "purged_with_residue"
    assert result["purge_state"] == "incomplete"
    with authority.store.connect() as conn:
        row = conn.execute(
            "SELECT status,remaining_locations_json FROM purge_operations WHERE operation_id=?",
            (result["operation_id"],),
        ).fetchone()
        assert row["status"] == "incomplete"
        assert json.loads(row["remaining_locations_json"]) == ["registered:unreadable"]
        assert conn.execute(
            "SELECT 1 FROM purge_receipts WHERE operation_id=?", (result["operation_id"],)
        ).fetchone() is None


def test_unbound_authority_blob_is_never_exempted_by_name(
    tmp_path, capture_envelope, signed_store,
):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    authority.store.apply_capture(capture_envelope)
    scope = capture_envelope["verdict"]["verdict_id"]
    attacker = root / "authority" / "keys" / "unbound.blob"
    attacker.parent.mkdir(parents=True, exist_ok=True)
    attacker.write_text(json.dumps({"subject_id": scope}))
    if os.name != "nt":
        attacker.chmod(0o600)
    result = authority.call(hard_purge, authority.store, root, scope, confirmation=scope)
    assert result["purge_state"] == "incomplete"
    # Authority startup may first quarantine the unbound blob under a random
    # orphan name; neither location becomes trusted by its extension.
    assert list((root / "authority").rglob("*.blob"))
    assert any("authority" in item and ".blob" in item for item in result["residue_locations"])


def test_ledger_bound_blob_loses_exemption_when_bytes_change(tmp_path, capture_envelope, signed_store):
    root = tmp_path / "operator"
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    with authority.store.connect() as conn:
        relative = conn.execute("SELECT blob_rel_path FROM authority_keys").fetchone()[0]
    blob = root / relative
    assert blob in _trusted_authority_paths(authority.store, root)
    original = blob.read_bytes()
    blob.write_bytes(original + b"tampered")
    if os.name != "nt":
        blob.chmod(0o600)
    assert blob not in _trusted_authority_paths(authority.store, root)
    residue = _scan_active_root(root, (set(), set()), authority.store)
    assert any(str(relative) in item and "untrusted_authority_artifact" in item for item in residue)
