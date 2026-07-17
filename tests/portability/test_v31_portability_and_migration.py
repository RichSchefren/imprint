from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from imprint.authority.keys import ALGORITHM_SUITE, generate_key
from imprint.authority.ledger import append_ledger_event, create_checkpoint
from imprint.backup import create_backup, restore_backup, verify_backup
from imprint.constants import ONTOLOGY_SCHEMA_VERSION, STORE_SCHEMA_VERSION
from imprint.errors import ValidationError
from imprint.health import health_report
from imprint.ontology.schema import canonical_bytes
from imprint.ontology.schema import make_urn
from imprint.portability.jsonld import (
    build_export_manifest, build_signed_export_manifest, canonical_ledger_digest,
    export_jsonld, import_jsonld, rdf_dataset_digest, semantic_digest,
    verify_export_manifest,
)
from imprint.portability.migrations import (
    apply_semantic_migration, classify_legacy_business_payload, pre_mutation_compatibility_gate,
    semantic_migration_preview,
)
from imprint.store import ImprintStore
from imprint.retrieve.store_source import StoreRetrievalSource


class _SnapshotConsole:
    def require_native(self):
        return None

    def write(self, _value):
        return None

    def read_line(self, _prompt):
        return "SIGN SNAPSHOT"

    def read_secret(self, _prompt):
        return "test authority passphrase"


def _source(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "source.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    return store


def _key_details(key, install_id):
    return {
        "key_id": key.key_id,
        "public_key_b64": base64.b64encode(key.public_key_raw).decode("ascii"),
        "public_key_fingerprint": key.fingerprint,
        "install_id": install_id,
        "blob_rel_path": f"authority/keys/{key.fingerprint.removeprefix('sha256:')}.blob",
        "blob_sha256": hashlib.sha256(b"portable-fixture-blob" + key.public_key_raw).hexdigest(),
        "blob_size": 1,
        "algorithm_suite": ALGORITHM_SUITE,
    }


def _paired_details(
    key, install_id, *, operator_id, store_identity, preceding_head,
):
    request = {
        "fixture": "portable-authority-pairing",
        "install_id": install_id,
        "key_id": key.key_id,
    }
    return {
        **_key_details(key, install_id),
        "authorization": {
            "certificate_version": "imprint.authority.authorize-installation/1.0.0",
            "operator_id": operator_id,
            "store_identity": store_identity,
            "new_install_id": install_id,
            "new_key_id": key.key_id,
            "new_public_key_b64": base64.b64encode(key.public_key_raw).decode("ascii"),
            "pairing_nonce": "portable-fixture-pairing-nonce",
            "pairing_request_sha256": hashlib.sha256(
                json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "preceding_authority_head_sha256": preceding_head,
            "expires_at": "2099-01-01T00:00:00Z",
        },
    }


def _authority_export_case(tmp_path, capture_envelope, signed_store, *, state="active"):
    harness = signed_store(tmp_path / "source.db", capture_envelope["operator_id"])
    harness.store.apply_capture(capture_envelope)
    paired = generate_key()
    paired_install = "urn:imprint:installation:paired-destination"
    with harness.store.connect() as conn:
        genesis = dict(conn.execute(
            "SELECT sequence,event_sha256,event_json FROM authority_ledger WHERE sequence=1"
        ).fetchone())
        genesis_event = json.loads(genesis["event_json"])
        from imprint.authority.keys import decrypt_private_key, key_aad, read_verified_blob
        binding = dict(conn.execute("SELECT * FROM authority_keys WHERE key_id=?", (genesis_event["key_id"],)).fetchone())
        genesis_key = decrypt_private_key(
            read_verified_blob(harness.service.data_root, binding),
            "test authority passphrase", aad=key_aad(binding),
        )
        append_ledger_event(
            conn, event_type="installation_paired", operator_id=capture_envelope["operator_id"],
            install_id=paired_install, key_id=paired.key_id,
            signer_key_id=binding["key_id"], signer_private_key=genesis_key,
            details=_paired_details(
                paired, paired_install,
                operator_id=capture_envelope["operator_id"],
                store_identity=genesis_event["store_identity"],
                preceding_head=genesis["event_sha256"],
            ),
        )
        checkpoint_key = paired
        checkpoint_binding = {"key_id": paired.key_id}
        if state == "retired":
            successor = generate_key()
            append_ledger_event(
                conn, event_type="key_rotated", operator_id=capture_envelope["operator_id"],
                install_id=paired_install, key_id=successor.key_id,
                signer_key_id=paired.key_id, signer_private_key=paired.private_key,
                details={
                    **_key_details(successor, paired_install),
                    "old_key_id": paired.key_id,
                },
            )
            checkpoint_key = successor
            checkpoint_binding = {"key_id": successor.key_id}
        elif state in {"revoked", "compromised"}:
            effective_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            append_ledger_event(
                conn, event_type="key_revoked" if state == "revoked" else "key_compromised",
                operator_id=capture_envelope["operator_id"],
                install_id=paired_install, key_id=paired.key_id,
                signer_key_id=binding["key_id"], signer_private_key=genesis_key,
                details={
                    "target_key_id": paired.key_id,
                    "effective_at": effective_at,
                    "compromised_at": effective_at if state == "compromised" else None,
                    "reason": f"portable fixture {state}",
                    "replacement_key_id": None,
                    "affected_installation_ids": [paired_install],
                    "evidence_sha256s": [],
                    "required_revocation_key_ids": [paired.key_id],
                },
            )
            checkpoint_key = type("Signer", (), {"private_key": genesis_key})()
            checkpoint_binding = {"key_id": binding["key_id"]}
        checkpoint_clock = None
        authority_now = None
        if state == "stale":
            issued = datetime.now(timezone.utc) - timedelta(hours=2)
            checkpoint_clock = lambda: issued
            authority_now = issued + timedelta(hours=2)
        checkpoint = create_checkpoint(
            conn, expected_operator_id=capture_envelope["operator_id"],
            signer_binding=checkpoint_binding,
            signer_private_key=checkpoint_key.private_key,
            clock=checkpoint_clock, ttl_seconds=3600 if state == "stale" else 86400,
        )
        head = dict(conn.execute(
            "SELECT sequence,event_sha256 FROM authority_ledger ORDER BY sequence DESC LIMIT 1"
        ).fetchone())
    document = export_jsonld(harness.store)
    document["imprint:manifest"] = build_export_manifest(
        document, operator_id=capture_envelope["operator_id"],
        install_id=paired_install, key_id=paired.key_id,
        ledger_sequence=head["sequence"], ledger_head_sha256=head["event_sha256"],
        snapshot_valid_as_of=checkpoint["issued_at"], private_key=paired.private_key,
    )
    return {
        "document": document, "checkpoint": checkpoint, "genesis": genesis,
        "genesis_event": genesis_event, "paired": paired, "head": head,
        "authority_now": authority_now,
    }


def test_complete_ledger_roundtrip_preserves_binary_semantic_bytes(
    tmp_path, signed_store,
):
    from tests.contract.test_semantic_first_write import _governed_store
    harness, ids = _governed_store(tmp_path, signed_store)
    source = harness.store
    raw = b"exact first-write evidence bytes\x00\xff"
    with source.connect() as conn:
        stored = conn.execute(
            "SELECT content FROM semantic_artifact_bytes WHERE version_id=?",
            (ids["artifact_version"],),
        ).fetchone()[0]
    assert bytes(stored) == raw
    document = export_jsonld(source)
    encoded = document["imprint:ledger"]["semantic_artifact_bytes"][0]["content"]
    assert set(encoded) == {"$imprint:base64"}
    target = ImprintStore(tmp_path / "target.db")
    import_jsonld(target, document)
    assert export_jsonld(target)["imprint:ledger"] == document["imprint:ledger"]
    with target.connect() as conn:
        assert bytes(conn.execute("SELECT content FROM semantic_artifact_bytes").fetchone()[0]) == raw


def test_manifest_signing_separates_ledger_and_semantic_digests(tmp_path, capture_envelope):
    document = export_jsonld(_source(tmp_path, capture_envelope))
    key = Ed25519PrivateKey.generate()
    manifest = build_export_manifest(
        document, operator_id=capture_envelope["operator_id"], install_id="install-a",
        key_id="key-a", ledger_sequence=7, ledger_head_sha256="a" * 64,
        snapshot_valid_as_of="2026-07-16T12:00:00Z", private_key=key,
    )
    document["imprint:manifest"] = manifest
    verified = verify_export_manifest(document, public_key=key.public_key())
    assert verified["authority_preserved"] is True
    assert manifest["canonical_ledger_sha256"] == canonical_ledger_digest(document)
    assert manifest["semantic_projection_sha256"] == rdf_dataset_digest(document)
    altered = deepcopy(document)
    altered["imprint:ledger"]["meta"][0]["value"] = "tampered"
    with pytest.raises(ValidationError, match="ledger digest"):
        verify_export_manifest(altered, public_key=key.public_key())


def test_strict_unsigned_authority_import_quarantines_without_database(
    tmp_path, capture_envelope,
):
    source = _source(tmp_path, capture_envelope)
    document = export_jsonld(source)
    # A public authority row is enough to require a verified chain in strict mode.
    document["imprint:ledger"]["authority_ledger"].append({
        "sequence": 1, "event_id": "urn:event:foreign", "event_type": "enrollment",
        "operator_id": "urn:operator:foreign", "install_id": "install-f",
        "key_id": "key-f", "event_json": "{}", "event_sha256": "0" * 64,
        "signature_b64": "", "previous_event_sha256": None,
        "created_at": "2026-07-16T12:00:00Z",
    })
    from imprint.portability.jsonld import _graph_from_ledger
    document["@graph"] = _graph_from_ledger(document["imprint:ledger"])
    document["imprint:semanticSha256"] = semantic_digest(document)
    document["imprint:canonicalLedgerSha256"] = canonical_ledger_digest(document)
    document["imprint:rdfDatasetSha256"] = rdf_dataset_digest(document)
    target = ImprintStore(tmp_path / "target.db")
    quarantine = tmp_path / "quarantine"
    with pytest.raises(ValidationError, match="E_IMPORT_AUTHORITY_QUARANTINED"):
        import_jsonld(
            target, document, enforce_authority=True, quarantine_dir=quarantine,
        )
    assert not target.path.exists()
    artifacts = list(quarantine.glob("foreign-import-*.quarantine.json"))
    assert len(artifacts) == 1
    envelope = json.loads(artifacts[0].read_bytes())
    assert set(envelope) == {
        "schema_version", "authority_tier", "disposition", "original_sha256",
        "original_bytes", "original_operator_id", "original_signature_b64",
        "rejection_reason", "artifact_encoding", "artifact_b64",
    }
    original = canonical_bytes(document)
    assert envelope["schema_version"] == "imprint.import.quarantine/1.0.0"
    assert envelope["authority_tier"] == "imported_floor"
    assert envelope["disposition"] == "noncanonical_private_quarantine"
    assert envelope["original_sha256"] == hashlib.sha256(original).hexdigest()
    assert envelope["original_bytes"] == len(original)
    assert base64.b64decode(envelope["artifact_b64"], validate=True) == original
    assert "destination operator identity is required" in envelope["rejection_reason"]
    assert artifacts[0].stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "case",
    ("unsigned", "unknown_unpaired", "foreign", "stale", "fork",
     "retired", "revoked", "compromised"),
)
def test_invalid_authority_chain_matrix_is_atomic_private_and_not_retrievable(
    tmp_path, capture_envelope, signed_store, case,
):
    chain_state = case if case in {"stale", "retired", "revoked", "compromised"} else "active"
    built = _authority_export_case(
        tmp_path / case, capture_envelope, signed_store, state=chain_state,
    )
    document = built["document"]
    manifest = document["imprint:manifest"]
    if case == "unsigned":
        document["imprint:manifest"] = build_export_manifest(
            document, operator_id=manifest["operator_id"],
            install_id=manifest["install_id"], key_id=manifest["key_id"],
            ledger_sequence=manifest["ledger_sequence"],
            ledger_head_sha256=manifest["ledger_head_sha256"],
            snapshot_valid_as_of=manifest["snapshot_valid_as_of"],
        )
    elif case == "unknown_unpaired":
        unknown = Ed25519PrivateKey.generate()
        document["imprint:manifest"] = build_export_manifest(
            document, operator_id=manifest["operator_id"],
            install_id="urn:imprint:installation:unpaired",
            key_id="urn:imprint:authority-key:unknown",
            ledger_sequence=manifest["ledger_sequence"],
            ledger_head_sha256=manifest["ledger_head_sha256"],
            snapshot_valid_as_of=manifest["snapshot_valid_as_of"], private_key=unknown,
        )
    operator_id = (
        "urn:imprint:operator:foreign" if case == "foreign"
        else capture_envelope["operator_id"]
    )
    pinned = {
        "sequence": built["genesis"]["sequence"],
        "event_sha256": built["genesis"]["event_sha256"],
    }
    if case == "fork":
        pinned["event_sha256"] = "f" * 64
    governance = ImprintStore(tmp_path / case / "local-governance.db")
    governance.initialize()
    target = ImprintStore(
        tmp_path / case / "target.db", expected_operator_id=capture_envelope["operator_id"],
    )
    target.initialize()
    before = target.path.read_bytes()
    quarantine = tmp_path / case / "quarantine"
    kwargs = {
        "enforce_authority": True,
        "local_governance_store": governance,
        "expected_operator_id": operator_id,
        "expected_store_identity": built["genesis_event"]["store_identity"],
        "authority_checkpoint": built["checkpoint"],
        "pinned_authority_head": pinned,
        "authority_now": built["authority_now"],
    }
    with pytest.raises(ValidationError, match="E_IMPORT_AUTHORITY_QUARANTINED"):
        import_jsonld(target, document, quarantine_dir=quarantine, **kwargs)
    assert target.path.read_bytes() == before
    assert StoreRetrievalSource(target).retrieval_candidates("snapshot") == []
    artifacts = list(quarantine.glob("foreign-import-*.quarantine.json"))
    assert len(artifacts) == 1
    envelope = json.loads(artifacts[0].read_bytes())
    assert envelope["authority_tier"] == "imported_floor"
    assert envelope["original_sha256"] == hashlib.sha256(canonical_bytes(document)).hexdigest()

    dry_target = ImprintStore(tmp_path / case / "dry-target.db")
    dry_quarantine = tmp_path / case / "dry-quarantine"
    with pytest.raises(ValidationError, match="E_IMPORT_AUTHORITY_QUARANTINED"):
        import_jsonld(
            dry_target, document, dry_run=True, quarantine_dir=dry_quarantine, **kwargs,
        )
    assert not dry_target.path.exists()
    assert not dry_quarantine.exists()


def test_compatibility_preview_and_legacy_adapter_never_invent(tmp_path, capture_envelope):
    missing = ImprintStore(tmp_path / "missing.db")
    before = pre_mutation_compatibility_gate(missing)
    assert before["status"] == "missing_store" and not missing.path.exists()

    store = _source(tmp_path, capture_envelope)
    with store._migration_connection(
        store_versions=frozenset({STORE_SCHEMA_VERSION}), ontology_versions=None,
    ) as conn:
        conn.execute("UPDATE meta SET value='3.0.1' WHERE key='ontology_schema_version'")
    gate = pre_mutation_compatibility_gate(store)
    assert gate["status"] == "migration_available"
    preview = semantic_migration_preview(store)
    assert preview["mutation_outcome"] == "none"
    assert preview["from_version"] == "3.0.1"
    adapted = classify_legacy_business_payload(
        node_type="Offer", payload_json='{"name":"Legacy"}', source_version_id="v1",
    )
    assert adapted["typed_projection"] is None
    assert adapted["classification"] == "legacy_business_semantics_unknown"
    assert adapted["invented_fields"] == []


def test_signed_and_unsigned_backup_labels_are_verifiable(tmp_path, capture_envelope):
    source = _source(tmp_path, capture_envelope)
    unsigned = create_backup(source, tmp_path / "data")
    verified = verify_backup(tmp_path / "data" / "backups" / unsigned["file"])
    assert verified["authenticity"] == "corruption-detection-only"
    assert verified["authority_preserved"] is False

    key = Ed25519PrivateKey.generate()
    signed = create_backup(
        source, tmp_path / "signed-data", signing_key=key, signing_key_id="key-1",
    )
    signed_path = tmp_path / "signed-data" / "backups" / signed["file"]
    assert verify_backup(signed_path, trusted_public_key=key.public_key())["authority_preserved"] is True
    receipt_path = signed_path.with_suffix(signed_path.suffix + ".receipt.json")
    receipt = json.loads(receipt_path.read_text())
    receipt["sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValidationError):
        verify_backup(signed_path, trusted_public_key=key.public_key())


def test_semantic_apply_is_staged_idempotent_and_failure_keeps_exact_live_bytes(
    tmp_path, capture_envelope,
):
    store = _source(tmp_path, capture_envelope)
    with store._migration_connection(
        store_versions=frozenset({STORE_SCHEMA_VERSION}), ontology_versions=None,
    ) as conn:
        conn.execute("UPDATE meta SET value='3.0.1' WHERE key='ontology_schema_version'")
    backup = create_backup(store, tmp_path / "migration-data")
    backup_path = tmp_path / "migration-data" / "backups" / backup["file"]
    before = store.path.read_bytes()

    def fail(point):
        if point == "candidate_committed":
            raise RuntimeError("fault before publication")

    with pytest.raises(RuntimeError, match="fault before publication"):
        apply_semantic_migration(store, backup_path=backup_path, fault_injector=fail)
    assert store.path.read_bytes() == before
    assert pre_mutation_compatibility_gate(store)["status"] == "migration_available"

    receipt = apply_semantic_migration(store, backup_path=backup_path)
    assert receipt["status"] == "applied"
    assert pre_mutation_compatibility_gate(store)["status"] == "current"
    replay = apply_semantic_migration(store, backup_path=backup_path)
    assert replay["status"] == "already-applied"
    assert replay["code_sha256"] == receipt["code_sha256"]


def test_authority_preserving_import_uses_only_local_consent_at_one_fresh_system_time(
    tmp_path, signed_store,
):
    from tests.contract.test_semantic_first_write import _governed_store
    harness, ids = _governed_store(tmp_path / "source", signed_store)
    paired = generate_key()
    paired_install = "urn:imprint:installation:paired-destination"
    with harness.store.connect() as conn:
        genesis = dict(conn.execute(
            "SELECT sequence,event_sha256,event_json FROM authority_ledger WHERE sequence=1"
        ).fetchone())
        genesis_event = json.loads(genesis["event_json"])
        from imprint.authority.keys import decrypt_private_key, key_aad, read_verified_blob
        binding = dict(conn.execute(
            "SELECT * FROM authority_keys WHERE key_id=?", (genesis_event["key_id"],)
        ).fetchone())
        genesis_key = decrypt_private_key(
            read_verified_blob(harness.service.data_root, binding),
            "test authority passphrase", aad=key_aad(binding),
        )
        append_ledger_event(
            conn, event_type="installation_paired", operator_id=ids["operator"],
            install_id=paired_install, key_id=paired.key_id,
            signer_key_id=binding["key_id"], signer_private_key=genesis_key,
            details=_paired_details(
                paired, paired_install, operator_id=ids["operator"],
                store_identity=genesis_event["store_identity"],
                preceding_head=genesis["event_sha256"],
            ),
        )
        checkpoint = create_checkpoint(
            conn, expected_operator_id=ids["operator"],
            signer_binding={"key_id": paired.key_id},
            signer_private_key=paired.private_key,
        )
        head = dict(conn.execute(
            "SELECT sequence,event_sha256 FROM authority_ledger ORDER BY sequence DESC LIMIT 1"
        ).fetchone())
    document = export_jsonld(harness.store)
    document["imprint:manifest"] = build_export_manifest(
        document, operator_id=ids["operator"], install_id=paired_install,
        key_id=paired.key_id, ledger_sequence=head["sequence"],
        ledger_head_sha256=head["event_sha256"],
        snapshot_valid_as_of=checkpoint["issued_at"], private_key=paired.private_key,
    )
    governance = ImprintStore(tmp_path / "local-governance.db")
    governance.initialize()
    calls = []

    def authorize(conn, consent_version_id, **kwargs):
        calls.append((consent_version_id, kwargs))
        return consent_version_id

    governance.authorize_consent_version = authorize  # type: ignore[method-assign]
    target = ImprintStore(tmp_path / "target.db")
    import_jsonld(
        target, document, enforce_authority=True,
        local_governance_store=governance, expected_operator_id=ids["operator"],
        expected_store_identity=genesis_event["store_identity"],
        authority_checkpoint=checkpoint,
        pinned_authority_head={
            "sequence": genesis["sequence"],
            "event_sha256": genesis["event_sha256"],
        },
    )
    assert calls
    assert {item[0] for item in calls} == {ids["consent_version"]}
    assert len({item[1]["system_at"] for item in calls}) == 1
    assert all(item[1]["operation"] == "store" for item in calls)


def test_health_accepts_exact_backup_receipt_v1_0_and_v1_1_but_rejects_future(
    tmp_path, capture_envelope,
):
    store = _source(tmp_path, capture_envelope)
    root_11 = tmp_path / "health-11"
    current = create_backup(store, root_11)
    report = health_report(root_11, store, {}, deep=True)
    assert report["metrics"]["verified_backup_count"] == 1

    root_10 = tmp_path / "health-10"
    legacy = create_backup(store, root_10)
    legacy_receipt = Path(legacy["receipt_path"])
    value = json.loads(legacy_receipt.read_text())
    value["backup_schema_version"] = "1.0.0"
    for field in (
        "ontology_schema_version", "authenticity", "signing_key_id", "signature_b64",
    ):
        value.pop(field)
    legacy_receipt.write_text(json.dumps(value))
    assert verify_backup(Path(legacy["path"]))["backup_schema_version"] == "1.0.0"
    report = health_report(root_10, store, {}, deep=True)
    assert report["metrics"]["verified_backup_count"] == 1

    value["backup_schema_version"] = "9.0.0"
    legacy_receipt.write_text(json.dumps(value))
    with pytest.raises(ValidationError, match="unsupported backup receipt schema"):
        verify_backup(Path(legacy["path"]))
    report = health_report(root_10, store, {}, deep=True)
    assert report["metrics"]["verified_backup_count"] == 0
    assert report["metrics"]["invalid_backup_count"] == 1


def test_signed_backup_restore_uses_chain_checkpoint_and_atomic_dry_run(
    tmp_path, capture_envelope, signed_store,
):
    root = tmp_path / "signed-restore"
    harness = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    harness.store.apply_capture(capture_envelope)
    backup = create_backup(
        harness.store, root, authority_service=harness.service,
        signing_console=_SnapshotConsole(),
    )
    source = Path(backup["path"])
    assert backup["authority_checkpoint"] is not None
    health = health_report(root, harness.store, {}, deep=True)
    assert health["metrics"]["verified_backup_count"] == 1
    assert health["metrics"]["invalid_backup_count"] == 0
    before = harness.store.path.read_bytes()
    dry = restore_backup(
        harness.store, root, source, confirmation="unused-in-dry-run", dry_run=True,
        authority_checkpoint=backup["authority_checkpoint"],
    )
    assert dry["status"] == "verified-dry-run"
    assert dry["authority_preserved"] is True
    assert harness.store.path.read_bytes() == before

    harness.call(
        harness.store.tombstone_node, capture_envelope["verdict"]["verdict_id"],
        reason="restore checkpoint integration",
    )
    changed = harness.store.path.read_bytes()
    assert changed != before
    restored = restore_backup(
        harness.store, root, source, confirmation=source.name,
        authority_checkpoint=backup["authority_checkpoint"],
    )
    assert restored["status"] == "restored"
    assert restored["authority_preserved"] is True
    assert capture_envelope["verdict"]["verdict_id"] in {
        node["node_id"] for node in harness.store.current_nodes()
    }


def test_service_signed_export_binds_one_checkpoint_without_private_key_escape(
    tmp_path, capture_envelope, signed_store,
):
    harness = signed_store(
        tmp_path / "signed-export" / "source.db", capture_envelope["operator_id"],
    )
    harness.store.apply_capture(capture_envelope)
    document = export_jsonld(harness.store)
    manifest, checkpoint = build_signed_export_manifest(
        document, authority_service=harness.service, console=_SnapshotConsole(),
    )
    document["imprint:manifest"] = manifest
    assert manifest["snapshot_valid_as_of"] == checkpoint["issued_at"]
    governance = ImprintStore(tmp_path / "signed-export" / "governance.db")
    governance.initialize()
    target = ImprintStore(tmp_path / "signed-export" / "target.db")
    digest = import_jsonld(
        target, document, dry_run=True, enforce_authority=True,
        local_governance_store=governance,
        expected_operator_id=capture_envelope["operator_id"],
        authority_checkpoint=checkpoint,
    )
    assert digest == document["imprint:semanticSha256"]
    assert not target.path.exists()


def test_unsigned_authority_backup_quarantines_without_live_mutation(
    tmp_path, capture_envelope, signed_store,
):
    root = tmp_path / "unsigned-restore"
    harness = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    harness.store.apply_capture(capture_envelope)
    backup = create_backup(harness.store, root)
    before = harness.store.path.read_bytes()
    quarantine = root / "explicit-quarantine"
    with pytest.raises(ValidationError, match="E_BACKUP_AUTHORITY_QUARANTINED"):
        restore_backup(
            harness.store, root, Path(backup["path"]), confirmation=Path(backup["path"]).name,
            quarantine_dir=quarantine,
        )
    assert harness.store.path.read_bytes() == before
    artifacts = list(quarantine.glob("foreign-backup-*.quarantine"))
    assert len(artifacts) == 1
    metadata = json.loads((artifacts[0] / "metadata.json").read_bytes())
    assert metadata["authority_tier"] == "imported_floor"
    assert metadata["original_sha256"] == hashlib.sha256(
        Path(backup["path"]).read_bytes()
    ).hexdigest()

    dry_quarantine = root / "dry-quarantine"
    with pytest.raises(ValidationError, match="E_BACKUP_AUTHORITY_QUARANTINED"):
        restore_backup(
            harness.store, root, Path(backup["path"]), confirmation="unused",
            quarantine_dir=dry_quarantine, dry_run=True,
        )
    assert not dry_quarantine.exists()


def test_business_partition_and_relation_governance_roundtrip_exactly(
    tmp_path, signed_store,
):
    from tests.contract.test_semantic_first_write import (
        NOW, _envelope, _governed_store, _provenance, ids_for,
        _business_confidence,
    )
    harness, ids = _governed_store(tmp_path / "business", signed_store)
    store = harness.store
    market_version, segment_version = make_urn("node-version"), make_urn("node-version")
    market = _envelope(
        "imprint.node.market/1.0.0", make_urn("market"), market_version,
        {"name": "Founder market", "category": "urn:market:founders", "definition": "Founder-led firms"},
        **ids_for(ids),
    )
    segment = _envelope(
        "imprint.node.segment/1.0.0", make_urn("segment"), segment_version,
        {"name": "Operators", "definition": "Founder operators", "criteria": [
            {"criterion_id": "urn:criterion:one", "field_id": "urn:field:role", "operator": "eq", "value": "founder"},
        ]}, **ids_for(ids),
    )
    segment_confidence = _business_confidence(segment_version, ids)
    segment["payload"]["confidence_assessment_version_id"] = segment_confidence["version_id"]
    harness.call(store.append_ontology_bundle, [market, segment, segment_confidence])
    relation_version = make_urn("relation-version")
    relation = {
        "relation_id": make_urn("relation"), "relation_version_id": relation_version,
        "predicate_id": "defines_segment", "predicate_version": 1,
        "source_version_id": market_version, "target_version_id": segment_version,
        "operator_id": ids["operator"], "actor_id": ids["actor_id"],
        "role_assignment_version_id": ids["role_version"],
        "provenance": _provenance(ids["actor_id"], ids["role_version"], ids["artifact_version"]),
        "evidence_version_ids": [ids["artifact_version"]], "why": "Market definition",
        "sensitivity": "standard", "access_policy_version_id": ids["policy_version"],
        "consent_version_id": ids["consent_version"], "valid_from": NOW, "valid_to": None,
        "qualifier_schema_id": "imprint.business.qualifier.link/1.1.0",
        "qualifier": {"rationale": "Exact governed link", "evidence_version_ids": [ids["artifact_version"]]},
        "extensions": {},
    }
    harness.call(store.append_business_relation, relation)
    source_document = export_jsonld(store)
    target = ImprintStore(tmp_path / "business-target.db")
    import_jsonld(target, source_document)
    assert export_jsonld(target)["imprint:ledger"] == source_document["imprint:ledger"]
    assert target.read_business_node(market_version)["partition"] == "business_declared"
    readback = target.read_business_relation(relation_version)
    assert (readback["policy"], readback["authority_minimum"]) == ("O", "J")
