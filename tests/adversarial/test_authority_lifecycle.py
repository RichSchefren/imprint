from __future__ import annotations

import json
import base64
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import imprint.authority.service as authority_service

from imprint.authority import AuthorityService, verify_authority_chain, verify_recovery_bundle
from imprint.authority.challenge import canonical_bytes, sha256_hex
from imprint.authority.keys import public_key_from_b64
from imprint.authority.trust import (
    finalize_anchor_advance, load_authority_trust_anchor,
    prepare_checkpoint_advance, retain_authority_conflict,
    verify_authority_transfer,
)
from imprint.backup import create_backup
from imprint.errors import ConflictError, ValidationError
from imprint.purge import _trusted_authority_paths
from imprint.store import ImprintStore


OPERATOR = "urn:imprint:operator:33333333-3333-4333-8333-333333333333"
AUTH_PASS = "authority lifecycle passphrase"
RECOVERY_PASS = "separate recovery passphrase"
NEW_PASS = "new machine authority passphrase"


class Console:
    def __init__(self, lines=(), secrets=()):
        self.lines = iter(lines)
        self.secrets = iter(secrets)
        self.output = []

    def require_native(self):
        return None

    def write(self, value):
        self.output.append(value)

    def read_line(self, prompt):
        self.output.append(prompt)
        return next(self.lines)

    def read_secret(self, prompt):
        self.output.append(prompt)
        return next(self.secrets)


def enrolled(root):
    store = ImprintStore(root / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(root, store, operator_id=OPERATOR)
    service.enroll(console=Console(
        ["ENROLL DECLINE-RECOVERY"], [AUTH_PASS, AUTH_PASS],
    ))
    return store, service


def recovery_bundle(service, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    service.create_recovery_bundle(
        path, console=Console(
            ["CREATE RECOVERY", "BIND RECOVERY KEY"],
            [AUTH_PASS, RECOVERY_PASS, RECOVERY_PASS],
        ),
    )
    return verify_recovery_bundle(path)


def fresh_transport(service, path, passphrase=AUTH_PASS):
    service.export_authority_transport(
        path, console=Console(["PUBLISH AUTHORITY TRANSPORT"], [passphrase]),
    )
    return path


def test_authority_store_fsync_uses_write_capable_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "imprint.db"
    path.write_bytes(b"sqlite")
    service = AuthorityService(
        tmp_path, SimpleNamespace(path=path), operator_id=OPERATOR,
    )
    opened: list[int] = []
    synced: list[int] = []
    closed: list[int] = []

    def fake_open(target, flags):
        assert Path(target) == path
        opened.append(flags)
        return 41

    monkeypatch.setattr(authority_service.os, "open", fake_open)
    monkeypatch.setattr(authority_service.os, "fsync", synced.append)
    monkeypatch.setattr(authority_service.os, "close", closed.append)
    monkeypatch.setattr(service, "_fsync_directory", lambda parent: None)

    service._fsync_store()

    assert opened and opened[0] & os.O_ACCMODE == os.O_RDWR
    assert synced == [41]
    assert closed == [41]


def test_signed_recovery_bundle_restores_distinct_paired_machine_and_excludes_private_blob_from_backup(tmp_path):
    source_store, source = enrolled(tmp_path / "source")
    package = tmp_path / "offline" / "authority-recovery.json"
    verified = recovery_bundle(source, package)
    transport = fresh_transport(source, tmp_path / "offline" / "authority-transport.json")
    assert verified["chain"]["head_sequence"] == 2
    assert verified["chain"]["keys"][verified["manifest"]["recovery_key_id"]]["kind"] == "recovery"

    backup = create_backup(source_store, tmp_path / "source")
    local_blob = next((tmp_path / "source" / "authority" / "keys").glob("*.blob"))
    encrypted_private = json.loads(local_blob.read_bytes())["ciphertext_b64"].encode()
    assert encrypted_private not in Path(backup["path"]).read_bytes()

    target_root = tmp_path / "target"
    target_store = ImprintStore(target_root / "imprint.db", expected_operator_id=OPERATOR)
    target = AuthorityService(target_root, target_store, operator_id=OPERATOR)
    target.bootstrap_recovery_trust(
        package, console=Console(["PIN RECOVERY TRUST"], [RECOVERY_PASS]),
    )
    restored = target.restore_recovery_bundle(
        package, console=Console(
            ["RESTORE AUTHORITY", "SIGN RESTORE CERTIFICATE"],
            [RECOVERY_PASS, NEW_PASS, NEW_PASS],
        ),
        authority_transport=transport,
    )
    assert restored["install_id"] != verified["manifest"]["signer_install_id"]
    assert restored["key_id"] != verified["manifest"]["signer_key_id"]
    with target_store.connect() as conn:
        chain = verify_authority_chain(
            conn, expected_operator_id=OPERATOR,
            expected_store_identity=verified["manifest"]["store_identity"],
            checkpoint=json.loads(Path(transport).read_text())["checkpoint"],
            pinned_head={
                "sequence": verified["manifest"]["ledger_sequence"],
                "event_sha256": verified["manifest"]["ledger_head_sha256"],
            },
        )
    assert chain["head_sequence"] == 3
    assert chain["unseen_newer_events"] is True
    assert len(chain["active_installations"]) == 2
    assert chain["keys"][restored["key_id"]]["paired"] is True


def test_recovery_tamper_wrong_passphrase_and_replay_restore_fail_closed(tmp_path):
    _, source = enrolled(tmp_path / "source")
    package = tmp_path / "authority-recovery.json"
    recovery_bundle(source, package)
    transport = fresh_transport(source, tmp_path / "authority-transport.json")
    value = json.loads(package.read_text())
    value["manifest"]["ledger_head_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="manifest signature|another ledger head"):
        verify_recovery_bundle(value)

    target_root = tmp_path / "wrong"
    target = AuthorityService(
        target_root, ImprintStore(target_root / "imprint.db", expected_operator_id=OPERATOR),
        operator_id=OPERATOR,
    )
    target.bootstrap_recovery_trust(
        package, console=Console(["PIN RECOVERY TRUST"], [RECOVERY_PASS]),
    )
    with pytest.raises(ValidationError, match="passphrase or bundle"):
        target.restore_recovery_bundle(
            package, authority_transport=transport,
            console=Console([], ["wrong passphrase value", NEW_PASS, NEW_PASS]),
        )
    with target.store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM authority_ledger").fetchone()[0] == 0

    target.restore_recovery_bundle(
        package, authority_transport=transport,
        console=Console(["RESTORE AUTHORITY", "SIGN RESTORE CERTIFICATE"], [RECOVERY_PASS, NEW_PASS, NEW_PASS]),
    )
    with pytest.raises(ConflictError, match="fresh authority ledger"):
        target.restore_recovery_bundle(
            package, authority_transport=transport,
            console=Console([], [RECOVERY_PASS, NEW_PASS, NEW_PASS]),
        )


def test_rotation_compromise_checkpoint_freshness_and_total_loss_fail_closed(tmp_path):
    store, service = enrolled(tmp_path / "source")
    package = tmp_path / "authority-recovery.json"
    bundled = recovery_bundle(service, package)
    old_key = bundled["manifest"]["signer_key_id"]
    rotated = service.rotate_key(console=Console(
        ["ROTATE AUTHORITY KEY", "SIGN EXACT ROTATION"], [AUTH_PASS, NEW_PASS, NEW_PASS],
    ))
    with store.connect() as conn:
        chain = verify_authority_chain(
            conn, expected_operator_id=OPERATOR,
            checkpoint=bundled["manifest"]["creation_checkpoint"],
        )
    assert chain["keys"][old_key]["status"] == "retired"
    assert chain["keys"][rotated["key_id"]]["status"] == "active"
    assert len(_trusted_authority_paths(store, tmp_path / "source")) == 2
    assert chain["checkpoint"]["signer_current_status"] == "retired"
    assert chain["unseen_newer_events"] is True

    stale_now = datetime.now(timezone.utc) + timedelta(days=2)
    with store.connect() as conn, pytest.raises(ValidationError, match="absent or stale"):
        verify_authority_chain(
            conn, expected_operator_id=OPERATOR,
            checkpoint=bundled["manifest"]["creation_checkpoint"], now=stale_now,
        )
    with store.connect() as conn, pytest.raises(ValidationError, match="fork or equivocation"):
        verify_authority_chain(
            conn, expected_operator_id=OPERATOR,
            pinned_head={"sequence": 2, "event_sha256": "0" * 64},
        )

    recovery_key_id = bundled["manifest"]["recovery_key_id"]
    service.change_key_state(
        recovery_key_id, state="revoked", reason="replace offline recovery",
        console=Console(["MARK REVOKED", "SIGN EXACT KEY STATE"], [NEW_PASS]),
    )
    with store.connect() as conn:
        revoked_chain = verify_authority_chain(conn, expected_operator_id=OPERATOR)
    assert revoked_chain["keys"][recovery_key_id]["status"] == "revoked"
    with pytest.raises(ValidationError, match="unknown or inactive"):
        service.change_key_state(
            recovery_key_id, state="revoked", reason="replay",
            console=Console(["MARK REVOKED"]),
        )

    # A new recovery package is required before emergency compromise after
    # revocation; the old package cannot authorize the current chain.
    with pytest.raises(ValidationError, match="not active in the current ledger"):
        service.change_key_state(
            rotated["key_id"], state="compromised", reason="machine stolen",
            recovery_bundle=package,
            console=Console(["MARK COMPROMISED"], [RECOVERY_PASS]),
        )


def test_no_key_escape_portable_signing_and_broken_chain_rejection(tmp_path):
    store, service = enrolled(tmp_path / "source")
    payload = {"manifest_version": "test", "sha256": "a" * 64}
    signed = service.sign_portable_payload(
        payload, domain_separator=b"imprint-export-manifest-v1\x00",
        checkpoint_time_field="snapshot_valid_as_of",
        console=Console(["SIGN SNAPSHOT"], [AUTH_PASS]),
    )
    with store.connect() as conn:
        chain = verify_authority_chain(
            conn, expected_operator_id=OPERATOR, checkpoint=signed["checkpoint"],
        )
    public_key_from_b64(chain["keys"][signed["signer_key_id"]]["public_key_b64"]).verify(
        base64.b64decode(signed["signature_b64"], validate=True),
        b"imprint-export-manifest-v1\x00" + canonical_bytes(signed["payload"]),
    )
    assert signed["payload"]["snapshot_valid_as_of"] == signed["checkpoint"]["issued_at"]
    assert signed["ledger_sequence"] == chain["head_sequence"]
    assert signed["ledger_head_sha256"] == chain["head_sha256"]

    package = tmp_path / "recovery.json"
    recovery_bundle(service, package)
    memory = sqlite3.connect(":memory:")
    memory.row_factory = sqlite3.Row
    with store.connect() as source:
        source.backup(memory)
    memory.execute("DROP TRIGGER authority_ledger_no_delete")
    memory.execute("DELETE FROM authority_ledger WHERE sequence=1")
    with pytest.raises(ValidationError, match="sequence is broken or forked"):
        verify_authority_chain(memory, expected_operator_id=OPERATOR)
    memory.close()


def test_emergency_recovery_compromise_creates_total_loss_boundary(tmp_path):
    store, service = enrolled(tmp_path / "source")
    package = tmp_path / "authority-recovery.json"
    recovery_bundle(service, package)
    rotated = service.rotate_key(console=Console(
        ["ROTATE AUTHORITY KEY", "SIGN EXACT ROTATION"], [AUTH_PASS, NEW_PASS, NEW_PASS],
    ))
    service.change_key_state(
        rotated["key_id"], state="compromised", reason="machine stolen",
        recovery_bundle=package,
        console=Console(["MARK COMPROMISED", "SIGN EXACT KEY STATE"], [RECOVERY_PASS]),
    )
    with store.connect() as conn:
        chain = verify_authority_chain(conn, expected_operator_id=OPERATOR)
    assert chain["keys"][rotated["key_id"]]["status"] == "compromised"
    assert chain["active_installations"] == []
    with pytest.raises(ValidationError, match="writes are blocked"):
        service.create_checkpoint(console=Console(secrets=[NEW_PASS]))


def test_recovery_restore_crash_after_blob_publication_rolls_back_and_retries(tmp_path):
    _, source = enrolled(tmp_path / "source")
    package = tmp_path / "authority-recovery.json"
    recovery_bundle(source, package)
    transport = fresh_transport(source, tmp_path / "authority-transport.json")
    target_root = tmp_path / "target"
    store = ImprintStore(target_root / "imprint.db", expected_operator_id=OPERATOR)

    class Crash(AuthorityService):
        def _checkpoint(self, name):
            if name == "recovery_restore_blob_published":
                raise RuntimeError(name)

    crashing = Crash(target_root, store, operator_id=OPERATOR)
    crashing.bootstrap_recovery_trust(
        package, console=Console(["PIN RECOVERY TRUST"], [RECOVERY_PASS]),
    )
    with pytest.raises(RuntimeError, match="recovery_restore_blob_published"):
        crashing.restore_recovery_bundle(
            package, console=Console(
                ["RESTORE AUTHORITY", "SIGN RESTORE CERTIFICATE"], [RECOVERY_PASS, NEW_PASS, NEW_PASS],
            ),
            authority_transport=transport,
        )
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM authority_ledger").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM authority_keys").fetchone()[0] == 0
    assert not list((target_root / "authority" / "keys").glob("*.blob"))

    recovered = AuthorityService(target_root, store, operator_id=OPERATOR)
    result = recovered.restore_recovery_bundle(
        package, console=Console(
            ["RESTORE AUTHORITY", "SIGN RESTORE CERTIFICATE"], [RECOVERY_PASS, NEW_PASS, NEW_PASS],
        ),
        authority_transport=transport,
    )
    assert result["status"] == "restored"



@pytest.mark.parametrize("checkpoint", [
    "rotation_ledger_intent", "rotation_blob_published",
])
def test_rotation_crash_leaves_old_active_and_restart_reconciles(tmp_path, checkpoint):
    store, base = enrolled(tmp_path / checkpoint)

    class Crash(AuthorityService):
        def _checkpoint(self, name):
            if name == checkpoint:
                raise RuntimeError(name)

    crashing = Crash(base.data_root, store, operator_id=OPERATOR)
    with pytest.raises(RuntimeError, match=checkpoint):
        crashing.rotate_key(console=Console(
            ["ROTATE AUTHORITY KEY", "SIGN EXACT ROTATION"], [AUTH_PASS, NEW_PASS, NEW_PASS],
        ))
    assert base.reconcile()["active_bindings"] >= 1
    with store.connect() as conn:
        chain = verify_authority_chain(conn, expected_operator_id=OPERATOR)
    assert chain["head_sequence"] == 1
    assert len(chain["active_installations"]) == 1


def test_recovery_is_selectable_at_first_enrollment_and_published_before_commit(tmp_path):
    root = tmp_path / "source"
    offline = tmp_path / "offline"
    offline.mkdir()
    package = offline / "recovery.json"
    store = ImprintStore(root / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(root, store, operator_id=OPERATOR)
    result = service.enroll(
        recovery_destination=package,
        console=Console(
            ["ENROLL WITH-RECOVERY", "BIND INITIAL AUTHORITY"],
            [AUTH_PASS, AUTH_PASS, RECOVERY_PASS, RECOVERY_PASS],
        ),
    )
    assert result["recovery"] == "created"
    verified = verify_recovery_bundle(package)
    assert verified["chain"]["head_sequence"] == 1
    assert verified["manifest"]["authority_ledger_genesis_sha256"] == verified["chain"]["genesis_event_sha256"]
    with store.connect() as conn:
        anchor = load_authority_trust_anchor(conn)
        assert anchor.recovery_key_id == verified["manifest"]["recovery_key_id"]
        assert conn.execute("SELECT COUNT(*) FROM authority_checkpoint_pins").fetchone()[0] == 1
    assert not service._recovery_journal_path().exists()


def test_recovery_publication_crash_retains_bundle_and_journal_but_not_ledger_activation(tmp_path):
    store, base = enrolled(tmp_path / "source")
    offline = tmp_path / "offline"
    offline.mkdir()
    package = offline / "recovery.json"

    class Crash(AuthorityService):
        def _checkpoint(self, name):
            if name == "recovery_bundle_published":
                raise RuntimeError(name)

    crashing = Crash(base.data_root, store, operator_id=OPERATOR)
    with pytest.raises(RuntimeError, match="recovery_bundle_published"):
        crashing.create_recovery_bundle(
            package,
            console=Console(
                ["CREATE RECOVERY", "BIND RECOVERY KEY"],
                [AUTH_PASS, RECOVERY_PASS, RECOVERY_PASS],
            ),
        )
    assert package.is_file()
    assert crashing._recovery_journal_path().is_file()
    with store.connect() as conn:
        chain = verify_authority_chain(conn, expected_operator_id=OPERATOR)
        anchor = load_authority_trust_anchor(conn)
    assert chain["head_sequence"] == 1
    assert anchor.recovery_key_id is None
    with pytest.raises(ValidationError, match="unfinished recovery publication"):
        crashing.create_recovery_bundle(
            offline / "retry.json",
            console=Console(
                ["CREATE RECOVERY", "BIND RECOVERY KEY"],
                [AUTH_PASS, RECOVERY_PASS, RECOVERY_PASS],
            ),
        )


def test_active_machine_pairing_uses_two_roots_and_destination_owned_pending_key(tmp_path):
    source_root = tmp_path / "source"
    offline = tmp_path / "offline"
    offline.mkdir()
    recovery = offline / "recovery.json"
    source_store = ImprintStore(source_root / "imprint.db", expected_operator_id=OPERATOR)
    source = AuthorityService(source_root, source_store, operator_id=OPERATOR)
    source.enroll(
        recovery_destination=recovery,
        console=Console(
            ["ENROLL WITH-RECOVERY", "BIND INITIAL AUTHORITY"],
            [AUTH_PASS, AUTH_PASS, RECOVERY_PASS, RECOVERY_PASS],
        ),
    )

    target_root = tmp_path / "target"
    target_store = ImprintStore(target_root / "imprint.db", expected_operator_id=OPERATOR)
    target = AuthorityService(target_root, target_store, operator_id=OPERATOR)
    target.bootstrap_recovery_trust(
        recovery, console=Console(["PIN RECOVERY TRUST"], [RECOVERY_PASS]),
    )
    request_path = offline / "pairing-request.json"
    requested = target.create_pairing_request(
        request_path,
        console=Console(["CREATE PAIRING REQUEST"], [NEW_PASS, NEW_PASS]),
    )
    assert not list(source_root.glob("**/*" + requested["request"]["public_key_fingerprint"].removeprefix("sha256:" ) + "*.blob"))
    package_path = offline / "pairing-package.json"
    source.authorize_pairing_request(
        request_path, package_path,
        console=Console(["AUTHORIZE EXACT PAIRING"], [AUTH_PASS]),
    )
    paired = target.finalize_pairing(
        package_path, console=Console(["FINALIZE EXACT PAIRING"]),
    )
    assert paired["install_id"] == requested["request"]["install_id"]
    with target_store.connect() as conn:
        chain = verify_authority_chain(conn, expected_operator_id=OPERATOR)
        anchor = load_authority_trust_anchor(conn)
        assert chain["keys"][paired["key_id"]]["status"] == "active"
        assert anchor.pinned_head_sha256 == chain["head_sha256"]
    target.create_checkpoint(console=Console(secrets=[NEW_PASS]))


def test_conflict_proofs_persist_write_block_until_recovery_signed_adjudication(tmp_path):
    root = tmp_path / "source"
    offline = tmp_path / "offline"
    offline.mkdir()
    recovery = offline / "recovery.json"
    store = ImprintStore(root / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(root, store, operator_id=OPERATOR)
    service.enroll(
        recovery_destination=recovery,
        console=Console(
            ["ENROLL WITH-RECOVERY", "BIND INITIAL AUTHORITY"],
            [AUTH_PASS, AUTH_PASS, RECOVERY_PASS, RECOVERY_PASS],
        ),
    )
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        anchor = load_authority_trust_anchor(conn)
        proof_id = retain_authority_conflict(
            conn, conflict_class="equal-sequence-different-head",
            local_proof={"checkpoint": anchor.checkpoint},
            candidate_proof={"checkpoint": {**anchor.checkpoint, "event_sha256": "f" * 64}},
        )
        conn.commit()
    with pytest.raises(ValidationError, match="writes are blocked"):
        service.create_checkpoint(console=Console(secrets=[AUTH_PASS]))
    result = service.adjudicate_authority_conflict(
        proof_id, chosen_checkpoint_sha256=anchor.checkpoint_sha256,
        reason="retain the physically pinned checkpoint", recovery_bundle=recovery,
        console=Console(["ADJUDICATE EXACT CONFLICT"], [RECOVERY_PASS]),
    )
    assert result["status"] == "adjudicated"
    with store.connect() as conn:
        anchor_after = load_authority_trust_anchor(conn)
        proof = conn.execute(
            "SELECT adjudication_event_sha256 FROM authority_equivocation_proofs WHERE proof_id=?",
            (proof_id,),
        ).fetchone()
    assert anchor_after.writes_blocked is False
    assert proof[0] == result["event_sha256"]


def test_transfer_prepare_finalize_is_destination_owned_commit_last_and_idempotent(tmp_path):
    source_root, target_root = tmp_path / "source", tmp_path / "target"
    offline = tmp_path / "offline"
    offline.mkdir()
    recovery, transport_path = offline / "recovery.json", offline / "transport.json"
    source_store = ImprintStore(source_root / "imprint.db", expected_operator_id=OPERATOR)
    source = AuthorityService(source_root, source_store, operator_id=OPERATOR)
    source.enroll(
        recovery_destination=recovery,
        console=Console(
            ["ENROLL WITH-RECOVERY", "BIND INITIAL AUTHORITY"],
            [AUTH_PASS, AUTH_PASS, RECOVERY_PASS, RECOVERY_PASS],
        ),
    )
    fresh_transport(source, transport_path)
    transport = json.loads(transport_path.read_text())

    target_store = ImprintStore(target_root / "imprint.db", expected_operator_id=OPERATOR)
    target = AuthorityService(target_root, target_store, operator_id=OPERATOR)
    target.bootstrap_recovery_trust(
        recovery, console=Console(["PIN RECOVERY TRUST"], [RECOVERY_PASS]),
    )
    target.create_pairing_request(
        offline / "unused-pairing-request.json",
        console=Console(["CREATE PAIRING REQUEST"], [NEW_PASS, NEW_PASS]),
    )
    with target_store.connect() as destination, source_store.connect() as source_conn:
        anchor = load_authority_trust_anchor(destination)
        verified = verify_authority_transfer(
            source_conn, local_anchor=anchor, checkpoint=transport["checkpoint"],
            checkpoint_history=transport["checkpoint_history"],
        )
        before = anchor.digest()
        destination.execute("BEGIN IMMEDIATE")
        prepare_checkpoint_advance(destination, verified, "d" * 64)
        destination.rollback()  # dry-run/crash cannot advance the anchor
        assert load_authority_trust_anchor(destination).digest() == before

        destination.execute("BEGIN IMMEDIATE")
        ticket = prepare_checkpoint_advance(destination, verified, "d" * 64)
        advanced = finalize_anchor_advance(destination, ticket)
        destination.commit()
        assert advanced.checkpoint_sha256 == sha256_hex(canonical_bytes(transport["checkpoint"]))
        destination.execute("BEGIN IMMEDIATE")
        repeated = finalize_anchor_advance(destination, ticket)
        destination.commit()
        assert repeated.digest() == advanced.digest()
