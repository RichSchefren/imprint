from __future__ import annotations

import base64
import copy
import hashlib
import json
import io
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

from imprint.authority import ApprovalToken, AuthorityService, ChallengeRequest
from imprint.authority.challenge import canonical_bytes, signature_message
from imprint.authority.ledger import prepare_mutation
from imprint.errors import ConflictError, ValidationError
from imprint.store import ImprintStore


OPERATOR = "urn:imprint:operator:22222222-2222-4222-8222-222222222222"
ZERO_SHA = "0" * 64


class FakeNativeConsole:
    def __init__(self, lines=(), secrets=(), *, native=True):
        self.lines = iter(lines)
        self.secrets = iter(secrets)
        self.native = native
        self.output = []

    def require_native(self):
        if not self.native:
            raise ValidationError("native TTY/console is required for authority operations")

    def write(self, value):
        self.output.append(value)

    def read_line(self, prompt):
        self.output.append(prompt)
        return next(self.lines)

    def read_secret(self, prompt):
        self.output.append(prompt)
        return next(self.secrets)


@pytest.fixture(scope="module")
def authority(tmp_path_factory):
    root = tmp_path_factory.mktemp("authority")
    store = ImprintStore(root / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(root, store, operator_id=OPERATOR)
    console = FakeNativeConsole(
        ["ENROLL DECLINE-RECOVERY"],
        ["correct horse battery staple", "correct horse battery staple"],
    )
    receipt = service.enroll(console=console)
    return root, store, service, receipt


def request(operation_id="urn:imprint:operation:test"):
    return ChallengeRequest(
        operation_id=operation_id,
        purpose="ratify exact proposal",
        payload_sha256=hashlib.sha256(b"payload").hexdigest(),
        prior_state_sha256=ZERO_SHA,
        execution_fields_sha256=hashlib.sha256(b"{}").hexdigest(),
        authority_transition="proposal_to_ratified_knowledge",
        subject_ids=("urn:imprint:node:subject",),
        proposal_ids=("urn:imprint:proposal:source",),
        scope=("operator",),
        field_paths=("/authority_tier",),
    )


def approve(service, req):
    with service.store.connect() as conn:
        prepared = conn.execute(
            "SELECT 1 FROM authority_prepared_mutations WHERE operation_id=?",
            (req.operation_id,),
        ).fetchone()
    if prepared is None:
        with service.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            prepare_mutation(
                conn, command_name="authority-test", request=req,
                intent={"operation_id": req.operation_id}, prior_state={},
                execution_fields={}, operator_id=service.operator_id, clock=service.clock,
            )
    console = FakeNativeConsole(["APPROVE"], ["correct horse battery staple"])
    return service.approve(req, console=console)


def test_enrollment_is_self_signed_and_blob_is_private(authority):
    root, store, service, receipt = authority
    assert receipt["recovery"] == "explicitly_declined"
    assert receipt["ledger_sequence"] == 1
    assert "passphrase" not in json.dumps(receipt).lower()
    assert service.reconcile() == {"quarantined_orphans": 0, "active_bindings": 1}
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM authority_ledger").fetchone()[0] == 1
        binding = conn.execute("SELECT * FROM authority_keys").fetchone()
        assert binding["operator_id"] == OPERATOR
        assert binding["blob_sha256"]
    blob = next((root / "authority" / "keys").glob("*.blob"))
    assert blob.stat().st_mode & 0o077 == 0
    assert b"correct horse" not in blob.read_bytes()


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner/mode fail-closed contract")
def test_committed_key_unsafe_mode_fails_closed_without_repair(authority):
    root, _, service, _ = authority
    blob = next((root / "authority" / "keys").glob("*.blob"))
    try:
        blob.chmod(0o644)
        with pytest.raises(ValidationError, match="unsafe permissions"):
            service.reconcile()
        assert blob.stat().st_mode & 0o777 == 0o644
    finally:
        blob.chmod(0o600)


def test_approval_consumes_nonce_and_provenance_atomically(authority):
    _, store, service, _ = authority
    req = request("urn:imprint:operation:atomic")
    token = approve(service, req)
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        provenance_id = service.verify_and_consume(conn, token, expected=req)
    with store.connect() as conn:
        row = conn.execute("SELECT * FROM authority_provenance WHERE provenance_id=?", (provenance_id,)).fetchone()
        assert row["operator_id"] == OPERATOR
        assert row["challenge_sha256"] == hashlib.sha256(canonical_bytes(token.challenge)).hexdigest()
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(ConflictError, match="already been consumed"):
            service.verify_and_consume(conn, token, expected=req)


def test_failed_mutation_rolls_back_nonce_and_provenance(authority):
    _, store, service, _ = authority
    req = request("urn:imprint:operation:rollback")
    token = approve(service, req)
    with pytest.raises(RuntimeError):
        with store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            service.verify_and_consume(conn, token, expected=req)
            raise RuntimeError("simulated mutation failure")
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        assert service.verify_and_consume(conn, token, expected=req).startswith(
            "urn:imprint:authority-provenance:"
        )


@pytest.mark.parametrize("mutation", ["payload", "subject", "scope", "prior"])
def test_changed_exact_mutation_is_rejected_without_consumption(authority, mutation):
    _, store, service, _ = authority
    req = request(f"urn:imprint:operation:changed-{mutation}")
    token = approve(service, req)
    values = dict(req.__dict__)
    if mutation == "payload":
        values["payload_sha256"] = "1" * 64
    elif mutation == "prior":
        values["prior_state_sha256"] = "2" * 64
    elif mutation == "subject":
        values["subject_ids"] = ("urn:imprint:node:other",)
    else:
        values["scope"] = ("other",)
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValidationError, match="exact mutation"):
            service.verify_and_consume(conn, token, expected=ChallengeRequest(**values))
    with store.connect() as conn:
        consumed = conn.execute(
            "SELECT consumed_at FROM authority_challenges WHERE operation_id=?",
            (req.operation_id,),
        ).fetchone()[0]
        assert consumed is None


def test_signature_or_key_copy_cannot_cross_operator_binding(authority):
    root, store, service, _ = authority
    req = request("urn:imprint:operation:operator-copy")
    token = approve(service, req)
    copied = copy.deepcopy(token.as_dict())
    copied["challenge"]["operator_id"] = "urn:imprint:operator:attacker"
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValidationError, match="operator or installation"):
            service.verify_and_consume(conn, copied, expected=req)


def test_expired_token_fails_without_db_delta(tmp_path):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    root = tmp_path
    store = ImprintStore(root / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(root, store, operator_id=OPERATOR, clock=lambda: now)
    service.enroll(console=FakeNativeConsole(
        ["ENROLL DECLINE-RECOVERY"], ["correct horse battery staple"] * 2,
    ))
    req = request("urn:imprint:operation:expired")
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        prepare_mutation(
            conn, command_name="authority-test", request=req,
            intent={"operation_id": req.operation_id}, prior_state={}, execution_fields={},
            operator_id=OPERATOR, clock=service.clock,
        )
    token = service.approve(
        req, console=FakeNativeConsole(["APPROVE"], ["correct horse battery staple"]),
        ttl_seconds=1,
    )
    expired_service = AuthorityService(
        root, store, operator_id=OPERATOR, clock=lambda: now + timedelta(seconds=1),
    )
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValidationError, match="not currently valid"):
            expired_service.verify_and_consume(conn, token, expected=req)
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM authority_provenance").fetchone()[0] == 0


def test_non_native_enrollment_and_approval_fail(authority, tmp_path):
    store = ImprintStore(tmp_path / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(tmp_path, store, operator_id=OPERATOR)
    with pytest.raises(ValidationError, match="native TTY"):
        service.enroll(console=FakeNativeConsole(native=False))
    _, _, enrolled, _ = authority
    with pytest.raises(ValidationError, match="native TTY"):
        enrolled.approve(request("urn:imprint:operation:headless"), console=FakeNativeConsole(native=False))


def test_redirected_process_stdin_cannot_raise_authority(monkeypatch):
    from imprint.authority.tty import NativeConsole

    monkeypatch.setattr(sys, "stdin", io.StringIO("APPROVE\nsecret\n"))
    with pytest.raises(ValidationError, match="redirected stdin"):
        NativeConsole().require_native()


def test_non_executable_standalone_proposal_surface_is_absent(authority):
    _, _, service, _ = authority
    assert not hasattr(service, "proposal")


def test_authority_provenance_is_immutable(authority):
    _, store, _, _ = authority
    with store.connect() as conn:
        with pytest.raises(Exception, match="immutable"):
            conn.execute("UPDATE authority_provenance SET authority_transition='forged'")


def test_verification_requires_callers_mutation_transaction(authority):
    _, store, service, _ = authority
    req = request("urn:imprint:operation:no-transaction")
    token = approve(service, req)
    with store.connect() as conn:
        with pytest.raises(ValidationError, match="active mutation transaction"):
            service.verify_and_consume(conn, token, expected=req)


def test_unsigned_capture_stays_candidate_then_signed_promotion_succeeds(authority):
    from imprint.capture import build_capture_envelope

    _, store, service, _ = authority
    envelope = build_capture_envelope(
        operator_id=OPERATOR,
        session_id="urn:imprint:session:11111111-1111-4111-8111-111111111111",
        node_id="primary",
        case_description="A concrete decision",
        raw_operator_text="That is exactly right",
        call_type="accept",
        capture_mechanism="explicit_cli",
        captured_by="imprint-recorder",
    )
    store.expected_node_id = "primary"
    assert store.apply_capture(envelope) == "captured"
    verdict_id = envelope["verdict"]["verdict_id"]
    current = next(item for item in store.current_nodes(["Verdict"]) if item["node_id"] == verdict_id)
    assert current["authority_tier"] == "observed_candidate"
    assert current["provenance"]["actor_class"] == "software"

    with pytest.raises(ValidationError, match="E_AUTH_APPROVAL_REQUIRED") as denied:
        store.ratify_node(verdict_id, ratifier=OPERATOR, note="human confirmed")
    request_json = denied.value.args[0].split("approval_request=", 1)[1]
    request_value = json.loads(request_json)
    approval_request = ChallengeRequest(**{
        **{name: request_value[name] for name in (
            "operation_id", "purpose", "payload_sha256", "prior_state_sha256",
            "execution_fields_sha256",
            "authority_transition",
        )},
        **{name: tuple(request_value[name]) for name in (
            "subject_ids", "source_ids", "target_ids", "proposal_ids",
            "result_version_ids", "scope", "field_paths",
        )},
    })
    token = approve(service, approval_request)
    store.ratify_node(
        verdict_id, ratifier=OPERATOR, note="human confirmed",
        approval_token=token.as_dict(),
    )
    promoted = next(item for item in store.current_nodes(["Verdict"]) if item["node_id"] == verdict_id)
    assert promoted["provenance_status"] == "captured"
    assert promoted["authority_tier"] == "captured_judgment"
    assert promoted["provenance"]["actor_class"] == "operator"


@pytest.mark.parametrize("tamper", ["generated_id", "system_time", "stored_hash"])
def test_signed_execution_fields_reject_id_time_or_hash_tampering(authority, tamper):
    from imprint.capture import build_capture_envelope

    _, store, service, _ = authority
    envelope = build_capture_envelope(
        operator_id=OPERATOR,
        session_id="urn:imprint:session:22222222-2222-4222-8222-222222222222",
        node_id="primary",
        case_description=f"Prepared execution tamper test: {tamper}",
        raw_operator_text=f"Keep exact generated fields: {tamper}",
        call_type="correct",
        capture_mechanism="explicit_cli",
        captured_by="imprint-recorder",
    )
    store.expected_node_id = "primary"
    store.apply_capture(envelope)
    verdict_id = envelope["verdict"]["verdict_id"]
    with pytest.raises(ValidationError, match="E_AUTH_APPROVAL_REQUIRED") as denied:
        store.ratify_node(verdict_id, ratifier=OPERATOR, note="exact")
    request_value = json.loads(str(denied.value).split("approval_request=", 1)[1])
    approval_request = ChallengeRequest(**{
        **{name: request_value[name] for name in (
            "operation_id", "purpose", "payload_sha256", "prior_state_sha256",
            "execution_fields_sha256", "authority_transition",
        )},
        **{name: tuple(request_value[name]) for name in (
            "subject_ids", "source_ids", "target_ids", "proposal_ids",
            "result_version_ids", "scope", "field_paths",
        )},
    })
    token = approve(service, approval_request)
    with store.connect() as conn:
        row = conn.execute(
            "SELECT execution_fields_json,execution_fields_sha256 FROM authority_prepared_mutations WHERE operation_id=?",
            (approval_request.operation_id,),
        ).fetchone()
        execution = json.loads(row["execution_fields_json"])
        conn.execute("DROP TRIGGER IF EXISTS authority_prepared_content_immutable")
        if tamper == "generated_id":
            execution["event_id"] = "urn:imprint:event:00000000-0000-4000-8000-000000000000"
            conn.execute(
                "UPDATE authority_prepared_mutations SET execution_fields_json=? WHERE operation_id=?",
                (canonical_bytes(execution).decode(), approval_request.operation_id),
            )
        elif tamper == "system_time":
            execution["system_time"] = "2099-01-01T00:00:00Z"
            conn.execute(
                "UPDATE authority_prepared_mutations SET execution_fields_json=? WHERE operation_id=?",
                (canonical_bytes(execution).decode(), approval_request.operation_id),
            )
        else:
            conn.execute(
                "UPDATE authority_prepared_mutations SET execution_fields_sha256=? WHERE operation_id=?",
                ("f" * 64, approval_request.operation_id),
            )
    with pytest.raises(ValidationError, match="execution-fields digest|does not bind"):
        store.ratify_node(
            verdict_id, ratifier=OPERATOR, note="exact",
            approval_token=token.as_dict(),
        )
    current = next(item for item in store.current_nodes(["Verdict"]) if item["node_id"] == verdict_id)
    assert current["authority_tier"] == "observed_candidate"
    with store.connect() as conn:
        assert conn.execute(
            "SELECT consumed_at FROM authority_challenges WHERE operation_id=?",
            (approval_request.operation_id,),
        ).fetchone()[0] is None


@pytest.mark.parametrize(
    ("checkpoint", "orphan_count"),
    [
        ("staging_durable", 0),
        ("sqlite_intent_inserted", 0),
        ("blob_published", 1),
        ("blob_reverified", 1),
    ],
)
def test_crash_before_commit_does_not_activate_authority(
    tmp_path, monkeypatch, checkpoint, orphan_count,
):
    store = ImprintStore(tmp_path / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(tmp_path, store, operator_id=OPERATOR)

    def crash(name):
        if name == checkpoint:
            raise RuntimeError(f"simulated crash at {checkpoint}")

    monkeypatch.setattr(service, "_checkpoint", crash)
    with pytest.raises(RuntimeError, match="simulated crash"):
        service.enroll(console=FakeNativeConsole(
            ["ENROLL DECLINE-RECOVERY"], ["correct horse battery staple"] * 2,
        ))
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM authority_ledger").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM authority_keys").fetchone()[0] == 0
    assert not list((tmp_path / "authority" / "keys").glob("*.blob"))
    quarantine = tmp_path / "authority" / "quarantine"
    observed_orphans = len(list(quarantine.glob("*.blob"))) if quarantine.exists() else 0
    assert observed_orphans == orphan_count


def test_crash_after_commit_recovers_complete_authority(tmp_path, monkeypatch):
    store = ImprintStore(tmp_path / "imprint.db", expected_operator_id=OPERATOR)
    service = AuthorityService(tmp_path, store, operator_id=OPERATOR)

    def crash(name):
        if name == "sqlite_committed":
            raise RuntimeError("simulated crash after commit")

    monkeypatch.setattr(service, "_checkpoint", crash)
    with pytest.raises(RuntimeError, match="after commit"):
        service.enroll(console=FakeNativeConsole(
            ["ENROLL DECLINE-RECOVERY"], ["correct horse battery staple"] * 2,
        ))
    monkeypatch.setattr(service, "_checkpoint", lambda name: None)
    assert service.reconcile() == {"quarantined_orphans": 0, "active_bindings": 1}
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM authority_ledger").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM authority_keys WHERE status='active'").fetchone()[0] == 1
