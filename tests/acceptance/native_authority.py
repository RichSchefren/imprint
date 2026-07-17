#!/usr/bin/env python3
"""Native-console authority acceptance driver; never uses a console test double."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from imprint.authority import AuthorityService, ChallengeRequest, verify_authority_chain
from imprint.capture import build_capture_envelope
from imprint.errors import ConflictError, ValidationError
from imprint.store import ImprintStore


def request_from_error(error: ValidationError) -> ChallengeRequest:
    prefix = "E_AUTH_APPROVAL_REQUIRED approval_request="
    if not str(error).startswith(prefix):
        raise error
    value = json.loads(str(error)[len(prefix):])
    return ChallengeRequest(
        operation_id=value["operation_id"], purpose=value["purpose"],
        payload_sha256=value["payload_sha256"], prior_state_sha256=value["prior_state_sha256"],
        execution_fields_sha256=value["execution_fields_sha256"],
        authority_transition=value["authority_transition"],
        subject_ids=tuple(value["subject_ids"]), source_ids=tuple(value["source_ids"]),
        target_ids=tuple(value["target_ids"]), proposal_ids=tuple(value["proposal_ids"]),
        result_version_ids=tuple(value["result_version_ids"]), scope=tuple(value["scope"]),
        field_paths=tuple(value["field_paths"]),
    )


def full(root: Path, operator: str) -> None:
    if not sys.stdin.isatty():
        raise SystemExit("native acceptance requires an attached terminal")
    store = ImprintStore(root / "imprint.db", expected_operator_id=operator, expected_node_id="native")
    service = AuthorityService(root, store, operator_id=operator)
    service.enroll()
    envelope = build_capture_envelope(
        operator_id=operator,
        session_id="urn:imprint:session:22222222-2222-4222-8222-222222222222",
        node_id="native", case_description="Native console authority acceptance",
        raw_operator_text="Preserve exact signed execution fields", call_type="correct",
        capture_mechanism="explicit_cli", captured_by="native-acceptance",
    )
    store.apply_capture(envelope)
    verdict_id = envelope["verdict"]["verdict_id"]
    try:
        store.ratify_node(verdict_id, ratifier=operator, note="native approval")
    except ValidationError as error:
        request = request_from_error(error)
    else:
        raise SystemExit("unsigned native mutation did not fail closed")
    token = service.approve(request)
    store.ratify_node(
        verdict_id, ratifier=operator, note="native approval", approval_token=token.as_dict(),
    )
    current = next(item for item in store.current_nodes(["Verdict"]) if item["node_id"] == verdict_id)
    if current["authority_tier"] != "captured_judgment":
        raise SystemExit("signed native promotion did not commit")
    print(json.dumps({"status": "PASS", "blob": service.reconcile(), "verdict_id": verdict_id}))


def verify_unsafe(root: Path, operator: str) -> None:
    service = AuthorityService(
        root, ImprintStore(root / "imprint.db", expected_operator_id=operator), operator_id=operator,
    )
    try:
        service.reconcile()
    except ValidationError as error:
        if "unsafe permissions" not in str(error):
            raise
        print(json.dumps({"status": "PASS", "unsafe_key_rejected": True}))
        return
    raise SystemExit("unsafe committed key was accepted or silently repaired")


def crash_reconcile(root: Path, operator: str) -> None:
    if not sys.stdin.isatty():
        raise SystemExit("native acceptance requires an attached terminal")
    store = ImprintStore(root / "imprint.db", expected_operator_id=operator)

    class CrashService(AuthorityService):
        def _checkpoint(self, name: str) -> None:
            if name == "blob_published":
                raise RuntimeError("native simulated crash after blob publication")

    try:
        CrashService(root, store, operator_id=operator).enroll()
    except RuntimeError as error:
        if "native simulated crash" not in str(error):
            raise
    else:
        raise SystemExit("crash checkpoint did not fire")
    quarantine = root / "authority" / "quarantine"
    retained = list(quarantine.glob("orphan-*.blob")) if quarantine.exists() else []
    if len(retained) != 1:
        raise SystemExit(f"crash cleanup did not retain exactly one quarantined key: {retained}")
    result = AuthorityService(root, store, operator_id=operator).reconcile()
    if result != {"quarantined_orphans": 0, "active_bindings": 0}:
        raise SystemExit(f"unexpected crash reconciliation: {result}")
    print(json.dumps({
        "status": "PASS", "crash_reconciliation": result,
        "retained_quarantined_keys": len(retained),
    }))


def lifecycle(root: Path, operator: str) -> None:
    """Exercise recovery, fresh transport, two-root pairing, rotation, and revocation."""
    if not sys.stdin.isatty():
        raise SystemExit("native acceptance requires an attached terminal")
    offline = root.parent / f"{root.name}-offline"
    restored_root = root.parent / f"{root.name}-restored"
    paired_root = root.parent / f"{root.name}-paired"
    offline.mkdir(mode=0o700)
    recovery = offline / "recovery.json"
    transport = offline / "transport.json"
    request = offline / "pairing-request.json"
    package = offline / "pairing-package.json"

    source_store = ImprintStore(root / "imprint.db", expected_operator_id=operator)
    source = AuthorityService(root, source_store, operator_id=operator)
    source.enroll(recovery_destination=recovery)
    source.export_authority_transport(transport)

    restored_store = ImprintStore(restored_root / "imprint.db", expected_operator_id=operator)
    restored = AuthorityService(restored_root, restored_store, operator_id=operator)
    restored.bootstrap_recovery_trust(recovery)
    restored.restore_recovery_bundle(recovery, authority_transport=transport)

    paired_store = ImprintStore(paired_root / "imprint.db", expected_operator_id=operator)
    paired = AuthorityService(paired_root, paired_store, operator_id=operator)
    paired.bootstrap_recovery_trust(recovery)
    paired.create_pairing_request(request)
    source.authorize_pairing_request(request, package)
    paired_result = paired.finalize_pairing(package)
    try:
        paired.finalize_pairing(package)
    except (ConflictError, ValidationError):
        pass
    else:
        raise SystemExit("pairing replay was accepted")

    rotated = source.rotate_key()
    source.change_key_state(
        paired_result["key_id"], state="revoked",
        reason="native lifecycle acceptance revocation",
        replacement_key_id=rotated["key_id"],
    )
    with source_store.connect() as conn:
        chain = verify_authority_chain(conn, expected_operator_id=operator)
    if chain["keys"][paired_result["key_id"]]["status"] != "revoked":
        raise SystemExit("native pairing revocation was not committed")
    print(json.dumps({
        "status": "PASS", "recovery": str(recovery),
        "restored_installations": 2, "paired_key": paired_result["key_id"],
        "rotated_key": rotated["key_id"], "revoked_pair": True,
    }))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("full", "verify-unsafe", "crash-reconcile", "lifecycle"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--operator", required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    {"full": full, "verify-unsafe": verify_unsafe, "crash-reconcile": crash_reconcile,
     "lifecycle": lifecycle}[args.mode](
        args.root, args.operator,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
