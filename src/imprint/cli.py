"""Command-line surface for the local canonical system."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .compiler import compile_spools, write_envelope
from .config import load_config, resolved_operator_root
from .durable_io import publish_new_private
from .errors import ImprintError, ValidationError
from .projections import markdown_document
from .permissions import secure_directory, secure_file, secure_tree
from .store import ImprintStore


def _store(root: Path) -> ImprintStore:
    return ImprintStore(root / "imprint.db")


def _write_json(value) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=False))
    sys.stdout.flush()


def _emit_retrieval_json(value: dict, *, root: Path, session_id: str,
                         snapshot_id: str, domain_id: str | None) -> None:
    """Flush payload at the outermost available boundary before committing it."""
    from .retrieve import commit_payload_delivery

    deferred = os.environ.get("IMPRINT_DEFER_DELIVERY_COMMIT") == "1"
    if deferred:
        value = dict(value)
        value["_imprint_delivery"] = {
            "session_id": session_id,
            "snapshot_id": snapshot_id,
            "domain_id": domain_id,
        }
    _write_json(value)
    if not deferred:
        commit_payload_delivery(
            root=root, session_id=session_id, snapshot_id=snapshot_id,
            domain_id=domain_id,
        )


def _validate_hook_event(event: dict, expected: str) -> None:
    schema = event.get("hook_schema_version")
    if schema is not None and schema != "1.0.0":
        raise ValidationError("unsupported hook_schema_version")
    native_name = event.get("hook_event_name")
    if native_name is not None and native_name != expected:
        raise ValidationError(f"hook_event_name must be {expected}")
    for field in ("session_id", "sessionId", "cwd", "working_directory", "transcript_path", "source"):
        if field in event and not isinstance(event[field], str):
            raise ValidationError(f"hook field {field} must be a string")


def _operator_urn(root: Path) -> str:
    """Create one local opaque operator identity without deriving personal data."""
    target = root / "identity.json"
    if target.exists():
        secure_file(target)
        value = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(value, dict) and str(value.get("operator_id", "")).startswith("urn:imprint:operator:"):
            return str(value["operator_id"])
        raise ImprintError("operator identity is corrupt")
    secure_directory(root)
    operator_id = f"urn:imprint:operator:{uuid.uuid4()}"
    fd, temporary = tempfile.mkstemp(prefix=".identity-", dir=root)
    temporary_path = Path(temporary)
    os.close(fd)
    try:
        secure_file(temporary_path)
        with temporary_path.open("w", encoding="utf-8") as handle:
            json.dump({"identity_schema_version": "1.0.0", "operator_id": operator_id}, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(temporary_path)
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        try:
            os.link(temporary, target)
        except FileExistsError:
            return _operator_urn(root)
    finally:
        temporary_path.unlink(missing_ok=True)
    secure_file(target)
    return operator_id


def _session_key(root: Path) -> bytes:
    """Return an installation-local key without persisting provider session IDs."""
    target = root / "session-map.key"
    if target.exists():
        secure_file(target)
        try:
            encoded = target.read_text(encoding="ascii").strip()
            key = bytes.fromhex(encoded)
        except (OSError, ValueError) as exc:
            raise ImprintError("session mapping key is corrupt") from exc
        if len(key) != 32:
            raise ImprintError("session mapping key is corrupt")
        return key
    secure_directory(root)
    encoded = secrets.token_hex(32)
    fd, temporary = tempfile.mkstemp(prefix=".session-map-", dir=root)
    temporary_path = Path(temporary)
    os.close(fd)
    try:
        secure_file(temporary_path)
        with temporary_path.open("w", encoding="ascii") as handle:
            handle.write(encoded + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        secure_file(temporary_path)
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        try:
            os.link(temporary, target)
        except FileExistsError:
            return _session_key(root)
    finally:
        temporary_path.unlink(missing_ok=True)
    secure_file(target)
    return bytes.fromhex(encoded)


def _opaque_session_urn(root: Path, native_session_id: str) -> str:
    """Map a native session to a stable opaque UUID without storing the input."""
    digest = hmac.new(
        _session_key(root), native_session_id.encode("utf-8"), hashlib.sha256,
    ).digest()
    mapped = uuid.UUID(bytes=digest[:16], version=4)
    return f"urn:imprint:session:{mapped}"


def _message_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(
            item["text"] for item in value
            if isinstance(item, dict) and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        )
    return ""


def _truncate_utf8(value: str, byte_limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= byte_limit:
        return value, False
    return encoded[:byte_limit].decode("utf-8", errors="ignore"), True


def _parse_large_native_transcript(path_value: str, *, snapshot=None) -> dict:
    """Recover final feedback from a huge transcript using a bounded tail read."""
    from .capture.transcript import _read_native_transcript_snapshot
    from .errors import ValidationError

    tail_limit = 2 * 1024 * 1024
    if snapshot is None:
        snapshot = _read_native_transcript_snapshot(path_value, tail_limit=tail_limit)
    size = snapshot.size
    offset = snapshot.offset
    tail = snapshot.data
    if offset:
        newline = tail.find(b"\n")
        tail = tail[newline + 1:] if newline >= 0 else b""
    try:
        decoded_lines = tail.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise ValidationError("transcript tail is not valid UTF-8") from exc
    messages: list[tuple[str, str]] = []
    skipped_malformed_lines: list[int] = []
    for number, raw_line in enumerate(decoded_lines, start=1):
        complete = raw_line.endswith(("\n", "\r"))
        raw = raw_line.rstrip("\r\n")
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            if not complete and number == len(decoded_lines):
                raise ValidationError(f"incomplete transcript line {number}") from exc
            skipped_malformed_lines.append(number)
            continue
        if not isinstance(item, dict) or item.get("type") not in {"user", "assistant"}:
            continue
        message = item.get("message")
        if not isinstance(message, dict):
            continue
        text = _message_text(message.get("content"))
        if text.strip():
            messages.append((item["type"], text))
    user_indexes = [index for index, (kind, _) in enumerate(messages) if kind == "user"]
    if not user_indexes:
        raise ValidationError("bounded transcript tail contains no user message")
    user_index = user_indexes[-1]
    operator_text = messages[user_index][1]
    prior_assistant = next(
        (messages[index][1] for index in range(user_index - 1, -1, -1)
         if messages[index][0] == "assistant"),
        None,
    )
    context_truncated = False
    if prior_assistant is not None:
        prior_assistant, context_truncated = _truncate_utf8(prior_assistant, 64 * 1024)
    evidence_sha256 = hashlib.sha256(tail).hexdigest()
    return {
        "operator_text": operator_text,
        "prior_assistant_output": prior_assistant,
        "case_description": "Explicit operator feedback witnessed in a bounded Claude Code transcript tail",
        "source_locator": f"transcript-tail:sha256:{evidence_sha256}",
        "degradation": {
            "schema_version": "1.0.0",
            "payload": {
                "transcript_bytes": size,
                "tail_bytes_examined": len(tail),
                "evidence_sha256": evidence_sha256,
                "hash_scope": "bounded_tail",
                "truncated": True,
                "context_truncated": context_truncated or offset > 0,
                "receipt": "huge_transcript_bounded_tail",
                "skipped_malformed_line_count": len(skipped_malformed_lines),
                "skipped_malformed_lines": skipped_malformed_lines,
            },
        },
    }


def _authority_request(path: Path):
    """Load one closed authority mutation request from a local proposal file."""
    from .authority import ChallengeRequest

    value = json.loads(path.read_text(encoding="utf-8"))
    fields = {
        "operation_id", "purpose", "payload_sha256", "prior_state_sha256", "execution_fields_sha256",
        "authority_transition", "subject_ids", "source_ids", "target_ids",
        "proposal_ids", "result_version_ids", "scope", "field_paths",
    }
    required = {
        "operation_id", "purpose", "payload_sha256", "prior_state_sha256", "execution_fields_sha256",
        "authority_transition",
    }
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(fields):
        raise ValidationError("authority request has unknown or missing fields")
    for name in fields - required:
        value.setdefault(name, [])
    list_fields = fields - required
    if any(not isinstance(value[name], list) for name in list_fields):
        raise ValidationError("authority request ID/scope fields must be arrays")
    request = ChallengeRequest(**{
        **{name: value[name] for name in required},
        **{name: tuple(value[name]) for name in list_fields},
    })
    request.validate()
    return request


def _approval_token(args) -> dict | None:
    path = getattr(args, "approval_token", None)
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and set(value) == {"status", "approval_token"}:
        value = value["approval_token"]
    if not isinstance(value, dict):
        raise ValidationError("approval token file must contain one token object")
    return value


def _add_approval_token(command) -> None:
    command.add_argument(
        "--approval-token", type=Path,
        help="signed token from `imprint authority approve`; required for authority changes",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="imprint", description="Local-first captured judgment")
    parser.add_argument("--config", type=Path)
    subs = parser.add_subparsers(dest="command", required=True)

    authority = subs.add_parser("authority", help="enroll or issue human-present signed approvals")
    authority_subs = authority.add_subparsers(dest="authority_action", required=True)
    authority_enroll = authority_subs.add_parser(
        "enroll", help="perform the native-terminal first-trust ceremony",
    )
    authority_enroll.add_argument("--recovery-output", type=Path)
    authority_approve = authority_subs.add_parser(
        "approve", help="sign an exact short-lived mutation at the native terminal",
    )
    authority_approve.add_argument("--input", type=Path, required=True)
    authority_approve.add_argument("--ttl-seconds", type=int, default=120)
    authority_recovery_create = authority_subs.add_parser(
        "recovery-create", help="create a signed encrypted offline recovery bundle",
    )
    authority_recovery_create.add_argument("--output", type=Path, required=True)
    authority_subs.add_parser(
        "recovery-reconcile", help="explicitly abandon an interrupted recovery publication journal",
    )
    authority_recovery_restore = authority_subs.add_parser(
        "recovery-restore", help="restore and pair a fresh installation from recovery",
    )
    authority_recovery_restore.add_argument("--input", type=Path, required=True)
    authority_recovery_restore.add_argument("--authority-transport", type=Path, required=True)
    authority_recovery_restore.add_argument("--replace-install-id")
    authority_subs.add_parser("rotate", help="rotate the active local authority key")
    authority_checkpoint = authority_subs.add_parser(
        "checkpoint", help="issue a signed checkpoint valid for at most 24 hours",
    )
    authority_checkpoint.add_argument("--ttl-seconds", type=int, default=24 * 60 * 60)
    authority_transport = authority_subs.add_parser(
        "transport", help="publish a fresh physical checkpoint and full public chain",
    )
    authority_transport.add_argument("--output", type=Path, required=True)
    trust_bootstrap = authority_subs.add_parser(
        "trust-bootstrap", help="separately pin recovery trust on a fresh destination",
    )
    trust_bootstrap.add_argument("--input", type=Path, required=True)
    pairing_request = authority_subs.add_parser("pair-request", help="create a fresh target-machine pairing request")
    pairing_request.add_argument("--output", type=Path, required=True)
    pairing_authorize = authority_subs.add_parser("pair-authorize", help="authorize a target request from an active machine")
    pairing_authorize.add_argument("--input", type=Path, required=True)
    pairing_authorize.add_argument("--output", type=Path, required=True)
    pairing_finalize = authority_subs.add_parser("pair-finalize", help="finalize a signed pairing package on its target")
    pairing_finalize.add_argument("--input", type=Path, required=True)
    adjudicate = authority_subs.add_parser("adjudicate", help="recovery-sign an exact retained fork decision")
    adjudicate.add_argument("proof_id")
    adjudicate.add_argument("--chosen-checkpoint-sha256", required=True)
    adjudicate.add_argument("--reason", required=True)
    adjudicate.add_argument("--recovery-bundle", type=Path, required=True)
    for action in ("revoke", "compromise"):
        command = authority_subs.add_parser(action, help=f"append an authority key {action} fact")
        command.add_argument("key_id")
        command.add_argument("--reason", required=True)
        command.add_argument("--recovery-bundle", type=Path)
        command.add_argument("--effective-at")
        command.add_argument("--compromised-at")
        command.add_argument("--replacement-key-id")
        command.add_argument("--evidence-sha256", action="append", default=[])

    capture = subs.add_parser("capture", help="write a validated event to the immutable spool")
    capture.add_argument("--event", required=True, type=Path)

    compile_cmd = subs.add_parser("compile", help="compile immutable spools into canonical state")
    compile_cmd.add_argument("--once", action="store_true")
    compile_cmd.add_argument("--recover-stale-lock", metavar="NONCE")

    store_cmd = subs.add_parser("store", help="inspect or recover canonical SQLite state")
    store_subs = store_cmd.add_subparsers(dest="store_action", required=True)
    store_subs.add_parser(
        "recover",
        help="exclusively replay and checkpoint crash-resident SQLite WAL state",
    )

    spool = subs.add_parser("spool", help="manage only this producer's acknowledged inputs")
    spool_subs = spool.add_subparsers(dest="spool_action", required=True)
    spool_prune = spool_subs.add_parser("prune")
    spool_prune.add_argument("--retention-days", type=int)

    derive = subs.add_parser("derive", help="submit or compile non-authoritative proposals")
    derive_group = derive.add_mutually_exclusive_group(required=True)
    derive_group.add_argument("--submit", metavar="PROPOSAL", type=Path)
    derive_group.add_argument(
        "--capture", metavar="CAPTURE", type=Path,
        help="run the shipped deterministic capture-to-Proposal invoker",
    )
    derive_group.add_argument("--pending", action="store_true")

    export = subs.add_parser("export", help="export current canonical state")
    export.add_argument("--format", choices=("jsonld", "markdown"), required=True)
    export.add_argument("--output", type=Path)
    export.add_argument("--checkpoint-output", type=Path)

    import_cmd = subs.add_parser("import", help="import into an empty compatible canonical store")
    import_cmd.add_argument("--format", choices=("jsonld",), required=True)
    import_cmd.add_argument("--input", type=Path, required=True)
    import_cmd.add_argument("--dry-run", action="store_true")
    import_cmd.add_argument("--checkpoint", type=Path)
    import_cmd.add_argument("--pinned-head", type=Path)
    import_cmd.add_argument("--governance-store", type=Path)
    import_cmd.add_argument("--expected-store-identity")
    import_cmd.add_argument("--quarantine-dir", type=Path)

    ingest = subs.add_parser("ingest", help="quarantine and rule on imported material")
    ingest_subs = ingest.add_subparsers(dest="ingest_action", required=True)
    ingest_scan = ingest_subs.add_parser("scan")
    ingest_scan.add_argument("--input", type=Path, required=True)
    ingest_show = ingest_subs.add_parser("show")
    ingest_show.add_argument("item_id")
    ingest_keep = ingest_subs.add_parser("keep")
    ingest_keep.add_argument("item_id")
    ingest_keep.add_argument("--why", required=True)
    ingest_kill = ingest_subs.add_parser("kill")
    ingest_kill.add_argument("item_id")
    ingest_kill.add_argument("--why")
    ingest_subs.add_parser("status")

    migrate = subs.add_parser("migrate", help="plan, apply, or verify additive migrations")
    migrate_subs = migrate.add_subparsers(dest="migrate_action", required=True)
    for action in ("plan", "apply"):
        command = migrate_subs.add_parser(action)
        command.add_argument("--spec", type=Path, required=True)
        if action == "apply":
            _add_approval_token(command)
    migrate_subs.add_parser("verify")
    migrate_subs.add_parser(
        "ontology-report",
        help="verify ontology compatibility and classify opaque legacy records",
    )

    review = subs.add_parser("review", help="inspect and explicitly dispose of derived proposals")
    review_subs = review.add_subparsers(dest="review_action", required=True)
    review_subs.add_parser("list")
    review_show = review_subs.add_parser("show")
    review_show.add_argument("node_id")
    review_ratify = review_subs.add_parser("ratify")
    review_ratify.add_argument("node_id")
    review_ratify.add_argument("--by")
    review_ratify.add_argument("--note", default="")
    _add_approval_token(review_ratify)
    review_successor = review_subs.add_parser(
        "authorize-successor",
        help="create one typed operator-authorized successor without mutating the Proposal",
    )
    review_successor.add_argument("proposal_id")
    review_successor.add_argument("--input", type=Path, required=True)
    review_successor.add_argument("--valid-from", required=True)
    review_successor.add_argument("--reason", required=True)
    review_successor.add_argument("--by")
    _add_approval_token(review_successor)
    review_reject = review_subs.add_parser("reject")
    review_reject.add_argument("node_id")
    review_reject.add_argument("--by")
    review_reject.add_argument("--reason", required=True)
    _add_approval_token(review_reject)
    review_defer = review_subs.add_parser("defer")
    review_defer.add_argument("node_id")
    review_defer.add_argument("--by")
    review_defer.add_argument("--reason", required=True)
    review_defer.add_argument("--revisit-after")
    _add_approval_token(review_defer)
    review_correct = review_subs.add_parser("correct")
    review_correct.add_argument("node_id")
    review_correct.add_argument("--by")
    review_correct.add_argument("--reason", required=True)
    review_correct.add_argument("--input", type=Path, required=True)
    _add_approval_token(review_correct)
    review_contest = review_subs.add_parser("contest")
    review_contest.add_argument("node_id")
    review_contest.add_argument("--by")
    review_contest.add_argument("--reason", required=True)
    _add_approval_token(review_contest)
    for action in ("edge-ratify", "edge-reject", "edge-defer"):
        command = review_subs.add_parser(action)
        command.add_argument("edge_id")
        command.add_argument("--by")
        if action == "edge-ratify":
            command.add_argument("--note", default="")
        else:
            command.add_argument("--reason", required=True)
        if action == "edge-defer":
            command.add_argument("--revisit-after")
        _add_approval_token(command)

    ontology = subs.add_parser("ontology", help="write closed, versioned semantic contracts")
    ontology_subs = ontology.add_subparsers(dest="ontology_action", required=True)
    ontology_subs.add_parser(
        "coverage", help="publish shipped-producer versus integration-only type coverage",
    )
    ontology_node = ontology_subs.add_parser("add-node")
    ontology_node.add_argument("--input", type=Path, required=True)
    ontology_node.add_argument("--valid-from", required=True)
    _add_approval_token(ontology_node)
    ontology_relation = ontology_subs.add_parser("add-relation")
    ontology_relation.add_argument("--input", type=Path, required=True)
    ontology_relation.add_argument("--valid-from", required=True)
    _add_approval_token(ontology_relation)

    for command_name, help_text in (
        ("observation", "write a closed observed-evidence contract"),
        ("outcome", "write a closed measured-outcome contract"),
    ):
        command = subs.add_parser(command_name, help=help_text)
        command_subs = command.add_subparsers(dest=f"{command_name}_action", required=True)
        add = command_subs.add_parser("add")
        add.add_argument("--input", type=Path, required=True)
        add.add_argument("--valid-from", required=True)
        _add_approval_token(add)

    consent = subs.add_parser("consent", help="grant, inspect, or revoke durable capture consent")
    consent_subs = consent.add_subparsers(dest="consent_action", required=True)
    consent_grant = consent_subs.add_parser("grant")
    consent_grant.add_argument("--input", type=Path, required=True)
    consent_grant.add_argument("--valid-from", required=True)
    _add_approval_token(consent_grant)
    consent_subs.add_parser("list")
    consent_revoke = consent_subs.add_parser("revoke")
    consent_revoke.add_argument("grant_id")
    consent_revoke.add_argument("--by")
    consent_revoke.add_argument("--reason", required=True)
    consent_revoke.add_argument("--revoked-at")
    _add_approval_token(consent_revoke)

    history = subs.add_parser("history", help="show immutable versions and dispositions")
    history.add_argument("node_id")

    verdict = subs.add_parser("verdict", help="append later WHY or reinforcement evidence")
    verdict_subs = verdict.add_subparsers(dest="verdict_action", required=True)
    add_reason = verdict_subs.add_parser("add-reason")
    add_reason.add_argument("node_id")
    add_reason.add_argument("--reason", required=True)
    add_reason.add_argument("--by")
    add_reason.add_argument("--source", default="explicit_cli")
    _add_approval_token(add_reason)
    reinforce = verdict_subs.add_parser("reinforce")
    reinforce.add_argument("node_id")
    reinforce.add_argument("--evidence", required=True)
    reinforce.add_argument("--by")
    reinforce.add_argument("--source", default="explicit_cli")
    _add_approval_token(reinforce)

    domain = subs.add_parser("domain", help="manage canonical Domain ontology nodes")
    domain_subs = domain.add_subparsers(dest="domain_action", required=True)
    domain_add = domain_subs.add_parser("add")
    domain_add.add_argument("domain_id")
    domain_add.add_argument("--label", required=True)
    domain_add.add_argument("--description", required=True)
    domain_add.add_argument("--evidence", action="append", required=True)
    domain_add.add_argument("--by")
    domain_add.add_argument("--valid-from")
    _add_approval_token(domain_add)
    domain_subs.add_parser("list")
    domain_select = domain_subs.add_parser("select")
    domain_select.add_argument("domain_id")
    domain_select.add_argument("--by")
    _add_approval_token(domain_select)
    domain_freeze = domain_subs.add_parser("freeze")
    domain_freeze.add_argument("domain_id")
    domain_freeze.add_argument("--by")
    _add_approval_token(domain_freeze)

    transition = subs.add_parser("transition", help="record canonical contradiction or supersession edges")
    transition_subs = transition.add_subparsers(dest="transition_action", required=True)
    for action in ("contradict", "supersede"):
        command = transition_subs.add_parser(action)
        command.add_argument("source_id", help="asserting node; for supersede, the replacement")
        command.add_argument("target_id", help="affected node; for supersede, the prior node retired")
        command.add_argument("--reason", required=True)
        command.add_argument("--evidence", action="append", required=True)
        command.add_argument("--by")
        _add_approval_token(command)

    backup = subs.add_parser("backup", help="create, verify, or safely restore a backup")
    backup_subs = backup.add_subparsers(dest="backup_action", required=True)
    backup_create = backup_subs.add_parser("create")
    backup_create.add_argument("--output", type=Path)
    backup_verify = backup_subs.add_parser("verify")
    backup_verify.add_argument("path", type=Path)
    backup_verify.add_argument("--checkpoint", type=Path)
    backup_restore = backup_subs.add_parser("restore")
    backup_restore.add_argument("path", type=Path)
    backup_restore.add_argument("--confirm", required=True)
    backup_restore.add_argument("--checkpoint", type=Path)
    backup_restore.add_argument("--dry-run", action="store_true")

    delete = subs.add_parser("delete", help="tombstone or explicitly hard-purge data")
    delete_subs = delete.add_subparsers(dest="delete_action", required=True)
    tombstone = delete_subs.add_parser("tombstone")
    tombstone.add_argument("--scope", required=True)
    tombstone.add_argument("--reason", required=True)
    _add_approval_token(tombstone)
    purge = delete_subs.add_parser("purge")
    purge.add_argument("--scope", required=True)
    purge.add_argument("--confirm")
    purge.add_argument("--sentinel")
    purge.add_argument("--preview", action="store_true")
    _add_approval_token(purge)

    retrieve = subs.add_parser("retrieve", help="build a bounded context payload")
    retrieve.add_argument("--session", required=True)
    retrieve.add_argument("--prompt", default="")
    retrieve.add_argument("--domain")
    retrieve.add_argument("--refresh", action="store_true")
    retrieve.add_argument(
        "--authority-mode", choices=("authoritative", "analytical"),
        default="authoritative",
    )
    retrieve.add_argument(
        "--partition", action="append", dest="partitions",
        choices=(
            "judgment", "self_model", "business_declared", "business_observed",
        ),
        help="explicit ontology partition; repeat to request multiple compatible partitions",
    )
    retrieve.add_argument(
        "--audit", action="store_true",
        help="emit the full structured provenance record instead of compact context",
    )

    hook = subs.add_parser("hook", help="execute one portable hook action")
    hook.add_argument("action", choices=("session-start", "user-prompt-submit", "stop-capture", "health-check"))

    subs.add_parser("delivery-commit", help=argparse.SUPPRESS)

    health = subs.add_parser("health", help="report content-free health as JSON")
    health.add_argument(
        "--deep", action="store_true",
        help="run integrity, permission, receipt, and backup verification scans",
    )
    subs.add_parser("whoami", help="print the configured opaque curation identity")
    log = subs.add_parser("log", help="list a bounded daily canonical event index")
    log.add_argument("--date", help="UTC date in YYYY-MM-DD form (default: today)")
    log.add_argument("--limit", type=int, default=100)
    log.add_argument("--query", default="", help="filter by event type or opaque event ID")
    subs.add_parser("version", help="print version")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        root = resolved_operator_root(config)
        store = _store(root)
        if args.command == "version":
            from . import __version__
            print(__version__)
            return 0
        store.expected_operator_id = _operator_urn(root)
        store.expected_node_id = str(config.get("node_id", "primary"))
        if hasattr(args, "by") and args.by is None:
            args.by = store.expected_operator_id
        if args.command == "whoami":
            _write_json({
                "status": "ok", "operator_id": store.expected_operator_id,
                "node_id": store.expected_node_id,
            })
            return 0
        if args.command == "log":
            day = args.date or datetime.now(timezone.utc).date().isoformat()
            try:
                datetime.strptime(day, "%Y-%m-%d")
            except ValueError as exc:
                raise ValidationError("log date must be YYYY-MM-DD") from exc
            if not 1 <= args.limit <= 200:
                raise ValidationError("log limit must be 1..200")
            store.initialize()
            pattern = f"%{args.query.strip()}%"
            with store.connect() as conn:
                rows = conn.execute(
                    """SELECT e.event_id,e.event_type,e.system_time,e.valid_time,
                              e.provenance_status,
                              COALESCE(GROUP_CONCAT(n.node_type, ','),'') AS node_types
                       FROM events e LEFT JOIN nodes n ON n.created_event_id=e.event_id
                       WHERE substr(e.system_time,1,10)=?
                         AND (?='' OR e.event_type LIKE ? OR e.event_id LIKE ?)
                       GROUP BY e.event_id
                       ORDER BY e.system_time DESC,e.event_id DESC LIMIT ?""",
                    (day, args.query.strip(), pattern, pattern, args.limit),
                ).fetchall()
            _write_json({
                "status": "ok", "date": day, "limit": args.limit,
                "count": len(rows), "items": [dict(row) for row in rows],
            })
            return 0
        if args.command == "authority":
            from .authority import AuthorityService

            service = AuthorityService(
                root, store, operator_id=store.expected_operator_id,
            )
            if args.authority_action == "enroll":
                _write_json(service.enroll(recovery_destination=args.recovery_output))
                return 0
            if args.authority_action == "recovery-create":
                _write_json(service.create_recovery_bundle(args.output))
                return 0
            if args.authority_action == "recovery-reconcile":
                _write_json(service.abandon_interrupted_recovery())
                return 0
            if args.authority_action == "recovery-restore":
                _write_json(service.restore_recovery_bundle(
                    args.input, authority_transport=args.authority_transport,
                    replace_install_id=args.replace_install_id,
                ))
                return 0
            if args.authority_action == "rotate":
                _write_json(service.rotate_key())
                return 0
            if args.authority_action == "checkpoint":
                _write_json(service.create_checkpoint(ttl_seconds=args.ttl_seconds))
                return 0
            if args.authority_action == "transport":
                _write_json(service.export_authority_transport(args.output))
                return 0
            if args.authority_action == "trust-bootstrap":
                _write_json(service.bootstrap_recovery_trust(args.input))
                return 0
            if args.authority_action == "pair-request":
                _write_json(service.create_pairing_request(args.output))
                return 0
            if args.authority_action == "pair-authorize":
                _write_json(service.authorize_pairing_request(args.input, args.output))
                return 0
            if args.authority_action == "pair-finalize":
                _write_json(service.finalize_pairing(args.input))
                return 0
            if args.authority_action == "adjudicate":
                _write_json(service.adjudicate_authority_conflict(
                    args.proof_id,
                    chosen_checkpoint_sha256=args.chosen_checkpoint_sha256,
                    reason=args.reason, recovery_bundle=args.recovery_bundle,
                ))
                return 0
            if args.authority_action in {"revoke", "compromise"}:
                _write_json(service.change_key_state(
                    args.key_id, state="revoked" if args.authority_action == "revoke" else "compromised",
                    reason=args.reason, recovery_bundle=args.recovery_bundle,
                    effective_at=args.effective_at, compromised_at=args.compromised_at,
                    replacement_key_id=args.replacement_key_id,
                    evidence_sha256s=tuple(args.evidence_sha256),
                ))
                return 0
            request = _authority_request(args.input)
            token = service.approve(request, ttl_seconds=args.ttl_seconds)
            _write_json({"status": "approved", "approval_token": token.as_dict()})
            return 0
        if args.command == "delivery-commit":
            from .retrieve import commit_payload_delivery
            receipt = json.load(sys.stdin)
            if not isinstance(receipt, dict) or set(receipt) != {"session_id", "snapshot_id", "domain_id"}:
                raise ValidationError("delivery commit receipt is invalid")
            if not isinstance(receipt["session_id"], str) or not isinstance(receipt["snapshot_id"], str):
                raise ValidationError("delivery commit identity is invalid")
            if receipt["domain_id"] is not None and not isinstance(receipt["domain_id"], str):
                raise ValidationError("delivery commit domain is invalid")
            committed = commit_payload_delivery(root=root, **receipt)
            _write_json({"status": "committed" if committed else "already_committed"})
            return 0
        if args.command == "capture":
            envelope = json.loads(args.event.read_text())
            if envelope.get("operator_id") != store.expected_operator_id or envelope.get("node_id") != store.expected_node_id:
                raise ValidationError("capture operator/node does not match configured identity")
            path = write_envelope(root, envelope)
            _write_json({"status": "queued", "path": str(path)})
            return 0
        if args.command == "compile":
            if args.recover_stale_lock:
                from .compiler import recover_stale_compiler_lock
                _write_json(recover_stale_compiler_lock(root, confirmation=args.recover_stale_lock))
                return 0
            counts = compile_spools(
                root, store, compiler_authorized=bool(config.get("compiler")),
                retention_days=int(config.get("spool_retention_days", 30)),
            )
            _write_json({"status": "ok", **counts})
            return 0 if counts["quarantined"] == 0 else 2
        if args.command == "store":
            if args.store_action == "recover":
                _write_json(store.recover())
                return 0
        if args.command == "spool":
            from .compiler import prune_acknowledged_spools
            days = args.retention_days
            if days is None:
                days = int(config.get("spool_retention_days", 30))
            result = prune_acknowledged_spools(
                root, source_node_id=str(config.get("node_id", "primary")),
                retention_days=days,
            )
            _write_json({"status": "ok" if result["invalid"] == 0 else "degraded", **result})
            return 0 if result["invalid"] == 0 else 2
        if args.command == "derive":
            from .derive import (
                ProposalSpoolWriter, ReferenceDerivationInvoker,
                compile_pending_proposals,
            )
            if args.submit:
                proposal = json.loads(args.submit.read_text(encoding="utf-8"))
                if not isinstance(proposal, dict):
                    raise ValidationError("proposal input must be an object")
                proposal_id = ProposalSpoolWriter(root).submit_proposal(proposal)
                _write_json({"status": "queued", "proposal_id": proposal_id})
                return 0
            if args.capture:
                from .capture import validate_capture_envelope
                capture = json.loads(args.capture.read_text(encoding="utf-8"))
                if not isinstance(capture, dict):
                    raise ValidationError("capture input must be an object")
                capture = validate_capture_envelope(capture)
                if capture["operator_id"] != store.expected_operator_id:
                    raise ValidationError("capture operator does not match configured identity")
                proposal_id = ReferenceDerivationInvoker(
                    ProposalSpoolWriter(root)
                ).run(capture)
                _write_json({
                    "status": "queued", "proposal_id": proposal_id,
                    "producer": "imprint-reference-deriver",
                })
                return 0
            result = compile_pending_proposals(root, store)
            _write_json({"status": "ok" if result["rejected"] == 0 else "degraded", **result})
            return 0 if result["rejected"] == 0 else 2
        if args.command == "export":
            from .portability import build_signed_export_manifest, export_jsonld
            store.initialize()
            snapshot = store.snapshot()
            checkpoint = None
            if args.format == "jsonld":
                document = export_jsonld(store)
                with store.connect() as conn:
                    authority_rows = int(conn.execute(
                        "SELECT COUNT(*) FROM authority_ledger"
                    ).fetchone()[0])
                if authority_rows:
                    if args.output is None:
                        raise ValidationError(
                            "authority-bearing JSON-LD export requires --output so its checkpoint can be preserved"
                        )
                    from .authority import AuthorityService
                    manifest, checkpoint = build_signed_export_manifest(
                        document,
                        authority_service=AuthorityService(
                            root, store, operator_id=store.expected_operator_id,
                        ),
                    )
                    document["imprint:manifest"] = manifest
                content = json.dumps(
                    document, indent=2, sort_keys=True, ensure_ascii=False,
                ) + "\n"
            else:
                content = markdown_document(snapshot)
            if args.output:
                if args.output.parent.exists():
                    if args.output.parent.is_symlink() or not args.output.parent.is_dir():
                        raise ValidationError("export parent must be a regular directory")
                else:
                    secure_directory(args.output.parent)
                checkpoint_path = args.checkpoint_output or Path(
                    str(args.output) + ".authority-checkpoint.json"
                )
                try:
                    publish_new_private(args.output, content.encode("utf-8"))
                    if checkpoint is not None:
                        publish_new_private(
                            checkpoint_path,
                            (json.dumps(checkpoint, sort_keys=True) + "\n").encode("utf-8"),
                        )
                except Exception:
                    if checkpoint is not None:
                        checkpoint_path.unlink(missing_ok=True)
                    args.output.unlink(missing_ok=True)
                    raise
                if root.exists():
                    secure_tree(root)
                result = {"status": "exported", "path": str(args.output)}
                if checkpoint is not None:
                    result["authority_checkpoint_path"] = str(checkpoint_path)
                _write_json(result)
            else:
                print(content, end="")
            return 0
        if args.command == "import":
            from .portability import import_jsonld
            document = json.loads(args.input.read_text(encoding="utf-8"))
            checkpoint = (
                json.loads(args.checkpoint.read_text(encoding="utf-8"))
                if args.checkpoint else None
            )
            pinned = (
                json.loads(args.pinned_head.read_text(encoding="utf-8"))
                if args.pinned_head else None
            )
            governance = (
                ImprintStore(
                    args.governance_store,
                    expected_operator_id=store.expected_operator_id,
                )
                if args.governance_store else None
            )
            digest = import_jsonld(
                store, document, dry_run=args.dry_run, enforce_authority=True,
                local_governance_store=governance,
                quarantine_dir=args.quarantine_dir or root / "quarantine" / "imports",
                expected_operator_id=store.expected_operator_id,
                expected_store_identity=args.expected_store_identity,
                authority_checkpoint=checkpoint, pinned_authority_head=pinned,
            )
            _write_json({"status": "validated" if args.dry_run else "imported", "semantic_sha256": digest})
            return 0
        if args.command == "ingest":
            from .ingest import IngestCandidate, IngestService
            service = IngestService(store, _operator_urn(root))
            if args.ingest_action == "scan":
                raw = json.loads(args.input.read_text(encoding="utf-8"))
                values = raw if isinstance(raw, list) else [raw]
                expected = {"source_kind", "source_locator", "content", "metadata", "extensions"}
                candidates = []
                for value in values:
                    if not isinstance(value, dict) or not set(value).issubset(expected):
                        raise ValidationError("ingest input contains unknown fields or is not an object")
                    required = expected - {"extensions"}
                    if not required.issubset(value):
                        raise ValidationError("ingest input is missing required fields")
                    candidates.append(IngestCandidate(**value))
                _write_json({"status": "quarantined", "items": service.scan(candidates)})
                return 0
            if args.ingest_action == "show":
                items = [item for item in service.list() if item["item_id"] == args.item_id]
                if not items:
                    raise ValidationError("unknown ingest item")
                _write_json({"status": "ok", "item": items[0]})
                return 0
            if args.ingest_action == "keep":
                ruling_id = service.keep(args.item_id, why=args.why)
                _write_json({"status": "kept", "ruling_id": ruling_id})
                return 0
            if args.ingest_action == "kill":
                ruling_id = service.kill(args.item_id, why=args.why)
                _write_json({"status": "killed", "ruling_id": ruling_id})
                return 0
            items = service.list()
            counts = {state: sum(item["status"] == state for item in items) for state in ("unruled", "kept", "killed")}
            _write_json({"status": "ok", "counts": counts})
            return 0
        if args.command == "migrate":
            from .portability import (
                Migration,
                MigrationRunner,
                ontology_migration_report,
                verify_ontology_schema,
            )
            if args.migrate_action == "ontology-report":
                result = ontology_migration_report(store)
                _write_json(result)
                return 0 if result["status"] in {"current", "migration_available"} else 2
            if args.migrate_action == "verify":
                if not store.path.exists():
                    store.initialize()
                with store.connect() as conn:
                    version = conn.execute("SELECT value FROM meta WHERE key='store_schema_version'").fetchone()[0]
                    receipts = conn.execute("SELECT migration_id,result_sha256 FROM migrations ORDER BY applied_at,migration_id").fetchall()
                ontology = verify_ontology_schema(store)
                healthy = store.integrity_check() == "ok" and ontology["compatible"]
                result = {"status": "ok" if healthy else "error", "store_schema_version": version, "ontology": ontology, "migrations": [dict(row) for row in receipts]}
                _write_json(result)
                return 0 if result["status"] == "ok" else 2
            runner = MigrationRunner(store)
            spec = json.loads(args.spec.read_text(encoding="utf-8"))
            expected = {"migration_id", "from_version", "to_version", "statements", "backup_receipt"}
            if not isinstance(spec, dict) or set(spec) != expected or not isinstance(spec["statements"], list):
                raise ValidationError("migration spec has invalid fields")
            migration = Migration(
                migration_id=spec["migration_id"], from_version=spec["from_version"],
                to_version=spec["to_version"], statements=tuple(spec["statements"]),
                backup_receipt=spec["backup_receipt"],
            )
            if args.migrate_action == "plan":
                with store.connect() as conn:
                    current = conn.execute("SELECT value FROM meta WHERE key='store_schema_version'").fetchone()[0]
                _write_json({"status": "applicable" if current == migration.from_version else "blocked", "current": current, "from": migration.from_version, "to": migration.to_version, "code_sha256": migration.code_sha256})
                return 0 if current == migration.from_version else 2
            _write_json({"status": runner.apply(migration, approval_token=_approval_token(args)), "migration_id": migration.migration_id})
            return 0
        if args.command == "review":
            from .lifecycle import review_list, review_show
            store.initialize()
            if args.review_action == "list":
                items = review_list(store)
                _write_json({"status": "ok", "count": len(items), "items": items})
                return 0
            if args.review_action == "show":
                _write_json({"status": "ok", "item": review_show(store, args.node_id)})
                return 0
            if args.review_action == "ratify":
                event_id = store.ratify_node(args.node_id, ratifier=args.by, note=args.note, approval_token=_approval_token(args))
                _write_json({"status": "ratified", "event_id": event_id, "node_id": args.node_id})
                return 0
            if args.review_action == "authorize-successor":
                contract = json.loads(args.input.read_text(encoding="utf-8"))
                if not isinstance(contract, dict):
                    raise ValidationError("successor input must be one typed node object")
                _write_json(store.authorize_proposal_successor(
                    args.proposal_id, successor_contract=contract,
                    operator_id=args.by, valid_from=args.valid_from,
                    reason=args.reason, approval_token=_approval_token(args),
                ))
                return 0
            if args.review_action == "defer":
                event_id = store.defer_node(
                    args.node_id, reviewer=args.by, reason=args.reason,
                    revisit_after=args.revisit_after, approval_token=_approval_token(args),
                )
                _write_json({"status": "deferred", "event_id": event_id, "node_id": args.node_id})
                return 0
            if args.review_action == "correct":
                contract = json.loads(args.input.read_text(encoding="utf-8"))
                if not isinstance(contract, dict):
                    raise ValidationError("corrected ontology input must be one JSON object")
                event_id = store.correct_typed_node(
                    args.node_id, corrected_contract=contract,
                    corrector=args.by, reason=args.reason, approval_token=_approval_token(args),
                )
                _write_json({"status": "corrected", "event_id": event_id, "node_id": args.node_id})
                return 0
            if args.review_action == "contest":
                event_id = store.contest_typed_node(
                    args.node_id, contestor=args.by, reason=args.reason, approval_token=_approval_token(args),
                )
                _write_json({"status": "contested", "event_id": event_id, "node_id": args.node_id})
                return 0
            if args.review_action == "edge-ratify":
                event_id = store.ratify_edge(args.edge_id, ratifier=args.by, note=args.note, approval_token=_approval_token(args))
                _write_json({"status": "edge_ratified", "event_id": event_id, "edge_id": args.edge_id})
                return 0
            if args.review_action == "edge-defer":
                event_id = store.defer_edge(
                    args.edge_id, reviewer=args.by, reason=args.reason,
                    revisit_after=args.revisit_after, approval_token=_approval_token(args),
                )
                _write_json({"status": "edge_deferred", "event_id": event_id, "edge_id": args.edge_id})
                return 0
            if args.review_action == "edge-reject":
                event_id = store.reject_edge(args.edge_id, rejector=args.by, reason=args.reason, approval_token=_approval_token(args))
                _write_json({"status": "edge_rejected", "event_id": event_id, "edge_id": args.edge_id})
                return 0
            event_id = store.reject_node(args.node_id, rejector=args.by, reason=args.reason, approval_token=_approval_token(args))
            _write_json({"status": "rejected", "event_id": event_id, "node_id": args.node_id})
            return 0
        if args.command == "ontology":
            if args.ontology_action == "coverage":
                from .ontology import producer_coverage
                _write_json({"status": "ok", **producer_coverage()})
                return 0
            store.initialize()
            value = json.loads(args.input.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValidationError("ontology input must be one JSON object")
            if value.get("operator_id") != store.expected_operator_id:
                raise ValidationError("ontology contract operator does not match configured identity")
            if args.ontology_action == "add-node":
                identifier = store.append_semantic_node(value, valid_from=args.valid_from, approval_token=_approval_token(args))
                _write_json({"status": "semantic_node_added", "node_id": identifier})
            else:
                identifier = store.append_semantic_relation(value, valid_from=args.valid_from, approval_token=_approval_token(args))
                _write_json({"status": "semantic_relation_added", "relation_id": identifier})
            return 0
        if args.command in {"observation", "outcome"}:
            store.initialize()
            value = json.loads(args.input.read_text(encoding="utf-8"))
            expected_type = "Observation" if args.command == "observation" else "Outcome"
            if not isinstance(value, dict) or value.get("node_type") != expected_type:
                raise ValidationError(f"{args.command} add requires one {expected_type} contract")
            if value.get("operator_id") != store.expected_operator_id:
                raise ValidationError(f"{args.command} contract operator does not match configured identity")
            identifier = store.append_semantic_node(value, valid_from=args.valid_from, approval_token=_approval_token(args))
            _write_json({"status": f"{args.command}_added", "node_id": identifier})
            return 0
        if args.command == "consent":
            store.initialize()
            if args.consent_action == "grant":
                value = json.loads(args.input.read_text(encoding="utf-8"))
                if not isinstance(value, dict) or value.get("node_type") != "ConsentGrant":
                    raise ValidationError("consent grant requires one ConsentGrant contract")
                if value.get("operator_id") != store.expected_operator_id:
                    raise ValidationError("consent contract operator does not match configured identity")
                identifier = store.append_semantic_node(value, valid_from=args.valid_from, approval_token=_approval_token(args))
                _write_json({"status": "consent_granted", "grant_id": identifier})
                return 0
            if args.consent_action == "list":
                items = store.current_nodes(["ConsentGrant"])
                _write_json({"status": "ok", "count": len(items), "items": items})
                return 0
            event_id = store.revoke_consent(
                args.grant_id, operator_id=args.by, reason=args.reason,
                revoked_at=args.revoked_at, approval_token=_approval_token(args),
            )
            _write_json({"status": "consent_revoked", "event_id": event_id, "grant_id": args.grant_id})
            return 0
        if args.command == "history":
            store.initialize()
            _write_json({"status": "ok", "history": store.node_history(args.node_id)})
            return 0
        if args.command == "verdict":
            store.initialize()
            if args.verdict_action == "add-reason":
                event_id = store.add_reason(
                    args.node_id, reason=args.reason, actor_id=args.by, source_locator=args.source,
                    approval_token=_approval_token(args),
                )
                status = "reason_added"
            else:
                event_id = store.reinforce_verdict(
                    args.node_id, evidence_text=args.evidence, actor_id=args.by, source_locator=args.source,
                    approval_token=_approval_token(args),
                )
                status = "reinforced"
            _write_json({"status": status, "event_id": event_id, "node_id": args.node_id})
            return 0
        if args.command == "domain":
            store.initialize()
            if args.domain_action == "add":
                node_id = store.add_domain(
                    domain_id=args.domain_id, public_label=args.label,
                    description=args.description, evidence_ids=args.evidence,
                    operator_id=_operator_urn(root), actor_id=args.by,
                    valid_from=args.valid_from, approval_token=_approval_token(args),
                )
                _write_json({"status": "domain_added", "node_id": node_id, "domain_id": args.domain_id})
                return 0
            if args.domain_action == "list":
                items = store.list_domains()
                _write_json({"status": "ok", "count": len(items), "items": items})
                return 0
            if args.domain_action == "select":
                event_id = store.select_domain(args.domain_id, actor_id=args.by, approval_token=_approval_token(args))
                _write_json({"status": "domain_selected", "event_id": event_id, "domain_id": args.domain_id})
                return 0
            event_id = store.freeze_domain(args.domain_id, actor_id=args.by, approval_token=_approval_token(args))
            _write_json({"status": "domain_frozen", "event_id": event_id, "domain_id": args.domain_id})
            return 0
        if args.command == "transition":
            store.initialize()
            relation = {"contradict": "contradicts", "supersede": "supersedes"}[args.transition_action]
            edge_id = store.add_transition(
                relation, args.source_id, args.target_id, reason=args.reason,
                evidence_ids=args.evidence, actor_id=args.by, approval_token=_approval_token(args),
            )
            _write_json({"status": relation, "edge_id": edge_id, "source_id": args.source_id, "target_id": args.target_id})
            return 0
        if args.command == "backup":
            from .backup import create_backup, restore_backup
            if args.backup_action == "create":
                store.initialize()
                with store.connect() as conn:
                    authority_rows = int(conn.execute(
                        "SELECT COUNT(*) FROM authority_ledger"
                    ).fetchone()[0])
                options = {}
                if authority_rows:
                    from .authority import AuthorityService
                    options = {
                        "authority_service": AuthorityService(
                            root, store, operator_id=store.expected_operator_id,
                        )
                    }
                _write_json({
                    "status": "created",
                    **create_backup(store, root, args.output, **options),
                })
                return 0
            checkpoint_path = args.checkpoint or Path(
                str(args.path) + ".authority-checkpoint.json"
            )
            checkpoint = None
            if checkpoint_path.exists():
                checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            if args.backup_action == "verify":
                verified = restore_backup(
                    store, root, args.path, confirmation="unused", dry_run=True,
                    authority_checkpoint=checkpoint,
                )
                verified["status"] = "verified"
                _write_json(verified)
                return 0
            _write_json(restore_backup(
                store, root, args.path, confirmation=args.confirm,
                dry_run=args.dry_run, authority_checkpoint=checkpoint,
            ))
            return 0
        if args.command == "delete":
            store.initialize()
            if args.delete_action == "tombstone":
                event_id = store.tombstone_node(args.scope, reason=args.reason, approval_token=_approval_token(args))
                _write_json({"status": "tombstoned", "event_id": event_id, "node_id": args.scope})
                return 0
            from .purge import hard_purge, preview_purge
            if args.preview:
                _write_json({"status": "preview", **preview_purge(store, root, args.scope)})
                return 0
            if args.confirm is None:
                raise ValidationError("hard purge requires --confirm with the exact scope")
            result = hard_purge(
                store, root, args.scope, confirmation=args.confirm, sentinel=args.sentinel,
                approval_token=_approval_token(args),
            )
            _write_json(result)
            return 0 if result.get("status") == "purged" else 2
        if args.command == "retrieve":
            from .retrieve import retrieve_payload
            store.initialize()
            result = retrieve_payload(
                store,
                root=root,
                session_id=args.session,
                prompt=args.prompt,
                explicit_domain=args.domain,
                budget=int(config["context_budget_bytes"]),
                refresh=args.refresh,
                output_format="audit" if args.audit else "compact",
                authority_mode=args.authority_mode,
                ontology_partitions=args.partitions,
            )
            if not args.refresh and result.get("status") == "delivered":
                _emit_retrieval_json(
                    result, root=root, session_id=args.session,
                    snapshot_id=str(result["snapshot_id"]),
                    domain_id=(
                        str(result["receipt_scope"])
                        if result.get("receipt_scope") is not None else None
                    ),
                )
            else:
                _write_json(result)
            return 0
        if args.command == "health":
            from .health import health_report
            result = health_report(root, store, config, deep=args.deep)
            _write_json(result)
            return 0 if result.get("status") == "healthy" else 2
        if args.command == "hook":
            event = json.load(sys.stdin)
            if not isinstance(event, dict):
                raise ImprintError("hook event must be an object")
            native_value = event.get("session_id") or event.get("sessionId")
            native_session = (
                str(native_value) if native_value
                else f"unavailable-event:{uuid.uuid4()}"
            )
            session = _opaque_session_urn(root, native_session)
            if args.action == "session-start":
                _validate_hook_event(event, "SessionStart")
                from .retrieve import retrieve_payload
                store.initialize()
                source = str(event.get("source") or "").strip().lower()
                context_was_reset = source in {"compact", "resume"}
                result = retrieve_payload(
                    store, root=root, session_id=session, prompt="",
                    budget=int(config["context_budget_bytes"]),
                    refresh=context_was_reset,
                )
                response = {
                    "hook_schema_version": "1.0.0",
                    "status": result["status"],
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": result.get("payload", ""),
                    },
                }
                if result.get("status") == "delivered" and not context_was_reset:
                    _emit_retrieval_json(
                        response, root=root, session_id=session,
                        snapshot_id=str(result["snapshot_id"]), domain_id=None,
                    )
                else:
                    _write_json(response)
                return 0
            if args.action == "user-prompt-submit":
                _validate_hook_event(event, "UserPromptSubmit")
                from .domains import registry_from_config
                from .retrieve import retrieve_payload
                store.initialize()
                prompt = str(event.get("prompt") or event.get("user_prompt") or "")
                selection = registry_from_config(config).select(
                    explicit=str(event["domain_id"]) if event.get("domain_id") else None,
                    path=str(event.get("cwd") or event.get("working_directory") or "") or None,
                    prompt=prompt,
                )
                domain = selection.domain_id
                if domain is None:
                    _write_json({
                        "hook_schema_version": "1.0.0", "status": "skipped",
                        "reason": selection.diagnostic_code,
                        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": ""},
                    })
                    return 0
                result = retrieve_payload(
                    store, root=root, session_id=session,
                    prompt=prompt, explicit_domain=domain,
                    budget=int(config["context_budget_bytes"]), domain_only=True,
                )
                response = {
                    "hook_schema_version": "1.0.0",
                    "status": result["status"],
                    "domain_id": domain,
                    "selection_method": selection.method,
                    "hookSpecificOutput": {
                        "hookEventName": "UserPromptSubmit",
                        "additionalContext": result.get("payload", ""),
                    },
                }
                if result.get("status") == "delivered":
                    _emit_retrieval_json(
                        response, root=root, session_id=session,
                        snapshot_id=str(result["snapshot_id"]), domain_id=domain,
                    )
                else:
                    _write_json(response)
                return 0
            if args.action == "stop-capture":
                _validate_hook_event(event, "Stop")
                from .capture import CapturePipeline
                from .capture.pipeline import CapturePersistenceError
                from .capture.transcript import (
                    MAX_TRANSCRIPT_BYTES,
                    _parse_native_stop_snapshot,
                    _read_native_transcript_snapshot,
                )
                operator_text = event.get("operator_text") or event.get("last_user_message")
                prior_assistant = event.get("prior_assistant_output")
                case_description = event.get("case_description")
                contextual_evidence = []
                extensions = {}
                if not operator_text and isinstance(event.get("transcript_path"), str):
                    snapshot = _read_native_transcript_snapshot(
                        event["transcript_path"], tail_limit=2 * 1024 * 1024,
                    )
                    if snapshot.size > MAX_TRANSCRIPT_BYTES:
                        native = _parse_large_native_transcript(
                            event["transcript_path"], snapshot=snapshot,
                        )
                        extensions["org.imprint.transcript"] = native["degradation"]
                    else:
                        native = _parse_native_stop_snapshot(snapshot)
                        if "degradation" in native:
                            extensions["org.imprint.transcript"] = native["degradation"]
                    operator_text = native["operator_text"]
                    prior_assistant = native["prior_assistant_output"]
                    case_description = native["case_description"]
                    if isinstance(prior_assistant, str) and prior_assistant:
                        contextual_evidence = [{
                            "kind": "context", "content": prior_assistant,
                            "source_locator": native["source_locator"],
                        }]
                if not isinstance(operator_text, str) or not operator_text.strip():
                    _write_json({"hook_schema_version": "1.0.0", "status": "skipped", "reason": "feedback_text_unavailable"})
                    return 0
                class HookSpool:
                    def persist(self, value):
                        return write_envelope(root, value)

                try:
                    captured = CapturePipeline(HookSpool()).capture(
                        operator_text=operator_text,
                        prior_operator_text=event.get("prior_operator_text"),
                        prior_assistant_output=prior_assistant,
                        operator_id=_operator_urn(root), session_id=session,
                        node_id=str(config.get("node_id", "primary")),
                        case_description=str(
                            case_description
                            or "Explicit operator feedback witnessed by explicit hook input"
                        ),
                        capture_mechanism="claude_code_stop_hook",
                        captured_by="imprint-hook",
                        reason=(
                            event.get("reason")
                            if isinstance(event.get("reason"), str) else None
                        ),
                        contextual_evidence=contextual_evidence,
                        extensions=extensions,
                    )
                except CapturePersistenceError as exc:
                    _write_json({
                        "hook_schema_version": "1.0.0", "status": "error",
                        "error_code": "spool_write_failed",
                        "error_type": type(exc.__cause__ or exc).__name__,
                    })
                    return 2
                if not captured.persisted:
                    _write_json({"hook_schema_version": "1.0.0", "status": "skipped", "reason": "not_explicit_feedback"})
                    return 0
                assert captured.envelope is not None
                envelope = captured.envelope
                path = captured.receipt
                receipt = {
                    "hook_schema_version": "1.0.0", "status": "queued",
                    "event_id": envelope["input_event_id"], "spool_file": path.name,
                    "canonical_status": "spool_only",
                }
                if bool(config.get("compiler")):
                    from .compiler import acknowledgement_committed
                    try:
                        counts = compile_spools(
                            root, store, compiler_authorized=True,
                            retention_days=int(config.get("spool_retention_days", 30)),
                        )
                        if not acknowledgement_committed(root, path, envelope):
                            raise ImprintError("Stop capture lacks exact durable canonical acknowledgement")
                    except Exception as exc:
                        # The raw envelope is already durably persisted.  A
                        # compiler outage must remain visible and retryable but
                        # must not trap Claude in a Stop-hook loop.
                        receipt["compile_status"] = "degraded"
                        receipt["compile_error_type"] = type(exc).__name__
                    else:
                        receipt["canonical_status"] = "compiled"
                        receipt["compile"] = counts
                        receipt["compile_status"] = (
                            "degraded" if counts["quarantined"] else "healthy"
                        )
                        if counts["quarantined"]:
                            receipt["unrelated_quarantine_count"] = counts["quarantined"]
                if extensions:
                    receipt["degradation"] = extensions["org.imprint.transcript"]["payload"]
                _write_json(receipt)
                return 0
            if args.action == "health-check":
                _validate_hook_event(event, "SessionStart")
                from .health import health_report
                result = health_report(root, store, config, deep=False)
                _write_json({"hook_schema_version": "1.0.0", **result})
                return 0 if result.get("status") == "healthy" else 2
    except (ImprintError, OSError, json.JSONDecodeError) as exc:
        _write_json({"status": "error", "error": str(exc), "error_type": type(exc).__name__})
        return 2
    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
