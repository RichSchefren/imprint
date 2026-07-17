"""Destination-owned authority trust anchors and monotonic transfer tickets."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping

from imprint.errors import ConflictError, ValidationError
from .challenge import canonical_bytes, parse_timestamp, sha256_hex
from .ledger import utc_now, utc_text, verify_authority_chain


@dataclass(frozen=True)
class AuthorityTrustAnchor:
    operator_id: str
    store_identity: str
    genesis_event_sha256: str
    recovery_key_id: str | None
    recovery_public_key_b64: str | None
    pinned_sequence: int
    pinned_head_sha256: str
    key_state_sha256: str
    checkpoint_sha256: str | None
    checkpoint: Mapping[str, Any] | None
    signer_certificate_sha256: str | None
    updated_at: str
    writes_blocked: bool
    block_reason: str | None

    def digest(self) -> str:
        return sha256_hex(canonical_bytes({
            "operator_id": self.operator_id,
            "store_identity": self.store_identity,
            "genesis_event_sha256": self.genesis_event_sha256,
            "recovery_key_id": self.recovery_key_id,
            "recovery_public_key_b64": self.recovery_public_key_b64,
            "pinned_sequence": self.pinned_sequence,
            "pinned_head_sha256": self.pinned_head_sha256,
            "key_state_sha256": self.key_state_sha256,
            "checkpoint_sha256": self.checkpoint_sha256,
            "signer_certificate_sha256": self.signer_certificate_sha256,
            "writes_blocked": self.writes_blocked,
            "block_reason": self.block_reason,
        }))


@dataclass(frozen=True)
class VerifiedTransfer:
    operator_id: str
    store_identity: str
    genesis_event_sha256: str
    source_head_sequence: int
    source_head_sha256: str
    checkpoint: Mapping[str, Any]
    checkpoint_sha256: str
    key_state_sha256: str
    signer_certificate_sha256: str
    prior_anchor_sha256: str


@dataclass(frozen=True)
class PreparedAnchorAdvance:
    ticket_id: str
    checkpoint_sha256: str
    operation_digest: str
    prior_anchor_sha256: str


def _checkpoint_sha256(checkpoint: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_bytes(dict(checkpoint)))


def load_authority_trust_anchor(conn: sqlite3.Connection) -> AuthorityTrustAnchor | None:
    row = conn.execute("SELECT * FROM authority_trust_anchor WHERE anchor_id=1").fetchone()
    if row is None:
        return None
    value = dict(row)
    try:
        checkpoint = json.loads(value["checkpoint_json"]) if value["checkpoint_json"] else None
    except json.JSONDecodeError as exc:
        raise ValidationError("local authority trust anchor is corrupt") from exc
    return AuthorityTrustAnchor(
        operator_id=value["operator_id"], store_identity=value["store_identity"],
        genesis_event_sha256=value["genesis_event_sha256"],
        recovery_key_id=value["recovery_key_id"],
        recovery_public_key_b64=value["recovery_public_key_b64"],
        pinned_sequence=int(value["pinned_sequence"]),
        pinned_head_sha256=value["pinned_head_sha256"],
        key_state_sha256=value["key_state_sha256"],
        checkpoint_sha256=value["checkpoint_sha256"], checkpoint=checkpoint,
        signer_certificate_sha256=value["signer_certificate_sha256"],
        updated_at=value["updated_at"], writes_blocked=bool(value["writes_blocked"]),
        block_reason=value["block_reason"],
    )


def assert_authority_writes_allowed(conn: sqlite3.Connection) -> AuthorityTrustAnchor:
    anchor = load_authority_trust_anchor(conn)
    if anchor is None:
        raise ValidationError("authority writes require a destination-owned trust anchor")
    if anchor.writes_blocked:
        raise ValidationError(
            "authority writes are blocked pending native signed adjudication: "
            + str(anchor.block_reason)
        )
    return anchor


def establish_authority_trust_anchor(
    conn: sqlite3.Connection, *, chain: Mapping[str, Any],
    recovery_key_id: str | None = None, recovery_public_key_b64: str | None = None,
    checkpoint: Mapping[str, Any] | None = None, now=None,
    checkpoint_history: list[Mapping[str, Any]] | None = None,
) -> AuthorityTrustAnchor:
    """Establish first local trust only from enrollment or a recovery ceremony."""
    if load_authority_trust_anchor(conn) is not None:
        raise ConflictError("authority trust anchor already exists")
    genesis_sha = chain.get("genesis_event_sha256")
    key_state_sha = chain.get("key_state_sha256")
    if not isinstance(genesis_sha, str) or not isinstance(key_state_sha, str):
        raise ValidationError("verified authority chain lacks trust-anchor fields")
    if (recovery_key_id is None) != (recovery_public_key_b64 is None):
        raise ValidationError("recovery trust anchor is incomplete")
    if recovery_key_id is not None:
        recovery = chain["keys"].get(recovery_key_id)
        if (
            recovery is None or recovery["kind"] != "recovery"
            or recovery["status"] != "active"
            or recovery["public_key_b64"] != recovery_public_key_b64
        ):
            raise ValidationError("recovery trust anchor is not active in the verified chain")
    history = checkpoint_history or ([checkpoint] if checkpoint is not None else [])
    if checkpoint is not None and (not history or dict(history[-1]) != dict(checkpoint)):
        raise ValidationError("trust bootstrap checkpoint history is inconsistent")
    prior = None
    for item in history:
        if item.get("prior_checkpoint_sha256") != prior:
            raise ValidationError("trust bootstrap checkpoint history is not closed")
        prior = _checkpoint_sha256(item)
    checkpoint_sha = _checkpoint_sha256(checkpoint) if checkpoint is not None else None
    certificate_sha = (
        sha256_hex(canonical_bytes(checkpoint["signer_certificate"]))
        if checkpoint is not None else None
    )
    updated = utc_text(utc_now((lambda: now) if now is not None else None))
    conn.execute(
        """INSERT INTO authority_trust_anchor(
          anchor_id,operator_id,store_identity,genesis_event_sha256,recovery_key_id,
          recovery_public_key_b64,pinned_sequence,pinned_head_sha256,key_state_sha256,
          checkpoint_sha256,checkpoint_json,signer_certificate_sha256,updated_at,
          writes_blocked,block_reason
        ) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL)""",
        (chain["operator_id"], chain["store_identity"], genesis_sha,
         recovery_key_id, recovery_public_key_b64, chain["head_sequence"],
         chain["head_sha256"], key_state_sha, checkpoint_sha,
         canonical_bytes(dict(checkpoint)).decode() if checkpoint is not None else None,
         certificate_sha, updated),
    )
    for item in history:
        item_sha = _checkpoint_sha256(item)
        item_certificate_sha = sha256_hex(canonical_bytes(item["signer_certificate"]))
        conn.execute(
            """INSERT INTO authority_checkpoint_pins VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (item_sha, chain["operator_id"], chain["store_identity"],
             item["sequence"], item["event_sha256"], item["key_state_sha256"],
             item["prior_checkpoint_sha256"], item_certificate_sha,
             canonical_bytes(dict(item)).decode(), updated, "trust-bootstrap"),
        )
    anchor = load_authority_trust_anchor(conn)
    assert anchor is not None
    return anchor


def verify_authority_transfer(
    source_conn: sqlite3.Connection, *, local_anchor: AuthorityTrustAnchor,
    checkpoint: Mapping[str, Any],
    checkpoint_history: list[Mapping[str, Any]] | None = None, now=None,
) -> VerifiedTransfer:
    """Verify a source only against destination-owned persisted trust."""
    if local_anchor.writes_blocked:
        raise ValidationError("local authority trust is blocked pending adjudication")
    history = checkpoint_history or [checkpoint]
    if not history or dict(history[-1]) != dict(checkpoint):
        raise ValidationError("authority transfer checkpoint history is inconsistent")
    start = 0
    if local_anchor.checkpoint_sha256 is not None:
        found = next(
            (index for index, item in enumerate(history)
             if _checkpoint_sha256(item) == local_anchor.checkpoint_sha256),
            None,
        )
        if found is None:
            raise ValidationError("authority transfer omits the destination-pinned checkpoint")
        start = found
    prior = local_anchor.checkpoint_sha256
    for item in history[start + 1:]:
        if item.get("prior_checkpoint_sha256") != prior:
            raise ValidationError("authority transfer checkpoint history does not extend local trust")
        verify_authority_chain(
            source_conn, expected_operator_id=local_anchor.operator_id,
            expected_store_identity=local_anchor.store_identity,
            checkpoint=item, pinned_head={
                "sequence": local_anchor.pinned_sequence,
                "event_sha256": local_anchor.pinned_head_sha256,
            }, now=now, enforce_checkpoint_freshness=(item == history[-1]),
        )
        prior = _checkpoint_sha256(item)
    chain = verify_authority_chain(
        source_conn, expected_operator_id=local_anchor.operator_id,
        expected_store_identity=local_anchor.store_identity,
        checkpoint=checkpoint,
        pinned_head={
            "sequence": local_anchor.pinned_sequence,
            "event_sha256": local_anchor.pinned_head_sha256,
        },
        now=now,
    )
    if chain["genesis_event_sha256"] != local_anchor.genesis_event_sha256:
        raise ValidationError("authority transfer belongs to a foreign trust genesis")
    checkpoint_sha = _checkpoint_sha256(checkpoint)
    if checkpoint["key_state_sha256"] != chain["key_state_sha256_at_checkpoint"]:
        raise ValidationError("authority checkpoint key-state digest disagrees with the chain")
    if checkpoint["sequence"] < local_anchor.pinned_sequence:
        raise ValidationError("authority transfer is a rollback")
    if checkpoint["sequence"] == local_anchor.pinned_sequence:
        if checkpoint["event_sha256"] != local_anchor.pinned_head_sha256:
            raise ValidationError("authority transfer equivocated at the pinned sequence")
        if (
            local_anchor.checkpoint_sha256 not in {None, checkpoint_sha}
            and len(history) == 1
        ):
            raise ValidationError("authority transfer supplied a conflicting checkpoint")
    elif local_anchor.checkpoint_sha256 is not None and len(history) == 1 and (
        checkpoint["prior_checkpoint_sha256"] != local_anchor.checkpoint_sha256
    ):
        raise ValidationError("authority checkpoint does not extend the locally pinned checkpoint")
    certificate_sha = sha256_hex(canonical_bytes(checkpoint["signer_certificate"]))
    return VerifiedTransfer(
        operator_id=chain["operator_id"], store_identity=chain["store_identity"],
        genesis_event_sha256=chain["genesis_event_sha256"],
        source_head_sequence=chain["head_sequence"],
        source_head_sha256=chain["head_sha256"], checkpoint=dict(checkpoint),
        checkpoint_sha256=checkpoint_sha,
        key_state_sha256=checkpoint["key_state_sha256"],
        signer_certificate_sha256=certificate_sha,
        prior_anchor_sha256=local_anchor.digest(),
    )


def prepare_checkpoint_advance(
    conn: sqlite3.Connection, verified_transfer: VerifiedTransfer, operation_digest: str,
    *, now=None,
) -> PreparedAnchorAdvance:
    anchor = assert_authority_writes_allowed(conn)
    if anchor.digest() != verified_transfer.prior_anchor_sha256:
        raise ConflictError("authority trust anchor changed before transfer preparation")
    if not isinstance(operation_digest, str) or len(operation_digest) != 64:
        raise ValidationError("authority transfer operation digest is invalid")
    ticket = PreparedAnchorAdvance(
        ticket_id=f"urn:imprint:authority-transfer:{uuid.uuid4()}",
        checkpoint_sha256=verified_transfer.checkpoint_sha256,
        operation_digest=operation_digest,
        prior_anchor_sha256=verified_transfer.prior_anchor_sha256,
    )
    prepared = utc_now((lambda: now) if now is not None else None)
    conn.execute(
        """INSERT INTO authority_transfer_intents(
           ticket_id,checkpoint_sha256,checkpoint_json,operation_digest,
           prior_anchor_sha256,source_store_identity,destination_store_identity,
           prior_sequence,prior_head_sha256,candidate_sequence,candidate_head_sha256,
           prepared_at,expires_at,status,finalized_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'prepared',NULL)""",
        (ticket.ticket_id, ticket.checkpoint_sha256,
         canonical_bytes(dict(verified_transfer.checkpoint)).decode(),
         operation_digest, ticket.prior_anchor_sha256,
         verified_transfer.store_identity, anchor.store_identity,
         anchor.pinned_sequence, anchor.pinned_head_sha256,
         verified_transfer.checkpoint["sequence"],
         verified_transfer.checkpoint["event_sha256"],
         utc_text(prepared), utc_text(prepared + timedelta(hours=24))),
    )
    return ticket


def finalize_anchor_advance(
    conn: sqlite3.Connection, ticket: PreparedAnchorAdvance, *, now=None,
) -> AuthorityTrustAnchor:
    row = conn.execute(
        "SELECT * FROM authority_transfer_intents WHERE ticket_id=?", (ticket.ticket_id,),
    ).fetchone()
    if row is None:
        raise ValidationError("authority transfer ticket is absent")
    if row["status"] == "finalized":
        if (
            row["checkpoint_sha256"] != ticket.checkpoint_sha256
            or row["operation_digest"] != ticket.operation_digest
            or row["prior_anchor_sha256"] != ticket.prior_anchor_sha256
        ):
            raise ValidationError("finalized authority transfer ticket binding mismatch")
        result = load_authority_trust_anchor(conn)
        if result is None or result.checkpoint_sha256 != ticket.checkpoint_sha256:
            raise ValidationError("finalized authority transfer is inconsistent with the anchor")
        return result
    if row["status"] != "prepared":
        raise ValidationError("authority transfer ticket is cancelled")
    current = utc_now((lambda: now) if now is not None else None)
    if current >= parse_timestamp(row["expires_at"]):
        conn.execute(
            "UPDATE authority_transfer_intents SET status='cancelled' WHERE ticket_id=? AND status='prepared'",
            (ticket.ticket_id,),
        )
        raise ValidationError("authority transfer ticket expired before finalization")
    if (
        row["checkpoint_sha256"] != ticket.checkpoint_sha256
        or row["operation_digest"] != ticket.operation_digest
        or row["prior_anchor_sha256"] != ticket.prior_anchor_sha256
    ):
        raise ValidationError("authority transfer ticket binding mismatch")
    anchor = assert_authority_writes_allowed(conn)
    if anchor.digest() != ticket.prior_anchor_sha256:
        raise ConflictError("authority trust anchor changed before transfer finalization")
    checkpoint = json.loads(row["checkpoint_json"])
    certificate_sha = sha256_hex(canonical_bytes(checkpoint["signer_certificate"]))
    accepted = utc_text(current)
    conn.execute(
        """INSERT OR IGNORE INTO authority_checkpoint_pins VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (ticket.checkpoint_sha256, checkpoint["operator_id"], checkpoint["store_identity"],
         checkpoint["sequence"], checkpoint["event_sha256"], checkpoint["key_state_sha256"],
         checkpoint["prior_checkpoint_sha256"], certificate_sha,
         canonical_bytes(checkpoint).decode(), accepted, ticket.operation_digest),
    )
    conn.execute(
        """UPDATE authority_trust_anchor SET
          pinned_sequence=?,pinned_head_sha256=?,key_state_sha256=?,checkpoint_sha256=?,
          checkpoint_json=?,signer_certificate_sha256=?,updated_at=? WHERE anchor_id=1""",
        (checkpoint["sequence"], checkpoint["event_sha256"],
         checkpoint["key_state_sha256"], ticket.checkpoint_sha256,
         canonical_bytes(checkpoint).decode(), certificate_sha, accepted),
    )
    conn.execute(
        "UPDATE authority_transfer_intents SET status='finalized',finalized_at=? WHERE ticket_id=?",
        (accepted, ticket.ticket_id),
    )
    result = load_authority_trust_anchor(conn)
    assert result is not None
    return result


def pin_local_checkpoint(
    conn: sqlite3.Connection, *, checkpoint: Mapping[str, Any],
    operation_digest: str = "local-checkpoint", now=None,
    enforce_freshness: bool = True,
) -> AuthorityTrustAnchor:
    """Persist a locally created checkpoint as the sole monotonic trusted head."""
    anchor = assert_authority_writes_allowed(conn)
    chain = verify_authority_chain(
        conn, expected_operator_id=anchor.operator_id,
        expected_store_identity=anchor.store_identity,
        checkpoint=checkpoint, now=now,
        enforce_checkpoint_freshness=enforce_freshness,
    )
    checkpoint_sha = _checkpoint_sha256(checkpoint)
    if checkpoint["genesis_event_sha256"] != anchor.genesis_event_sha256:
        raise ValidationError("local checkpoint belongs to another trust genesis")
    if checkpoint["sequence"] < anchor.pinned_sequence:
        raise ValidationError("local checkpoint would roll back the trusted head")
    if checkpoint["sequence"] == anchor.pinned_sequence and checkpoint["event_sha256"] != anchor.pinned_head_sha256:
        raise ValidationError("local checkpoint equivocates at the trusted sequence")
    if anchor.checkpoint_sha256 is not None and checkpoint["prior_checkpoint_sha256"] != anchor.checkpoint_sha256:
        raise ValidationError("local checkpoint does not extend the pinned checkpoint")
    certificate_sha = sha256_hex(canonical_bytes(checkpoint["signer_certificate"]))
    accepted = utc_text(utc_now((lambda: now) if now is not None else None))
    conn.execute(
        """INSERT INTO authority_checkpoint_pins VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (checkpoint_sha, anchor.operator_id, anchor.store_identity,
         checkpoint["sequence"], checkpoint["event_sha256"],
         checkpoint["key_state_sha256"], checkpoint["prior_checkpoint_sha256"],
         certificate_sha, canonical_bytes(dict(checkpoint)).decode(), accepted,
         operation_digest),
    )
    conn.execute(
        """UPDATE authority_trust_anchor SET
          pinned_sequence=?,pinned_head_sha256=?,key_state_sha256=?,checkpoint_sha256=?,
          checkpoint_json=?,signer_certificate_sha256=?,updated_at=? WHERE anchor_id=1""",
        (checkpoint["sequence"], checkpoint["event_sha256"], chain["key_state_sha256_at_checkpoint"],
         checkpoint_sha, canonical_bytes(dict(checkpoint)).decode(), certificate_sha, accepted),
    )
    result = load_authority_trust_anchor(conn)
    assert result is not None
    return result


def advance_anchor_to_local_head(
    conn: sqlite3.Connection, *, chain: Mapping[str, Any], now=None,
) -> AuthorityTrustAnchor:
    """Advance only over a fully verified local ledger extending the durable pin."""
    anchor = assert_authority_writes_allowed(conn)
    if (
        chain.get("operator_id") != anchor.operator_id
        or chain.get("store_identity") != anchor.store_identity
        or chain.get("genesis_event_sha256") != anchor.genesis_event_sha256
    ):
        raise ValidationError("local authority chain belongs to another trust anchor")
    row = conn.execute(
        "SELECT event_sha256 FROM authority_ledger WHERE sequence=?",
        (anchor.pinned_sequence,),
    ).fetchone()
    if row is None or row[0] != anchor.pinned_head_sha256:
        raise ValidationError("local authority chain does not extend the pinned head")
    if int(chain["head_sequence"]) < anchor.pinned_sequence:
        raise ValidationError("local authority chain would roll back the pinned head")
    updated = utc_text(utc_now((lambda: now) if now is not None else None))
    conn.execute(
        """UPDATE authority_trust_anchor SET
           pinned_sequence=?,pinned_head_sha256=?,key_state_sha256=?,updated_at=?
           WHERE anchor_id=1""",
        (chain["head_sequence"], chain["head_sha256"], chain["key_state_sha256"], updated),
    )
    result = load_authority_trust_anchor(conn)
    assert result is not None
    return result


def retain_authority_conflict(
    conn: sqlite3.Connection, *, conflict_class: str,
    local_proof: Mapping[str, Any], candidate_proof: Mapping[str, Any], now=None,
) -> str:
    """Retain both proofs and durably block authority until signed adjudication."""
    local_json = canonical_bytes(dict(local_proof)).decode()
    candidate_json = canonical_bytes(dict(candidate_proof)).decode()
    proof_id = f"urn:imprint:authority-conflict:{uuid.uuid4()}"
    detected = utc_text(utc_now((lambda: now) if now is not None else None))
    conn.execute(
        """INSERT INTO authority_equivocation_proofs VALUES(?,?,?,?,?,?,?,NULL)""",
        (proof_id, conflict_class, local_json, candidate_json,
         sha256_hex(local_json.encode()), sha256_hex(candidate_json.encode()), detected),
    )
    changed = conn.execute(
        """UPDATE authority_trust_anchor SET writes_blocked=1,block_reason=?,updated_at=?
           WHERE anchor_id=1""",
        (f"{conflict_class}:{proof_id}", detected),
    ).rowcount
    if changed != 1:
        raise ValidationError("cannot retain authority conflict without local trust anchor")
    return proof_id


__all__ = [
    "AuthorityTrustAnchor", "PreparedAnchorAdvance", "VerifiedTransfer",
    "assert_authority_writes_allowed", "establish_authority_trust_anchor",
    "advance_anchor_to_local_head", "finalize_anchor_advance", "load_authority_trust_anchor",
    "pin_local_checkpoint", "prepare_checkpoint_advance", "retain_authority_conflict",
    "verify_authority_transfer",
]
