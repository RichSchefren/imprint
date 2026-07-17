"""Immutable proposal spool and deterministic canonical proposal writer."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from imprint.errors import ConflictError, SafetyError, ValidationError
from imprint.durable_io import publish_new_private
from imprint.ontology.schema import canonical_bytes, payload_sha256
from imprint.permissions import secure_directory, secure_file
from imprint.store import ImprintStore

from .proposals import validate_proposal


def _safe_directory(path: Path) -> None:
    secure_directory(path)
    if path.is_symlink() or not path.is_dir():
        raise SafetyError("proposal spool directory must be a real directory")


def _immutable_write(path: Path, content: bytes) -> str:
    """Create path exactly once; identical replay is idempotent."""
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise SafetyError("proposal spool target is not a regular file")
        secure_file(path)
        if path.read_bytes() == content:
            return "duplicate"
        raise ConflictError("proposal spool identity already contains different bytes")
    try:
        publish_new_private(path, content)
    except SafetyError:
        if path.exists():
            return _immutable_write(path, content)
        raise
    return "written"


class ProposalSpoolWriter:
    """Validate and persist proposals without granting canonical write authority."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.pending = self.root / "proposal-spool" / "pending"

    def submit_proposal(self, proposal: Mapping[str, Any]) -> str:
        value = validate_proposal(proposal)
        _safe_directory(self.pending)
        proposal_uuid = value["proposal_id"].rsplit(":", 1)[1]
        content = canonical_bytes(value) + b"\n"
        _immutable_write(self.pending / f"{proposal_uuid}.json", content)
        return value["proposal_id"]


def _receipt_path(root: Path, source: Path) -> Path:
    receipts = root / "proposal-spool" / "receipts"
    _safe_directory(receipts)
    return receipts / f"{source.stem}.receipt.json"


def _receipt_is_current(receipt_path: Path, source_hash: str, source_raw: bytes, store: ImprintStore) -> bool:
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise SafetyError("proposal receipt is not a regular file")
    try:
        receipt = json.loads(receipt_path.read_bytes())
    except json.JSONDecodeError as exc:
        raise SafetyError("proposal receipt is corrupt") from exc
    expected = {"receipt_schema_version", "proposal_id", "source_sha256", "status"}
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise SafetyError("proposal receipt has invalid fields")
    if receipt["receipt_schema_version"] != "1.0.0" or receipt["status"] != "accepted":
        raise SafetyError("proposal receipt does not prove accepted canonical state")
    if receipt["source_sha256"] != source_hash:
        raise ConflictError("proposal receipt does not match immutable source bytes")
    try:
        source_value = json.loads(source_raw)
    except json.JSONDecodeError as exc:
        raise ValidationError("receipted proposal source is corrupt") from exc
    if not isinstance(source_value, dict):
        raise ValidationError("receipted proposal source must be an object")
    source_value = validate_proposal(source_value)
    if receipt["proposal_id"] != source_value["proposal_id"]:
        raise ConflictError("proposal receipt identity does not match its source")
    nodes = [node for node in store.current_nodes(["Proposal"]) if node["node_id"] == receipt["proposal_id"]]
    return bool(nodes and nodes[0]["payload_sha256"] == payload_sha256(source_value))


def compile_pending_proposals(root: Path, store: ImprintStore) -> dict[str, Any]:
    """Apply each unreceipted proposal through the deterministic store writer."""
    pending = Path(root) / "proposal-spool" / "pending"
    _safe_directory(pending)
    counts = {"applied": 0, "duplicates": 0, "rejected": 0, "skipped": 0}
    failures: list[dict[str, str]] = []
    for source in sorted(pending.glob("*.json"), key=lambda item: item.name):
        if source.is_symlink() or not source.is_file():
            counts["rejected"] += 1
            failures.append({"file": source.name, "error_type": "SafetyError", "error": "proposal source is not a regular file"})
            continue
        receipt_path = _receipt_path(Path(root), source)
        raw = source.read_bytes()
        source_hash = hashlib.sha256(raw).hexdigest()
        if receipt_path.exists():
            try:
                if _receipt_is_current(receipt_path, source_hash, raw, store):
                    counts["skipped"] += 1
                    continue
            except (ValidationError, ConflictError, SafetyError) as exc:
                counts["rejected"] += 1
                failures.append({"file": source.name, "error_type": type(exc).__name__, "error": str(exc)})
                continue
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValidationError("proposal spool record must be an object")
            expected_name = f"{str(value.get('proposal_id', '')).rsplit(':', 1)[-1]}.json"
            if source.name != expected_name:
                raise ValidationError("proposal filename does not match proposal_id")
            result = store.append_proposal(value)
            status = "applied" if result == "applied" else "duplicate"
            counts["applied" if result == "applied" else "duplicates"] += 1
            receipt = {
                "receipt_schema_version": "1.0.0", "proposal_id": value["proposal_id"],
                "source_sha256": source_hash, "status": "accepted",
            }
        except (ValidationError, ConflictError, SafetyError, json.JSONDecodeError) as exc:
            counts["rejected"] += 1
            failures.append({"file": source.name, "error_type": type(exc).__name__, "error": str(exc)})
            receipt = {
                "receipt_schema_version": "1.0.0", "proposal_file": source.name,
                "source_sha256": source_hash, "status": "rejected",
                "error_type": type(exc).__name__, "error": str(exc),
            }
        _immutable_write(receipt_path, canonical_bytes(receipt) + b"\n")
    return {**counts, "failures": failures}
