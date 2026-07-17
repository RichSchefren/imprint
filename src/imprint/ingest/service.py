"""Deterministic ingestion floor.

External material is quarantined first. It has no ontology authority until an
operator explicitly rules on it, and KEEP never promotes it beyond the
``imported_floor`` tier.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from imprint.errors import ConflictError, ValidationError
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256
from imprint.store import ImprintStore
from imprint.store.service import insert_node_version, utc_now, version_provenance


@dataclass(frozen=True)
class IngestCandidate:
    source_kind: str
    source_locator: str
    content: str
    metadata: dict[str, Any]
    extensions: dict[str, Any] | None = None

    def validate(self) -> None:
        if not self.source_kind.strip():
            raise ValidationError("source_kind is required")
        if not self.source_locator.strip():
            raise ValidationError("source_locator is required")
        if not isinstance(self.content, str) or not self.content:
            raise ValidationError("candidate content is required")
        if not isinstance(self.metadata, dict):
            raise ValidationError("metadata must be an object")
        if self.extensions is not None:
            if not isinstance(self.extensions, dict):
                raise ValidationError("extensions must be an object")
            for namespace, body in self.extensions.items():
                if "." not in namespace or not isinstance(body, dict):
                    raise ValidationError("extensions require namespaced object keys")

    def payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "content": self.content,
            "metadata": self.metadata,
            "extensions": self.extensions or {},
        }


class IngestService:
    """Quarantine scanner and insert-only ruling service."""

    def __init__(self, store: ImprintStore, operator_id: str):
        if store.expected_operator_id is not None and operator_id != store.expected_operator_id:
            raise ValidationError("ingest operator does not match configured identity")
        self.store = store
        self.operator_id = operator_id
        self.store.initialize()

    def scan(self, candidates: Iterable[IngestCandidate]) -> list[dict[str, str]]:
        """Quarantine candidates idempotently; never creates canonical nodes."""
        results: list[dict[str, str]] = []
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for candidate in candidates:
                payload = candidate.payload()
                raw = canonical_bytes(payload).decode()
                source_hash = hashlib.sha256(candidate.content.encode()).hexdigest()
                payload_hash = payload_sha256(payload)
                prior = conn.execute(
                    """SELECT item_id,payload_sha256,status FROM ingest_items
                       WHERE source_kind=? AND source_locator=? AND source_sha256=?""",
                    (candidate.source_kind, candidate.source_locator, source_hash),
                ).fetchone()
                if prior:
                    if prior["payload_sha256"] != payload_hash:
                        raise ConflictError("same ingest source identity has different metadata bytes")
                    results.append({"item_id": prior["item_id"], "status": prior["status"]})
                    continue
                item_id = make_urn("ingested-item")
                source_id = make_urn("source")
                scope = candidate.metadata.get("imprint_scope", {})
                if not isinstance(scope, dict):
                    raise ValidationError("metadata.imprint_scope must be an object")
                session_id = scope.get("session_id")
                node_id = scope.get("node_id")
                if session_id is not None and not isinstance(session_id, str):
                    raise ValidationError("metadata.imprint_scope.session_id must be a string")
                if node_id is not None and not isinstance(node_id, str):
                    raise ValidationError("metadata.imprint_scope.node_id must be a string")
                if self.store.expected_node_id is not None and node_id is not None and node_id != self.store.expected_node_id:
                    raise ValidationError("ingest producer node does not match configured identity")
                conn.execute(
                    "INSERT INTO ingest_items VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (item_id, self.operator_id, session_id, node_id, source_id,
                     candidate.source_kind, candidate.source_locator, source_hash,
                     raw, payload_hash, utc_now(), "unruled"),
                )
                results.append({"item_id": item_id, "status": "unruled"})
        return results

    def list(self, *, status: str | None = None) -> list[dict[str, Any]]:
        if status is not None and status not in {"unruled", "kept", "killed"}:
            raise ValidationError("invalid ingest status")
        query = "SELECT * FROM ingest_items"
        params: tuple[Any, ...] = ()
        if status is not None:
            query += " WHERE status=?"
            params = (status,)
        query += " ORDER BY discovered_at,item_id"
        with self.store.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result

    def kill(self, item_id: str, *, why: str | None = None) -> str:
        """Record a KILL. A reason is optional but the ruling is permanent evidence."""
        return self._rule(item_id, "KILL", why=why)

    def keep(self, item_id: str, *, why: str) -> str:
        """KEEP requires WHY and creates exactly one imported-floor node."""
        if not isinstance(why, str) or not why.strip():
            raise ValidationError("KEEP requires a non-empty WHY")
        return self._rule(item_id, "KEEP", why=why)

    def _rule(self, item_id: str, verdict: str, *, why: str | None) -> str:
        now = utc_now()
        event_id = make_urn("event")
        ruling_id = make_urn("ruling")
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT * FROM ingest_items WHERE item_id=?", (item_id,)).fetchone()
            if not item:
                raise ValidationError("unknown ingest item")
            wanted = "kept" if verdict == "KEEP" else "killed"
            if item["status"] != "unruled":
                if item["status"] == wanted:
                    prior = conn.execute(
                        "SELECT ruling_id,why FROM ingest_rulings WHERE item_id=? AND verdict=?",
                        (item_id, verdict),
                    ).fetchone()
                    if prior["why"] != why:
                        raise ConflictError("same ingest ruling was replayed with a different WHY")
                    return str(prior["ruling_id"])
                raise ConflictError("ingest item already has the opposite ruling")
            event_payload = {
                "item_id": item_id,
                "verdict": verdict,
                "why": why,
                "source_kind": item["source_kind"],
                "source_locator": item["source_locator"],
                "source_sha256": item["source_sha256"],
                "payload_sha256": item["payload_sha256"],
                "source_id": item["source_id"],
            }
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, "ingest_ruled", self.operator_id, now, now,
                 canonical_bytes(event_payload).decode(), payload_sha256(event_payload), None,
                 "extracted"),
            )
            conn.execute(
                "INSERT INTO ingest_rulings VALUES(?,?,?,?,?)",
                (ruling_id, item_id, verdict, why, event_id),
            )
            kept_node_id = None
            if verdict == "KEEP":
                kept_node_id = make_urn("ingested-item")
                source_id = item["source_id"]
                node_payload = json.loads(item["payload_json"])
                node_payload["ingest_why"] = why
                node_payload["imported_selected"] = True
                node_payload["source"] = {
                    "source_kind": item["source_kind"],
                    "source_locator": item["source_locator"],
                    "source_sha256": item["source_sha256"],
                }
                conn.execute(
                    "INSERT INTO nodes VALUES(?,?,?,?)",
                    (kept_node_id, "IngestedItem", self.operator_id, event_id),
                )
                insert_node_version(
                    conn,
                    (make_urn("node-version"), kept_node_id, canonical_bytes(node_payload).decode(),
                     payload_sha256(node_payload), "extracted", "imported_floor",
                     canonical_bytes(version_provenance(
                         status="extracted", authority_tier="imported_floor", actor_class="operator",
                         actor_id=self.operator_id, mechanism="ingest_keep_with_why", event_id=event_id,
                     )).decode(), json.dumps([source_id]), now, None, now, None, event_id, None),
                )
                conn.execute(
                    "INSERT INTO source_receipts VALUES(?,?,?,?,?)",
                    (source_id, item["source_kind"], item["source_locator"],
                     item["source_sha256"], event_id),
                )
            conn.execute(
                "UPDATE ingest_items SET status=?,kept_node_id=? WHERE item_id=?",
                (wanted, kept_node_id, item_id),
            )
        return ruling_id
