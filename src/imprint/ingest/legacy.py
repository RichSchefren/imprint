"""Fail-closed legacy Principle import.

Legacy flat principles remain Principles. Missing Cases, Verdicts, Beliefs, and
Values are never guessed or reconstructed.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from imprint.errors import ValidationError
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256
from imprint.store import ImprintStore
from imprint.store.service import utc_now


def import_legacy_principles(
    store: ImprintStore,
    records: Iterable[dict[str, Any]],
    *,
    operator_id: str,
    source_version: str,
    source_locator: str,
) -> list[str]:
    if source_version not in {"1", "1.0", "2", "2.0", "2.0.0"}:
        raise ValidationError("only declared v1/v2 legacy formats are supported")
    created = []
    for record in records:
        if not isinstance(record, dict) or set(record) - {"text", "extensions"}:
            raise ValidationError("legacy Principle record must contain only text and extensions")
        text = record.get("text")
        if not isinstance(text, str) or not text:
            raise ValidationError("legacy Principle text is required")
        extensions = record.get("extensions", {})
        if not isinstance(extensions, dict) or any(
            "." not in namespace or not isinstance(body, dict)
            for namespace, body in extensions.items()
        ):
            raise ValidationError("legacy extensions require namespaced object keys")
        source_id = make_urn("source")
        imported_at = utc_now()
        source_event_id = make_urn("event")
        source_payload = {
            "source_id": source_id,
            "source_kind": f"legacy_v{source_version}",
            "source_locator": source_locator,
            "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
        with store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (source_event_id, "imported", operator_id, imported_at, imported_at,
                 canonical_bytes(source_payload).decode(), payload_sha256(source_payload), None,
                 "extracted"),
            )
            conn.execute(
                "INSERT INTO source_receipts VALUES(?,?,?,?,?)",
                (source_id, f"legacy_v{source_version}", source_locator,
                 source_payload["content_sha256"], source_event_id),
            )
        node_id = store.append_derived_node(
            node_type="Principle",
            payload={
                "text": text,
                "legacy_source_version": source_version,
                "legacy_source_locator": source_locator,
                "legacy_valid_time_unknown": True,
                "imported_selected": True,
                "extensions": extensions,
            },
            provenance_status="extracted",
            authority_tier="imported_floor",
            evidence_ids=[source_id],
            operator_id=operator_id,
            valid_from=imported_at,
            proposed_by="deterministic-legacy-importer",
        )
        created.append(node_id)
    return created
