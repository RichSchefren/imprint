from __future__ import annotations

import json

import pytest

from imprint.errors import ValidationError
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256
from imprint.store import ImprintStore
from imprint.store.service import version_provenance


NOW = "2026-07-16T16:00:00Z"


def _grant(
    store: ImprintStore,
    operator_id: str,
    *,
    provenance_status: str = "captured",
    authority_tier: str = "captured_judgment",
    **changes,
) -> str:
    node_id, version_id, event_id = make_urn("consentgrant"), make_urn("node-version"), make_urn("event")
    payload = {
        "operator_id": operator_id,
        "source_class": "operator_explicit",
        "purposes": ["self_modeling", "retrieval"],
        "allowed_operations": ["store", "retrieve"],
        "effective_from": "2026-07-16T15:00:00Z",
        "effective_to": "2026-07-16T17:00:00Z",
        "retention": {"mode": "until_revoked", "days": None, "delete_on_revoke": False},
        "revoked_at": None,
    }
    payload.update(changes)
    provenance = version_provenance(
        status=provenance_status,
        authority_tier=authority_tier,
        actor_class="operator",
        actor_id=operator_id,
        mechanism="test_import" if provenance_status == "extracted" else "explicit_consent",
        event_id=event_id,
    )
    source_id = make_urn("source") if provenance_status == "extracted" else None
    evidence_ids = [source_id] if source_id is not None else []
    with store.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            (event_id, "consent_granted", operator_id, NOW, NOW,
             canonical_bytes(payload).decode(), payload_sha256(payload), None, provenance_status),
        )
        if source_id is not None:
            conn.execute(
                "INSERT INTO source_receipts VALUES(?,?,?,?,?)",
                (source_id, "test_import", "fixture://consent-grant", payload_sha256(payload), event_id),
            )
        conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (node_id, "ConsentGrant", operator_id, event_id))
        conn.execute(
            "INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (version_id, node_id, canonical_bytes(payload).decode(), payload_sha256(payload),
             provenance_status, authority_tier, canonical_bytes(provenance).decode(), json.dumps(evidence_ids),
             "2026-07-16T15:00:00Z", "2026-07-16T17:00:00Z",
             "2026-07-16T15:30:00Z", None, event_id, None),
        )
    return version_id


def test_dual_time_consent_is_half_open_and_has_no_operator_self_exemption(tmp_path):
    operator_id = make_urn("operator")
    store = ImprintStore(tmp_path / "imprint.db", expected_operator_id=operator_id)
    store.initialize()
    version_id = _grant(store, operator_id)
    with store.connect() as conn:
        assert store.authorize_consent_version(
            conn, version_id, operator_id=operator_id, source_class="operator_explicit",
            purpose="retrieval", operation="retrieve", valid_at="2026-07-16T16:00:00Z",
            system_at="2026-07-16T16:00:00Z",
        ) == version_id
        with pytest.raises(ValidationError, match="E_CONSENT_VERSION_REQUIRED"):
            store.authorize_consent_version(
                conn, version_id, operator_id=operator_id, source_class="operator_explicit",
                purpose="retrieval", operation="retrieve", valid_at="2026-07-16T17:00:00Z",
                system_at="2026-07-16T16:00:00Z",
            )
        with pytest.raises(ValidationError, match="future time exceeds"):
            store.authorize_consent_version(
                conn, version_id, operator_id=operator_id, source_class="operator_explicit",
                purpose="retrieval", operation="retrieve", valid_at="2026-07-16T16:03:00Z",
                system_at="2026-07-16T16:00:00Z",
            )


def test_revocation_and_foreign_or_imported_grants_deny(tmp_path):
    operator_id = make_urn("operator")
    store = ImprintStore(tmp_path / "imprint.db", expected_operator_id=operator_id)
    store.initialize()
    revoked = _grant(store, operator_id, revoked_at="2026-07-16T15:45:00Z")
    with store.connect() as conn:
        with pytest.raises(ValidationError, match="E_CONSENT_REVOKED"):
            store.authorize_consent_version(
                conn, revoked, operator_id=operator_id, source_class="operator_explicit",
                purpose="retrieval", operation="retrieve", valid_at="2026-07-16T15:45:00Z",
                system_at="2026-07-16T16:00:00Z",
            )
    imported = _grant(
        store,
        operator_id,
        provenance_status="extracted",
        authority_tier="imported_floor",
    )
    with store.connect() as conn:
        with pytest.raises(ValidationError, match="imported or unratified"):
            store.authorize_consent_version(
                conn, imported, operator_id=operator_id, source_class="operator_explicit",
                purpose="retrieval", operation="retrieve", valid_at="2026-07-16T15:30:00Z",
                system_at="2026-07-16T15:30:00Z",
            )
