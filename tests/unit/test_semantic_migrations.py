from __future__ import annotations

import json

from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.ontology.schema import canonical_bytes, payload_sha256
from imprint.portability import ontology_migration_report, verify_ontology_schema
from imprint.store import ImprintStore


def _legacy_node(store, *, node_id, node_type, event_id, payload):
    with store.connect() as conn:
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            (event_id, "proposal_created", "operator", "2026-01-01T00:00:00Z",
             "2026-01-01T00:00:00Z", "{}", payload_sha256({}), None, "inferred"),
        )
        conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", (node_id, node_type, "operator", event_id))
        conn.execute(
            "INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (node_id + ":v1", node_id, canonical_bytes(payload).decode(), payload_sha256(payload),
             "inferred", "inferred_candidate", "{}", "[]", "2026-01-01T00:00:00Z",
             None, "2026-01-01T00:00:00Z", None, event_id, None),
        )


def test_current_ontology_version_is_verified_explicitly(tmp_path):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    result = verify_ontology_schema(store)
    assert result == {
        "status": "current",
        "compatible": True,
        "store_ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "expected_ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "migration_path": [],
    }


def test_known_old_version_reports_catalog_path_without_mutation(tmp_path):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    with store.connect() as conn:
        conn.execute("UPDATE meta SET value='3.0.0' WHERE key='ontology_schema_version'")
    result = ontology_migration_report(store)
    assert result["status"] == "migration_available"
    assert result["verification"]["migration_path"][0]["migration_id"] == "ontology-3.0.0-to-3.1.0"
    assert result["catalog"][0]["auto_converts_legacy"] is False
    with store._migration_connection(
        store_versions=frozenset({"3.0.0"}), ontology_versions=None,
    ) as conn:
        assert conn.execute("SELECT value FROM meta WHERE key='ontology_schema_version'").fetchone()[0] == "3.0.0"


def test_opaque_profile_and_business_records_are_legacy_untyped_not_converted(tmp_path):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    profile = {"fields": {"hidden_narrative": "unverified profile prose"}}
    business = {"description": "legacy customer prose"}
    _legacy_node(store, node_id="legacy-profile", node_type="FeedbackProfile", event_id="event-profile", payload=profile)
    _legacy_node(store, node_id="legacy-customer", node_type="Customer", event_id="event-customer", payload=business)

    before = store.path.read_bytes()
    result = ontology_migration_report(store)
    after = store.path.read_bytes()

    assert result["legacy_untyped_count"] == 2
    assert {item["classification"] for item in result["legacy_untyped_records"]} == {"legacy_untyped"}
    assert {item["reason"] for item in result["legacy_untyped_records"]} == {
        "opaque_feedback_profile", "opaque_business_record",
    }
    assert all(item["auto_conversion"] == "forbidden" for item in result["legacy_untyped_records"])
    assert result["legacy_policy"]["auto_convert_profile_prose"] is False
    assert before == after


def test_typed_business_node_is_not_classified_as_legacy(tmp_path):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    payload = {"ontology_schema_version": ONTOLOGY_SCHEMA_VERSION}
    with store.connect() as conn:
        conn.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            ("event-typed", "semantic_node", "operator", "2026-01-01T00:00:00Z",
             "2026-01-01T00:00:00Z", json.dumps(payload), payload_sha256(payload), None, "captured"),
        )
        conn.execute("INSERT INTO nodes VALUES(?,?,?,?)", ("typed-customer", "Customer", "operator", "event-typed"))
    assert ontology_migration_report(store)["legacy_untyped_records"] == []
