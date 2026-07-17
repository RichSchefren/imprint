from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

from imprint.compiler import (
    compile_spools, compiler_lock_state, prune_acknowledged_spools,
    recover_stale_compiler_lock, write_envelope,
)
from imprint.compiler.spool import LOCK_STALE_SECONDS
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.errors import ConflictError, SafetyError, ValidationError
from imprint.capture.schema import validate_capture_envelope
from imprint.capture.schema import build_capture_envelope, new_urn
from imprint.ontology.schema import canonical_bytes, make_urn, payload_sha256
from imprint.portability import export_jsonld, import_jsonld
from imprint.portability.jsonld import semantic_digest
from imprint.projections import jsonld_document, markdown_document
from imprint.store import ImprintStore


def test_capture_persists_raw_graph(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    assert store.apply_capture(capture_envelope) == "captured"
    types = {node["node_type"] for node in store.current_nodes()}
    assert types == {"Case", "Verdict", "Call", "Evidence"}
    edges = {edge["edge_type"] for edge in store.current_edges()}
    assert edges == {"verdict_about_case", "made_call", "supported_by"}
    assert all(node["provenance_status"] == "captured" for node in store.current_nodes())
    assert all(edge["provenance_status"] == "captured" for edge in store.current_edges())
    required = {
        "provenance_schema_version", "status", "authority_tier", "actor_class",
        "actor_id", "mechanism", "software", "model", "prompt_recipe",
        "proposal_id", "ratifier", "event_id", "relation",
    }
    assert all(set(item["provenance"]) == required for item in [*store.current_nodes(), *store.current_edges()])
    assert store.integrity_check() == "ok"


def test_required_graph_and_history_indexes_exist(tmp_path):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    with store.connect() as conn:
        indexes = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
    assert {
        "edges_by_source", "edges_by_target", "node_version_history",
        "disposition_subjects_by_subject",
    }.issubset(indexes)


def test_database_rejects_raw_authority_lattice_bypass(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    verdict = store.current_nodes(["Verdict"])[0]
    with store.connect() as conn, pytest.raises(sqlite3.IntegrityError, match="authority lattice"):
        conn.execute(
            "UPDATE node_versions SET authority_tier='ratified_knowledge' WHERE version_id=?",
            (verdict["version_id"],),
        )


def test_base_version_helper_rejects_column_provenance_disagreement(
    tmp_path, capture_envelope,
):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    with store.connect() as conn:
        row = conn.execute(
            "SELECT * FROM node_versions WHERE node_id=?",
            (capture_envelope["verdict"]["verdict_id"],),
        ).fetchone()
        values = list(tuple(row))
        values[0] = make_urn("node-version")
        values[5] = "captured_judgment"
        with pytest.raises(ValidationError, match="provenance disagrees"):
            store._insert_node_version(conn, tuple(values))


def test_no_production_base_version_insert_bypasses_canonical_funnels():
    source_root = Path(__file__).parents[2] / "src" / "imprint"
    node_sql = 'conn.execute("INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)'
    edge_sql = 'conn.execute("INSERT INTO edge_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)'
    direct_node = []
    direct_edge = []
    for path in source_root.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        if "INSERT INTO node_versions VALUES" in source:
            direct_node.append((path.relative_to(source_root).as_posix(), source.count("INSERT INTO node_versions VALUES")))
        if "INSERT INTO edge_versions VALUES" in source:
            direct_edge.append((path.relative_to(source_root).as_posix(), source.count("INSERT INTO edge_versions VALUES")))
    assert direct_node == [("store/service.py", 1)]
    assert direct_edge == [("store/service.py", 1)]
    service_source = (source_root / "store" / "service.py").read_text(encoding="utf-8")
    assert service_source.count(node_sql) == 1
    assert service_source.count(edge_sql) == 1


def test_raw_insert_still_cannot_mint_ratified_version_without_proof(
    tmp_path, capture_envelope,
):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    with store.connect() as conn:
        row = list(tuple(conn.execute(
            "SELECT * FROM node_versions WHERE node_id=?",
            (capture_envelope["verdict"]["verdict_id"],),
        ).fetchone()))
        row[0] = make_urn("node-version")
        row[4] = "ratified"
        row[5] = "ratified_knowledge"
        provenance = json.loads(row[6])
        provenance["status"] = "ratified"
        provenance["authority_tier"] = "ratified_knowledge"
        provenance["ratifier"] = None
        row[6] = canonical_bytes(provenance).decode()
        with pytest.raises(sqlite3.IntegrityError, match="authority lattice"):
            conn.execute(
                "INSERT INTO node_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(row),
            )


def test_disposition_subject_index_drives_history_and_upgrade_backfill(
    tmp_path, capture_envelope, signed_store,
):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    node_id = store.append_derived_node(
        node_type="Principle", payload={"statement": "Expose material failures"},
        provenance_status="inferred", authority_tier="inferred_candidate",
        evidence_ids=[evidence_id], operator_id=capture_envelope["operator_id"],
        valid_from="2026-07-14T18:00:00Z", proposed_by="test-agent",
    )
    event_id = authority.call(
        store.reject_node, node_id,
        rejector=capture_envelope["operator_id"], reason="Too broad",
    )
    with store.read_connection() as conn:
        subject = conn.execute(
            "SELECT subject_role,subject_id FROM event_disposition_subjects WHERE event_id=?",
            (event_id,),
        ).fetchone()
        plan = " ".join(
            row[3] for row in conn.execute(
                "EXPLAIN QUERY PLAN SELECT event_id FROM event_disposition_subjects WHERE subject_id=?",
                (node_id,),
            )
        )
    assert tuple(subject) == ("node_id", node_id)
    assert "disposition_subjects_by_subject" in plan
    assert store.node_history(node_id)["dispositions"][0]["event_id"] == event_id

    with store.connect() as conn:
        conn.execute("DROP TRIGGER event_disposition_subjects_insert")
        conn.execute("DROP TABLE event_disposition_subjects")
    store.initialize()
    with store.read_connection() as conn:
        rebuilt = conn.execute(
            "SELECT subject_role,subject_id FROM event_disposition_subjects WHERE event_id=?",
            (event_id,),
        ).fetchone()
    assert tuple(rebuilt) == ("node_id", node_id)


def test_two_read_only_connections_coexist_and_reject_mutation(
    tmp_path, capture_envelope,
):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    with store.read_connection() as first, store.read_connection() as second:
        assert first.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 4
        assert second.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == 3
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            first.execute("UPDATE meta SET value='broken' WHERE key='store_identity'")


def test_read_only_connection_coexists_with_live_writer_and_reads_committed_wal(
    tmp_path, capture_envelope,
):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    with store.connect() as writer:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("INSERT INTO meta(key,value) VALUES('concurrency_probe','pending')")
        assert Path(str(store.path) + "-wal").exists()
        with store.read_connection() as reader:
            assert reader.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 4
            assert reader.execute(
                "SELECT value FROM meta WHERE key='concurrency_probe'"
            ).fetchone() is None
    with store.read_connection() as reader:
        assert reader.execute(
            "SELECT value FROM meta WHERE key='concurrency_probe'"
        ).fetchone()[0] == "pending"


def test_capture_fails_closed_on_wrong_operator_or_producer_node(tmp_path, capture_envelope):
    store = ImprintStore(
        tmp_path / "imprint.db",
        expected_operator_id=capture_envelope["operator_id"],
        expected_node_id=capture_envelope["node_id"],
    )
    store.initialize()
    wrong_operator = json.loads(json.dumps(capture_envelope))
    wrong_operator["operator_id"] = new_urn("operator")
    with pytest.raises(ValidationError, match="operator"):
        store.apply_capture(wrong_operator)
    wrong_node = json.loads(json.dumps(capture_envelope))
    wrong_node["node_id"] = "foreign-producer"
    with pytest.raises(ValidationError, match="producer node"):
        store.apply_capture(wrong_node)
    assert store.current_nodes() == []


def test_semantic_relation_fails_before_lookup_for_foreign_configured_operator(tmp_path):
    configured = make_urn("operator")
    foreign = make_urn("operator")
    store = ImprintStore(tmp_path / "imprint.db", expected_operator_id=configured)
    store.initialize()
    relation = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "relation_id": make_urn("relation"), "relation_type": "inferred_from",
        "source_id": make_urn("principle"), "source_type": "Principle",
        "target_id": make_urn("verdict"), "target_type": "Verdict",
        "operator_id": foreign, "evidence_mode": "inferred",
        "why": "A foreign configured identity cannot write this relation.",
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": make_urn("model"),
            "mechanism": "identity_boundary_test", "evidence_ids": [make_urn("evidence")],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }
    with pytest.raises(ValidationError, match="configured identity"):
        store.append_semantic_relation(relation, valid_from="2026-07-14T12:00:00Z")
    assert store.current_edges() == []


def test_null_reason_is_first_class(tmp_path, capture_envelope):
    capture_envelope["verdict"]["reason"] = None
    capture_envelope["verdict"]["reason_status"] = "pending"
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    verdict = store.current_nodes(["Verdict"])[0]
    assert verdict["payload"]["reason"] is None
    assert verdict["payload"]["reason_status"] == "pending"


def test_alternatives_survive_projection(tmp_path, capture_envelope):
    chosen = make_urn("alternative")
    rejected = make_urn("alternative")
    capture_envelope["alternatives"] = [
        {"alternative_id": chosen, "description": "Report the failed source", "disposition": "chosen"},
        {"alternative_id": rejected, "description": "Hide it in a positive summary", "disposition": "rejected"},
    ]
    capture_envelope["verdict"]["chosen_alternative_ids"] = [chosen]
    capture_envelope["verdict"]["rejected_alternative_ids"] = [rejected]
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    snapshot = store.snapshot()
    graph = jsonld_document(snapshot)["@graph"]
    assert any(item.get("@type") == "imprint:Alternative" and item["payload"]["description"] == "Report the failed source" for item in graph)
    assert {edge["edge_type"] for edge in snapshot["edges"]} >= {"chose_alternative", "rejected_alternative"}


def test_same_event_is_idempotent_and_collision_fails(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    assert store.apply_capture(capture_envelope) == "captured"
    assert store.apply_capture(capture_envelope) == "duplicate"
    capture_envelope["case"]["description"] = "different bytes"
    with pytest.raises(ConflictError):
        store.apply_capture(capture_envelope)


def test_post_close_oserror_does_not_turn_committed_capture_into_failure(
    tmp_path, capture_envelope, monkeypatch,
):
    import imprint.store.service as service_module

    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    real_secure = service_module._secure_sqlite_state
    calls = 0

    def fail_only_post_close(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated post-close identity failure")
        return real_secure(path)

    monkeypatch.setattr(service_module, "_secure_sqlite_state", fail_only_post_close)
    assert store.apply_capture(capture_envelope) == "captured"
    monkeypatch.setattr(service_module, "_secure_sqlite_state", real_secure)
    assert store.apply_capture(capture_envelope) == "duplicate"


def test_post_close_oserror_does_not_mask_inflight_exception(tmp_path, monkeypatch):
    import imprint.store.service as service_module

    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    real_secure = service_module._secure_sqlite_state
    calls = 0

    def fail_only_post_close(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated post-close identity failure")
        return real_secure(path)

    monkeypatch.setattr(service_module, "_secure_sqlite_state", fail_only_post_close)
    with pytest.raises(RuntimeError, match="original transaction failure"):
        with store.connect():
            raise RuntimeError("original transaction failure")


def test_equivalent_feedback_content_is_deduplicated_across_new_event_ids(
    tmp_path, capture_envelope,
):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    assert store.apply_capture(capture_envelope) == "captured"
    repeated = json.loads(json.dumps(capture_envelope))
    repeated["input_event_id"] = new_urn("event")
    repeated["case"]["case_id"] = new_urn("case")
    repeated["verdict"]["verdict_id"] = new_urn("verdict")
    repeated["verdict"]["call"]["call_id"] = new_urn("call")
    for evidence in repeated["evidence"]:
        old_id = evidence["evidence_id"]
        evidence["evidence_id"] = new_urn("evidence")
        repeated["case"]["source_refs"] = [
            evidence["evidence_id"] if value == old_id else value
            for value in repeated["case"]["source_refs"]
        ]
        repeated["provenance"]["evidence_ids"] = [
            evidence["evidence_id"] if value == old_id else value
            for value in repeated["provenance"]["evidence_ids"]
        ]
    repeated["verdict"]["raw_operator_text"] = (
        "  " + repeated["verdict"]["raw_operator_text"].upper() + "  "
    )
    repeated["evidence"][0]["content"] = repeated["verdict"]["raw_operator_text"]
    repeated["evidence"][0]["content_sha256"] = hashlib.sha256(
        repeated["evidence"][0]["content"].encode("utf-8")
    ).hexdigest()
    assert store.apply_capture(repeated) == "duplicate"
    assert len(store.current_nodes(["Verdict"])) == 1


def test_spool_is_immutable_and_foreign_files_unchanged(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    path = write_envelope(root, capture_envelope)
    before = path.read_bytes()
    store = ImprintStore(root / "imprint.db")
    counts = compile_spools(root, store, compiler_authorized=True)
    assert counts == {"captured": 1, "duplicate": 0, "quarantined": 0}
    assert path.read_bytes() == before
    counts = compile_spools(root, store, compiler_authorized=True)
    assert counts == {"captured": 0, "duplicate": 0, "quarantined": 0}
    assert path.read_bytes() == before


def test_acknowledged_spool_retention_is_time_relative_and_producer_scoped(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    path = write_envelope(root, capture_envelope)
    store = ImprintStore(root / "imprint.db")
    assert compile_spools(root, store, compiler_authorized=True)["captured"] == 1
    ack = next((root / "runtime" / "acknowledgements" / capture_envelope["node_id"]).glob("*.json"))
    value = json.loads(ack.read_text())
    value["acknowledged_at"] = "2026-07-01T00:00:00Z"
    ack.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    early = prune_acknowledged_spools(
        root, source_node_id=capture_envelope["node_id"], retention_days=14,
        now=datetime(2026, 7, 14, tzinfo=timezone.utc),
    )
    assert early == {
        "deleted": 0, "retained": 1, "already_pruned": 0,
        "acknowledgements_deleted": 0, "quarantine_deleted": 0,
        "invalid": 0,
    }
    assert path.exists()
    due = prune_acknowledged_spools(
        root, source_node_id=capture_envelope["node_id"], retention_days=14,
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    assert due == {
        "deleted": 1, "retained": 0, "already_pruned": 0,
        "acknowledgements_deleted": 1, "quarantine_deleted": 0,
        "invalid": 0,
    }
    assert not path.exists() and not ack.exists()


def test_legacy_ack_with_already_pruned_exact_source_is_cleaned_not_invalid(
    tmp_path, capture_envelope,
):
    root = tmp_path / "operator"
    path = write_envelope(root, capture_envelope)
    store = ImprintStore(root / "imprint.db")
    assert compile_spools(root, store, compiler_authorized=True)["captured"] == 1
    ack = next((root / "runtime" / "acknowledgements" / capture_envelope["node_id"]).glob("*.json"))
    path.unlink()

    result = prune_acknowledged_spools(
        root, source_node_id=capture_envelope["node_id"], retention_days=30,
    )
    assert result["already_pruned"] == 1
    assert result["acknowledgements_deleted"] == 1
    assert result["invalid"] == 0
    assert not ack.exists()


def test_successful_compile_auto_prunes_stale_exact_ack_and_source(
    tmp_path, capture_envelope,
):
    root = tmp_path / "operator"
    path = write_envelope(root, capture_envelope)
    store = ImprintStore(root / "imprint.db")
    assert compile_spools(root, store, compiler_authorized=True)["captured"] == 1
    ack = next((root / "runtime" / "acknowledgements" / capture_envelope["node_id"]).glob("*.json"))
    value = json.loads(ack.read_text())
    value["acknowledged_at"] = "2020-01-01T00:00:00Z"
    ack.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")

    assert compile_spools(
        root, store, compiler_authorized=True, retention_days=1,
    ) == {"captured": 0, "duplicate": 0, "quarantined": 0}
    assert not path.exists()
    assert not ack.exists()


def test_prune_sweeps_stale_content_free_quarantine_receipts(
    tmp_path, capture_envelope,
):
    root = tmp_path / "operator"
    malformed = root / "spool" / capture_envelope["node_id"] / "malformed.json"
    malformed.parent.mkdir(parents=True)
    malformed.write_text("{not-json")
    store = ImprintStore(root / "imprint.db")
    assert compile_spools(root, store, compiler_authorized=True)["quarantined"] == 1
    receipt = next((root / "quarantine").glob("*.json"))
    value = json.loads(receipt.read_text())
    value["recorded_at"] = "2020-01-01T00:00:00Z"
    receipt.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")

    result = prune_acknowledged_spools(
        root, source_node_id=capture_envelope["node_id"], retention_days=1,
    )
    assert result["quarantine_deleted"] == 1
    assert result["invalid"] == 0
    assert not receipt.exists()


def test_capture_batch_uses_one_connection_and_isolates_identity_conflict(
    tmp_path, capture_envelope, monkeypatch,
):
    root = tmp_path / "operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    first = json.loads(json.dumps(capture_envelope))
    conflict = build_capture_envelope(
        operator_id=first["operator_id"], session_id=new_urn("session"),
        node_id=first["node_id"], case_description="Conflicting reused case identity",
        raw_operator_text="No, this conflict must quarantine without stopping its neighbors.",
        call_type="reject", capture_mechanism="explicit_cli", captured_by="test",
    )
    conflict["case"]["case_id"] = first["case"]["case_id"]
    third = build_capture_envelope(
        operator_id=first["operator_id"], session_id=new_urn("session"),
        node_id=first["node_id"], case_description="Valid neighbor after conflict",
        raw_operator_text="No, the valid neighbor after a conflict still must commit.",
        call_type="reject", capture_mechanism="explicit_cli", captured_by="test",
    )
    real_connect = store.connect
    connection_count = 0

    @contextmanager
    def counted_connect():
        nonlocal connection_count
        connection_count += 1
        with real_connect() as conn:
            yield conn

    monkeypatch.setattr(store, "connect", counted_connect)
    results = store.apply_capture_batch([
        (first, "spool/primary/first.json"),
        (conflict, "spool/primary/conflict.json"),
        (third, "spool/primary/third.json"),
    ], batch_size=2)
    assert results[0] == "captured"
    assert isinstance(results[1], ConflictError)
    assert results[2] == "captured"
    assert connection_count == 1
    monkeypatch.setattr(store, "connect", real_connect)
    assert len(store.current_nodes(["Verdict"])) == 2


def test_noncompiler_refuses_mutation(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    write_envelope(root, capture_envelope)
    with pytest.raises(SafetyError):
        compile_spools(root, ImprintStore(root / "imprint.db"), compiler_authorized=False)


def test_second_compiler_refuses_existing_writer_lock(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    write_envelope(root, capture_envelope)
    (root / "compiler.lock").mkdir()
    with pytest.raises(SafetyError, match="second writer"):
        compile_spools(root, ImprintStore(root / "imprint.db"), compiler_authorized=True)


def test_compiler_lock_state_and_exact_nonce_stale_recovery(tmp_path, monkeypatch):
    root = tmp_path / "operator"
    lock = root / "compiler.lock"
    lock.mkdir(parents=True)
    assert compiler_lock_state(root)["state"] == "invalid"
    assert compiler_lock_state(root)["stale"] is False
    old_mtime = time.time() - LOCK_STALE_SECONDS - 2
    os.utime(lock, (old_mtime, old_mtime))
    with pytest.raises(SafetyError, match="RECOVER-INVALID-LOCK"):
        recover_stale_compiler_lock(root, confirmation="anything")

    nonce = "a" * 32
    (lock / "owner.json").write_text(json.dumps({
        "lock_schema_version": "1.0.0", "nonce": nonce, "pid": 1,
        "host": "test-host", "created_at": "2000-01-01T00:00:00Z",
        "heartbeat_at": "2000-01-01T00:00:00Z",
    }))
    state = compiler_lock_state(root)
    assert state["state"] == "held" and state["stale"] is True
    with pytest.raises(SafetyError, match="exact owner nonce"):
        recover_stale_compiler_lock(root, confirmation="b" * 32)
    assert recover_stale_compiler_lock(root, confirmation=nonce) == {
        "status": "recovered", "nonce": nonce,
    }
    assert compiler_lock_state(root) == {"state": "absent", "stale": False}


def test_malformed_spool_creates_content_free_quarantine_receipt(tmp_path):
    root = tmp_path / "operator"
    spool = root / "spool" / "node-a"
    spool.mkdir(parents=True)
    source = spool / "malformed.json"
    source.write_text('{"private":"sentinel-secret"')
    before = source.read_bytes()
    counts = compile_spools(root, ImprintStore(root / "imprint.db"), compiler_authorized=True)
    assert counts == {"captured": 0, "duplicate": 0, "quarantined": 1}
    assert source.read_bytes() == before
    receipts = list((root / "quarantine").glob("*.json"))
    assert len(receipts) == 1
    receipt_text = receipts[0].read_text()
    assert "sentinel-secret" not in receipt_text
    assert json.loads(receipt_text)["content_included"] is False


def test_unknown_top_level_and_authority_escalation_fail(capture_envelope):
    capture_envelope["surprise"] = True
    with pytest.raises(ValidationError):
        validate_capture_envelope(capture_envelope)
    capture_envelope.pop("surprise")
    capture_envelope["provenance"]["status"] = "ratified"
    with pytest.raises(ValidationError):
        validate_capture_envelope(capture_envelope)


def test_projection_is_deterministic(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    one = markdown_document(store.snapshot())
    two = markdown_document(store.snapshot())
    assert one == two
    assert "[captured" in one
    assert capture_envelope["verdict"]["raw_operator_text"] in one
    projected = jsonld_document(store.snapshot())
    assert json.dumps(projected, sort_keys=True) == json.dumps(jsonld_document(store.snapshot()), sort_keys=True)
    assert all(isinstance(item["provenance"], dict) for item in projected["@graph"])
    assert all(item["provenanceStatus"] == item["provenance"]["status"] for item in projected["@graph"])


def test_inferred_pattern_requires_multiple_evidence_records(tmp_path):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    with pytest.raises(ValidationError, match="at least two cases"):
        store.append_derived_node(
            node_type="Pattern",
            payload={"statement": "Prefer explicit failure reports"},
            provenance_status="inferred",
            authority_tier="inferred_pattern",
            evidence_ids=[make_urn("evidence")],
            operator_id=make_urn("operator"),
            valid_from="2026-07-14T12:00:00Z",
            proposed_by="derive-agent",
        )


def test_derived_node_stays_non_authoritative_until_explicit_ratification(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    evidence_ids = [item["node_id"] for item in store.current_nodes(["Evidence"])]
    node_id = store.append_derived_node(
        node_type="Principle",
        payload={"statement": "Report every material source failure"},
        provenance_status="inferred",
        authority_tier="inferred_candidate",
        evidence_ids=evidence_ids,
        operator_id=capture_envelope["operator_id"],
        valid_from="2026-07-14T12:00:00Z",
        proposed_by="derive-agent",
    )
    before = store.current_nodes(["Principle"])[0]
    assert before["node_id"] == node_id
    assert before["provenance_status"] == "inferred"
    deferred = authority.call(store.defer_node,
        node_id,
        reviewer=capture_envelope["operator_id"],
        reason="Need another live example",
        revisit_after="2026-08-01T12:00:00Z",
    )
    assert deferred.startswith("urn:imprint:event:")
    assert store.current_nodes(["Principle"])[0]["provenance_status"] == "inferred"
    assert store.node_history(node_id)["dispositions"][-1]["event_type"] == "deferred"
    event_id = authority.call(store.ratify_node, node_id, ratifier=capture_envelope["operator_id"], note="Confirmed explicitly")
    after = store.current_nodes(["Principle"])[0]
    assert after["provenance_status"] == "ratified"
    assert after["authority_tier"] == "ratified_knowledge"
    assert event_id.startswith("urn:imprint:event:")
    with store.connect() as conn:
        versions = conn.execute(
            "SELECT provenance_status,system_to FROM node_versions WHERE node_id=? ORDER BY system_from",
            (node_id,),
        ).fetchall()
    assert [row["provenance_status"] for row in versions] == ["inferred", "ratified"]
    assert versions[0]["system_to"] is not None
    assert versions[1]["system_to"] is None


def test_strict_semantic_writer_preserves_typed_contract_and_legacy_path_cannot_write_new_types(
    tmp_path, capture_envelope,
):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    node_id = make_urn("principle")
    model_id = make_urn("model")
    contract = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": node_id,
        "node_type": "Principle",
        "operator_id": capture_envelope["operator_id"],
        "payload": {"statement": "Report material source failures explicitly."},
        "provenance": {
            "status": "inferred",
            "authority_tier": "inferred_candidate",
            "actor_class": "model",
            "actor_id": model_id,
            "mechanism": "typed_ontology_proposal",
            "evidence_ids": [evidence_id],
            "model": "synthetic-test-model",
            "ratifier_id": None,
        },
    }
    assert store.append_semantic_node(contract, valid_from="2026-07-14T12:00:00Z") == node_id
    saved = store.current_nodes(["Principle"])[0]
    assert saved["payload"] == contract["payload"]
    assert saved["provenance_status"] == "inferred"
    assert saved["authority_tier"] == "inferred_candidate"

    verdict_id = store.current_nodes(["Verdict"])[0]["node_id"]
    relation_id = make_urn("relation")
    relation = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "relation_id": relation_id,
        "relation_type": "inferred_from",
        "source_id": node_id,
        "source_type": "Principle",
        "target_id": verdict_id,
        "target_type": "Verdict",
        "operator_id": capture_envelope["operator_id"],
        "evidence_mode": "inferred",
        "why": "The proposed principle was inferred from this witnessed verdict.",
        "provenance": contract["provenance"],
    }
    assert store.append_semantic_relation(
        relation, valid_from="2026-07-14T12:00:00Z",
    ) == relation_id
    saved_edge = next(edge for edge in store.current_edges() if edge["edge_id"] == relation_id)
    assert saved_edge["edge_type"] == "inferred_from"
    assert saved_edge["provenance_status"] == "inferred"

    with pytest.raises(ValidationError, match="unsupported derived ontology"):
        store.append_derived_node(
            node_type="SelfModelAssertion",
            payload={}, provenance_status="inferred", authority_tier="inferred_candidate",
            evidence_ids=[evidence_id], operator_id=capture_envelope["operator_id"],
            valid_from="2026-07-14T12:00:00Z", proposed_by="legacy-path",
        )


def test_semantic_observation_requires_matching_durable_consent(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    operator_id = capture_envelope["operator_id"]
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    grant_id = make_urn("consentgrant")
    grant_payload = {
        "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "operator_id": operator_id,
        "source_class": "transcript",
        "purposes": ["behavioral_observation"],
        "sensitivity": "sensitive",
        "allowed_operations": ["store"],
        "retention": {"mode": "until_revoked", "days": None, "delete_on_revoke": True},
        "effective_from": "2026-07-01T00:00:00Z",
        "effective_to": None,
        "granted_by": operator_id,
        "granted_at": "2026-07-01T00:00:00Z",
        "revoked_at": None,
        "revocation_reason": None,
        "extensions": {},
    }
    captured_provenance = {
        "status": "captured", "authority_tier": "captured_judgment",
        "actor_class": "operator", "actor_id": operator_id,
        "mechanism": "explicit_consent", "evidence_ids": [],
        "model": None, "ratifier_id": None,
    }
    authority.call(store.append_semantic_node, {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": grant_id, "node_type": "ConsentGrant", "operator_id": operator_id,
        "payload": grant_payload, "provenance": captured_provenance,
    }, valid_from="2026-07-01T00:00:00Z")

    confidence = {
        "score": 0.8, "assessor_id": "synthetic-observer", "method": "model_estimate",
        "basis_evidence_ids": [evidence_id], "assessed_at": "2026-07-14T12:00:00Z",
        "calibration_trial_id": None, "uncertainty_note": "Single observation.",
    }
    observation_payload = {
        "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "operator_id": operator_id, "source_class": "transcript",
        "observation_kind": "behavior", "subject_id": operator_id,
        "description": "Explicitly reports failed sources.",
        "observed_at": "2026-07-14T12:00:00Z",
        "window_start": "2026-07-14T11:00:00Z", "window_end": "2026-07-14T13:00:00Z",
        "evidence_ids": [evidence_id], "confidence": confidence,
        "consent_grant_id": grant_id, "attributes": {}, "extensions": {},
    }
    observed_provenance = {
        "status": "extracted", "authority_tier": "observed_candidate",
        "actor_class": "software", "actor_id": make_urn("software"),
        "mechanism": "typed_observation", "evidence_ids": [evidence_id],
        "model": None, "ratifier_id": None,
    }
    observation_id = make_urn("observation")
    store.append_semantic_node({
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": observation_id, "node_type": "Observation", "operator_id": operator_id,
        "payload": observation_payload, "provenance": observed_provenance,
    }, valid_from="2026-07-14T12:00:00Z")
    assert store.current_nodes(["Observation"])[0]["node_id"] == observation_id

    portable = export_jsonld(store)
    unauthorized = json.loads(json.dumps(portable))
    grant_version = next(
        row for row in unauthorized["imprint:ledger"]["node_versions"]
        if row["node_id"] == grant_id
    )
    changed_grant = json.loads(grant_version["payload_json"])
    changed_grant["purposes"] = ["self_modeling"]
    grant_version["payload_json"] = canonical_bytes(changed_grant).decode()
    grant_version["payload_sha256"] = payload_sha256(changed_grant)
    grant_graph = next(item for item in unauthorized["@graph"] if item["@id"] == grant_version["version_id"])
    grant_graph["imprint:payload"] = changed_grant
    grant_graph["imprint:payloadSha256"] = grant_version["payload_sha256"]
    grant_node = next(row for row in unauthorized["imprint:ledger"]["nodes"] if row["node_id"] == grant_id)
    grant_event = next(
        row for row in unauthorized["imprint:ledger"]["events"]
        if row["event_id"] == grant_node["created_event_id"]
    )
    grant_event_payload = json.loads(grant_event["payload_json"])
    grant_event_payload["payload"] = changed_grant
    grant_event["payload_json"] = canonical_bytes(grant_event_payload).decode()
    grant_event["payload_sha256"] = payload_sha256(grant_event_payload)
    unauthorized["imprint:semanticSha256"] = semantic_digest(unauthorized)
    unauthorized_target = ImprintStore(tmp_path / "unauthorized-import.db")
    with pytest.raises(ValidationError, match="does not authorize imported"):
        import_jsonld(unauthorized_target, unauthorized)
    assert not unauthorized_target.path.exists()

    event_mismatch = json.loads(json.dumps(portable))
    observation_version = next(
        row for row in event_mismatch["imprint:ledger"]["node_versions"]
        if row["node_id"] == observation_id
    )
    changed_observation = json.loads(observation_version["payload_json"])
    changed_observation["description"] = "Altered without changing its creation event."
    observation_version["payload_json"] = canonical_bytes(changed_observation).decode()
    observation_version["payload_sha256"] = payload_sha256(changed_observation)
    observation_graph = next(
        item for item in event_mismatch["@graph"] if item["@id"] == observation_version["version_id"]
    )
    observation_graph["imprint:payload"] = changed_observation
    observation_graph["imprint:payloadSha256"] = observation_version["payload_sha256"]
    event_mismatch["imprint:semanticSha256"] = semantic_digest(event_mismatch)
    with pytest.raises(ValidationError, match="creation event does not match"):
        import_jsonld(ImprintStore(tmp_path / "event-mismatch.db"), event_mismatch)

    denied = json.loads(json.dumps(observation_payload))
    denied["source_class"] = "screenpipe"
    with pytest.raises(ValidationError, match="E_CONSENT_VERSION_REQUIRED"):
        store.append_semantic_node({
            "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "node_id": make_urn("observation"), "node_type": "Observation", "operator_id": operator_id,
            "payload": denied, "provenance": observed_provenance,
        }, valid_from="2026-07-14T12:00:00Z")

    authority.call(store.revoke_consent,
        grant_id, operator_id=operator_id, reason="Stop transcript observation",
        revoked_at="2026-07-14T12:30:00Z",
    )
    revoked = store.current_nodes(["ConsentGrant"])[0]
    assert revoked["payload"]["revoked_at"] == "2026-07-14T12:30:00Z"
    with pytest.raises(ValidationError, match="E_CONSENT_REVOKED"):
        store.append_semantic_node({
            "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "node_id": make_urn("observation"), "node_type": "Observation", "operator_id": operator_id,
            "payload": observation_payload, "provenance": observed_provenance,
        }, valid_from="2026-07-14T13:00:00Z")


def test_self_model_review_state_survives_defer_then_ratification(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    operator_id = capture_envelope["operator_id"]
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    model_id = make_urn("model")
    with store.connect() as conn:
        evidence_version_id = conn.execute(
            "SELECT version_id FROM node_versions WHERE node_id=? AND system_to IS NULL",
            (evidence_id,),
        ).fetchone()[0]
    trace_id = make_urn("derivationtrace")
    store.append_semantic_node({
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": trace_id, "node_type": "DerivationTrace", "operator_id": operator_id,
        "payload": {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
            "operator_id": operator_id, "element_version_id": evidence_version_id,
            "source_phase": "example.approved-import", "derived_from_rule": "synthetic-test-v1",
            "computed_at": "2026-07-14T12:00:00Z", "input_ids": [evidence_id],
            "input_snapshot_sha256": "a" * 64, "model_id": "synthetic-model",
            "prompt_id": "synthetic-prompt-v1", "extensions": {},
        },
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": model_id,
            "mechanism": "synthetic_derivation", "evidence_ids": [evidence_id],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }, valid_from="2026-07-14T12:00:00Z")
    payload = {
        "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "operator_id": operator_id, "function_class": "example.self-model",
        "dimension": "example.review-signal", "subtype": "example.profile-element",
        "statement": "Completion pressure can trigger unnecessary reframing.",
        "polarity": "constraint", "scope": "public release work", "source_phase": "example.approved-import",
        "derivation_trace_id": trace_id, "evidence_ids": [evidence_id],
        "confidence": {
            "score": 0.7, "assessor_id": "synthetic-model", "method": "model_estimate",
            "basis_evidence_ids": [evidence_id], "assessed_at": "2026-07-14T12:00:00Z",
            "calibration_trial_id": None, "uncertainty_note": "Requires operator review.",
        },
        "freshness": {
            "valid_from": "2026-07-14T12:00:00Z", "valid_to": None,
            "last_reviewed_at": None, "revalidate_after": "2026-08-14T12:00:00Z",
            "evidence_window_start": "2026-07-01T00:00:00Z",
            "evidence_window_end": "2026-07-14T12:00:00Z", "status": "current",
        },
        "review_state": "proposed", "structure": {},
        "provenance": {
            "status": "inferred", "actor_class": "model", "actor_id": model_id,
            "model_id": "synthetic-model", "prompt_id": "synthetic-prompt-v1",
        },
        "extensions": {},
    }
    node_id = make_urn("selfmodelassertion")
    store.append_semantic_node({
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": node_id, "node_type": "SelfModelAssertion", "operator_id": operator_id,
        "payload": payload,
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": model_id,
            "mechanism": "self_model_proposal_import", "evidence_ids": [evidence_id],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }, valid_from="2026-07-14T12:00:00Z")

    authority.call(store.defer_node, node_id, reviewer=operator_id, reason="Need another example")
    deferred = store.current_nodes(["SelfModelAssertion"])[0]
    assert deferred["payload"]["review_state"] == "deferred"
    assert deferred["provenance_status"] == "inferred"

    authority.call(store.ratify_node, node_id, ratifier=operator_id, note="Confirmed with scope intact")
    confirmed = store.current_nodes(["SelfModelAssertion"])[0]
    assert confirmed["payload"]["review_state"] == "confirmed"
    assert confirmed["payload"]["provenance"]["status"] == "ratified"
    assert confirmed["provenance_status"] == "ratified"


def test_ratification_requires_nonblank_operator_identity(tmp_path, capture_envelope):
    store = ImprintStore(tmp_path / "imprint.db")
    store.initialize()
    store.apply_capture(capture_envelope)
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    node_id = store.append_derived_node(
        node_type="Rule", payload={"statement": "Synthetic"},
        provenance_status="inferred", authority_tier="inferred_candidate",
        evidence_ids=[evidence_id], operator_id=capture_envelope["operator_id"],
        valid_from="2026-07-14T12:00:00Z", proposed_by="test",
    )
    with pytest.raises(ValidationError, match="ratifier identity"):
        store.ratify_node(node_id, ratifier="  ")
    assert store.current_nodes(["Rule"])[0]["provenance_status"] == "inferred"


def test_tombstone_preserves_history_and_removes_current_authority(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    verdict_id = capture_envelope["verdict"]["verdict_id"]
    event_id = authority.call(store.tombstone_node, verdict_id, reason="Operator reversed this judgment")
    assert event_id.startswith("urn:imprint:event:")
    assert verdict_id not in {node["node_id"] for node in store.current_nodes()}
    assert all(
        verdict_id not in {edge["source_id"], edge["target_id"]}
        for edge in store.current_edges()
    )
    with store.connect() as conn:
        historical = conn.execute(
            "SELECT COUNT(*) FROM node_versions WHERE node_id=? AND system_to IS NOT NULL",
            (verdict_id,),
        ).fetchone()[0]
        reversal = conn.execute(
            "SELECT event_type,payload_json FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
    assert historical == 1
    assert reversal["event_type"] == "tombstoned"
    assert json.loads(reversal["payload_json"])["reason"] == "Operator reversed this judgment"


def test_ratification_requires_one_signed_promotion_and_cannot_reratify(tmp_path, capture_envelope, signed_store):
    authority = signed_store(tmp_path / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    store.apply_capture(capture_envelope)
    verdict_id = capture_envelope["verdict"]["verdict_id"]
    authority.call(store.ratify_node, verdict_id, ratifier=capture_envelope["operator_id"])
    assert store.current_nodes(["Verdict"])[0]["authority_tier"] == "captured_judgment"
    with pytest.raises(ValidationError, match="only recorder candidates or inferred/extracted"):
        authority.call(store.ratify_node, verdict_id, ratifier=capture_envelope["operator_id"])


def test_canonical_capture_with_alternatives_compiles_end_to_end(tmp_path):
    envelope = build_capture_envelope(
        operator_id=new_urn("operator"),
        session_id=new_urn("session"),
        node_id="node-integration",
        case_description="Choosing how to report a failed source",
        raw_operator_text="Use the explicit failure report, not the softened summary.",
        call_type="prefer",
        capture_mechanism="explicit_cli",
        captured_by="integration-test",
        chosen_alternatives=["Explicitly identify the failed source"],
        rejected_alternatives=["Soften the result and omit the source failure"],
    )
    root = tmp_path / "operator"
    write_envelope(root, envelope)
    store = ImprintStore(root / "imprint.db")
    assert compile_spools(root, store, compiler_authorized=True) == {
        "captured": 1,
        "duplicate": 0,
        "quarantined": 0,
    }
    alternatives = store.current_nodes(["Alternative"])
    assert {item["payload"]["disposition"] for item in alternatives} == {"chosen", "rejected"}
    assert {item["edge_type"] for item in store.current_edges()} >= {
        "chose_alternative",
        "rejected_alternative",
    }
