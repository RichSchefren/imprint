"""Synthetic lifecycle proof run by installed-artifact acceptance scripts."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from imprint.backup import create_backup, restore_backup, verify_backup
from imprint.capture.schema import build_capture_envelope, new_urn
from imprint.compiler import (
    compile_spools, compiler_lock_state, recover_stale_compiler_lock, write_envelope,
)
from imprint.derive.cold_start import finished_deliverable_decision
from imprint.errors import ValidationError
from imprint.ingest import IngestCandidate, IngestService
from imprint.portability import export_jsonld, import_jsonld
from imprint.portability.migrations import Migration, MigrationRunner
from imprint.permissions import unsafe_private_permissions
from imprint.projections import jsonld_document
from imprint.purge import hard_purge, preview_purge
from imprint.retrieve import RetrievalEngine, StoreRetrievalSource
from imprint.retrieve.receipts import DeliveryReceipts
from imprint.store import ImprintStore


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    operator_root = args.data_root / "default"
    operator = new_urn("operator")
    event = build_capture_envelope(
        operator_id=operator,
        session_id=new_urn("session"),
        node_id="acceptance-node",
        case_description="A synthetic answer hid a failed source.",
        raw_operator_text="Report the failed source explicitly because silent omission corrupts the decision.",
        call_type="correct",
        reason="Silent omission corrupts the decision.",
        capture_mechanism="explicit_cli",
        captured_by="artifact-acceptance/3.1.1",
        chosen_alternatives=["Report the failed source"],
        rejected_alternatives=["Omit the failure"],
    )
    write_envelope(operator_root, event)
    store = ImprintStore(operator_root / "imprint.db")
    assert compile_spools(operator_root, store, compiler_authorized=True) == {
        "captured": 1, "duplicate": 0, "quarantined": 0,
    }
    snapshot = store.snapshot()
    assert {item["node_type"] for item in snapshot["nodes"]} >= {
        "Case", "Verdict", "Call", "Alternative", "Evidence",
    }
    document = jsonld_document(snapshot)
    encoded = json.dumps(document, sort_keys=True)
    assert event["verdict"]["raw_operator_text"] in encoded
    assert event["verdict"]["reason"] in encoded
    assert all(isinstance(item["provenance"], dict) for item in document["@graph"])

    retrieval = RetrievalEngine(StoreRetrievalSource(store)).retrieve(
        snapshot_id="artifact-acceptance", query="failed source",
    )
    # Recorder output is an observed candidate until a native, signed operator
    # approval promotes it. The ordinary authoritative retrieval surface must
    # not expose it merely because the synthetic recorder supplied an operator
    # identifier; native authority acceptance proves the later promotion path.
    assert event["verdict"]["verdict_id"] not in retrieval.selected_ids
    assert retrieval.selected_bytes <= 32768

    assert not finished_deliverable_decision(lifecycle_status="published").accepted
    ingest = IngestService(store, operator)
    item = ingest.scan([IngestCandidate(
        source_kind="synthetic", source_locator="acceptance:item-1",
        content="An imported suggestion", metadata={"test": True},
    )])[0]
    assert store.current_nodes(["IngestedItem"]) == []
    ingest.keep(item["item_id"], why="Synthetic acceptance ruling")
    kept = store.current_nodes(["IngestedItem"])
    assert len(kept) == 1 and kept[0]["authority_tier"] == "imported_floor"

    # Lossless export/import must round-trip the entire versioned ledger.
    portable = export_jsonld(store)
    imported = ImprintStore(args.data_root / "roundtrip" / "imprint.db")
    digest = import_jsonld(imported, portable)
    assert digest == portable["imprint:semanticSha256"]
    assert export_jsonld(imported)["imprint:ledger"] == portable["imprint:ledger"]

    # A verified backup must restore canonical state after a destructive local mutation.
    backup = create_backup(store, operator_root)
    assert verify_backup(Path(backup["path"]))["status"] == "verified"
    verdict_id = event["verdict"]["verdict_id"]
    # Use non-authority diagnostic metadata for the destructive probe. A real
    # node tombstone is a governed mutation in v3.1 and requires a native signed
    # approval, which is proved by the separate native authority acceptance.
    with store.connect() as conn:
        conn.execute("INSERT INTO meta(key,value) VALUES('acceptance_restore_probe','mutated')")
    with store.connect() as conn:
        assert conn.execute(
            "SELECT value FROM meta WHERE key='acceptance_restore_probe'"
        ).fetchone()[0] == "mutated"
    restore_backup(
        store, operator_root, Path(backup["path"]),
        confirmation=Path(backup["path"]).name,
    )
    assert verdict_id in {item["node_id"] for item in store.current_nodes()}
    with store.connect() as conn:
        assert conn.execute(
            "SELECT 1 FROM meta WHERE key='acceptance_restore_probe'"
        ).fetchone() is None

    delivery = DeliveryReceipts(operator_root / "runtime" / "delivery")
    state, cached = delivery.prepare_delivery(
        "acceptance-session", "acceptance-snapshot", None,
        {"payload": "bounded response", "budget_bytes": 64},
    )
    assert state == "prepared" and cached is not None
    assert delivery.commit_delivery("acceptance-session", "acceptance-snapshot", None)

    executable = Path(sys.executable).with_name("imprint.exe" if os.name == "nt" else "imprint")
    installed_env = dict(os.environ, IMPRINT_CONFIG=str(args.config))
    def assert_healthy_private_state() -> None:
        health = subprocess.run(
            [str(executable), "health"], text=True, capture_output=True,
            env=installed_env, check=False,
        )
        if health.returncode != 0 and os.name == "nt":
            permission_probe = subprocess.run([
                sys.executable, "-c",
                "from pathlib import Path; from imprint.permissions import unsafe_windows_permissions; "
                "import sys; print(unsafe_windows_permissions(Path(sys.argv[1])))",
                str(operator_root),
            ], text=True, capture_output=True, env=installed_env, check=False)
            raise AssertionError(
                health.stdout + health.stderr + "\npermission_probe="
                + permission_probe.stdout + permission_probe.stderr
            )
        assert health.returncode == 0, health.stdout + health.stderr
        assert json.loads(health.stdout)["status"] == "healthy"

    projection = operator_root / "projections" / "imprint.jsonld"
    exported = subprocess.run(
        [str(executable), "export", "--format", "jsonld", "--output", str(projection)],
        text=True, capture_output=True, env=installed_env, check=False,
    )
    assert exported.returncode == 0, exported.stdout + exported.stderr
    assert_healthy_private_state()

    # Migration runner must fail closed on a destructive statement.
    try:
        MigrationRunner(store).apply(Migration(
            migration_id="acceptance-destructive", from_version="3.0.0",
            to_version="3.0.1", statements=("DROP TABLE nodes",),
            backup_receipt=backup["receipt_path"],
        ))
    except ValidationError:
        pass
    else:
        raise AssertionError("destructive migration was accepted")

    # Lease recovery is manual and requires the exact stale nonce.
    lock = operator_root / "compiler.lock"
    lock.mkdir()
    nonce = "c" * 32
    (lock / "owner.json").write_text(json.dumps({
        "lock_schema_version": "1.0.0", "nonce": nonce, "pid": 1,
        "host": "artifact-acceptance", "created_at": "2000-01-01T00:00:00Z",
        "heartbeat_at": "2000-01-01T00:00:00Z",
    }))
    assert compiler_lock_state(operator_root)["stale"] is True
    assert recover_stale_compiler_lock(operator_root, confirmation=nonce)["status"] == "recovered"

    # Exercise the installed native Stop-hook transcript contract, not an in-tree shortcut.
    hook_data = args.data_root / "native-hook"
    hook_config = args.data_root / "native-hook-config.json"
    hook_config.write_text(json.dumps({
        "config_version": "3.0.0", "data_root": str(hook_data),
        "operator_slug": "acceptance", "node_id": "primary", "compiler": True,
        "context_budget_bytes": 32768,
    }))
    transcript = args.data_root / "native-transcript.jsonl"
    transcript.write_text("\n".join([
        json.dumps({"type": "assistant", "message": {"role": "assistant", "content": "I omitted the failed source."}}),
        json.dumps({"type": "user", "message": {"role": "user", "content": "No, report the failed source because it changes the decision."}}),
        json.dumps({"type": "assistant", "message": {"role": "assistant", "content": "Corrected."}}),
    ]) + "\n")
    env = dict(os.environ, IMPRINT_CONFIG=str(hook_config))
    queued = subprocess.run(
        [str(executable), "hook", "stop-capture"], input=json.dumps({
            "hook_event_name": "Stop", "session_id": "artifact-native",
            "transcript_path": str(transcript), "cwd": str(args.data_root),
            "stop_hook_active": False,
        }), text=True, capture_output=True, env=env, check=False,
    )
    assert queued.returncode == 0, queued.stdout + queued.stderr
    queued_receipt = json.loads(queued.stdout)
    assert queued_receipt["status"] == "queued"
    assert queued_receipt["canonical_status"] == "compiled"
    assert queued_receipt["compile"]["captured"] == 1

    # Execute every installed bridge and verify its invalid-input failure policy.
    install_root = executable.parents[2]
    policies = {
        "stop_capture.py": (2, "fail_closed"),
        "session_start.py": (0, "fail_open"),
        "user_prompt_submit.py": (0, "fail_open"),
        "health_check.py": (0, "fail_open"),
    }
    for script, (expected_code, expected_policy) in policies.items():
        bridged = subprocess.run(
            [sys.executable, str(install_root / "hooks" / script)],
            input="not-json", text=True, capture_output=True, env=env, check=False,
        )
        assert bridged.returncode == expected_code, bridged.stdout + bridged.stderr
        assert json.loads(bridged.stdout)["failure_policy"] == expected_policy

    # Purge is its own acceptance boundary: exact confirmation is necessary but
    # never sufficient. Without enrolled native authority and a signed approval,
    # the installed artifact must fail closed and preserve canonical state.
    preview = preview_purge(store, operator_root, operator)
    assert preview["confirmation_required"] == operator
    try:
        hard_purge(
            store, operator_root, operator, confirmation=operator,
            sentinel=event["verdict"]["raw_operator_text"],
        )
    except ValidationError as exc:
        assert "configured operator" in str(exc)
    else:
        raise AssertionError("unsigned purge unexpectedly succeeded")
    assert store.current_nodes()
    unsafe = unsafe_private_permissions(operator_root)
    assert unsafe == (), f"unsafe private-state paths: {unsafe}"
    sentinel = operator_root / "acceptance-data-sentinel.txt"
    sentinel.write_text("preserve-me\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "sentinel": str(sentinel)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
