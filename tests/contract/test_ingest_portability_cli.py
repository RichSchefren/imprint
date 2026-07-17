from __future__ import annotations

import json

from imprint.cli import main


def _config(tmp_path, name):
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps({"operator_slug": name, "data_root": str(tmp_path / name)}))
    return path


def test_ingest_export_import_and_migrate_cli(
    tmp_path, capsys, signed_store, signed_cli, monkeypatch,
):
    source_config = _config(tmp_path, "source")
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps({
        "source_kind": "memory_export",
        "source_locator": "synthetic://cli/1",
        "content": "Imported context is not captured judgment.",
        "metadata": {"fixture": True},
        "extensions": {"org.example.cli": {"schema_version": "1.0.0", "payload": {"x": 1}}},
    }))
    assert main(["--config", str(source_config), "ingest", "scan", "--input", str(candidate)]) == 0
    item_id = json.loads(capsys.readouterr().out)["items"][0]["item_id"]
    assert main(["--config", str(source_config), "ingest", "keep", item_id, "--why", "useful context only"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "kept"
    assert main(["--config", str(source_config), "ingest", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"] == {"unruled": 0, "kept": 1, "killed": 0}

    exported = tmp_path / "imprint.jsonld"
    assert main(["--config", str(source_config), "export", "--format", "jsonld", "--output", str(exported)]) == 0
    capsys.readouterr()
    document = json.loads(exported.read_text())
    assert document["imprint:ledger"]["ingest_rulings"][0]["why"] == "useful context only"

    target_config = _config(tmp_path, "target")
    assert main(["--config", str(target_config), "import", "--format", "jsonld", "--input", str(exported), "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "validated"
    assert main(["--config", str(target_config), "import", "--format", "jsonld", "--input", str(exported)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "imported"
    target_identity = next((tmp_path / "target").rglob("identity.json"))
    operator_id = json.loads(target_identity.read_text())["operator_id"]
    authority = signed_store(target_identity.parent / "imprint.db", operator_id)
    from tests.conftest import _TestNativeConsole
    monkeypatch.setattr(
        "imprint.authority.service.NativeConsole", lambda: _TestNativeConsole(),
    )

    spec = tmp_path / "migration.json"
    assert main(["--config", str(target_config), "backup", "create"]) == 0
    backup_path = json.loads(capsys.readouterr().out)["path"]
    spec.write_text(json.dumps({
        "migration_id": "3.0.0-cli-labels",
        "from_version": "3.0.0",
        "to_version": "3.0.1",
        "statements": ["CREATE TABLE IF NOT EXISTS cli_labels (id TEXT PRIMARY KEY)"],
        "backup_receipt": backup_path,
    }))
    assert main(["--config", str(target_config), "migrate", "plan", "--spec", str(spec)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "applicable"
    assert signed_cli(main, ["--config", str(target_config), "migrate", "apply", "--spec", str(spec)], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "applied"
    # The additive migration is durable, but this 3.0.0 storage engine must not
    # continue ordinary operation against a newly labeled 3.0.1 store. A binary
    # that explicitly supports that target version is required to reopen it.
    assert main(["--config", str(target_config), "migrate", "verify"]) == 2
    refused = json.loads(capsys.readouterr().out)
    assert refused["error_type"] == "ValidationError"
    assert "incompatible store schema" in refused["error"]
