from __future__ import annotations

import json

from imprint.cli import main
from imprint.store import ImprintStore


def _configured(tmp_path, operator_id):
    data = tmp_path / "data"
    root = data / "test-operator"
    root.mkdir(parents=True)
    (root / "identity.json").write_text(json.dumps({
        "identity_schema_version": "1.0.0", "operator_id": operator_id,
    }))
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"operator_slug": "test-operator", "data_root": str(data), "compiler": True}))
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    return config, store


def test_domain_and_transition_cli_are_machine_readable(tmp_path, capsys, capture_envelope, signed_store, signed_cli):
    config, store = _configured(tmp_path, capture_envelope["operator_id"])
    store.apply_capture(capture_envelope)
    authority = signed_store(store.path, capture_envelope["operator_id"])
    store = authority.store
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]

    assert signed_cli(main, ["--config", str(config), "domain", "add", "research", "--label", "Research",
                 "--description", "Research judgments", "--evidence", evidence_id, "--by", capture_envelope["operator_id"]], capsys, authority) == 0
    added = json.loads(capsys.readouterr().out)
    assert added["status"] == "domain_added"
    assert signed_cli(main, ["--config", str(config), "domain", "select", "research", "--by", capture_envelope["operator_id"]], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "domain_selected"
    assert signed_cli(main, ["--config", str(config), "domain", "freeze", "research", "--by", capture_envelope["operator_id"]], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "domain_frozen"
    assert main(["--config", str(config), "domain", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["count"] == 1 and listed["items"][0]["payload"]["frozen"] is True

    evidence = [evidence_id]
    prior = store.append_derived_node(
        node_type="Rule", payload={"statement": "Old"}, provenance_status="inferred",
        authority_tier="inferred_candidate", evidence_ids=evidence,
        operator_id=capture_envelope["operator_id"], valid_from="2026-07-14T12:00:00Z", proposed_by="test",
    )
    replacement = store.append_derived_node(
        node_type="Rule", payload={"statement": "New"}, provenance_status="inferred",
        authority_tier="inferred_candidate", evidence_ids=evidence,
        operator_id=capture_envelope["operator_id"], valid_from="2026-07-14T13:00:00Z", proposed_by="test",
    )
    assert signed_cli(main, ["--config", str(config), "transition", "supersede", replacement, prior,
                 "--reason", "New rule replaces old", "--evidence", evidence_id, "--by", capture_envelope["operator_id"]], capsys, authority) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "supersedes" and result["edge_id"].startswith("urn:imprint:edge:")
