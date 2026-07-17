from __future__ import annotations

import json

from imprint.cli import main
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.ontology.schema import make_urn
from imprint.store import ImprintStore


def _configured(tmp_path):
    data = tmp_path / "data"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "operator_slug": "test-operator",
        "data_root": str(data),
        "compiler": True,
        "experimental": {"digest": False, "profile_learning": False},
    }))
    root = data / "test-operator"
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    return config, root, store


def _proposal(store):
    evidence_ids = [item["node_id"] for item in store.current_nodes(["Evidence"])]
    operator_id = store.current_nodes()[0]["operator_id"]
    return store.append_derived_node(
        node_type="Principle",
        payload={"statement": "Report failures explicitly"},
        provenance_status="inferred",
        authority_tier="inferred_candidate",
        evidence_ids=evidence_ids,
        operator_id=operator_id,
        valid_from="2026-07-14T18:00:00Z",
        proposed_by="contract-test",
    )


def test_review_history_and_backup_cli_are_machine_readable(
    tmp_path, capsys, capture_envelope, signed_store, signed_cli, monkeypatch,
):
    config, root, store = _configured(tmp_path)
    store.apply_capture(capture_envelope)
    (root / "identity.json").write_text(json.dumps({"identity_schema_version": "1.0.0", "operator_id": capture_envelope["operator_id"]}))
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    store = authority.store
    from tests.conftest import _TestNativeConsole
    monkeypatch.setattr(
        "imprint.authority.service.NativeConsole", lambda: _TestNativeConsole(),
    )
    node_id = _proposal(store)

    assert main(["--config", str(config), "review", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["count"] == 1 and listed["items"][0]["node_id"] == node_id

    assert signed_cli(main, ["--config", str(config), "review", "reject", node_id, "--by", capture_envelope["operator_id"], "--reason", "too broad"], capsys, authority) == 0
    rejected = json.loads(capsys.readouterr().out)
    assert rejected["status"] == "rejected"

    assert main(["--config", str(config), "history", node_id]) == 0
    history = json.loads(capsys.readouterr().out)
    assert history["history"]["dispositions"][0]["event_type"] == "rejected"

    assert main(["--config", str(config), "backup", "create"]) == 0
    backup = json.loads(capsys.readouterr().out)
    assert backup["status"] == "created"
    assert main(["--config", str(config), "backup", "verify", backup["path"]]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "verified"



def test_purge_cli_requires_separate_exact_confirmation(tmp_path, capsys, capture_envelope, signed_store, signed_cli):
    config, root, store = _configured(tmp_path)
    store.apply_capture(capture_envelope)
    (root / "identity.json").write_text(json.dumps({"identity_schema_version": "1.0.0", "operator_id": capture_envelope["operator_id"]}))
    authority = signed_store(root / "imprint.db", capture_envelope["operator_id"])
    scope = capture_envelope["verdict"]["verdict_id"]

    assert main(["--config", str(config), "delete", "purge", "--scope", scope, "--preview"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["status"] == "preview"
    assert preview["confirmation_required"] == scope

    assert main(["--config", str(config), "delete", "purge", "--scope", scope]) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["error_type"] == "ValidationError"

    assert signed_cli(main, [
        "--config", str(config), "delete", "purge", "--scope", scope, "--confirm", scope,
    ], capsys, authority) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "purged" and result["active_root_scan"] == "clear"


def test_typed_ontology_and_defer_cli_use_canonical_writer(tmp_path, capsys, capture_envelope, signed_store, signed_cli):
    config, root, store = _configured(tmp_path)
    assert main(["--config", str(config), "health"]) in {0, 2}
    capsys.readouterr()
    operator_id = json.loads((root / "identity.json").read_text())["operator_id"]
    capture_envelope["operator_id"] = operator_id
    store.apply_capture(capture_envelope)
    authority = signed_store(root / "imprint.db", operator_id)
    store = authority.store
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    node_id = make_urn("principle")
    contract = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": node_id, "node_type": "Principle", "operator_id": operator_id,
        "payload": {"statement": "Preserve typed evidence from the first build."},
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": make_urn("model"),
            "mechanism": "contract_test", "evidence_ids": [evidence_id],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }
    input_path = tmp_path / "semantic-node.json"
    input_path.write_text(json.dumps(contract))
    assert main([
        "--config", str(config), "ontology", "add-node", "--input", str(input_path),
        "--valid-from", "2026-07-14T18:00:00Z",
    ]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "node_id": node_id, "status": "semantic_node_added",
    }
    assert signed_cli(main, [
        "--config", str(config), "review", "defer", node_id, "--by", operator_id,
        "--reason", "Need one more witnessed case",
        "--revisit-after", "2026-08-01T00:00:00Z",
    ], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "deferred"
    assert store.node_history(node_id)["dispositions"][-1]["event_type"] == "deferred"


def test_dedicated_consent_observation_and_outcome_cli_commands(
    tmp_path, capsys, capture_envelope, signed_store, signed_cli,
):
    config, root, store = _configured(tmp_path)
    assert main(["--config", str(config), "health"]) in {0, 2}
    capsys.readouterr()
    operator_id = json.loads((root / "identity.json").read_text())["operator_id"]
    capture_envelope["operator_id"] = operator_id
    store.apply_capture(capture_envelope)
    authority = signed_store(root / "imprint.db", operator_id)
    store = authority.store
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    grant_id = make_urn("consentgrant")
    captured = {
        "status": "captured", "authority_tier": "captured_judgment",
        "actor_class": "operator", "actor_id": operator_id,
        "mechanism": "explicit_consent", "evidence_ids": [],
        "model": None, "ratifier_id": None,
    }
    grant = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": grant_id, "node_type": "ConsentGrant", "operator_id": operator_id,
        "payload": {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION, "operator_id": operator_id,
            "source_class": "transcript",
            "purposes": ["behavioral_observation", "outcome_learning"],
            "sensitivity": "sensitive", "allowed_operations": ["store"],
            "retention": {"mode": "until_revoked", "days": None, "delete_on_revoke": False},
            "effective_from": "2026-07-01T00:00:00Z", "effective_to": None,
            "granted_by": operator_id, "granted_at": "2026-07-01T00:00:00Z",
            "revoked_at": None, "revocation_reason": None, "extensions": {},
        },
        "provenance": captured,
    }
    grant_path = tmp_path / "grant.json"
    grant_path.write_text(json.dumps(grant))
    assert signed_cli(main, [
        "--config", str(config), "consent", "grant", "--input", str(grant_path),
        "--valid-from", "2026-07-01T00:00:00Z",
    ], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "consent_granted"

    observed = {
        "status": "extracted", "authority_tier": "observed_candidate",
        "actor_class": "software", "actor_id": make_urn("software"),
        "mechanism": "typed_observation", "evidence_ids": [evidence_id],
        "model": None, "ratifier_id": None,
    }
    confidence = {
        "score": 0.8, "assessor_id": "synthetic-observer", "method": "model_estimate",
        "basis_evidence_ids": [evidence_id], "assessed_at": "2026-07-14T12:00:00Z",
        "calibration_trial_id": None, "uncertainty_note": "Synthetic CLI fixture.",
    }
    observation = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": make_urn("observation"), "node_type": "Observation", "operator_id": operator_id,
        "payload": {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION, "operator_id": operator_id,
            "source_class": "transcript", "observation_kind": "behavior",
            "subject_id": operator_id, "description": "Reports failed sources explicitly.",
            "observed_at": "2026-07-14T12:00:00Z", "window_start": "2026-07-14T11:00:00Z",
            "window_end": "2026-07-14T13:00:00Z", "evidence_ids": [evidence_id],
            "confidence": confidence, "consent_grant_id": grant_id,
            "attributes": {}, "extensions": {},
        },
        "provenance": observed,
    }
    observation_path = tmp_path / "observation.json"
    observation_path.write_text(json.dumps(observation))
    assert main([
        "--config", str(config), "observation", "add", "--input", str(observation_path),
        "--valid-from", "2026-07-14T12:00:00Z",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "observation_added"

    outcome = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": make_urn("outcome"), "node_type": "Outcome", "operator_id": operator_id,
        "payload": {
            "ontology_schema_version": ONTOLOGY_SCHEMA_VERSION, "operator_id": operator_id,
            "evidence_mode": "observed", "subject_id": make_urn("verdict"),
            "description": "Conversion increased after the decision.",
            "metric": "conversion_rate", "value": 0.31, "unit": "ratio",
            "window_start": "2026-07-01T00:00:00Z", "window_end": "2026-07-14T12:00:00Z",
            "source_class": "transcript", "attribution_status": "contributory",
            "observed_at": "2026-07-14T12:00:00Z", "source_refs": [evidence_id],
            "consent_grant_id": grant_id, "attributes": {},
        },
        "provenance": observed,
    }
    outcome_path = tmp_path / "outcome.json"
    outcome_path.write_text(json.dumps(outcome))
    assert main([
        "--config", str(config), "outcome", "add", "--input", str(outcome_path),
        "--valid-from", "2026-07-14T12:00:00Z",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "outcome_added"
