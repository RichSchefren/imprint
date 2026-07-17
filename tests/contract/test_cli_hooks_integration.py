from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from imprint.cli import main
from imprint.constants import ONTOLOGY_SCHEMA_VERSION
from imprint.ontology.schema import make_urn
from imprint.store import ImprintStore


def _run(repo: Path, config: Path, action: str, event: dict) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["IMPRINT_CONFIG"] = str(config)
    return subprocess.run(
        [sys.executable, "-m", "imprint.cli", "hook", action],
        input=json.dumps(event), text=True, capture_output=True, cwd=repo, env=env, check=False,
    )


def test_hook_capture_compile_retrieve_and_once_delivery(
    tmp_path, signed_store, signed_cli, capsys,
):
    repo = Path(__file__).parents[2]
    data = tmp_path / "data root with spaces"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "config_version": "3.0.0", "data_root": str(data),
        "operator_slug": "test-operator", "node_id": "test-node", "compiler": True,
        "context_budget_bytes": 32768,
    }))
    event = {
        "session_id": "hook-session-1",
        "operator_text": "No, report the failed source explicitly because missing evidence changes the conclusion.",
        "case_description": "Reviewing a multi-source synthesis",
    }
    captured = _run(repo, config, "stop-capture", event)
    assert captured.returncode == 0, captured.stderr
    receipt = json.loads(captured.stdout)
    assert receipt["status"] == "queued"
    assert receipt["canonical_status"] == "compiled"
    assert receipt["compile"] == {"captured": 1, "duplicate": 0, "quarantined": 0}

    operator_id = json.loads((data / "test-operator" / "identity.json").read_text())["operator_id"]
    authority = signed_store(data / "test-operator" / "imprint.db", operator_id)
    store = authority.store
    verdict_id = store.current_nodes(["Verdict"])[0]["node_id"]
    authority.call(store.ratify_node, verdict_id, ratifier=operator_id)
    evidence_id = store.current_nodes(["Evidence"])[0]["node_id"]
    rule_id = make_urn("rule")
    contract = {
        "record_schema_version": ONTOLOGY_SCHEMA_VERSION,
        "node_id": rule_id, "node_type": "Rule", "operator_id": operator_id,
        "payload": {
            "statement": "Cite every failed source in the research domain.",
            "domain_id": "research",
        },
        "provenance": {
            "status": "inferred", "authority_tier": "inferred_candidate",
            "actor_class": "model", "actor_id": make_urn("model"),
            "mechanism": "public_cli_contract_test", "evidence_ids": [evidence_id],
            "model": "synthetic-model", "ratifier_id": None,
        },
    }
    semantic_input = tmp_path / "domain-rule.json"
    semantic_input.write_text(json.dumps(contract), encoding="utf-8")
    assert main([
        "--config", str(config), "ontology", "add-node", "--input", str(semantic_input),
        "--valid-from", "2026-07-14T12:00:00Z",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "semantic_node_added"
    assert signed_cli(main, [
        "--config", str(config), "review", "ratify", rule_id,
        "--by", operator_id, "--note", "Public domain retrieval contract",
    ], capsys, authority) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ratified"
    config_value = json.loads(config.read_text())
    config_value["domains"] = [{
        "domain_id": "research", "public_label": "Research",
        "safe_paths": ["Projects/Research"], "keywords": ["sources"], "frozen": False,
    }]
    config.write_text(json.dumps(config_value))

    first = _run(repo, config, "session-start", {"session_id": "fresh-session"})
    assert first.returncode == 0, first.stderr
    first_body = json.loads(first.stdout)
    assert first_body["status"] == "delivered"
    assert "failed source" in first_body["hookSpecificOutput"]["additionalContext"]
    assert "Case: Reviewing a multi-source synthesis" in first_body["hookSpecificOutput"]["additionalContext"]
    second = _run(repo, config, "session-start", {"session_id": "fresh-session"})
    assert json.loads(second.stdout)["status"] == "already_delivered"

    compacted = _run(repo, config, "session-start", {
        "hook_event_name": "SessionStart", "session_id": "fresh-session",
        "source": "compact",
    })
    assert compacted.returncode == 0, compacted.stderr
    compacted_body = json.loads(compacted.stdout)
    assert compacted_body["status"] == "delivered"
    assert "failed source" in compacted_body["hookSpecificOutput"]["additionalContext"]

    resumed = _run(repo, config, "session-start", {
        "hook_event_name": "SessionStart", "session_id": "fresh-session",
        "source": "resume",
    })
    assert resumed.returncode == 0, resumed.stderr
    assert json.loads(resumed.stdout)["status"] == "delivered"

    ordinary_again = _run(repo, config, "session-start", {"session_id": "fresh-session"})
    assert json.loads(ordinary_again.stdout)["status"] == "already_delivered"

    domain = _run(repo, config, "user-prompt-submit", {
        "session_id": "fresh-session", "cwd": "Projects/Research/Current", "prompt": "review",
    })
    assert domain.returncode == 0, domain.stderr
    domain_body = json.loads(domain.stdout)
    assert domain_body["domain_id"] == "research"
    assert domain_body["selection_method"] == "path"
    context = domain_body["hookSpecificOutput"]["additionalContext"]
    assert "research domain" in context
    assert "missing evidence changes" not in context
    domain_again = _run(repo, config, "user-prompt-submit", {
        "session_id": "fresh-session", "cwd": "Projects/Research/Current", "prompt": "review",
    })
    assert json.loads(domain_again.stdout)["status"] == "already_delivered"

    assert store.integrity_check() == "ok"
    verdict = store.current_nodes(["Verdict"])[0]
    assert verdict["payload"]["reason"] is None
    assert verdict["payload"]["reason_status"] == "absent"


def test_stop_hook_without_feedback_text_is_honest_noop(tmp_path):
    repo = Path(__file__).parents[2]
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"data_root": str(tmp_path / "data"), "operator_slug": "test"}))
    result = _run(repo, config, "stop-capture", {"session_id": "s"})
    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "hook_schema_version": "1.0.0",
        "reason": "feedback_text_unavailable",
        "status": "skipped",
    }


def test_native_claude_stop_payload_mines_bounded_transcript(tmp_path):
    repo = Path(__file__).parents[2]
    data = tmp_path / "data"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "data_root": str(data), "operator_slug": "test", "node_id": "primary",
    }))
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text("\n".join([
        json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "I omitted one failed source."}]}}),
        json.dumps({"type": "user", "message": {"role": "user", "content": "No, explicitly report every failed source because omission changes the decision."}}),
        json.dumps({"type": "assistant", "message": {"role": "assistant", "content": "Understood."}}),
    ]) + "\n")
    result = _run(repo, config, "stop-capture", {
        "hook_event_name": "Stop", "session_id": "native-session",
        "transcript_path": str(transcript), "cwd": str(tmp_path),
        "stop_hook_active": False,
    })
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "queued"
    assert receipt["canonical_status"] == "compiled"
    assert receipt["compile"]["captured"] == 1
    store = ImprintStore(data / "test" / "imprint.db")
    verdict = store.current_nodes(["Verdict"])[0]
    assert verdict["payload"]["raw_operator_text"].startswith("No, explicitly report")
    assert len(verdict["evidence"]) == 2


def test_hook_rejects_wrong_event_contract(tmp_path):
    repo = Path(__file__).parents[2]
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"data_root": str(tmp_path / "data"), "operator_slug": "test"}))
    result = _run(repo, config, "stop-capture", {
        "hook_schema_version": "9.0.0", "hook_event_name": "SessionStart",
    })
    assert result.returncode == 2
    assert json.loads(result.stdout)["error_type"] == "ValidationError"
