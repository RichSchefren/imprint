from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from imprint.store import ImprintStore


ROOT = Path(__file__).parents[2]


def _config(tmp_path: Path, *, compiler: bool) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    data = tmp_path / "data"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "config_version": "3.0.0", "data_root": str(data),
        "operator_slug": "test", "node_id": "primary", "compiler": compiler,
        "context_budget_bytes": 32768,
    }))
    return config, data


def _hook(config: Path, action: str, event: dict) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, IMPRINT_CONFIG=str(config))
    return subprocess.run(
        [sys.executable, "-m", "imprint.cli", "hook", action],
        input=json.dumps(event), text=True, capture_output=True,
        cwd=ROOT, env=env, check=False,
    )


def test_stop_capture_closes_canon_on_compiler_but_noncompiler_is_spool_only(tmp_path):
    config, data = _config(tmp_path / "compiler", compiler=True)
    result = _hook(config, "stop-capture", {
        "session_id": "native-compiler-session",
        "operator_text": "No, report every failed source because omissions change the decision.",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["canonical_status"] == "compiled"
    assert receipt["compile"] == {"captured": 1, "duplicate": 0, "quarantined": 0}
    store = ImprintStore(data / "test" / "imprint.db")
    assert store.current_nodes(["Verdict"])[0]["payload"]["raw_operator_text"].startswith("No, report")

    config, data = _config(tmp_path / "producer", compiler=False)
    result = _hook(config, "stop-capture", {
        "session_id": "native-producer-session",
        "operator_text": "No, preserve the exact correction because provenance matters.",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["canonical_status"] == "spool_only"
    assert len(list((data / "test" / "spool" / "primary").glob("*.json"))) == 1
    assert not (data / "test" / "imprint.db").exists()


def test_native_session_mapping_is_stable_local_opaque_and_never_stores_raw_id(tmp_path):
    config, data = _config(tmp_path, compiler=True)
    raw_same = "claude-native-sensitive-session-123"
    raw_other = "claude-native-sensitive-session-456"
    for raw, text in (
        (raw_same, "No, preserve the source because the evidence changes the recommendation."),
        (raw_same, "No, state the uncertainty because confidence was not established."),
        (raw_other, "No, retain the rejected option because the tradeoff matters."),
    ):
        result = _hook(config, "stop-capture", {"session_id": raw, "operator_text": text})
        assert result.returncode == 0, result.stdout + result.stderr
    spools = [json.loads(path.read_text()) for path in sorted(
        (data / "test" / "spool" / "primary").glob("*.json")
    )]
    session_counts = {}
    for item in spools:
        session_counts[item["session_id"]] = session_counts.get(item["session_id"], 0) + 1
    assert sorted(session_counts.values()) == [1, 2]
    assert all(item["session_id"].startswith("urn:imprint:session:") for item in spools)
    key = data / "test" / "session-map.key"
    assert len(key.read_text().strip()) == 64
    for path in (data / "test").rglob("*"):
        if path.is_file() and path.suffix in {".json", ".key"}:
            content = path.read_text(encoding="utf-8")
            assert raw_same not in content and raw_other not in content


def test_missing_native_session_ids_receive_distinct_event_local_opaque_sessions(tmp_path):
    config, data = _config(tmp_path, compiler=True)
    for text in (
        "No, preserve the source because it changes the decision.",
        "No, preserve the uncertainty because it changes the confidence.",
    ):
        result = _hook(config, "stop-capture", {"operator_text": text})
        assert result.returncode == 0, result.stdout + result.stderr
    spools = [json.loads(path.read_text()) for path in
              (data / "test" / "spool" / "primary").glob("*.json")]
    assert len({item["session_id"] for item in spools}) == 2


def test_huge_transcript_preserves_feedback_with_bounded_hashed_evidence(tmp_path):
    config, data = _config(tmp_path, compiler=True)
    transcript = tmp_path / "huge.jsonl"
    bounded_context = json.dumps({
        "type": "assistant", "message": {"role": "assistant", "content": "context " * 20000},
    })
    feedback = "No, keep the correction even when the transcript is huge because losing it corrupts the record."
    user = json.dumps({"type": "user", "message": {"role": "user", "content": feedback}})
    tail_payload = ("\n" + bounded_context + "\n" + user + "\n").encode()
    with transcript.open("wb") as handle:
        handle.seek((1024 * 1024 * 1024) - len(tail_payload))
        handle.write(tail_payload)
    started = time.monotonic()
    result = _hook(config, "stop-capture", {
        "hook_event_name": "Stop", "session_id": "huge-native-session",
        "transcript_path": str(transcript),
    })
    assert time.monotonic() - started < 5
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["canonical_status"] == "compiled"
    assert receipt["degradation"]["truncated"] is True
    assert receipt["degradation"]["transcript_bytes"] == transcript.stat().st_size
    assert len(receipt["degradation"]["evidence_sha256"]) == 64
    assert receipt["degradation"]["hash_scope"] == "bounded_tail"
    spool = json.loads(next((data / "test" / "spool" / "primary").glob("*.json")).read_text())
    assert spool["verdict"]["raw_operator_text"] == feedback
    assert len(spool["evidence"]) == 2
    assert len(spool["evidence"][1]["content"].encode("utf-8")) <= 64 * 1024
    extension = spool["extensions"]["org.imprint.transcript"]["payload"]
    assert extension["receipt"] == "huge_transcript_bounded_tail"
    assert extension["truncated"] is True


def test_huge_transcript_skips_historic_malformed_complete_tail_line(tmp_path):
    config, data = _config(tmp_path, compiler=True)
    transcript = tmp_path / "malformed-huge.jsonl"
    user = json.dumps({
        "type": "user",
        "message": {"role": "user", "content": "No, preserve the correction because it matters."},
    })
    tail = ("\n{malformed complete json}\n" + user + "\n").encode()
    with transcript.open("wb") as handle:
        handle.seek((17 * 1024 * 1024) - len(tail))
        handle.write(tail)

    result = _hook(config, "stop-capture", {
        "hook_event_name": "Stop", "session_id": "malformed-tail",
        "transcript_path": str(transcript),
    })
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["canonical_status"] == "compiled"
    assert receipt["degradation"]["skipped_malformed_line_count"] == 1
    assert len(list((data / "test" / "spool").glob("*/*.json"))) == 1


def test_regular_transcript_skips_blank_and_historic_malformed_lines_with_receipt(tmp_path):
    config, data = _config(tmp_path, compiler=True)
    transcript = tmp_path / "historic-malformed.jsonl"
    user = json.dumps({
        "type": "user",
        "message": {"role": "user", "content": "No, preserve this latest complete correction because it matters."},
    })
    transcript.write_text("\n{historic malformed json}\n\n" + user + "\n")

    result = _hook(config, "stop-capture", {
        "hook_event_name": "Stop", "session_id": "historic-malformed",
        "transcript_path": str(transcript),
    })
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["canonical_status"] == "compiled"
    assert receipt["degradation"] == {
        "receipt": "historic_malformed_lines_skipped",
        "truncated": False,
        "skipped_malformed_line_count": 1,
        "skipped_malformed_lines": [2],
    }
    assert len(list((data / "test" / "spool").glob("*/*.json"))) == 1


def test_transcript_fails_closed_on_incomplete_final_json_instead_of_using_older_user(tmp_path):
    config, data = _config(tmp_path, compiler=True)
    transcript = tmp_path / "incomplete-final.jsonl"
    older = json.dumps({
        "type": "user",
        "message": {
            "role": "user",
            "content": "No, this older correction must never substitute for a partial newer turn.",
        },
    })
    transcript.write_text(older + '\n{"type":"user","message":{"content":"No, newer')

    result = _hook(config, "stop-capture", {
        "hook_event_name": "Stop", "session_id": "incomplete-final",
        "transcript_path": str(transcript),
    })
    assert result.returncode == 2
    assert "incomplete transcript line" in result.stdout
    assert not list((data / "test" / "spool").glob("*/*.json"))


def test_stop_current_ack_succeeds_with_truthful_unrelated_quarantine_metadata(tmp_path):
    config, data = _config(tmp_path, compiler=True)
    unrelated = data / "test" / "spool" / "other-node" / "malformed.json"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text('{"unrelated":"malformed"')

    result = _hook(config, "stop-capture", {
        "session_id": "mixed-spool-current",
        "operator_text": "No, compile this exact correction even when an unrelated spool is malformed.",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["canonical_status"] == "compiled"
    assert receipt["compile"] == {
        "captured": 1, "duplicate": 0, "quarantined": 1,
    }
    assert receipt["compile_status"] == "degraded"
    assert receipt["unrelated_quarantine_count"] == 1
    store = ImprintStore(data / "test" / "imprint.db")
    current = store.current_nodes(["Verdict"])
    assert len(current) == 1
    assert current[0]["payload"]["raw_operator_text"].startswith("No, compile this exact")
    assert len(list((data / "test" / "runtime" / "acknowledgements" / "primary").glob("*.json"))) == 1


def test_stop_never_claims_compiled_without_exact_durable_ack_but_preserves_spool(
    tmp_path, monkeypatch, capsys,
):
    import imprint.cli as cli
    import imprint.compiler as compiler

    config, _ = _config(tmp_path, compiler=True)
    monkeypatch.setattr(cli, "compile_spools", lambda *args, **kwargs: {
        "captured": 1, "duplicate": 0, "quarantined": 0,
    })
    monkeypatch.setattr(compiler, "acknowledgement_committed", lambda *args: False)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(json.dumps({
        "session_id": "missing-ack",
        "operator_text": "No, preserve exact commit proof because false success is corrupting.",
    })))

    assert cli.main(["--config", str(config), "hook", "stop-capture"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "queued"
    assert body["canonical_status"] == "spool_only"
    assert body["compile_status"] == "degraded"
    assert body["compile_error_type"] == "ImprintError"


def _bridge_module():
    spec = importlib.util.spec_from_file_location("imprint_test_bridge", ROOT / "hooks" / "_bridge.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("script,expected", [
    ("stop_capture.py", 2),
    ("session_start.py", 0),
    ("user_prompt_submit.py", 0),
    ("health_check.py", 0),
])
def test_every_installed_hook_bridge_has_documented_invalid_input_policy(script, expected):
    result = subprocess.run(
        [sys.executable, str(ROOT / "hooks" / script)], input="not-json",
        text=True, capture_output=True, cwd=ROOT / "hooks", check=False,
    )
    assert result.returncode == expected
    body = json.loads(result.stdout)
    assert body["failure_policy"] == ("fail_closed" if expected else "fail_open")


@pytest.mark.parametrize("action,expected", [
    ("stop-capture", 2), ("session-start", 0),
    ("user-prompt-submit", 0), ("health-check", 0),
])
def test_hook_child_hang_is_killed_at_bound_with_declared_policy(tmp_path, monkeypatch, capsys, action, expected):
    bridge = _bridge_module()
    bridge.HOOK_TIMEOUT_SECONDS = 0.05
    monkeypatch.setattr(bridge, "_invoke_cli", lambda *args, **kwargs: time.sleep(60))
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("{}"))
    assert bridge.run(action) == expected
    body = json.loads(capsys.readouterr().out)
    assert body["error"] == "hook_action_timeout"
    assert body["failure_policy"] == ("fail_closed" if expected else "fail_open")


@pytest.mark.parametrize("action,expected", [
    ("stop-capture", 2), ("session-start", 0),
    ("user-prompt-submit", 0), ("health-check", 0),
])
def test_inprocess_hook_runtime_failure_uses_declared_policy(monkeypatch, capsys, action, expected):
    bridge = _bridge_module()
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("{}"))
    monkeypatch.setattr(bridge, "_invoke_cli", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("failed")))
    assert bridge.run(action) == expected
    body = json.loads(capsys.readouterr().out)
    assert body["error"] == "hook_runtime_failed"
    assert body["failure_policy"] == ("fail_closed" if expected else "fail_open")


def test_bridge_flushes_payload_before_delivery_commit(monkeypatch):
    bridge = _bridge_module()

    class FlushedOutput(io.StringIO):
        flushed = False

        def flush(self):
            self.flushed = True
            return super().flush()

    output = FlushedOutput()
    calls = []

    def invoke(argv, input_text):
        calls.append(argv)
        if len(calls) == 1:
            body = {
                "hook_schema_version": "1.0.0", "status": "delivered",
                "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "payload"},
                "_imprint_delivery": {"session_id": "opaque", "snapshot_id": "snapshot", "domain_id": None},
            }
            return bridge._Invocation(0, json.dumps(body), "")
        assert output.flushed is True
        assert argv[-1] == "delivery-commit"
        return bridge._Invocation(0, '{"status":"committed"}\n', "")

    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("{}"))
    monkeypatch.setattr(bridge.sys, "stdout", output)
    monkeypatch.setattr(bridge, "_invoke_cli", invoke)
    assert bridge.run("session-start") == 0
    assert len(calls) == 2
    visible = json.loads(output.getvalue())
    assert visible["hookSpecificOutput"]["additionalContext"] == "payload"
    assert "_imprint_delivery" not in visible


def test_real_bridge_commits_only_after_visible_delivery(tmp_path, signed_store):
    config, data = _config(tmp_path, compiler=True)
    seeded = _hook(config, "stop-capture", {
        "session_id": "seed",
        "operator_text": "No, preserve the failed source because it changes the decision.",
    })
    assert seeded.returncode == 0, seeded.stdout + seeded.stderr
    root = data / "test"
    operator_id = json.loads((root / "identity.json").read_text())["operator_id"]
    authority = signed_store(root / "imprint.db", operator_id)
    verdict_id = authority.store.current_nodes(["Verdict"])[0]["node_id"]
    authority.call(authority.store.ratify_node, verdict_id, ratifier=operator_id)
    env = dict(os.environ, IMPRINT_CONFIG=str(config))
    event = json.dumps({"hook_event_name": "SessionStart", "session_id": "bridge-session"})

    first = subprocess.run(
        [sys.executable, str(ROOT / "hooks" / "session_start.py")],
        input=event, text=True, capture_output=True, env=env, check=False,
    )
    assert first.returncode == 0, first.stdout + first.stderr
    first_body = json.loads(first.stdout)
    assert first_body["status"] == "delivered"
    assert first_body["hookSpecificOutput"]["additionalContext"]

    second = subprocess.run(
        [sys.executable, str(ROOT / "hooks" / "session_start.py")],
        input=event, text=True, capture_output=True, env=env, check=False,
    )
    assert second.returncode == 0, second.stdout + second.stderr
    assert json.loads(second.stdout)["status"] == "already_delivered"
