from __future__ import annotations

import io
import json
from hooks import _bridge
from imprint.capture.durability import (
    mark_stop_capture_persisted,
    mark_stop_capture_persisting,
)


def test_malformed_stop_input_is_fail_closed(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("not-json"))
    assert _bridge.run("stop-capture") == 2
    captured = capsys.readouterr()
    assert "hook_input_invalid" in captured.err
    assert json.loads(captured.out)["failure_policy"] == "fail_closed"


def test_unclassified_pre_persist_stop_failure_is_visible_and_blocks(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"stop_hook_active": False})))
    monkeypatch.setattr(_bridge, "_invoke_cli", lambda *a, **k: _bridge._Invocation(2, "", ""))
    assert _bridge.run("stop-capture") == 2
    captured = capsys.readouterr()
    assert "hook_action_failed" in captured.err
    assert json.loads(captured.out)["failure_policy"] == "fail_closed"


def test_stop_failure_does_not_create_repeated_stop_loop(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"stop_hook_active": True})))
    monkeypatch.setattr(_bridge, "_invoke_cli", lambda *a, **k: _bridge._Invocation(2, "", ""))
    assert _bridge.run("stop-capture") == 0
    captured = capsys.readouterr()
    assert "hook_action_failed" in captured.err


def test_timeout_during_persist_blocks_once_with_visible_reason(monkeypatch, capsys):
    def timeout_during_persist(*_args, **_kwargs):
        mark_stop_capture_persisting()
        raise _bridge._HookTimeout()

    monkeypatch.setattr(_bridge, "_invoke_cli", timeout_during_persist)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"stop_hook_active": False})))
    assert _bridge.run("stop-capture") == 2
    captured = capsys.readouterr()
    assert "hook_action_timeout" in captured.err
    assert json.loads(captured.out)["failure_policy"] == "fail_closed"


def test_timeout_after_persist_fails_open(monkeypatch, capsys):
    def timeout_after_persist(*_args, **_kwargs):
        mark_stop_capture_persisted()
        raise _bridge._HookTimeout()

    monkeypatch.setattr(_bridge, "_invoke_cli", timeout_after_persist)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"stop_hook_active": False})))
    assert _bridge.run("stop-capture") == 0
    captured = capsys.readouterr()
    assert "hook_action_timeout" in captured.err
    assert json.loads(captured.out)["failure_policy"] == "fail_open"


def test_generic_failure_after_persist_fails_open(monkeypatch, capsys):
    def fail_after_persist(*_args, **_kwargs):
        mark_stop_capture_persisted()
        raise RuntimeError("injected post-persist failure")

    monkeypatch.setattr(_bridge, "_invoke_cli", fail_after_persist)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"stop_hook_active": False})))
    assert _bridge.run("stop-capture") == 0
    captured = capsys.readouterr()
    assert "hook_runtime_failed" in captured.err
    assert json.loads(captured.out)["failure_policy"] == "fail_open"


def test_generic_pre_persist_failure_blocks_only_first_stop(monkeypatch, capsys):
    monkeypatch.setattr(
        _bridge, "_invoke_cli",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("pre-persist")),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"stop_hook_active": False})))
    assert _bridge.run("stop-capture") == 2
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"stop_hook_active": True})))
    assert _bridge.run("stop-capture") == 0
    captured = capsys.readouterr()
    assert "hook_runtime_failed" in captured.err
    assert json.loads(captured.out)["failure_policy"] == "fail_closed"


def test_exact_spool_write_failure_blocks_only_first_attempt(monkeypatch, capsys):
    events = iter((False, True))

    def failed_process(*args, **kwargs):
        return _bridge._Invocation(
            2, json.dumps({"status": "error", "error_code": "spool_write_failed"}), "",
        )

    monkeypatch.setattr(_bridge, "_invoke_cli", failed_process)
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"stop_hook_active": next(events)})),
    )
    assert _bridge.run("stop-capture") == 2
    capsys.readouterr()
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"stop_hook_active": next(events)})),
    )
    assert _bridge.run("stop-capture") == 0
    assert "spool_write_failed" in capsys.readouterr().err
