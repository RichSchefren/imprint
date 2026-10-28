"""Portable single-interpreter Claude Code hook bridge."""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import NamedTuple

# Windows cold starts pay import and security-scanning latency that a healthy
# hook cannot control, so the shipped Windows deadline is deliberately wider.
DEFAULT_HOOK_TIMEOUT_SECONDS = 60 if os.name == "nt" else 10
MINIMUM_HOOK_TIMEOUT_SECONDS = 1
MAXIMUM_HOOK_TIMEOUT_SECONDS = 300
HOOK_TIMEOUT_ENV = "IMPRINT_HOOK_TIMEOUT_SECONDS"
_EVENT_NAMES = {
    "session-start": "SessionStart",
    "user-prompt-submit": "UserPromptSubmit",
    "health-check": "SessionStart",
}


class _HookTimeout(Exception):
    pass


def _config_file() -> Path:
    """Mirror ``imprint.config.config_path`` without importing the package.

    The deadline has to be known before any Imprint import runs, because that
    import is part of what the deadline bounds. Parity with the real resolver
    is asserted by the hook contract tests.
    """
    override = os.environ.get("IMPRINT_CONFIG")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home())) / "Imprint" / "config.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "imprint" / "config.json"


def _bounded_timeout(value: object, *, text: bool = False) -> int | None:
    """Accept only whole seconds inside the supported deadline range.

    JSON booleans are Python integers but are never valid settings, and a JSON
    string is rejected here exactly as ``imprint.config`` rejects it, so the
    hook and ``imprint health`` never disagree about which values are valid.
    """
    if isinstance(value, bool):
        return None
    if text:
        try:
            seconds = int(str(value).strip())
        except (TypeError, ValueError):
            return None
    elif isinstance(value, int):
        seconds = value
    else:
        return None
    if MINIMUM_HOOK_TIMEOUT_SECONDS <= seconds <= MAXIMUM_HOOK_TIMEOUT_SECONDS:
        return seconds
    return None


def _configured_timeout() -> int | None:
    """Read only this one setting, with stdlib calls the deadline can afford."""
    try:
        loaded = json.loads(_config_file().read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    if not isinstance(loaded, dict):
        return None
    return _bounded_timeout(loaded.get("hook_timeout_seconds"))


def hook_timeout_seconds() -> int:
    """Resolve the hook deadline: environment, then config, then platform default.

    An out-of-range or malformed value never disables hooks; it falls through to
    the next source. ``imprint health`` reports the same value as invalid config.
    """
    from_env = _bounded_timeout(os.environ.get(HOOK_TIMEOUT_ENV), text=True)
    if from_env is not None:
        return from_env
    configured = _configured_timeout()
    if configured is not None:
        return configured
    return DEFAULT_HOOK_TIMEOUT_SECONDS


class _Invocation(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


def _reset_stop_capture_phase(action: str) -> None:
    if action == "stop-capture":
        from imprint.capture.durability import reset_stop_capture_phase
        reset_stop_capture_phase()


def _stop_capture_was_lost(action: str) -> bool:
    if action != "stop-capture":
        return False
    from imprint.capture.durability import stop_capture_is_durable
    return not stop_capture_is_durable()


def _failure(action: str, error: str, *, stop_hook_active: bool = False,
             capture_was_lost: bool = False, timeout_seconds: int | None = None) -> int:
    """Block Stop once unless durable spool publication is positively known."""
    body = {
        "hook_schema_version": "1.0.0",
        "status": "degraded",
        "error": error,
        "hook_action": action,
        "failure_policy": (
            "fail_closed" if action == "stop-capture" and capture_was_lost
            else "fail_open"
        ),
    }
    if timeout_seconds is not None:
        body["timeout_seconds"] = timeout_seconds
    if action != "stop-capture":
        body["hookSpecificOutput"] = {
            "hookEventName": _EVENT_NAMES[action],
            "additionalContext": "",
        }
    print(json.dumps(body, sort_keys=True))
    if action == "stop-capture":
        print(f"Imprint Stop capture failed: {error}", file=sys.stderr)
        return 2 if capture_was_lost and not stop_hook_active else 0
    return 0


@contextlib.contextmanager
def _deadline(action: str, stop_hook_active: bool):
    """Enforce a process-local deadline; Windows uses a terminating watchdog."""
    timeout = hook_timeout_seconds()
    if hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread():
        def expired(_signum, _frame):
            raise _HookTimeout()

        prior = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, timeout)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prior)
        return

    def terminate() -> None:
        # A stuck in-process hook cannot be safely interrupted on Windows.
        # Write to OS handles because the stuck call may have redirected Python
        # streams. Unknown or pre-publication Stop state blocks once; a known
        # durable spool means only optional post-persist work timed out.
        capture_was_lost = _stop_capture_was_lost(action)
        body = {
            "hook_schema_version": "1.0.0", "status": "degraded",
            "error": "hook_action_timeout",
            "hook_action": action,
            "timeout_seconds": timeout,
            "failure_policy": (
                "fail_closed"
                if action == "stop-capture" and capture_was_lost
                else "fail_open"
            ),
        }
        if action != "stop-capture":
            body["hookSpecificOutput"] = {
                "hookEventName": _EVENT_NAMES[action], "additionalContext": "",
            }
        os.write(1, (json.dumps(body, sort_keys=True) + "\n").encode("utf-8"))
        if action == "stop-capture":
            os.write(2, b"Imprint Stop capture failed: hook_action_timeout\n")
        # os._exit skips compile_spools' release. Mark any held compiler lease
        # abandoned so the next compile can reclaim it. Look the module up
        # rather than import it: the stuck thread may hold the import lock.
        spool = sys.modules.get("imprint.compiler.spool")
        if spool is not None:
            try:
                spool.abandon_held_compiler_leases()
            except Exception:  # noqa: BLE001 - best effort while the process ends
                pass
        os._exit(2 if capture_was_lost and not stop_hook_active else 0)

    watchdog = threading.Timer(timeout, terminate)
    watchdog.daemon = True
    watchdog.start()
    try:
        yield
    finally:
        watchdog.cancel()


def _invoke_cli(argv: list[str], input_text: str) -> _Invocation:
    """Run the CLI in this hook interpreter with isolated standard streams."""
    from imprint.cli import main

    output, errors = io.StringIO(), io.StringIO()
    prior_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(input_text)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            returncode = main(argv)
    finally:
        sys.stdin = prior_stdin
    return _Invocation(returncode, output.getvalue(), errors.getvalue())


def run(action: str) -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # No durable capture can exist when Stop input cannot even be decoded.
        # Fail closed; unlike a valid repeated Stop event, malformed input has
        # no trustworthy stop_hook_active field with which to suppress a loop.
        return _failure(
            action, "hook_input_invalid",
            capture_was_lost=(action == "stop-capture"),
        )
    stop_hook_active = bool(event.get("stop_hook_active")) if isinstance(event, dict) else False
    prior_defer = os.environ.get("IMPRINT_DEFER_DELIVERY_COMMIT")
    os.environ["IMPRINT_DEFER_DELIVERY_COMMIT"] = "1"
    _reset_stop_capture_phase(action)
    try:
        with _deadline(action, stop_hook_active):
            process = _invoke_cli(
                ["hook", action],
                json.dumps(event, ensure_ascii=False, separators=(",", ":")),
            )
    except _HookTimeout:
        return _failure(
            action, "hook_action_timeout", stop_hook_active=stop_hook_active,
            capture_was_lost=_stop_capture_was_lost(action),
            timeout_seconds=hook_timeout_seconds(),
        )
    except Exception:
        return _failure(
            action, "hook_runtime_failed", stop_hook_active=stop_hook_active,
            capture_was_lost=_stop_capture_was_lost(action),
        )
    finally:
        if prior_defer is None:
            os.environ.pop("IMPRINT_DEFER_DELIVERY_COMMIT", None)
        else:
            os.environ["IMPRINT_DEFER_DELIVERY_COMMIT"] = prior_defer
    if process.returncode:
        error_code = None
        if action == "stop-capture" and process.stdout:
            try:
                failed_body = json.loads(process.stdout)
            except json.JSONDecodeError:
                failed_body = None
            if isinstance(failed_body, dict):
                error_code = failed_body.get("error_code")
        return _failure(
            action, str(error_code or "hook_action_failed"),
            stop_hook_active=stop_hook_active,
            capture_was_lost=(
                error_code == "spool_write_failed"
                or _stop_capture_was_lost(action)
            ),
        )
    if process.stdout:
        try:
            body = json.loads(process.stdout)
        except json.JSONDecodeError:
            return _failure(
                action, "hook_output_invalid", stop_hook_active=stop_hook_active,
                capture_was_lost=_stop_capture_was_lost(action),
            )
        delivery = body.pop("_imprint_delivery", None) if isinstance(body, dict) else None
        sys.stdout.write(json.dumps(body, sort_keys=True) + "\n")
        sys.stdout.flush()
        if delivery is not None:
            try:
                with _deadline(action, stop_hook_active):
                    _invoke_cli(["delivery-commit"], json.dumps(delivery, sort_keys=True))
            except (_HookTimeout, Exception):
                # Pending receipt intentionally remains replayable.
                pass
    return 0
