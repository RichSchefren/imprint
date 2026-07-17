#!/usr/bin/env python3
"""Register or remove only Imprint-owned Claude Code hooks.

The marker is deliberately embedded in each command so registration remains
idempotent even when the same settings file contains unrelated user hooks.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any

MARKER = "imprint-local-managed-hook"
BACKUP_RETENTION = 3
EVENTS = {
    "SessionStart": ("session_start.py", "health_check.py"),
    "UserPromptSubmit": ("user_prompt_submit.py",),
    "Stop": ("stop_capture.py",),
}


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Claude settings must contain a JSON object")
    hooks = value.get("hooks", {})
    if hooks is not None and not isinstance(hooks, dict):
        raise ValueError("Claude settings hooks must contain a JSON object")
    return value


def _command(python: Path, script: Path) -> str:
    if os.name == "nt":
        # Claude Code executes hook commands through the platform shell.
        quote = lambda value: '"' + str(value).replace('"', '\\"') + '"'
        return f"{quote(python)} {quote(script)} # {MARKER}"
    return f"{shlex.quote(str(python))} {shlex.quote(str(script))} # {MARKER}"


def _owned(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks", []):
        if isinstance(hook, dict) and MARKER in str(hook.get("command", "")):
            return True
    return False


def _desired(python: Path, hooks_dir: Path) -> dict[str, list[dict[str, Any]]]:
    return {
        event: [
            {
                "matcher": "",
                "hooks": [{"type": "command", "command": _command(python, hooks_dir / source)}],
            }
            for source in sources
        ]
        for event, sources in EVENTS.items()
    }


def _counts(settings: dict[str, Any]) -> dict[str, int]:
    hooks = settings.get("hooks", {})
    return {
        event: sum(1 for item in hooks.get(event, []) if _owned(item))
        for event in EVENTS
    }


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(f"{path.name}.imprint-backup-{time.time_ns()}")
        backup.write_bytes(path.read_bytes())
        backups = sorted(
            path.parent.glob(f"{path.name}.imprint-backup-*"),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )
        for stale in backups[BACKUP_RETENTION:]:
            stale.unlink()
    temporary = path.with_suffix(path.suffix + ".imprint-tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def mutate(settings: dict[str, Any], action: str, python: Path, hooks_dir: Path) -> dict[str, Any]:
    hooks = settings.setdefault("hooks", {})
    for event in EVENTS:
        existing = hooks.get(event, [])
        if not isinstance(existing, list):
            raise ValueError(f"Claude settings hooks.{event} must contain a list")
        hooks[event] = [item for item in existing if not _owned(item)]
        if action == "register":
            hooks[event].extend(_desired(python, hooks_dir)[event])
        if not hooks[event]:
            hooks.pop(event)
    if not hooks:
        settings.pop("hooks", None)
    return settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("register", "unregister", "status"))
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--hooks-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        settings = _read(args.settings)
        if args.action != "status":
            # Keep the venv interpreter path itself. Resolving venv/bin/python
            # follows its symlink to the system interpreter, which cannot
            # import the package installed only inside the venv.
            settings = mutate(settings, args.action, args.python, args.hooks_dir)
            _write(args.settings, settings)
        counts = _counts(settings)
        expected = {event: len(sources) if args.action != "unregister" else 0 for event, sources in EVENTS.items()}
        okay = counts == expected
        print(json.dumps({"status": "ok" if okay else "error", "counts": counts}, sort_keys=True))
        return 0 if okay else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
