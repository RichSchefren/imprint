from __future__ import annotations

import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "tools" / "install" / "manage_hooks.py"
SPEC = importlib.util.spec_from_file_location("imprint_manage_hooks", MODULE_PATH)
assert SPEC and SPEC.loader
hooks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hooks)


def test_registration_is_idempotent_and_preserves_unrelated_hooks(tmp_path):
    settings = {
        "theme": "dark",
        "hooks": {
            "Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "other-tool"}]}],
        },
    }
    python = tmp_path / "Python With Spaces" / "python"
    directory = tmp_path / "Hooks With Spaces"
    once = hooks.mutate(settings, "register", python, directory)
    twice = hooks.mutate(once, "register", python, directory)
    assert twice["theme"] == "dark"
    assert sum("other-tool" in json.dumps(item) for item in twice["hooks"]["Stop"]) == 1
    assert hooks._counts(twice) == {"SessionStart": 2, "UserPromptSubmit": 1, "Stop": 1}


def test_unregistration_removes_only_owned_entries(tmp_path):
    settings = {"hooks": {"Stop": [
        {"matcher": "", "hooks": [{"type": "command", "command": "other-tool"}]},
        {"matcher": "", "hooks": [{"type": "command", "command": "run # imprint-local-managed-hook"}]},
    ]}}
    result = hooks.mutate(settings, "unregister", tmp_path / "python", tmp_path / "hooks")
    assert result["hooks"]["Stop"] == [
        {"matcher": "", "hooks": [{"type": "command", "command": "other-tool"}]},
    ]


def test_atomic_write_creates_parseable_settings_and_backup(tmp_path):
    path = tmp_path / "Claude Settings" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"existing": true}\n', encoding="utf-8")
    hooks._write(path, {"existing": True, "new": "value"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"existing": True, "new": "value"}
    assert list(path.parent.glob("settings.json.imprint-backup-*"))


def test_atomic_write_caps_settings_backups(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"generation": 0}\n', encoding="utf-8")
    for generation in range(1, 7):
        hooks._write(path, {"generation": generation})
    backups = list(path.parent.glob("settings.json.imprint-backup-*"))
    assert len(backups) == hooks.BACKUP_RETENTION == 3
    assert json.loads(path.read_text(encoding="utf-8")) == {"generation": 6}
