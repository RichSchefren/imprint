import ast
import json
from pathlib import Path


ROOT = Path(__file__).parents[2]
HOOKS = ROOT / "hooks"


def test_hook_manifest_registers_all_required_events_and_sources():
    manifest = json.loads((HOOKS / "hooks.json").read_text(encoding="utf-8"))
    assert manifest["hook_schema_version"] == "1.0.0"
    registrations = manifest["hooks"]
    assert len(registrations) == 4
    assert {item["event"] for item in registrations} == {"SessionStart", "UserPromptSubmit", "Stop"}
    assert {item["purpose"] for item in registrations} == {
        "bounded_core_general_retrieval",
        "deterministic_domain_injection",
        "explicit_feedback_capture",
        "content_free_health",
    }
    for item in registrations:
        assert (HOOKS / item["source"]).is_file()


def test_all_bundled_hook_python_is_valid_and_portable():
    sources = sorted(HOOKS.glob("*.py"))
    assert {source.name for source in sources} == {
        "_bridge.py", "health_check.py", "session_start.py", "stop_capture.py", "user_prompt_submit.py"
    }
    for source in sources:
        text = source.read_text(encoding="utf-8")
        ast.parse(text, filename=source.name)
        assert "/Users/" not in text
        assert "richardschefren" not in text.casefold()

