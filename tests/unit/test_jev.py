from __future__ import annotations

import json

import pytest

from imprint.retrieve.jev import JevSelector, prefilter
from imprint.retrieve.models import RetrievalRecord


def item(record_id: str, text: str) -> RetrievalRecord:
    return RetrievalRecord(record_id, text, "general", "captured", "captured_judgment", ("e",), ("c",), provenance_complete=True)


def test_prefilter_is_bounded_and_relevance_ordered():
    values = [item("irrelevant", "gardening flowers"), item("relevant", "deploy production safely")]
    assert [x.record_id for x in prefilter("production deploy", values, keep=1)] == ["relevant"]


def stub_request(monkeypatch, selector, response):
    monkeypatch.setenv("JEV_TEST_KEY", "not-a-real-key")
    monkeypatch.setattr(selector, "_request", lambda *args, **kwargs: response)


def test_selector_parses_scores_floor_top_and_dedupes(monkeypatch):
    values = [item(name, "write a safe release") for name in "abcd"]
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    stub_request(monkeypatch, selector, {
        "answers": {
            "a": {"noul": 0.9},
            "b": {"noul": 0.4},
            "c": {"noul": 0.8},
            "d": {"noul": 0.7},
            "unknown": {"noul": 0.99},
        },
    })
    result = selector.select("release", values, top=2, floor=0.55)
    assert [(x.record_id, score) for x, score in result] == [("a", 0.9), ("c", 0.8)]
    assert len({x.record_id for x, _ in result}) == len(result)


def test_selector_ignores_answers_outside_the_documented_shape(monkeypatch):
    values = [item("a", "write a safe release"), item("b", "write a safe release")]
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    stub_request(monkeypatch, selector, {"answers": {"a": 0.9, "b": {"noul": "0.9"}}})
    assert selector.select("release", values) == []
    stub_request(monkeypatch, selector, {"scores": {"a": {"noul": 0.9}}})
    assert selector.select("release", values) is None


def test_request_sends_state_and_noul_questions(monkeypatch):
    sent = {}

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"answers": {"a": {"noul": 0.9}}}'

    def fake_urlopen(request, timeout):
        sent["body"] = json.loads(request.data)
        sent["timeout"] = timeout
        return Reply()

    monkeypatch.setenv("JEV_TEST_KEY", "not-a-real-key")
    monkeypatch.setattr("imprint.retrieve.jev.urllib.request.urlopen", fake_urlopen)
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    result = selector.select("release", [item("a", "write a safe release")], timeout=2.5)
    assert [(x.record_id, score) for x, score in result] == [("a", 0.9)]
    assert sent["timeout"] == 2.5
    assert sent["body"]["model"] == "jev"
    assert sent["body"]["state"] == "release"
    assert sent["body"]["questions"]["a"]["type"] == "noul"


def test_missing_key_falls_back(monkeypatch):
    monkeypatch.delenv("JEV_TEST_MISSING", raising=False)
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_MISSING")
    monkeypatch.setattr(selector, "_request", lambda *args, **kwargs: pytest.fail("network must not be reached"))
    assert selector.select("one", [item("a", "one")]) is None


def test_network_error_and_timeout_fall_back(monkeypatch):
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="JEV_TEST_KEY")
    monkeypatch.setenv("JEV_TEST_KEY", "not-a-real-key")
    for error in (OSError("network down"), TimeoutError()):
        def fail(*args, error=error, **kwargs):
            raise error

        monkeypatch.setattr(selector, "_request", fail)
        assert selector.select("one", [item("a", "one")]) is None


def _write_config(tmp_path, selector):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"config_version": "3.1.1", "selector": selector}), encoding="utf-8")
    return path


def test_selector_defaults_to_deterministic(tmp_path):
    from imprint.config import load_config

    assert load_config(tmp_path / "missing.json")["selector"]["mode"] == "deterministic"


def test_selector_config_accepts_jev_mode_with_partial_overrides(tmp_path):
    from imprint.config import load_config

    path = _write_config(tmp_path, {"mode": "jev", "jev": {"top": 5}})
    assert load_config(path)["selector"]["mode"] == "jev"


@pytest.mark.parametrize("selector", [
    {"mode": "fast"},
    {"mode": "jev", "extra": 1},
    {"mode": "jev", "jev": {"unknown": 1}},
    {"mode": "jev", "jev": {"top": 0}},
    {"mode": "jev", "jev": {"top": True}},
    {"mode": "jev", "jev": {"score_floor": 1.5}},
    {"mode": "jev", "jev": {"timeout_seconds": 0}},
    {"mode": "jev", "jev": {"prefilter_keep": 0}},
    {"mode": "jev", "jev": {"endpoint": " "}},
])
def test_selector_config_rejects_invalid_values(tmp_path, selector):
    from imprint.config import load_config
    from imprint.errors import ValidationError

    with pytest.raises(ValidationError):
        load_config(_write_config(tmp_path, selector))
