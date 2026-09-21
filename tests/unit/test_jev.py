from __future__ import annotations

import json

from imprint.retrieve.jev import JevSelector, prefilter
from imprint.retrieve.models import RetrievalRecord


def item(record_id: str, text: str) -> RetrievalRecord:
    return RetrievalRecord(record_id, text, "general", "captured", "captured_judgment", ("e",), ("c",), provenance_complete=True)


def test_prefilter_is_bounded_and_relevance_ordered():
    values = [item("irrelevant", "gardening flowers"), item("relevant", "deploy production safely")]
    assert [x.record_id for x in prefilter("production deploy", values, keep=1)] == ["relevant"]


def test_selector_parses_scores_floor_top_and_dedupes(monkeypatch):
    values = [item("a", "write a safe release"), item("b", "write a safe release"), item("c", "write a safe release")]
    selector = JevSelector(endpoint="https://example.invalid", model="jev")
    monkeypatch.setenv("KEY", "secret")
    monkeypatch.setattr(selector, "_request", lambda *args, **kwargs: {"answers": {"a": {"noul": 0.9}, "a": 0.9, "b": 0.4, "c": 0.8}})
    result = selector.select("release", values, top=2, floor=0.55)
    assert [(x.record_id, score) for x, score in result] == [("a", 0.9), ("c", 0.8)]


def test_missing_key_and_network_error_fall_back(monkeypatch):
    values = [item("a", "one")]
    selector = JevSelector(endpoint="https://example.invalid", model="jev", api_key_env="MISSING")
    assert selector.select("one", values) is None
    monkeypatch.setenv("MISSING", "secret")
    monkeypatch.setattr(selector, "_request", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()))
    assert selector.select("one", values) is None
