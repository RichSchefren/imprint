from __future__ import annotations

import hashlib
import json

from imprint.cli import build_parser, main
from imprint.store import ImprintStore


def _config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "config_version": "3.1.1",
        "data_root": str(tmp_path / "data"),
        "operator_slug": "operator",
    }))
    return path, tmp_path / "data" / "operator"


def test_whoami_prints_opaque_identity_and_curation_by_defaults(capsys, tmp_path):
    config, _root = _config(tmp_path)
    assert main(["--config", str(config), "whoami"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["operator_id"].startswith("urn:imprint:operator:")
    assert result["node_id"] == "primary"
    assert build_parser().parse_args(["review", "ratify", "urn:imprint:test:x"]).by is None


def test_log_is_daily_content_free_queryable_and_bounded(capsys, tmp_path):
    config, root = _config(tmp_path)
    store = ImprintStore(root / "imprint.db")
    store.initialize()
    with store.connect() as conn:
        for index, kind in enumerate(("captured", "tombstoned", "captured")):
            event_id = f"urn:imprint:event:{index}"
            payload = "{}"
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                (event_id, kind, "urn:imprint:operator:test",
                 f"2026-07-16T12:00:0{index}Z", f"2026-07-16T12:00:0{index}Z",
                 payload, hashlib.sha256(payload.encode()).hexdigest(), None, "captured"),
            )
    assert main([
        "--config", str(config), "log", "--date", "2026-07-16",
        "--query", "captured", "--limit", "1",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["count"] == 1
    assert result["items"][0]["event_type"] == "captured"
    assert "payload_json" not in result["items"][0]


def test_log_rejects_unbounded_limit(capsys, tmp_path):
    config, _root = _config(tmp_path)
    assert main(["--config", str(config), "log", "--limit", "201"]) == 2
    assert "1..200" in json.loads(capsys.readouterr().out)["error"]
