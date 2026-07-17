from __future__ import annotations

import json

from imprint.cli import main
from imprint.compiler import compile_spools, write_envelope
from imprint.store import ImprintStore


def test_spool_prune_cli_uses_configured_producer_and_retention(tmp_path, capsys, capture_envelope):
    data = tmp_path / "data"
    root = data / "test"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "data_root": str(data), "operator_slug": "test",
        "node_id": capture_envelope["node_id"], "compiler": True,
        "spool_retention_days": 36500,
    }))
    path = write_envelope(root, capture_envelope)
    assert compile_spools(root, ImprintStore(root / "imprint.db"), compiler_authorized=True)["captured"] == 1
    assert main(["--config", str(config), "spool", "prune"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "deleted": 0, "retained": 1, "already_pruned": 0,
        "acknowledgements_deleted": 0, "quarantine_deleted": 0,
        "invalid": 0, "status": "ok",
    }
    assert path.exists()
