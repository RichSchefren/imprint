from __future__ import annotations

import json

from imprint.cli import main


def test_ontology_report_and_verify_expose_independent_schema_status(tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"operator_slug": "test", "data_root": str(tmp_path / "data")}))

    assert main(["--config", str(config), "migrate", "ontology-report"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "current"
    assert report["legacy_policy"]["auto_convert_profile_prose"] is False

    assert main(["--config", str(config), "migrate", "verify"]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["status"] == "ok"
    assert verified["ontology"]["status"] == "current"
