from __future__ import annotations

import json

import pytest

from imprint.cli import build_parser, main
from imprint.ontology import NODE_TYPES, producer_coverage


def test_every_preserved_ontology_type_has_truthful_producer_classification():
    coverage = producer_coverage()
    rows = coverage["types"]
    assert {row["node_type"] for row in rows} == set(NODE_TYPES) | {"Evidence", "Proposal"}
    assert {row["classification"] for row in rows} == {"shipped", "integration_only"}
    assert coverage["integration_only_count"] > 0
    assert next(row for row in rows if row["node_type"] == "Proposal") == {
        "node_type": "Proposal", "classification": "shipped",
        "producer": "reference_deriver",
    }


def test_coverage_cli_and_retrieval_flags_are_public_and_closed(tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"data_root": str(tmp_path / "data"), "operator_slug": "test"}))
    assert main(["--config", str(config), "ontology", "coverage"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    args = build_parser().parse_args([
        "retrieve", "--session", "s", "--authority-mode", "analytical",
        "--partition", "self_model",
    ])
    assert args.authority_mode == "analytical"
    assert args.partitions == ["self_model"]
    with pytest.raises(SystemExit):
        build_parser().parse_args([
            "retrieve", "--session", "s", "--authority-mode", "unlabelled",
        ])
