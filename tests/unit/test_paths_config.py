from __future__ import annotations

from pathlib import Path

import pytest

from imprint.config import resolved_operator_root
from imprint.config import load_config
from imprint.errors import SafetyError, ValidationError


def test_explicit_data_root_with_spaces_is_validated_and_supported(tmp_path):
    base = tmp_path / "local data with spaces"
    assert resolved_operator_root({"data_root": str(base), "operator_slug": "operator-a"}) == base / "operator-a"


@pytest.mark.parametrize("marker", ["Dropbox", "OneDrive", "CloudStorage", "Google Drive"])
def test_explicit_sync_root_is_refused(tmp_path, marker):
    with pytest.raises(SafetyError, match="Cloud-sync"):
        resolved_operator_root({"data_root": str(tmp_path / marker / "Imprint"), "operator_slug": "operator-a"})


def test_home_as_explicit_data_root_is_refused():
    with pytest.raises(SafetyError, match="root or home"):
        resolved_operator_root({"data_root": str(Path.home()), "operator_slug": "operator-a"})


def test_higher_context_budget_requires_explicit_bounded_opt_in(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"context_budget_bytes":40000}')
    with pytest.raises(ValidationError, match="allow_higher_budget"):
        load_config(config)
    config.write_text('{"context_budget_bytes":40000,"allow_higher_budget":true}')
    assert load_config(config)["context_budget_bytes"] == 40000
    config.write_text('{"context_budget_bytes":131073,"allow_higher_budget":true}')
    with pytest.raises(ValidationError, match="4096..131072"):
        load_config(config)


def test_unknown_bare_config_key_is_rejected_but_namespaced_is_kept(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"spool_retention_dayz":7}')
    with pytest.raises(ValidationError, match="unknown config keys"):
        load_config(config)
    config.write_text('{"org.example.ext":{"anything":true}}')
    loaded = load_config(config)
    assert loaded["org.example.ext"] == {"anything": True}


def test_unsupported_config_version_is_rejected(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"config_version":"2.0.0"}')
    with pytest.raises(ValidationError, match="config_version"):
        load_config(config)


def test_legacy_config_is_upcast_and_removed_false_flags_are_discarded(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"config_version":"3.0.0","experimental":{"digest":false}}')
    loaded = load_config(config)
    assert loaded["config_version"] == "3.1.1"
    assert "experimental" not in loaded


def test_future_config_and_unknown_experimental_flag_fail_truthfully(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"config_version":"9.0.0"}')
    with pytest.raises(ValidationError, match="unsupported config_version"):
        load_config(config)
    config.write_text('{"experimental":{"digest":true}}')
    with pytest.raises(ValidationError, match="flags were removed"):
        load_config(config)
