"""Portable public configuration. Private runtime state is never packaged."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .paths import default_data_root, operator_root, validate_data_root

CURRENT_CONFIG_VERSION = "3.1.1"
SUPPORTED_CONFIG_VERSIONS = frozenset({"3.0.0", CURRENT_CONFIG_VERSION})

DEFAULTS = {
    "config_version": CURRENT_CONFIG_VERSION,
    "operator_slug": "default",
    "node_id": "primary",
    "compiler": True,
    "context_budget_bytes": 32768,
    "allow_higher_budget": False,
    "spool_retention_days": 30,
    "domains": [],
}

# Keys the loader recognizes. ``data_root`` and ``hooks_dir`` are written by the
# installers but are not part of the portable defaults. Unknown keys are rejected
# unless namespaced with a dot, which reserves an extension space the loader
# preserves but does not interpret.
KNOWN_TOP_LEVEL = frozenset(DEFAULTS) | {"data_root", "hooks_dir", "experimental"}
SAFE_LOCAL_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


def _is_int(value: Any) -> bool:
    """JSON booleans are Python integers, but never valid numeric settings."""
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_config(data: dict[str, Any]) -> None:
    if data.get("config_version") != CURRENT_CONFIG_VERSION:
        raise ValidationError("unsupported config_version")
    for field in ("operator_slug", "node_id"):
        value = data.get(field)
        if not isinstance(value, str) or SAFE_LOCAL_ID.fullmatch(value) is None:
            raise ValidationError(f"{field} must be a safe lowercase identifier")
    for field in ("compiler", "allow_higher_budget"):
        if not isinstance(data.get(field), bool):
            raise ValidationError(f"{field} must be a boolean")
    if not _is_int(data.get("context_budget_bytes")) or not 4096 <= data["context_budget_bytes"] <= 131072:
        raise ValidationError("context_budget_bytes must be 4096..131072")
    if data["context_budget_bytes"] > 32768 and data["allow_higher_budget"] is not True:
        raise ValidationError("context_budget_bytes above 32768 requires allow_higher_budget=true")
    if not _is_int(data.get("spool_retention_days")) or not 1 <= data["spool_retention_days"] <= 36500:
        raise ValidationError("spool_retention_days must be 1..36500")
    if not isinstance(data.get("domains"), list):
        raise ValidationError("domains must be an array")
    domain_fields = {"domain_id", "public_label", "safe_paths", "keywords", "frozen"}
    for domain in data["domains"]:
        if not isinstance(domain, dict) or not {"domain_id", "public_label"}.issubset(domain):
            raise ValidationError("each domain must be an object with domain_id and public_label")
        if set(domain) - domain_fields:
            raise ValidationError("domain config contains unknown fields")
        if not isinstance(domain["domain_id"], str) or SAFE_LOCAL_ID.fullmatch(domain["domain_id"]) is None:
            raise ValidationError("domain_id must be a safe lowercase identifier")
        if not isinstance(domain["public_label"], str) or not domain["public_label"].strip():
            raise ValidationError("domain public_label must be a non-empty string")
        for field in ("safe_paths", "keywords"):
            value = domain.get(field, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValidationError(f"domain {field} must be an array of strings")
        if "frozen" in domain and not isinstance(domain["frozen"], bool):
            raise ValidationError("domain frozen must be a boolean")
    for field in ("data_root", "hooks_dir"):
        if field in data and (not isinstance(data[field], str) or not data[field].strip()):
            raise ValidationError(f"{field} must be a non-empty path string")
    if "hooks_dir" in data:
        hooks_dir = Path(data["hooks_dir"]).expanduser()
        if not hooks_dir.is_absolute() or "\x00" in data["hooks_dir"]:
            raise ValidationError("hooks_dir must be an absolute safe path")


def config_path() -> Path:
    override = os.environ.get("IMPRINT_CONFIG")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
        return base / "Imprint" / "config.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "imprint" / "config.json"


def load_config(path: Path | None = None) -> dict[str, Any]:
    target = path or config_path()
    data = dict(DEFAULTS)
    if target.exists():
        try:
            loaded = json.loads(target.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"corrupt config: {target}") from exc
        if not isinstance(loaded, dict):
            raise ValidationError("config must be an object")
        unknown = {key for key in loaded if key not in KNOWN_TOP_LEVEL and "." not in key}
        if unknown:
            raise ValidationError(
                f"unknown config keys: {sorted(unknown)}; namespace extensions with a dot"
            )
        supplied_version = loaded.get("config_version", "3.0.0")
        if not isinstance(supplied_version, str) or supplied_version not in SUPPORTED_CONFIG_VERSIONS:
            raise ValidationError("unsupported config_version")
        legacy_experimental = loaded.pop("experimental", None)
        if legacy_experimental is not None:
            if (
                not isinstance(legacy_experimental, dict)
                or set(legacy_experimental) - {"digest", "profile_learning"}
                or any(value is not False for value in legacy_experimental.values())
            ):
                raise ValidationError(
                    "experimental flags were removed because no shipped runtime implemented them"
                )
        data.update(loaded)
        # Supported legacy files are upcast in memory. Persistence remains an
        # explicit installer/user action; loading never rewrites private config.
        data["config_version"] = CURRENT_CONFIG_VERSION
    _validate_config(data)
    try:
        from .domains import registry_from_config
        registry_from_config(data)
    except ValueError as exc:
        raise ValidationError(f"invalid domains config: {exc}") from exc
    return data


def resolved_operator_root(config: dict[str, Any]) -> Path:
    explicit = config.get("data_root")
    base = validate_data_root(Path(explicit).expanduser()) if explicit else default_data_root()
    return operator_root(str(config["operator_slug"]), base)
