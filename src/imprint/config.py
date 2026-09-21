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
DEFAULT_SELECTOR = {"mode": "deterministic", "jev": {"endpoint": "https://openrouter.ai/api/alpha/decisions", "model": "typesafe/jev-1.13", "api_key_env": "OPENROUTER_API_KEY", "top": 20, "score_floor": 0.55, "timeout_seconds": 3, "prefilter_keep": 150}}
DEFAULTS = {"config_version": CURRENT_CONFIG_VERSION, "operator_slug": "default", "node_id": "primary", "compiler": True, "context_budget_bytes": 32768, "allow_higher_budget": False, "spool_retention_days": 30, "hook_timeout_seconds": 60 if os.name == "nt" else 10, "domains": [], "selector": DEFAULT_SELECTOR}
MINIMUM_HOOK_TIMEOUT_SECONDS = 1
MAXIMUM_HOOK_TIMEOUT_SECONDS = 300
KNOWN_TOP_LEVEL = frozenset(DEFAULTS) | {"data_root", "hooks_dir", "experimental"}
SAFE_LOCAL_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_config(data: dict[str, Any]) -> None:
    if data.get("config_version") != CURRENT_CONFIG_VERSION: raise ValidationError("unsupported config_version")
    for field in ("operator_slug", "node_id"):
        if not isinstance(data.get(field), str) or SAFE_LOCAL_ID.fullmatch(data[field]) is None: raise ValidationError(f"{field} must be a safe lowercase identifier")
    for field in ("compiler", "allow_higher_budget"):
        if not isinstance(data.get(field), bool): raise ValidationError(f"{field} must be a boolean")
    if not _is_int(data.get("context_budget_bytes")) or not 4096 <= data["context_budget_bytes"] <= 131072: raise ValidationError("context_budget_bytes must be 4096..131072")
    if data["context_budget_bytes"] > 32768 and not data["allow_higher_budget"]: raise ValidationError("context_budget_bytes above 32768 requires allow_higher_budget=true")
    if not _is_int(data.get("spool_retention_days")) or not 1 <= data["spool_retention_days"] <= 36500: raise ValidationError("spool_retention_days must be 1..36500")
    if not _is_int(data.get("hook_timeout_seconds")) or not 1 <= data["hook_timeout_seconds"] <= 300: raise ValidationError("hook_timeout_seconds must be 1..300")
    if not isinstance(data.get("domains"), list): raise ValidationError("domains must be an array")
    selector = data.get("selector")
    if not isinstance(selector, dict) or set(selector) - {"mode", "jev"} or selector.get("mode") not in {"deterministic", "jev"}: raise ValidationError("selector mode must be deterministic or jev")
    jev = selector.get("jev", {})
    if not isinstance(jev, dict) or set(jev) - {"endpoint", "model", "api_key_env", "top", "score_floor", "timeout_seconds", "prefilter_keep"}: raise ValidationError("invalid selector jev fields")
    merged = dict(DEFAULT_SELECTOR["jev"]); merged.update(jev)
    if any(not isinstance(merged[key], str) or not merged[key].strip() for key in ("endpoint", "model", "api_key_env")): raise ValidationError("selector Jev strings are required")
    if not _is_int(merged["top"]) or not 1 <= merged["top"] <= 150: raise ValidationError("selector top must be 1..150")
    if not isinstance(merged["score_floor"], (int, float)) or not 0 <= merged["score_floor"] <= 1: raise ValidationError("selector score_floor must be 0..1")
    if not isinstance(merged["timeout_seconds"], (int, float)) or not 0 < merged["timeout_seconds"] <= 30: raise ValidationError("selector timeout_seconds must be 0..30")
    if not _is_int(merged["prefilter_keep"]) or not 1 <= merged["prefilter_keep"] <= 10000: raise ValidationError("selector prefilter_keep must be 1..10000")
    domain_fields = {"domain_id", "public_label", "safe_paths", "keywords", "frozen"}
    for domain in data["domains"]:
        if not isinstance(domain, dict) or not {"domain_id", "public_label"}.issubset(domain) or set(domain) - domain_fields: raise ValidationError("invalid domain config")
        if not isinstance(domain["domain_id"], str) or SAFE_LOCAL_ID.fullmatch(domain["domain_id"]) is None: raise ValidationError("domain_id must be a safe lowercase identifier")
        if not isinstance(domain["public_label"], str) or not domain["public_label"].strip(): raise ValidationError("domain public_label must be a non-empty string")
        for field in ("safe_paths", "keywords"):
            if not isinstance(domain.get(field, []), list) or any(not isinstance(item, str) for item in domain.get(field, [])): raise ValidationError(f"domain {field} must be an array of strings")
    for field in ("data_root", "hooks_dir"):
        if field in data and (not isinstance(data[field], str) or not data[field].strip()): raise ValidationError(f"{field} must be a non-empty path string")
    if "hooks_dir" in data and (not Path(data["hooks_dir"]).expanduser().is_absolute() or "\x00" in data["hooks_dir"]): raise ValidationError("hooks_dir must be an absolute safe path")


def config_path() -> Path:
    override = os.environ.get("IMPRINT_CONFIG")
    if override: return Path(override).expanduser()
    return (Path(os.environ.get("APPDATA", Path.home())) / "Imprint" / "config.json") if os.name == "nt" else (Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "imprint" / "config.json")


def load_config(path: Path | None = None) -> dict[str, Any]:
    target = path or config_path(); data = json.loads(json.dumps(DEFAULTS))
    if target.exists():
        try: loaded = json.loads(target.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: raise ValidationError(f"corrupt config: {target}") from exc
        if not isinstance(loaded, dict): raise ValidationError("config must be an object")
        unknown = {key for key in loaded if key not in KNOWN_TOP_LEVEL and "." not in key}
        if unknown: raise ValidationError(f"unknown config keys: {sorted(unknown)}; namespace extensions with a dot")
        supplied_version = loaded.get("config_version", "3.0.0")
        if not isinstance(supplied_version, str) or supplied_version not in SUPPORTED_CONFIG_VERSIONS: raise ValidationError("unsupported config_version")
        legacy = loaded.pop("experimental", None)
        if legacy is not None and (not isinstance(legacy, dict) or set(legacy) - {"digest", "profile_learning"} or any(value is not False for value in legacy.values())): raise ValidationError("experimental flags were removed because no shipped runtime implemented them")
        data.update(loaded); data["config_version"] = CURRENT_CONFIG_VERSION
    _validate_config(data)
    try:
        from .domains import registry_from_config; registry_from_config(data)
    except ValueError as exc: raise ValidationError(f"invalid domains config: {exc}") from exc
    return data


def resolved_operator_root(config: dict[str, Any]) -> Path:
    explicit = config.get("data_root"); base = validate_data_root(Path(explicit).expanduser()) if explicit else default_data_root(); return operator_root(str(config["operator_slug"]), base)
