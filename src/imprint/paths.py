"""Portable paths with explicit override and sync-root refusal."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .errors import SafetyError

SYNC_MARKERS = ("Dropbox", "OneDrive", "CloudStorage", "Google Drive")


@dataclass(frozen=True)
class ContentLocation:
    """One typed, purge-owned content surface.

    ``relative_path`` is deliberately static and reviewable. New content
    writers must register a surface here or the completeness test fails.
    Authority key blobs are not content and are excluded by type, never by a
    blanket directory exemption.
    """

    surface_id: str
    kind: Literal["sqlite", "directory", "file_pattern", "registered_external"]
    relative_path: str
    recursive: bool = True


CONTENT_LOCATION_REGISTRY: tuple[ContentLocation, ...] = (
    ContentLocation("sqlite.canonical_rows", "sqlite", "imprint.db", False),
    ContentLocation("sqlite.projections", "sqlite", "imprint.db", False),
    ContentLocation("retrieval.receipts", "directory", "receipts"),
    ContentLocation("retrieval.prepared_payloads", "directory", "receipts"),
    ContentLocation("capture.spool", "directory", "spool"),
    ContentLocation("derive.proposal_spool", "directory", "proposal-spool/pending"),
    ContentLocation("derive.proposal_receipts", "directory", "proposal-spool/receipts"),
    ContentLocation("compiler.acknowledgements", "directory", "runtime/acknowledgements"),
    ContentLocation("compiler.delivery_retry", "directory", "runtime"),
    ContentLocation("import.quarantine", "directory", "quarantine"),
    ContentLocation("projection.jsonld_markdown", "directory", "projections"),
    ContentLocation("retrieval.indexes", "directory", "indexes"),
    ContentLocation("retrieval.caches", "directory", "cache"),
    ContentLocation("graphrag.projections", "directory", "graphrag"),
    ContentLocation("lifecycle.temporary", "file_pattern", ".tmp-*", False),
    ContentLocation("lifecycle.rollback", "file_pattern", ".restore-*", False),
    ContentLocation("export.configured", "directory", "exports"),
    ContentLocation("backup.configured", "directory", "backups"),
    ContentLocation("authority.nontrust_content_guard", "directory", "authority"),
    ContentLocation("external.registered", "registered_external", "", False),
)


def content_locations(root: Path) -> tuple[tuple[ContentLocation, Path], ...]:
    """Resolve the complete static registry without following links."""
    validated = validate_data_root(root)
    return tuple(
        (entry, validated / entry.relative_path)
        for entry in CONTENT_LOCATION_REGISTRY
        if entry.kind != "registered_external"
    )


def default_data_root() -> Path:
    override = os.environ.get("IMPRINT_DATA_ROOT")
    if override:
        root = Path(override).expanduser()
    elif platform.system() == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise SafetyError("LOCALAPPDATA is required on Windows")
        root = Path(base) / "Imprint"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "imprint"
    return validate_data_root(root)


def validate_data_root(path: Path, *, allow_sync: bool = False) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        raise SafetyError("Imprint data root must be absolute")
    resolved = path.resolve(strict=False)
    if resolved == Path(resolved.anchor) or resolved == Path.home().resolve():
        raise SafetyError("Refusing root or home as Imprint data root")
    if not allow_sync and any(marker.lower() in str(resolved).lower() for marker in SYNC_MARKERS):
        raise SafetyError("Cloud-sync roots are unsupported for the canonical database")
    return resolved


def operator_root(operator_id: str, base: Path | None = None) -> Path:
    safe = operator_id.strip().lower()
    if not safe or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in safe):
        raise SafetyError("operator_id must use lowercase letters, digits, and hyphens")
    return (base or default_data_root()) / safe
