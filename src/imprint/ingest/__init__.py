"""Quarantined ingestion with explicit human KEEP/KILL rulings."""

from .service import IngestCandidate, IngestService
from .legacy import import_legacy_principles

__all__ = ["IngestCandidate", "IngestService", "import_legacy_principles"]
