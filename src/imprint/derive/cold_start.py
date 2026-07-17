"""Conservative cold-start refusal and idempotent progress keys."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ScanDecision:
    accepted: bool
    reason: str


def finished_deliverable_decision(*, lifecycle_status: str | None, immutable: bool = False) -> ScanDecision:
    """Never mine an artifact explicitly marked as a finished deliverable."""
    status = (lifecycle_status or "").strip().lower().replace("-", "_")
    if immutable or status in {"final", "finished", "approved", "published", "frozen"}:
        return ScanDecision(False, "finished_deliverable_refused")
    return ScanDecision(True, "eligible_candidate")


class ProgressStore(Protocol):
    def contains(self, key: str) -> bool: ...
    def add(self, key: str) -> None: ...


def progress_key(source_id: str, content: bytes) -> str:
    return hashlib.sha256(source_id.encode("utf-8") + b"\0" + content).hexdigest()


def mark_progress_once(store: ProgressStore, source_id: str, content: bytes) -> bool:
    """Return False for replay; stores should enforce key uniqueness atomically."""
    key = progress_key(source_id, content)
    if store.contains(key):
        return False
    store.add(key)
    return True
