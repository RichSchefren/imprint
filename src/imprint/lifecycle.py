"""Operator-controlled review and history services."""

from __future__ import annotations

from typing import Any

from .errors import ValidationError
from .store import ImprintStore


REVIEWABLE = {"inferred", "extracted"}


def review_list(store: ImprintStore) -> list[dict[str, Any]]:
    """Return proposals awaiting an explicit operator disposition."""
    return [
        node for node in store.current_nodes()
        if node["provenance_status"] in REVIEWABLE
    ]


def review_show(store: ImprintStore, node_id: str) -> dict[str, Any]:
    matches = [node for node in store.current_nodes() if node["node_id"] == node_id]
    if not matches:
        raise ValidationError("review object is missing or not current")
    node = matches[0]
    if node["provenance_status"] not in REVIEWABLE:
        raise ValidationError("object is not awaiting review")
    return node
