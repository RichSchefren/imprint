"""Offline document projection suitable for an optional Atlas import.

This module performs no network access and imports no Atlas dependency. Users
may write these returned documents to JSON and load them with their own vetted
client if they choose.
"""

from __future__ import annotations

from typing import Any

from .generic import generic_graph


def atlas_documents(document: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    graph = generic_graph(document)
    return {
        "imprint_nodes": [{"_id": item["id"], **{k: v for k, v in item.items() if k != "id"}} for item in graph["nodes"]],
        "imprint_edges": [{"_id": item["id"], **{k: v for k, v in item.items() if k != "id"}} for item in graph["edges"]],
    }
