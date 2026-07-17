"""Dependency-free graph adapter consuming a lossless JSON-LD export."""

from __future__ import annotations

import json
from typing import Any

from imprint.errors import ValidationError


def generic_graph(document: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    ledger = document.get("imprint:ledger")
    if not isinstance(ledger, dict):
        raise ValidationError("adapter requires a lossless Imprint JSON-LD document")
    nodes_by_id = {row["node_id"]: row for row in ledger.get("nodes", [])}
    current_node_versions = {
        row["node_id"]: row for row in ledger.get("node_versions", []) if row["system_to"] is None
    }
    current_edge_versions = {
        row["edge_id"]: row for row in ledger.get("edge_versions", []) if row["system_to"] is None
    }
    nodes = []
    for node_id in sorted(current_node_versions):
        identity = nodes_by_id[node_id]
        version = current_node_versions[node_id]
        nodes.append({
            "id": node_id,
            "type": identity["node_type"],
            "payload": json.loads(version["payload_json"]),
            "payload_sha256": version["payload_sha256"],
            "provenance": version["provenance_status"],
            "authority_tier": version["authority_tier"],
        })
    edges = []
    for edge in sorted(ledger.get("edges", []), key=lambda row: row["edge_id"]):
        version = current_edge_versions.get(edge["edge_id"])
        if version is None:
            continue
        edges.append({
            "id": edge["edge_id"],
            "type": edge["edge_type"],
            "source": edge["source_id"],
            "target": edge["target_id"],
            "payload": json.loads(version["payload_json"]),
            "payload_sha256": version["payload_sha256"],
            "provenance": version["provenance_status"],
            "authority_tier": version["authority_tier"],
        })
    return {"nodes": nodes, "edges": edges}
