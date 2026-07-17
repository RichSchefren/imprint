"""Readable projection. Canonical state never depends on editing this file."""

from __future__ import annotations

from typing import Any


def markdown_document(snapshot: dict[str, Any]) -> str:
    lines = ["# Imprint", "", "> Generated view. Use the CLI to change canonical state.", ""]
    related: dict[str, list[dict[str, Any]]] = {}
    for edge in snapshot["edges"]:
        related.setdefault(edge["source_id"], []).append(edge)
        related.setdefault(edge["target_id"], []).append(edge)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for node in snapshot["nodes"]:
        grouped.setdefault(node["node_type"], []).append(node)
    for node_type in sorted(grouped):
        lines.extend([f"## {node_type}", ""])
        for node in grouped[node_type]:
            payload = node["payload"]
            label = payload.get("statement") or payload.get("principle") or payload.get("raw_operator_text") or payload.get("description") or payload.get("call_type") or payload.get("text") or node["node_id"]
            domain = payload.get("domain_id", "general")
            lines.append(
                f"- **{node['node_id']}** [{node['provenance_status']} · "
                f"{node['authority_tier']} · valid {node['valid_from']}..{node['valid_to'] or 'current'} · domain {domain}] {label}"
            )
            if node["evidence"]:
                lines.append(f"  - Evidence: {', '.join(node['evidence'])}")
            links = related.get(node["node_id"], [])
            cases = sorted({
                edge["target_id"] if edge["source_id"] == node["node_id"] else edge["source_id"]
                for edge in links if edge["edge_type"] == "verdict_about_case"
            })
            if cases:
                lines.append(f"  - Supporting Case/Verdict: {', '.join(cases)}")
            revisions = sorted({
                f"{edge['edge_type']}:{edge['target_id'] if edge['source_id'] == node['node_id'] else edge['source_id']}"
                for edge in links if edge["edge_type"] in {"contradicts", "supersedes", "weakens", "extends"}
            })
            if revisions:
                lines.append(f"  - Revision links: {', '.join(revisions)}")
            lines.append(f"  - History: `imprint history '{node['node_id']}'`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
