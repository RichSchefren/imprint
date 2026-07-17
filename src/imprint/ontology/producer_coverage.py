"""Truthful producer coverage for the preserved public ontology."""

from __future__ import annotations

from .contracts import NODE_TYPES

_CAPTURE = frozenset({"Case", "Verdict", "Call", "Alternative", "Evidence"})
_DEDICATED = frozenset({"Domain", "Observation", "Outcome", "ConsentGrant"})
_REFERENCE = frozenset({"Proposal"})


def producer_coverage() -> dict[str, object]:
    """Classify every public type without pretending generic validation is a producer."""
    rows = []
    for node_type in sorted(NODE_TYPES | _CAPTURE | _REFERENCE):
        if node_type in _CAPTURE:
            classification, producer = "shipped", "capture_pipeline"
        elif node_type in _REFERENCE:
            classification, producer = "shipped", "reference_deriver"
        elif node_type in _DEDICATED:
            classification, producer = "shipped", "dedicated_cli"
        else:
            classification, producer = "integration_only", "ontology_add_node"
        rows.append({
            "node_type": node_type,
            "classification": classification,
            "producer": producer,
        })
    return {
        "coverage_schema_version": "1.0.0",
        "types": rows,
        "shipped_count": sum(row["classification"] == "shipped" for row in rows),
        "integration_only_count": sum(
            row["classification"] == "integration_only" for row in rows
        ),
    }
