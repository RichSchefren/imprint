"""Lossless JSON-LD projection of current semantic graph."""

from __future__ import annotations

from typing import Any


CONTEXT = {
    "@version": 1.1,
    "imprint": "https://imprint.local/schema/v3#",
    "type": "@type",
    "id": "@id",
    "provenance": "imprint:provenance",
    "validFrom": "imprint:validFrom",
    "systemFrom": "imprint:systemFrom",
    "ontologySchemaVersion": "imprint:ontologySchemaVersion",
    "payload": "imprint:payload",
    "evidence": "imprint:evidence",
    "operator": "imprint:operator",
    "confidence": "imprint:confidence",
    "sourcePhase": "imprint:sourcePhase",
    "derivation": "imprint:derivation",
    "authorizedBy": {"@id": "imprint:authorizedBy", "@type": "@id"},
}


def jsonld_document(snapshot: dict[str, Any]) -> dict[str, Any]:
    graph = []
    for node in snapshot["nodes"]:
        graph.append({
            "@id": node["node_id"],
            "@type": f"imprint:{node['node_type']}",
            "payload": node["payload"],
            "payloadSha256": node["payload_sha256"],
            "provenanceStatus": node["provenance_status"],
            "provenance": node["provenance"],
            "authorityTier": node["authority_tier"],
            "evidence": node["evidence"],
            "validFrom": node["valid_from"],
            "validTo": node["valid_to"],
            "systemFrom": node["system_from"],
            "systemTo": node["system_to"],
        })
    for edge in snapshot["edges"]:
        graph.append({
            "@id": edge["edge_id"],
            "@type": f"imprint:{edge['edge_type']}",
            "source": {"@id": edge["source_id"]},
            "target": {"@id": edge["target_id"]},
            "payload": edge["payload"],
            "payloadSha256": edge["payload_sha256"],
            "provenanceStatus": edge["provenance_status"],
            "provenance": edge["provenance"],
            "authorityTier": edge["authority_tier"],
            "evidence": edge["evidence"],
            "validFrom": edge["valid_from"],
            "validTo": edge["valid_to"],
            "systemFrom": edge["system_from"],
            "systemTo": edge["system_to"],
        })
    return {
        "@context": CONTEXT,
        "schemaVersion": snapshot["store_schema_version"],
        "ontologySchemaVersion": snapshot["ontology_schema_version"],
        "@graph": graph,
    }
