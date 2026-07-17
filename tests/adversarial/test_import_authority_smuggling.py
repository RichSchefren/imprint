"""Import must re-validate authority and consent regardless of creation event.

These cover the class of attack where a crafted JSON-LD document keeps every
internal consistency gate satisfied (payload hashes, @graph derivation, semantic
digest) but points a record's creation event at a non-``semantic_*`` event type
to skip the typed contract and consent re-checks. See B1 in the pre-release audit.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from imprint.errors import ValidationError
from imprint.ontology.schema import make_urn, payload_sha256
from imprint.portability import export_jsonld, import_jsonld
from imprint.portability.jsonld import _graph_from_ledger, semantic_digest
from imprint.store import ImprintStore


def _reseal(document: dict) -> dict:
    """Recompute every derived field so only the authority checks can reject it."""
    ledger = document["imprint:ledger"]
    for row in ledger["node_versions"] + ledger["edge_versions"]:
        import json

        row["payload_sha256"] = payload_sha256(json.loads(row["payload_json"]))
    document["@graph"] = _graph_from_ledger(ledger)
    document["imprint:semanticSha256"] = semantic_digest(document)
    return document


def _source_document(tmp_path, capture_envelope) -> dict:
    source = ImprintStore(tmp_path / "source.db")
    source.initialize()
    source.apply_capture(capture_envelope)
    return export_jsonld(source)


def test_forged_model_authority_on_captured_node_is_rejected(tmp_path, capture_envelope):
    import json

    document = _source_document(tmp_path, capture_envelope)
    # Take a legitimately captured node version and try to re-author it as a model.
    version = document["imprint:ledger"]["node_versions"][0]
    provenance = json.loads(version["provenance_json"])
    provenance["actor_class"] = "model"
    provenance["model"] = "smuggled-model"
    version["provenance_json"] = json.dumps(provenance)
    _reseal(document)

    target = ImprintStore(tmp_path / "target.db")
    with pytest.raises(ValidationError, match="captured authority cannot be escalated"):
        import_jsonld(target, document)


def test_forged_ratified_tier_on_captured_node_is_rejected(tmp_path, capture_envelope):
    import json

    document = _source_document(tmp_path, capture_envelope)
    version = document["imprint:ledger"]["node_versions"][0]
    version["provenance_status"] = "ratified"
    version["authority_tier"] = "ratified_knowledge"
    provenance = json.loads(version["provenance_json"])
    provenance["actor_class"] = "model"
    provenance["ratifier"] = None
    version["provenance_json"] = json.dumps(provenance)
    _reseal(document)

    target = ImprintStore(tmp_path / "target.db")
    with pytest.raises(ValidationError, match="ratified authority requires operator ratification"):
        import_jsonld(target, document)


def _inject_semantic_only_node(document: dict, node_type: str) -> dict:
    """Add a node of a semantic-only type whose creation event is the captured one."""
    import json

    ledger = document["imprint:ledger"]
    captured_event = next(row for row in ledger["events"] if row["event_type"] == "captured")
    template = deepcopy(ledger["node_versions"][0])
    node_id = make_urn(node_type.lower())
    ledger["nodes"].append({
        "node_id": node_id,
        "node_type": node_type,
        "operator_id": captured_event["operator_id"],
        "created_event_id": captured_event["event_id"],
    })
    provenance = json.loads(template["provenance_json"])
    provenance.update({
        "status": "ratified", "authority_tier": "ratified_knowledge",
        "actor_class": "operator", "ratifier": captured_event["operator_id"],
        "event_id": captured_event["event_id"],
    })
    template.update({
        "version_id": make_urn("node-version"),
        "node_id": node_id,
        "payload_json": json.dumps({"smuggled": True}),
        "provenance_status": "ratified",
        "authority_tier": "ratified_knowledge",
        "provenance_json": json.dumps(provenance),
        "event_id": captured_event["event_id"],
        "prior_version_id": None,
    })
    ledger["node_versions"].append(template)
    return _reseal(document)


def test_semantic_only_node_via_captured_event_is_rejected(tmp_path, capture_envelope):
    document = _inject_semantic_only_node(_source_document(tmp_path, capture_envelope), "SelfModelAssertion")
    target = ImprintStore(tmp_path / "target.db")
    with pytest.raises(ValidationError, match="non-semantic creation event"):
        import_jsonld(target, document)


def test_consent_bearing_observation_via_captured_event_is_rejected(tmp_path, capture_envelope):
    # An Observation smuggled through a captured event would otherwise skip the
    # write-time consent re-check entirely.
    document = _inject_semantic_only_node(_source_document(tmp_path, capture_envelope), "Observation")
    target = ImprintStore(tmp_path / "target.db")
    with pytest.raises(ValidationError, match="non-semantic creation event"):
        import_jsonld(target, document)


def test_untampered_export_still_imports(tmp_path, capture_envelope):
    document = _source_document(tmp_path, capture_envelope)
    target = ImprintStore(tmp_path / "target.db")
    digest = import_jsonld(target, document)
    assert digest == document["imprint:semanticSha256"]
    assert len(target.current_nodes()) == len(ImprintStore(tmp_path / "source.db").current_nodes())


def test_dry_run_does_not_create_a_database_file(tmp_path, capture_envelope):
    document = _source_document(tmp_path, capture_envelope)
    target_path = tmp_path / "dry" / "target.db"
    digest = import_jsonld(ImprintStore(target_path), document, dry_run=True)
    assert digest == document["imprint:semanticSha256"]
    assert not target_path.exists()
