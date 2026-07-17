"""Lossless JSON-LD ledger projection and compatible-store importer."""

from __future__ import annotations

import hashlib
import json
import base64
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from imprint.constants import (
    AUTHORITY_TIERS,
    ONTOLOGY_SCHEMA_VERSION,
    PROVENANCE,
    STORE_SCHEMA_VERSION,
)
from imprint.errors import ConflictError, ValidationError
from imprint.durable_io import publish_new_private
from imprint.permissions import secure_directory
from imprint.ontology.schema import canonical_bytes
from imprint.ontology.contracts import (
    NODE_TYPES,
    validate_node_contract,
    validate_relation_contract,
)
from imprint.ontology.references import validate_payload_references
from imprint.portability.context import (
    BUSINESS_CONTEXT_VERSION, CONTEXT_VERSION, local_context,
)
from imprint.store import ImprintStore
from imprint.store.schema import SCHEMA_SQL
from imprint.store.service import utc_now

# Node types the canonical writer produces only through the strict semantic
# contract path (append_semantic_node), i.e. everything except the raw-capture
# and derived/proposal families. A record of one of these types therefore MUST
# have been created by a ``semantic_*`` event; if an imported document presents
# one with any other creation event, it is refusing to be re-validated and is
# rejected. This is what stops a document from tagging a SelfModelAssertion or a
# consent-bearing Observation with a ``captured`` creation event to skip the
# typed contract and consent re-checks below.
_CAPTURE_NODE_TYPES = frozenset({"Case", "Verdict", "Call", "Alternative"})
_DERIVED_NODE_TYPES = frozenset({
    "Principle", "Belief", "Value", "Rule", "Domain", "Pattern",
    "FeedbackProfile", "Proposal",
})
SEMANTIC_ONLY_NODE_TYPES = frozenset(NODE_TYPES) - _CAPTURE_NODE_TYPES - _DERIVED_NODE_TYPES


CORE_TABLES = (
    "meta", "events", "nodes", "node_versions", "edges", "edge_versions",
    "source_receipts", "ingest_items", "ingest_rulings", "migrations",
    "consumed_inputs", "captured_feedback_dedup", "projection_state", "purge_receipts",
)
SEMANTIC_TABLES = (
    "semantic_node_versions", "semantic_artifact_bytes",
    "semantic_business_node_versions", "semantic_relation_versions",
    "semantic_business_relation_versions", "semantic_correction_events",
    "semantic_contest_events", "semantic_confidence_heads",
)
AUTHORITY_TABLES = (
    "authority_keys", "authority_ledger", "authority_provenance",
)
# Challenges and prepared mutations are deliberately excluded. They are
# short-lived replay-control state, not portable authority history. Exporting a
# still-signable nonce would create a replay surface on the destination.
TABLES = CORE_TABLES + SEMANTIC_TABLES + AUTHORITY_TABLES
PRIMARY_KEYS = {
    "meta": "key", "events": "event_id", "nodes": "node_id",
    "node_versions": "version_id", "edges": "edge_id",
    "edge_versions": "version_id", "source_receipts": "source_id",
    "ingest_items": "item_id", "ingest_rulings": "ruling_id",
    "migrations": "migration_id", "consumed_inputs": "input_event_id",
    "captured_feedback_dedup": "operator_id,content_sha256",
    "projection_state": "projection",
    "purge_receipts": "operation_id",
    "semantic_node_versions": "version_id",
    "semantic_artifact_bytes": "version_id",
    "semantic_business_node_versions": "version_id",
    "semantic_relation_versions": "relation_version_id",
    "semantic_business_relation_versions": "relation_version_id",
    "semantic_correction_events": "correction_event_id",
    "semantic_contest_events": "contest_event_id",
    "semantic_confidence_heads": "assessment_version_id",
    "authority_keys": "key_id", "authority_ledger": "sequence",
    "authority_provenance": "provenance_id",
}
TABLE_COLUMNS = {
    "meta": ("key", "value"),
    "events": ("event_id", "event_type", "operator_id", "system_time", "valid_time", "payload_json", "payload_sha256", "prior_event_id", "provenance_status"),
    "nodes": ("node_id", "node_type", "operator_id", "created_event_id"),
    "node_versions": ("version_id", "node_id", "payload_json", "payload_sha256", "provenance_status", "authority_tier", "provenance_json", "evidence_json", "valid_from", "valid_to", "system_from", "system_to", "event_id", "prior_version_id"),
    "edges": ("edge_id", "edge_type", "source_id", "target_id", "operator_id", "created_event_id"),
    "edge_versions": ("version_id", "edge_id", "payload_json", "payload_sha256", "provenance_status", "authority_tier", "provenance_json", "evidence_json", "valid_from", "valid_to", "system_from", "system_to", "event_id", "prior_version_id"),
    "source_receipts": ("source_id", "kind", "locator", "content_sha256", "event_id"),
    "ingest_items": ("item_id", "operator_id", "session_id", "node_id", "source_id", "source_kind", "source_locator", "source_sha256", "payload_json", "payload_sha256", "discovered_at", "status", "kept_node_id"),
    "ingest_rulings": ("ruling_id", "item_id", "verdict", "why", "event_id"),
    "migrations": ("migration_id", "from_version", "to_version", "code_sha256", "applied_at", "backup_receipt", "result_sha256"),
    "consumed_inputs": ("input_event_id", "payload_sha256", "consumed_at", "source_path"),
    "captured_feedback_dedup": (
        "operator_id", "content_sha256", "first_event_id", "first_captured_at",
    ),
    "projection_state": ("projection", "snapshot_sha256", "generator_version", "generated_at"),
    "purge_receipts": ("operation_id", "purged_at", "schema_version", "scope_class", "counts_json"),
    "semantic_node_versions": ("version_id", "record_id", "payload_schema_id", "record_schema_version", "ontology_schema_version", "provenance_v2_1_json", "sensitivity", "access_policy_version_id", "consent_version_id", "actor_id", "role_assignment_version_id", "scope_id", "contested_set_id", "envelope_json", "envelope_sha256"),
    "semantic_artifact_bytes": ("version_id", "content", "content_sha256", "byte_count"),
    "semantic_business_node_versions": ("version_id", "partition_id"),
    "semantic_relation_versions": ("relation_version_id", "relation_id", "predicate_id", "predicate_version", "source_version_id", "target_version_id", "operator_id", "qualifier_schema_id", "qualifier_json", "envelope_json", "envelope_sha256", "valid_from", "valid_to", "system_from", "system_to", "contested_set_id"),
    "semantic_business_relation_versions": ("relation_version_id", "policy_code", "authority_minimum"),
    "semantic_correction_events": ("correction_event_id", "record_id", "scope_id", "prior_version_id", "carry_forward_version_id", "corrected_version_id", "effective_from", "evidence_version_ids_json", "diff_json", "event_id"),
    "semantic_contest_events": ("contest_event_id", "contested_set_id", "record_id", "scope_id", "prior_version_id", "preserved_version_id", "competing_version_id", "evidence_version_ids_json", "event_id"),
    "semantic_confidence_heads": ("subject_version_id", "assessor_actor_version_id", "method", "scale", "assessment_version_id"),
    "authority_keys": ("key_id", "operator_id", "install_id", "store_identity", "public_key_b64", "public_key_fingerprint", "status", "ledger_sequence", "blob_rel_path", "blob_sha256", "blob_size", "algorithm_suite", "enrollment_nonce", "created_at"),
    "authority_ledger": ("sequence", "event_id", "event_type", "operator_id", "install_id", "key_id", "event_json", "event_sha256", "signature_b64", "previous_event_sha256", "created_at"),
    "authority_provenance": ("provenance_id", "operation_id", "operator_id", "install_id", "key_id", "ledger_sequence", "challenge_json", "challenge_sha256", "signature_b64", "authority_transition", "committed_at"),
}

EXPORT_MANIFEST_VERSION = "imprint.export.manifest/1.0.0"
EXPORT_SIGNATURE_DOMAIN = b"imprint-export-manifest-v1\x00"
_BYTES_TAG = "$imprint:base64"


def _portable_cell(value: Any) -> Any:
    if isinstance(value, bytes):
        return {_BYTES_TAG: base64.b64encode(value).decode("ascii")}
    return value


def _database_cell(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {_BYTES_TAG}:
        encoded = value[_BYTES_TAG]
        if not isinstance(encoded, str):
            raise ValidationError("invalid portable binary cell")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValidationError("invalid portable binary cell") from exc
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise ValidationError("non-canonical portable binary cell")
        return raw
    return value


def _rows(store: ImprintStore, table: str) -> list[dict[str, Any]]:
    key = PRIMARY_KEYS[table]
    with store.connect() as conn:
        return [
            {name: _portable_cell(value) for name, value in dict(row).items()}
            for row in conn.execute(f"SELECT * FROM {table} ORDER BY {key}").fetchall()
        ]


def semantic_digest(document: dict[str, Any]) -> str:
    portable = {
        "schemaVersion": document.get("schemaVersion"),
        "ontologySchemaVersion": document.get("ontologySchemaVersion"),
        "ledger": document.get("imprint:ledger"),
        "graph": document.get("@graph"),
    }
    return hashlib.sha256(canonical_bytes(portable)).hexdigest()


def _expand_term(term: str, context: Mapping[str, Any]) -> str:
    if term.startswith("@"):
        return term
    if ":" in term:
        prefix, suffix = term.split(":", 1)
        base = context.get(prefix)
        if isinstance(base, str):
            return base + suffix
        return term
    definition = context.get(term)
    if isinstance(definition, str):
        return definition if definition.startswith(("@", "http")) else _expand_term(definition, context)
    if isinstance(definition, dict) and isinstance(definition.get("@id"), str):
        return _expand_term(definition["@id"], context)
    return str(context["@vocab"]) + term


def _expand_value(value: Any, context: Mapping[str, Any]) -> Any:
    if isinstance(value, list):
        return [_expand_value(item, context) for item in value]
    if not isinstance(value, dict):
        return value
    expanded: dict[str, Any] = {}
    for key, item in value.items():
        if key == "@context":
            continue
        expanded[_expand_term(key, context)] = _expand_value(item, context)
    return expanded


def expand_local_jsonld(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Expand the graph using only the exact bundled context; never dereference."""
    expected = {**local_context(), "ledger": "imprint:ledger"}
    if document.get("@context") != expected:
        raise ValidationError("E_JSONLD_CONTEXT_INCOMPLETE")
    graph = document.get("@graph")
    if not isinstance(graph, list) or any(not isinstance(item, dict) for item in graph):
        raise ValidationError("JSON-LD graph must be an array of objects")
    expanded = [_expand_value(item, expected) for item in graph]
    return sorted(expanded, key=canonical_bytes)


def rdf_dataset_digest(document: Mapping[str, Any]) -> str:
    """Canonical offline semantic-projection identity over expanded graph."""
    rows = [canonical_bytes(item) for item in expand_local_jsonld(document)]
    return hashlib.sha256(b"\n".join(rows)).hexdigest()


def canonical_ledger_digest(document: Mapping[str, Any]) -> str:
    """Digest the complete lossless ledger independently of its projection."""
    ledger = document.get("imprint:ledger")
    if not isinstance(ledger, dict):
        raise ValidationError("JSON-LD ledger is missing")
    return hashlib.sha256(canonical_bytes(ledger)).hexdigest()


def build_export_manifest(
    document: Mapping[str, Any], *, operator_id: str, install_id: str,
    key_id: str, ledger_sequence: int, ledger_head_sha256: str,
    snapshot_valid_as_of: str, private_key: Ed25519PrivateKey | None = None,  # gitleaks:allow -- a type annotation
) -> dict[str, Any]:
    """Build a canonical manifest; absence of a signature is labelled honestly."""
    manifest = {
        "manifest_schema_version": EXPORT_MANIFEST_VERSION,
        "operator_id": operator_id, "install_id": install_id, "key_id": key_id,
        "ledger_sequence": ledger_sequence, "ledger_head_sha256": ledger_head_sha256,
        "snapshot_valid_as_of": snapshot_valid_as_of,
        "canonical_ledger_sha256": canonical_ledger_digest(document),
        "semantic_projection_sha256": rdf_dataset_digest(document),
        "authenticity": "signed-authority-snapshot" if private_key else "corruption-detection-only",
    }
    if private_key is not None:
        signature = private_key.sign(EXPORT_SIGNATURE_DOMAIN + canonical_bytes(manifest))
        manifest["signature_b64"] = base64.b64encode(signature).decode("ascii")
    else:
        manifest["signature_b64"] = None
    return manifest


def build_signed_export_manifest(
    document: Mapping[str, Any], *, authority_service: Any,
    console: Any | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build one checkpoint-bound manifest through the native signing service."""
    from imprint.authority.ledger import active_binding, verify_authority_chain
    with authority_service.store.connect() as conn:
        binding = active_binding(
            conn, expected_operator_id=authority_service.operator_id,
        )
        chain = verify_authority_chain(
            conn, expected_operator_id=authority_service.operator_id,
        )
    payload = {
        "manifest_schema_version": EXPORT_MANIFEST_VERSION,
        "operator_id": chain["operator_id"],
        "install_id": binding["install_id"],
        "key_id": binding["key_id"],
        "ledger_sequence": chain["head_sequence"],
        "ledger_head_sha256": chain["head_sha256"],
        "canonical_ledger_sha256": canonical_ledger_digest(document),
        "semantic_projection_sha256": rdf_dataset_digest(document),
        "authenticity": "signed-authority-snapshot",
    }
    signed = authority_service.sign_portable_payload(
        payload, domain_separator=EXPORT_SIGNATURE_DOMAIN,
        checkpoint_time_field="snapshot_valid_as_of", console=console,
    )
    if (
        signed["signer_key_id"] != binding["key_id"]
        or signed["signer_install_id"] != binding["install_id"]
        or signed["ledger_sequence"] != chain["head_sequence"]
        or signed["ledger_head_sha256"] != chain["head_sha256"]
    ):
        raise ValidationError("export authority changed during snapshot approval")
    manifest = {**signed["payload"], "signature_b64": signed["signature_b64"]}
    return manifest, signed["checkpoint"]


def verify_export_manifest(
    document: Mapping[str, Any], *, public_key: Ed25519PublicKey | None = None,
) -> dict[str, Any]:
    """Verify digests and, when claimed, the Ed25519 snapshot signature."""
    manifest = document.get("imprint:manifest")
    if not isinstance(manifest, dict):
        raise ValidationError("export manifest is missing")
    required = {
        "manifest_schema_version", "operator_id", "install_id", "key_id",
        "ledger_sequence", "ledger_head_sha256", "snapshot_valid_as_of",
        "canonical_ledger_sha256", "semantic_projection_sha256", "authenticity",
        "signature_b64",
    }
    if set(manifest) != required or manifest["manifest_schema_version"] != EXPORT_MANIFEST_VERSION:
        raise ValidationError("export manifest has unknown, missing, or unsupported fields")
    if manifest["canonical_ledger_sha256"] != canonical_ledger_digest(document):
        raise ValidationError("export canonical ledger digest mismatch")
    if manifest["semantic_projection_sha256"] != rdf_dataset_digest(document):
        raise ValidationError("export semantic projection digest mismatch")
    unsigned = {key: value for key, value in manifest.items() if key != "signature_b64"}
    if manifest["authenticity"] == "corruption-detection-only":
        if manifest["signature_b64"] is not None:
            raise ValidationError("unsigned export has a contradictory signature")
        return {**manifest, "authority_preserved": False}
    if manifest["authenticity"] != "signed-authority-snapshot" or public_key is None:
        raise ValidationError("signed export requires its trusted Ed25519 public key")
    try:
        signature = base64.b64decode(manifest["signature_b64"], validate=True)
        public_key.verify(signature, EXPORT_SIGNATURE_DOMAIN + canonical_bytes(unsigned))
    except (TypeError, ValueError, base64.binascii.Error, InvalidSignature) as exc:
        raise ValidationError("export manifest signature is invalid") from exc
    return {**manifest, "authority_preserved": True}


def _graph_from_ledger(ledger: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    graph: list[dict[str, Any]] = []
    nodes = {row["node_id"]: row for row in ledger["nodes"]}
    edges = {row["edge_id"]: row for row in ledger["edges"]}
    business_nodes = {
        row["version_id"]: row for row in ledger["semantic_business_node_versions"]
    }
    business_relations = {
        row["relation_version_id"]: row
        for row in ledger["semantic_business_relation_versions"]
    }
    for row in ledger["node_versions"]:
        node = nodes[row["node_id"]]
        item = {
            "@id": row["version_id"],
            "@type": "imprint:NodeVersion",
            "imprint:entity": {"@id": row["node_id"]},
            "imprint:entityType": node["node_type"],
            "imprint:operator": node["operator_id"],
            "imprint:payload": json.loads(row["payload_json"]),
            "imprint:payloadSha256": row["payload_sha256"],
            "imprint:provenance": row["provenance_status"],
            "imprint:provenanceRecord": json.loads(row["provenance_json"]),
            "imprint:authorityTier": row["authority_tier"],
            "imprint:evidence": json.loads(row["evidence_json"]),
            "imprint:validFrom": row["valid_from"],
            "imprint:validTo": row["valid_to"],
            "imprint:systemFrom": row["system_from"],
            "imprint:systemTo": row["system_to"],
        }
        if row["version_id"] in business_nodes:
            item["business:partition"] = business_nodes[row["version_id"]]["partition_id"]
        graph.append(item)
    for row in ledger["edge_versions"]:
        edge = edges[row["edge_id"]]
        item = {
            "@id": row["version_id"],
            "@type": "imprint:EdgeVersion",
            "imprint:entity": {"@id": row["edge_id"]},
            "imprint:relationType": edge["edge_type"],
            "imprint:operator": edge["operator_id"],
            "imprint:source": {"@id": edge["source_id"]},
            "imprint:target": {"@id": edge["target_id"]},
            "imprint:payload": json.loads(row["payload_json"]),
            "imprint:payloadSha256": row["payload_sha256"],
            "imprint:provenance": row["provenance_status"],
            "imprint:provenanceRecord": json.loads(row["provenance_json"]),
            "imprint:authorityTier": row["authority_tier"],
            "imprint:evidence": json.loads(row["evidence_json"]),
            "imprint:validFrom": row["valid_from"],
            "imprint:validTo": row["valid_to"],
            "imprint:systemFrom": row["system_from"],
            "imprint:systemTo": row["system_to"],
        }
        governance = business_relations.get(row["version_id"])
        if governance:
            item["business:policyCode"] = governance["policy_code"]
            item["business:authorityMinimum"] = governance["authority_minimum"]
        graph.append(item)
    for row in ledger["semantic_node_versions"]:
        item = {
            "@id": row["version_id"],
            "@type": "imprint:SemanticNodeEnvelope",
            "imprint:recordId": row["record_id"],
            "imprint:payloadSchemaId": row["payload_schema_id"],
            "imprint:recordSchemaVersion": row["record_schema_version"],
            "imprint:ontologySchemaVersion": row["ontology_schema_version"],
            "imprint:provenanceV2_1": json.loads(row["provenance_v2_1_json"]),
            "imprint:sensitivity": row["sensitivity"],
            "imprint:accessPolicyVersion": {"@id": row["access_policy_version_id"]},
            "imprint:consentVersion": (
                {"@id": row["consent_version_id"]}
                if row["consent_version_id"] is not None else None
            ),
            "imprint:actor": {"@id": row["actor_id"]},
            "imprint:roleAssignmentVersion": {"@id": row["role_assignment_version_id"]},
            "imprint:scopeId": row["scope_id"],
            "imprint:contestedSetId": row["contested_set_id"],
            "imprint:envelope": json.loads(row["envelope_json"]),
            "imprint:envelopeSha256": row["envelope_sha256"],
        }
        if row["version_id"] in business_nodes:
            item["business:partition"] = business_nodes[row["version_id"]]["partition_id"]
        graph.append(item)
    for row in ledger["semantic_relation_versions"]:
        item = {
            "@id": row["relation_version_id"],
            "@type": "imprint:SemanticRelationVersion",
            "imprint:relationId": row["relation_id"],
            "imprint:predicateId": row["predicate_id"],
            "imprint:predicateVersion": row["predicate_version"],
            "imprint:sourceVersion": {"@id": row["source_version_id"]},
            "imprint:targetVersion": {"@id": row["target_version_id"]},
            "imprint:operator": row["operator_id"],
            "imprint:qualifierSchemaId": row["qualifier_schema_id"],
            "imprint:qualifier": json.loads(row["qualifier_json"]),
            "imprint:envelope": json.loads(row["envelope_json"]),
            "imprint:envelopeSha256": row["envelope_sha256"],
            "imprint:validFrom": row["valid_from"],
            "imprint:validTo": row["valid_to"],
            "imprint:systemFrom": row["system_from"],
            "imprint:systemTo": row["system_to"],
            "imprint:contestedSetId": row["contested_set_id"],
        }
        governance = business_relations.get(row["relation_version_id"])
        if governance:
            item["business:policyCode"] = governance["policy_code"]
            item["business:authorityMinimum"] = governance["authority_minimum"]
        graph.append(item)
    for row in ledger["semantic_artifact_bytes"]:
        graph.append({
            "@id": f"{row['version_id']}#exact-bytes",
            "@type": "imprint:ArtifactByteIdentity",
            "imprint:artifactVersion": {"@id": row["version_id"]},
            "imprint:contentSha256": row["content_sha256"],
            "imprint:byteCount": row["byte_count"],
        })
    graph.sort(key=lambda item: (item["@type"], item["@id"]))
    return graph


def export_jsonld(
    store: ImprintStore, *, manifest_factory: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Export every canonical/version/receipt row, including opaque extensions."""
    store.initialize()
    ledger = {table: _rows(store, table) for table in TABLES}
    document = {
        "@context": {**local_context(), "ledger": "imprint:ledger"},
        "schemaVersion": STORE_SCHEMA_VERSION,
        "ontologySchemaVersion": ONTOLOGY_SCHEMA_VERSION,
        "@graph": _graph_from_ledger(ledger),
        "imprint:ledger": ledger,
    }
    document["imprint:semanticSha256"] = semantic_digest(document)
    document["imprint:canonicalLedgerSha256"] = canonical_ledger_digest(document)
    document["imprint:rdfDatasetSha256"] = rdf_dataset_digest(document)
    document["imprint:context"] = {
        "core": CONTEXT_VERSION,
        "business": BUSINESS_CONTEXT_VERSION,
        "sha256": hashlib.sha256(canonical_bytes(document["@context"])).hexdigest(),
    }
    if manifest_factory is not None:
        manifest = manifest_factory(document)
        if not isinstance(manifest, dict):
            raise ValidationError("manifest factory must return an object")
        document["imprint:manifest"] = manifest
    return document


def _assert_payload_hashes(ledger: dict[str, list[dict[str, Any]]]) -> None:
    for table in ("events", "node_versions", "edge_versions", "ingest_items"):
        for row in ledger[table]:
            try:
                payload = json.loads(row["payload_json"])
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ValidationError(f"invalid payload_json in {table}") from exc
            actual = hashlib.sha256(canonical_bytes(payload)).hexdigest()
            if actual != row["payload_sha256"]:
                raise ValidationError(f"payload hash mismatch in {table}")


def _contract_provenance(row: dict[str, Any]) -> dict[str, Any]:
    try:
        stored = json.loads(row["provenance_json"])
        evidence_ids = json.loads(row["evidence_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValidationError("invalid semantic provenance or evidence JSON") from exc
    return {
        "status": row["provenance_status"],
        "authority_tier": row["authority_tier"],
        "actor_class": stored.get("actor_class"),
        "actor_id": stored.get("actor_id"),
        "mechanism": stored.get("mechanism"),
        "evidence_ids": evidence_ids,
        "model": stored.get("model"),
        "ratifier_id": stored.get("ratifier"),
    }


def _assert_provenance_floor(kind: str, status: Any, tier: Any, provenance: dict[str, Any]) -> None:
    """Enforce the authority lattice on every imported version, of any type.

    This mirrors the status/tier/actor/model/ratifier rules of
    ``validate_provenance_contract`` but without the ontology-URN actor shape, so
    it also covers rows written by the capture, domain, transition, and derived
    writers (which use free-form actor identifiers). Trusting only the internal
    self-consistency gates (hashes, @graph, digest) is not enough: those are all
    recomputable by whoever authored the document. The floor is what prevents an
    imported record from declaring ``ratified``/``ratified_knowledge`` or
    model-authored authority that the originating writer would never have granted.
    """
    actor_class = provenance.get("actor_class")
    model = provenance.get("model")
    ratifier = provenance.get("ratifier", provenance.get("ratifier_id"))
    if status not in PROVENANCE or tier not in AUTHORITY_TIERS:
        raise ValidationError(f"{kind} has an unsupported provenance status or authority tier")
    if actor_class not in {"operator", "software", "model", "importer"}:
        raise ValidationError(f"{kind} has an unsupported provenance actor_class")
    if status == "captured":
        signed_operator_capture = tier == "captured_judgment" and actor_class == "operator"
        recorder_candidate = tier == "observed_candidate" and actor_class == "software"
        if not (signed_operator_capture or recorder_candidate) or model is not None or ratifier is not None:
            raise ValidationError(f"{kind} captured authority cannot be escalated or model-authored")
    elif status == "extracted":
        if tier not in {"imported_floor", "observed_candidate"} or ratifier is not None:
            raise ValidationError(f"{kind} extracted authority cannot be ratified")
    elif status == "inferred":
        if tier != "inferred_candidate" or actor_class not in {"model", "software"} or ratifier is not None:
            raise ValidationError(f"{kind} inferred authority must remain a machine candidate")
        if actor_class == "model" and not model:
            raise ValidationError(f"{kind} model inference must identify its model")
    elif status == "ratified":
        if tier != "ratified_knowledge" or actor_class != "operator" or ratifier is None:
            raise ValidationError(f"{kind} ratified authority requires operator ratification")


def _version_provenance(row: dict[str, Any], kind: str) -> dict[str, Any]:
    try:
        provenance = json.loads(row["provenance_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid {kind} provenance JSON") from exc
    if not isinstance(provenance, dict):
        raise ValidationError(f"{kind} provenance must be an object")
    return provenance


def _validate_semantic_rows(
    ledger: dict[str, list[dict[str, Any]]], ontology_version: str,
) -> None:
    """Revalidate typed ledger rows; valid hashes alone cannot grant meaning."""
    events = {row["event_id"]: row for row in ledger["events"]}
    nodes = {row["node_id"]: row for row in ledger["nodes"]}
    edges = {row["edge_id"]: row for row in ledger["edges"]}
    receipts = {row["source_id"]: row for row in ledger["source_receipts"]}
    versions = {row["version_id"]: row for row in ledger["node_versions"]}
    versions_by_node: dict[str, list[dict[str, Any]]] = {}
    for version in ledger["node_versions"]:
        versions_by_node.setdefault(version["node_id"], []).append(version)
    v31_versions = {row["version_id"] for row in ledger["semantic_node_versions"]}
    legacy_consent_versions: set[str] = set()

    def node_lookup(identifier: str) -> tuple[str, str] | None:
        node = nodes.get(identifier)
        if node:
            return node["node_type"], node["operator_id"]
        receipt = receipts.get(identifier)
        event = events.get(receipt["event_id"]) if receipt else None
        return ("Evidence", event["operator_id"]) if event else None

    def version_lookup(identifier: str) -> tuple[str, str] | None:
        version = versions.get(identifier)
        node = nodes.get(version["node_id"]) if version else None
        return (node["node_id"], node["operator_id"]) if node else None

    typed_nodes: set[str] = set()
    for node_id, node in nodes.items():
        created = events.get(node["created_event_id"])
        if any(row["version_id"] in v31_versions for row in versions_by_node.get(node_id, [])):
            # The 3.1 envelope/table compiler below is the sole validator for
            # these rows; its event name is not part of the legacy 3.0 contract.
            continue
        if (
            node["node_type"] == "ConsentGrant" and created
            and created["event_type"] in {"consent_granted", "test_consent"}
        ):
            # Preserve legacy grants as history. They are not accepted as local
            # 3.1 consent by the strict authority-import path.
            legacy_consent_versions.update(
                row["version_id"] for row in versions_by_node.get(node_id, [])
            )
            continue
        if created and str(created["event_type"]).startswith("semantic_"):
            try:
                created_payload = json.loads(created["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValidationError("invalid typed semantic creation event") from exc
            if created_payload.get("ontology_schema_version") != ontology_version:
                raise ValidationError("typed node ontology schema version mismatch")
            if created["operator_id"] != node["operator_id"]:
                raise ValidationError("typed node creation event operator mismatch")
            created_versions = [
                row for row in versions_by_node.get(node_id, [])
                if row["event_id"] == node["created_event_id"]
            ]
            if len(created_versions) != 1:
                raise ValidationError("typed node creation event must create exactly one version")
            created_version = created_versions[0]
            expected_creation = {
                "ontology_schema_version": ontology_version,
                "node_id": node_id, "node_type": node["node_type"],
                "payload": json.loads(created_version["payload_json"]),
                "provenance": _contract_provenance(created_version),
            }
            if created_payload != expected_creation:
                raise ValidationError("typed node creation event does not match its created version")
            typed_nodes.add(node_id)
        elif node["node_type"] in SEMANTIC_ONLY_NODE_TYPES:
            # A semantic-only type can only originate from append_semantic_node,
            # which always stamps a semantic_* creation event. Any other creation
            # event means the document is trying to route it around the typed
            # contract and consent re-checks below.
            raise ValidationError("typed semantic node has a non-semantic creation event")

    # Authority floor first, for EVERY version regardless of writer family, so a
    # forged ratified/model tier on a capture- or derived-family record is caught
    # even though such records are not re-run through the typed node contract.
    for row in ledger["node_versions"]:
        if row["version_id"] in legacy_consent_versions:
            continue
        _assert_provenance_floor(
            "node version", row["provenance_status"], row["authority_tier"],
            _version_provenance(row, "node version"),
        )

    for row in ledger["node_versions"]:
        if row["node_id"] not in typed_nodes:
            continue
        node = nodes[row["node_id"]]
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValidationError("invalid typed semantic node payload") from exc
        contract = validate_node_contract({
            "record_schema_version": ontology_version,
            "node_id": node["node_id"], "node_type": node["node_type"],
            "operator_id": node["operator_id"], "payload": payload,
            "provenance": _contract_provenance(row),
        })
        validate_payload_references(
            node["node_type"],
            contract["payload"],
            operator_id=node["operator_id"],
            provenance_evidence_ids=contract["provenance"]["evidence_ids"],
            node_lookup=node_lookup,
            version_lookup=version_lookup,
        )
        if node["node_type"] in {"Observation", "Outcome"}:
            grant_id = payload.get("consent_grant_id")
            if grant_id is not None:
                observation_system_time = datetime.fromisoformat(
                    row["system_from"].replace("Z", "+00:00")
                )
                active_grants = []
                for grant_version in versions_by_node.get(grant_id, []):
                    system_from = datetime.fromisoformat(
                        grant_version["system_from"].replace("Z", "+00:00")
                    )
                    system_to = (
                        datetime.fromisoformat(grant_version["system_to"].replace("Z", "+00:00"))
                        if grant_version["system_to"] is not None else None
                    )
                    if system_from <= observation_system_time and (
                        system_to is None or observation_system_time < system_to
                    ):
                        active_grants.append(grant_version)
                if len(active_grants) != 1:
                    raise ValidationError("semantic observation lacks one active ConsentGrant version")
                from imprint.ontology.operator import consent_authorizes, validate_operator_payload
                grant_payload = validate_operator_payload(
                    "ConsentGrant", json.loads(active_grants[0]["payload_json"])
                )
                purpose = "outcome_learning" if node["node_type"] == "Outcome" else "behavioral_observation"
                if not consent_authorizes(
                    grant_payload, source_class=payload["source_class"], purpose=purpose,
                    operation="store", at=row["valid_from"],
                ):
                    raise ValidationError("ConsentGrant does not authorize imported semantic observation")

    for row in ledger["edge_versions"]:
        _assert_provenance_floor(
            "edge version", row["provenance_status"], row["authority_tier"],
            _version_provenance(row, "edge version"),
        )
        edge = edges[row["edge_id"]]
        created = events.get(edge["created_event_id"])
        if not created or created["event_type"] != "semantic_relation":
            continue
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValidationError("invalid typed semantic relation payload") from exc
        if payload.get("ontology_schema_version") != ontology_version:
            raise ValidationError("typed relation ontology schema version mismatch")
        source = nodes.get(edge["source_id"])
        target = nodes.get(edge["target_id"])
        if not source or not target or created["operator_id"] != edge["operator_id"]:
            raise ValidationError("typed relation has invalid canonical endpoints or operator")
        relation_contract = validate_relation_contract({
            "record_schema_version": ontology_version,
            "relation_id": edge["edge_id"], "relation_type": edge["edge_type"],
            "source_id": edge["source_id"], "source_type": source["node_type"],
            "target_id": edge["target_id"], "target_type": target["node_type"],
            "operator_id": edge["operator_id"], "evidence_mode": payload.get("evidence_mode"),
            "why": payload.get("why"), "provenance": _contract_provenance(row),
        })
        if row["event_id"] == edge["created_event_id"]:
            try:
                creation_payload = json.loads(created["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValidationError("invalid typed relation creation event") from exc
            if creation_payload != relation_contract:
                raise ValidationError("typed relation creation event does not match its created version")


def _validate_v31_portable_tables(ledger: dict[str, list[dict[str, Any]]]) -> None:
    """Recompile every v3.1 envelope and exact artifact/relation identity."""
    from imprint.ontology.business import (
        BUSINESS_NODE_SCHEMA_IDS, BUSINESS_RELATION_SPECS,
        validate_business_payload, validate_business_relation,
    )
    from imprint.store.service import _V31_SCHEMA_TYPES

    business_types = {
        BUSINESS_NODE_SCHEMA_IDS[0]: "Market", BUSINESS_NODE_SCHEMA_IDS[1]: "Positioning",
        BUSINESS_NODE_SCHEMA_IDS[2]: "TermSet", BUSINESS_NODE_SCHEMA_IDS[3]: "Asset",
        BUSINESS_NODE_SCHEMA_IDS[4]: "Campaign", BUSINESS_NODE_SCHEMA_IDS[5]: "BusinessEvent",
        BUSINESS_NODE_SCHEMA_IDS[6]: "Segment", BUSINESS_NODE_SCHEMA_IDS[7]: "Situation",
        BUSINESS_NODE_SCHEMA_IDS[8]: "RequiredBehavior",
        BUSINESS_NODE_SCHEMA_IDS[9]: "CampaignPerformanceMeasurement",
        BUSINESS_NODE_SCHEMA_IDS[10]: "PerformanceDisposition",
    }
    versions = {row["version_id"]: row for row in ledger["node_versions"]}
    nodes = {row["node_id"]: row for row in ledger["nodes"]}
    portable = {row["version_id"]: row for row in ledger["semantic_node_versions"]}
    business_node_meta = {
        row["version_id"]: row for row in ledger["semantic_business_node_versions"]
    }
    business_relation_meta = {
        row["relation_version_id"]: row
        for row in ledger["semantic_business_relation_versions"]
    }
    parsed: dict[str, dict[str, Any]] = {}
    for row in ledger["semantic_node_versions"]:
        try:
            envelope = json.loads(row["envelope_json"])
            provenance = json.loads(row["provenance_v2_1_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValidationError("invalid v3.1 semantic envelope JSON") from exc
        if canonical_bytes(envelope).decode() != row["envelope_json"]:
            raise ValidationError("v3.1 semantic envelope is not canonical JSON")
        if hashlib.sha256(canonical_bytes(envelope)).hexdigest() != row["envelope_sha256"]:
            raise ValidationError("v3.1 semantic envelope digest mismatch")
        generic = versions.get(row["version_id"])
        node = nodes.get(generic["node_id"]) if generic else None
        schema_id = row["payload_schema_id"]
        expected_type = _V31_SCHEMA_TYPES.get(schema_id) or business_types.get(schema_id)
        if generic is None or node is None or expected_type is None or node["node_type"] != expected_type:
            raise ValidationError("v3.1 semantic envelope generic identity mismatch")
        exact = {
            "version_id": row["version_id"], "record_id": row["record_id"],
            "payload_schema_id": schema_id, "record_schema_version": row["record_schema_version"],
            "ontology_schema_version": row["ontology_schema_version"],
            "sensitivity": row["sensitivity"],
            "access_policy_version_id": row["access_policy_version_id"],
            "consent_version_id": row["consent_version_id"], "actor_id": row["actor_id"],
            "role_assignment_version_id": row["role_assignment_version_id"],
            "scope_id": row["scope_id"],
        }
        if any(envelope.get(key) != value for key, value in exact.items()):
            raise ValidationError("v3.1 semantic envelope columns disagree with canonical envelope")
        if envelope.get("provenance") != provenance:
            raise ValidationError("v3.1 semantic provenance copies disagree")
        if canonical_bytes(envelope.get("payload")).decode() != generic["payload_json"]:
            raise ValidationError("v3.1 semantic payload differs from generic immutable version")
        if schema_id not in business_types:
            if row["version_id"] in business_node_meta:
                raise ValidationError("core semantic node has business partition metadata")
            append_envelope = dict(envelope)
            if append_envelope.pop("system_from", generic["system_from"]) != generic["system_from"]:
                raise ValidationError("v3.1 semantic system_from mismatch")
            if append_envelope.pop("system_to", generic["system_to"]) != generic["system_to"]:
                raise ValidationError("v3.1 semantic system_to mismatch")
            ImprintStore._validate_v31_envelope(append_envelope)
        else:
            expected_partition = (
                "business_observed" if expected_type in {"BusinessEvent", "CampaignPerformanceMeasurement"}
                else "business_declared"
            )
            validate_business_payload(
                schema_id, envelope.get("payload"), partition=expected_partition,
            )
            metadata = business_node_meta.get(row["version_id"])
            if metadata is None or metadata["partition_id"] != expected_partition:
                raise ValidationError("E_BUSINESS_PARTITION_MISMATCH")
        parsed[row["version_id"]] = envelope

    artifact_rows = {row["version_id"]: row for row in ledger["semantic_artifact_bytes"]}
    for version_id, row in artifact_rows.items():
        envelope = parsed.get(version_id)
        if envelope is None or envelope["payload_schema_id"] != "imprint.node.evidence-artifact/1.0.0":
            raise ValidationError("artifact bytes lack an exact EvidenceArtifact envelope")
        raw = _database_cell(row["content"])
        if (
            not isinstance(raw, bytes) or len(raw) != row["byte_count"]
            or hashlib.sha256(raw).hexdigest() != row["content_sha256"]
            or envelope["payload"]["original_sha256"] != row["content_sha256"]
            or envelope["payload"]["byte_count"] != row["byte_count"]
        ):
            raise ValidationError("E_ARTIFACT_DIGEST_MISMATCH")
    for version_id, envelope in parsed.items():
        if (
            envelope["payload_schema_id"] == "imprint.node.evidence-artifact/1.0.0"
            and envelope["payload"].get("content_state") != "purged"
            and version_id not in artifact_rows
        ):
            raise ValidationError("E_ARTIFACT_DIGEST_MISMATCH")

    type_by_version = {
        version_id: nodes[versions[version_id]["node_id"]]["node_type"]
        for version_id in versions if versions[version_id]["node_id"] in nodes
    }
    for row in ledger["semantic_relation_versions"]:
        try:
            envelope = json.loads(row["envelope_json"])
            qualifier = json.loads(row["qualifier_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValidationError("invalid v3.1 semantic relation JSON") from exc
        if (
            canonical_bytes(envelope).decode() != row["envelope_json"]
            or hashlib.sha256(canonical_bytes(envelope)).hexdigest() != row["envelope_sha256"]
        ):
            raise ValidationError("v3.1 semantic relation envelope digest mismatch")
        if row["predicate_id"] in BUSINESS_RELATION_SPECS:
            source_type = type_by_version.get(row["source_version_id"])
            target_type = type_by_version.get(row["target_version_id"])
            source_payload = parsed.get(row["source_version_id"], {}).get("payload")
            checked = validate_business_relation(
                row["predicate_id"], source_type, target_type, qualifier,
                source_payload=source_payload, target_version_id=row["target_version_id"],
                source_partition=("business_observed" if source_type in {"BusinessEvent", "CampaignPerformanceMeasurement"} else "business_declared"),
                target_partition=("business_observed" if target_type in {"BusinessEvent", "CampaignPerformanceMeasurement", "Outcome"} else "business_declared"),
            )
            metadata = business_relation_meta.get(row["relation_version_id"])
            if (
                metadata is None or metadata["policy_code"] != checked["policy"]
                or metadata["authority_minimum"] != checked["authority_minimum"]
            ):
                raise ValidationError("business relation governance metadata mismatch")
        elif row["relation_version_id"] in business_relation_meta:
            raise ValidationError("core semantic relation has business governance metadata")
    if set(business_node_meta) - set(parsed):
        raise ValidationError("orphan business partition metadata")
    relation_ids = {row["relation_version_id"] for row in ledger["semantic_relation_versions"]}
    if set(business_relation_meta) - relation_ids:
        raise ValidationError("orphan business relation governance metadata")


def _quarantine_foreign_import(
    document: Mapping[str, Any], directory: Path, *, reason: str,
) -> Path:
    """Publish one immutable, non-canonical imported-floor quarantine artifact.

    The rejected export is preserved byte-for-byte in canonical form inside a
    closed metadata envelope.  It is deliberately not materialized in an
    Imprint store: local re-ratification must create a new signed successor
    referring to ``original_sha256`` rather than mutating this artifact.
    """
    payload = canonical_bytes(document)
    digest = hashlib.sha256(payload).hexdigest()
    manifest = document.get("imprint:manifest")
    if not isinstance(manifest, Mapping):
        manifest = {}
    envelope = {
        "schema_version": "imprint.import.quarantine/1.0.0",
        "authority_tier": "imported_floor",
        "disposition": "noncanonical_private_quarantine",
        "original_sha256": digest,
        "original_bytes": len(payload),
        "original_operator_id": manifest.get("operator_id"),
        "original_signature_b64": manifest.get("signature_b64"),
        "rejection_reason": reason,
        "artifact_encoding": "base64-canonical-json",
        "artifact_b64": base64.b64encode(payload).decode("ascii"),
    }
    encoded = canonical_bytes(envelope)
    target = directory / f"foreign-import-{digest}.quarantine.json"
    secure_directory(directory)
    if target.exists():
        try:
            existing = json.loads(target.read_bytes())
            existing_artifact = base64.b64decode(existing["artifact_b64"], validate=True)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, base64.binascii.Error) as exc:
            raise ConflictError("foreign import quarantine artifact is corrupt") from exc
        if (
            set(existing) != set(envelope)
            or existing.get("original_sha256") != digest
            or existing_artifact != payload
        ):
            raise ConflictError("foreign import quarantine digest collision")
        return target
    publish_new_private(target, encoded)
    return target


def _validate_local_import_consent(
    governance_store: ImprintStore, ledger: Mapping[str, list[dict[str, Any]]],
) -> None:
    """Re-authorize imported governed rows against pre-existing local grants."""
    if not governance_store.path.exists():
        raise ValidationError("authoritative import requires a pre-existing local governance store")
    system_at = utc_now()
    from imprint.ontology.business import BUSINESS_NODE_SCHEMA_IDS
    generic_versions = {row["version_id"]: row for row in ledger["node_versions"]}

    with governance_store.connect() as conn:
        for row in ledger["semantic_node_versions"]:
            consent_version_id = row["consent_version_id"]
            if consent_version_id is None:
                continue
            try:
                envelope = json.loads(row["envelope_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValidationError("invalid semantic envelope JSON") from exc
            payload = envelope.get("payload", {})
            schema_id = row["payload_schema_id"]
            if schema_id.endswith("expected-outcome/1.0.0"):
                purpose = "outcome_learning"
            elif schema_id in BUSINESS_NODE_SCHEMA_IDS or schema_id.endswith("evidence-artifact/1.0.0"):
                purpose = "business_analysis"
            else:
                purpose = "self_modeling"
            governance_store.authorize_consent_version(
                conn, consent_version_id, operator_id=envelope["operator_id"],
                source_class=payload.get("source_class", "operator_explicit"),
                purpose=purpose, operation="store",
                valid_at=generic_versions[row["version_id"]]["valid_from"],
                system_at=system_at,
            )


def _insert_portable_ledger(
    conn: sqlite3.Connection, ledger: Mapping[str, list[dict[str, Any]]],
) -> None:
    """Insert a validated portable ledger into one caller-owned transaction."""
    for table in TABLES:
        rows = ledger[table]
        if table == "meta":
            conn.execute("DELETE FROM meta")
        for row in rows:
            columns = TABLE_COLUMNS[table]
            placeholders = ",".join("?" for _ in columns)
            names = ",".join(columns)
            conn.execute(
                f"INSERT INTO {table} ({names}) VALUES ({placeholders})",
                tuple(_database_cell(row[column]) for column in columns),
            )
    # Graph INSERT triggers intentionally advance the target's retrieval
    # generation during replay.  Exact lossless import restores the source's
    # already-validated counter after all rows are present; later mutations
    # continue incrementing it transactionally.
    source_meta = {row["key"]: row["value"] for row in ledger["meta"]}
    if "content_generation" in source_meta:
        conn.execute(
            "UPDATE meta SET value=? WHERE key='content_generation'",
            (_database_cell(source_meta["content_generation"]),),
        )


def _verify_portable_authority(
    document: Mapping[str, Any], ledger: Mapping[str, list[dict[str, Any]]], *,
    expected_operator_id: str | None,
    expected_store_identity: str | None,
    checkpoint: Mapping[str, Any] | None,
    pinned_head: Mapping[str, Any] | None,
    now: datetime | None,
) -> dict[str, Any]:
    """Verify source history using the production chain/checkpoint verifier."""
    if not expected_operator_id:
        raise ValidationError("destination operator identity is required")
    if checkpoint is None:
        raise ValidationError("a physically supplied fresh authority checkpoint is required")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA_SQL)
        conn.execute("BEGIN IMMEDIATE")
        _insert_portable_ledger(conn, ledger)
        from imprint.authority.ledger import verify_authority_chain
        from imprint.authority.keys import public_key_from_b64

        chain = verify_authority_chain(
            conn, expected_operator_id=expected_operator_id,
            expected_store_identity=expected_store_identity,
            checkpoint=checkpoint, pinned_head=pinned_head,
            now=now or datetime.now(timezone.utc),
        )
        manifest = document.get("imprint:manifest")
        if not isinstance(manifest, Mapping):
            raise ValidationError("export manifest is missing")
        signer = chain["keys"].get(manifest.get("key_id"))
        if (
            not isinstance(signer, Mapping)
            or signer.get("kind") != "installation"
            or signer.get("status") != "active"
            or signer.get("paired") is not True
            or signer.get("install_id") != manifest.get("install_id")
        ):
            raise ValidationError("export signer is not an active paired installation key")
        verified = verify_export_manifest(
            document, public_key=public_key_from_b64(signer["public_key_b64"]),
        )
        if (
            verified["authority_preserved"] is not True
            or verified["operator_id"] != chain["operator_id"]
            or verified["ledger_sequence"] != chain["head_sequence"]
            or verified["ledger_head_sha256"] != chain["head_sha256"]
            or verified["snapshot_valid_as_of"] != chain["snapshot_valid_as_of"]
            or chain["checkpoint"] is None
        ):
            raise ValidationError("export manifest does not bind the verified authority chain")
        return chain
    finally:
        conn.close()


def import_jsonld(
    store: ImprintStore, document: dict[str, Any], *, dry_run: bool = False,
    enforce_authority: bool = False,
    local_governance_store: ImprintStore | None = None,
    quarantine_dir: Path | None = None,
    expected_operator_id: str | None = None,
    expected_store_identity: str | None = None,
    authority_checkpoint: Mapping[str, Any] | None = None,
    pinned_authority_head: Mapping[str, Any] | None = None,
    authority_now: datetime | None = None,
) -> str:
    """Import a complete export only into an empty compatible store."""
    if not isinstance(document, dict) or document.get("schemaVersion") != STORE_SCHEMA_VERSION:
        raise ValidationError("incompatible or missing JSON-LD schemaVersion")
    if document.get("ontologySchemaVersion") != ONTOLOGY_SCHEMA_VERSION:
        raise ValidationError("incompatible or missing ontologySchemaVersion")
    ledger = document.get("imprint:ledger")
    if not isinstance(ledger, dict) or set(ledger) != set(TABLES):
        raise ValidationError("JSON-LD ledger is missing or has unknown tables")
    if document.get("imprint:semanticSha256") != semantic_digest(document):
        raise ValidationError("JSON-LD semantic digest mismatch")
    context_receipt = document.get("imprint:context")
    expected_context = {**local_context(), "ledger": "imprint:ledger"}
    if (
        not isinstance(context_receipt, dict)
        or context_receipt.get("core") != CONTEXT_VERSION
        or context_receipt.get("business") != BUSINESS_CONTEXT_VERSION
        or context_receipt.get("sha256") != hashlib.sha256(canonical_bytes(document.get("@context"))).hexdigest()
        or document.get("@context") != expected_context
    ):
        raise ValidationError("E_JSONLD_CONTEXT_INCOMPLETE")
    for table in TABLES:
        if not isinstance(ledger[table], list):
            raise ValidationError(f"ledger table {table} must be an array")
        for row in ledger[table]:
            if not isinstance(row, dict) or set(row) != set(TABLE_COLUMNS[table]):
                raise ValidationError(f"invalid row in {table}")
    _assert_payload_hashes(ledger)
    _validate_semantic_rows(ledger, document["ontologySchemaVersion"])
    _validate_v31_portable_tables(ledger)
    if document.get("imprint:canonicalLedgerSha256") != canonical_ledger_digest(document):
        raise ValidationError("JSON-LD canonical ledger digest mismatch")
    if document.get("@graph") != _graph_from_ledger(ledger):
        raise ValidationError("JSON-LD graph does not match its canonical ledger")
    if document.get("imprint:rdfDatasetSha256") != rdf_dataset_digest(document):
        raise ValidationError("E_JSONLD_CONTEXT_INCOMPLETE")
    if enforce_authority and any(ledger[table] for table in AUTHORITY_TABLES):
        try:
            _verify_portable_authority(
                document, ledger, expected_operator_id=expected_operator_id,
                expected_store_identity=expected_store_identity,
                checkpoint=authority_checkpoint, pinned_head=pinned_authority_head,
                now=authority_now,
            )
            if local_governance_store is None:
                raise ValidationError("pre-existing local governance is required")
            _validate_local_import_consent(local_governance_store, ledger)
        except ValidationError as exc:
            if not dry_run and quarantine_dir is not None:
                _quarantine_foreign_import(document, quarantine_dir, reason=str(exc))
            raise ValidationError("E_IMPORT_AUTHORITY_QUARANTINED: foreign, unsigned, stale, or unpaired authority") from exc
    if dry_run:
        # A dry run must not touch the filesystem. A store that does not exist yet
        # is trivially empty; only an existing store needs the emptiness check.
        if store.path.exists():
            with store.connect() as conn:
                non_meta = sum(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES if table != "meta")
            if non_meta:
                raise ConflictError("JSON-LD import requires an empty compatible store")
        return document["imprint:semanticSha256"]
    store.initialize()
    with store.connect() as conn:
        non_meta = sum(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES if table != "meta")
        if non_meta:
            raise ConflictError("JSON-LD import requires an empty compatible store")
        conn.execute("BEGIN IMMEDIATE")
        _insert_portable_ledger(conn, ledger)
        inserted = {
            table: [
                {name: _portable_cell(value) for name, value in dict(row).items()}
                for row in conn.execute(
                    f"SELECT * FROM {table} ORDER BY {PRIMARY_KEYS[table]}"
                ).fetchall()
            ]
            for table in TABLES
        }
        replay = {
            "@context": {**local_context(), "ledger": "imprint:ledger"},
            "schemaVersion": STORE_SCHEMA_VERSION,
            "ontologySchemaVersion": ONTOLOGY_SCHEMA_VERSION,
            "@graph": _graph_from_ledger(inserted),
            "imprint:ledger": inserted,
        }
        replay["imprint:semanticSha256"] = semantic_digest(replay)
        replay["imprint:canonicalLedgerSha256"] = canonical_ledger_digest(replay)
        replay["imprint:rdfDatasetSha256"] = rdf_dataset_digest(replay)
        if replay["imprint:semanticSha256"] != document["imprint:semanticSha256"]:
            raise ConflictError("imported store semantic digest differs from source")
        if replay["imprint:canonicalLedgerSha256"] != document["imprint:canonicalLedgerSha256"]:
            raise ConflictError("imported store canonical ledger digest differs from source")
    return document["imprint:semanticSha256"]
