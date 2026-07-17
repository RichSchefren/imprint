"""Read-only adapter from canonical SQLite state to retrieval records."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Sequence

from imprint.errors import ValidationError
from imprint.ontology.world import DECLARED_BUSINESS_TYPES, OBSERVED_BUSINESS_TYPES
from imprint.store import ImprintStore

from .models import (
    BUSINESS_DECLARED_PARTITION,
    BUSINESS_OBSERVED_PARTITION,
    JUDGMENT_PARTITION,
    SELF_MODEL_PARTITION,
    RetrievalRecord,
)


_JUDGMENT_TYPES = {"Verdict", "Principle", "Belief", "Value", "Rule", "Pattern", "IngestedItem"}
_SEMANTIC_TYPES = (
    _JUDGMENT_TYPES
    | {"SelfModelAssertion", "Observation", "Outcome"}
    | set(DECLARED_BUSINESS_TYPES)
    | set(OBSERVED_BUSINESS_TYPES)
)


def _partition(node_type: str, payload: dict) -> str:
    if node_type == "SelfModelAssertion":
        return SELF_MODEL_PARTITION
    if node_type in DECLARED_BUSINESS_TYPES:
        return BUSINESS_DECLARED_PARTITION
    if node_type in OBSERVED_BUSINESS_TYPES or node_type in {"Observation", "Outcome"}:
        return BUSINESS_OBSERVED_PARTITION
    return JUDGMENT_PARTITION


def _path(node_type: str, payload: dict, partition: str) -> tuple[str, ...]:
    if node_type == "SelfModelAssertion":
        return tuple(str(item) for item in (
            "operator", "self_model", payload.get("function_class"),
            payload.get("subtype"), payload.get("dimension"),
        ) if item)
    if partition in {BUSINESS_DECLARED_PARTITION, BUSINESS_OBSERVED_PARTITION}:
        return ("business_world", str(payload.get("evidence_mode", "unclassified")), node_type)
    return ("judgment", node_type)


def _text(node_type: str, payload: dict) -> str | None:
    for key in (
        "statement", "raw_operator_text", "description", "content", "text",
        "name", "definition", "action", "metric", "status", "referred_party",
        "candidate_move",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    if node_type in {"Price", "Purchase", "Refund"} and payload.get("amount") is not None:
        return f"{node_type}: {payload.get('amount')} {payload.get('currency', '')}".strip()
    if node_type == "Result" and payload.get("value") is not None:
        return f"{payload.get('metric')}: {payload.get('value')} {payload.get('unit', '')}".strip()
    return None


def _confidence(payload: dict) -> float | None:
    confidence = payload.get("confidence")
    if isinstance(confidence, dict):
        score = confidence.get("score")
        if not isinstance(score, bool) and isinstance(score, (int, float)) and 0 <= score <= 1:
            return float(score)
    return None


def _disclosure(status: str, authority: str) -> str:
    if authority == "imported_floor":
        return "approved_import_not_operator_judgment"
    return {
        "captured": "operator_captured",
        "ratified": "operator_ratified",
        "extracted": "source_extracted_not_operator_ratified",
        "inferred": "model_inference_not_operator_authority",
    }.get(status, "authority_unclassified")


class StoreRetrievalSource:
    """Expose only provenance-complete, current canonical records.

    ``provenance_complete`` is computed here rather than trusted from a model or
    serialized projection. Evidence and Case links must exist in canonical
    state before captured judgment can enter context.
    """

    def __init__(self, store: ImprintStore):
        self.store = store

    def _operator_id(self, nodes: Sequence[dict]) -> str | None:
        configured = getattr(self.store, "expected_operator_id", None)
        if configured is not None:
            return configured
        operators = {item.get("operator_id") for item in nodes if item.get("operator_id")}
        if len(operators) > 1:
            raise ValidationError("operator-scoped retrieval requires a configured operator for a mixed store")
        return next(iter(operators), None)

    def retrieval_candidates(self, snapshot_id: str) -> Sequence[RetrievalRecord]:
        del snapshot_id  # snapshot identity is enforced by the caller/receipt.
        # Keep product retrieval proportional to potentially useful context,
        # not to every canonical ontology/governance row in the store.
        if isinstance(self.store, ImprintStore):
            nodes = self.store.current_nodes(_SEMANTIC_TYPES | {"Evidence", "Case"})
        else:
            # Retrieval-source test/integration adapters predate the optional
            # store-side type filter; eligibility below remains authoritative.
            nodes = self.store.current_nodes()
        operator_id = self._operator_id(nodes)
        if operator_id is not None:
            nodes = [item for item in nodes if item.get("operator_id") == operator_id]
        evidence_nodes = {item["node_id"] for item in nodes if item["node_type"] == "Evidence"}
        semantic_governance: dict[str, tuple[str | None, str]] = {}
        with self.store.connect() as conn:
            if isinstance(self.store, ImprintStore):
                edge_sql = """SELECT e.edge_type,e.source_id,e.target_id,e.operator_id
                              FROM edges e JOIN edge_versions ev USING(edge_id)
                              WHERE ev.system_to IS NULL
                              AND e.edge_type IN ('verdict_about_case','supported_by')"""
                edge_params: tuple[str, ...] = ()
                if operator_id is not None:
                    edge_sql += " AND e.operator_id=?"
                    edge_params = (operator_id,)
                edges = [dict(row) for row in conn.execute(edge_sql, edge_params)]
            else:
                edges = [
                    item for item in self.store.current_edges()
                    if item["edge_type"] in {"verdict_about_case", "supported_by"}
                    and (
                        operator_id is None
                        or item.get("operator_id", operator_id) == operator_id
                    )
                ]
            if operator_id is None:
                source_receipts = {row[0] for row in conn.execute("SELECT source_id FROM source_receipts")}
            else:
                source_receipts = {
                    row[0] for row in conn.execute(
                        """SELECT sr.source_id FROM source_receipts sr
                           JOIN events e USING(event_id) WHERE e.operator_id=?""",
                        (operator_id,),
                    )
                }
            known = (
                {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if isinstance(self.store, ImprintStore) else set()
            )
            if "semantic_node_versions" in known:
                for row in conn.execute(
                    """SELECT version_id,consent_version_id,access_policy_version_id
                       FROM semantic_node_versions"""
                ):
                    semantic_governance[str(row[0])] = (row[1], str(row[2]))
            transaction_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            allowed_versions: set[str] = set()
            for node in nodes:
                version_id = node.get("version_id")
                governance = semantic_governance.get(version_id)
                if governance is None:
                    allowed_versions.add(str(version_id))
                    continue
                consent_version_id, policy_version_id = governance
                if not consent_version_id or operator_id is None:
                    continue
                policy = conn.execute(
                    """SELECT n.operator_id,nv.payload_json FROM node_versions nv
                       JOIN nodes n USING(node_id) WHERE nv.version_id=?
                       AND n.node_type='AccessPolicy'""",
                    (policy_version_id,),
                ).fetchone()
                if policy is None or policy["operator_id"] != operator_id:
                    continue
                policy_payload = json.loads(policy["payload_json"])
                if "retrieve" not in policy_payload.get("operations", []):
                    continue
                try:
                    self.store.authorize_consent_version(
                        conn, consent_version_id, operator_id=operator_id,
                        source_class=node["payload"].get("source_class", "operator_explicit"),
                        purpose="retrieval", operation="retrieve",
                        valid_at=node["valid_from"], system_at=transaction_time,
                    )
                except ValidationError:
                    continue
                allowed_versions.add(str(version_id))
        nodes = [
            item for item in nodes
            if item.get("version_id") is None or str(item.get("version_id")) in allowed_versions
        ]
        case_nodes = {item["node_id"] for item in nodes if item["node_type"] == "Case"}
        case_referents = {
            item["node_id"]: value
            for item in nodes if item["node_type"] == "Case"
            if (value := _text("Case", item["payload"])) is not None
        }
        cases_by_source: dict[str, set[str]] = defaultdict(set)
        evidence_by_source: dict[str, set[str]] = defaultdict(set)
        for edge in edges:
            if edge["edge_type"] == "verdict_about_case" and edge["target_id"] in case_nodes:
                cases_by_source[edge["source_id"]].add(edge["target_id"])
            if edge["edge_type"] == "supported_by" and edge["target_id"] in evidence_nodes:
                evidence_by_source[edge["source_id"]].add(edge["target_id"])

        records: list[RetrievalRecord] = []
        for node in nodes:
            if node["node_type"] not in _SEMANTIC_TYPES:
                continue
            payload = node["payload"]
            evidence = tuple(sorted(set(node["evidence"])))
            linked_evidence = evidence_by_source.get(node["node_id"], set())
            evidence_complete = bool(evidence) and all(
                item in evidence_nodes or item in source_receipts for item in evidence
            )
            if node["node_type"] == "Verdict":
                evidence_complete = evidence_complete and set(evidence).issubset(linked_evidence)
            cases = tuple(sorted(cases_by_source.get(node["node_id"], set())))
            status = node["provenance_status"]
            authority = node["authority_tier"]
            domain_id = payload.get("domain_id") if isinstance(payload.get("domain_id"), str) else None
            partition = _partition(node["node_type"], payload)
            section = "domain" if domain_id else (
                "core" if node["node_type"] in {"Belief", "Value", "SelfModelAssertion"}
                else "general"
            )
            text = _text(node["node_type"], payload)
            if not isinstance(text, str) or not text.strip():
                continue
            imported_selected = bool(payload.get("imported_selected", False))
            records.append(RetrievalRecord(
                record_id=node["node_id"],
                text=text,
                section=section,
                provenance_status=status,
                authority_tier=authority,
                evidence_ids=evidence,
                case_ids=cases,
                case_referents=tuple(
                    case_referents[case_id]
                    for case_id in cases if case_id in case_referents
                ),
                source_receipt_ids=tuple(item for item in evidence if item in source_receipts),
                domain_id=domain_id,
                pinned=bool(payload.get("pinned", False)),
                recurrence_count=int(payload.get("recurrence_count", 0)),
                valid_from=node["valid_from"],
                valid_until=node["valid_to"],
                provenance_complete=evidence_complete and (
                    status != "captured" or partition == BUSINESS_DECLARED_PARTITION or bool(cases)
                ),
                imported_selected=imported_selected,
                ontology_partition=partition,
                ontology_type=node["node_type"],
                ontology_path=_path(node["node_type"], payload, partition),
                confidence=_confidence(payload),
                disclosure=_disclosure(status, authority),
            ))
        return records
