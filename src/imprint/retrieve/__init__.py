"""Deterministic, provenance-gated context retrieval."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence

from .engine import RetrievalEngine
from .models import (
    BUSINESS_DECLARED_PARTITION,
    BUSINESS_OBSERVED_PARTITION,
    JUDGMENT_PARTITION,
    ONTOLOGY_PARTITIONS,
    SELF_MODEL_PARTITION,
    AuthorityMode,
    RetrievalConfig,
    RetrievalRecord,
    RetrievalResult,
)
from .receipts import DeliveryReceipts
from .store_source import StoreRetrievalSource
from .jev import JevSelector


def _snapshot_id(store) -> str:
    """Return a stable O(1) identity without materializing canonical content."""
    identity, generation = store.retrieval_generation()
    raw = f"{identity}:{generation}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def retrieve_payload(store, *, root: Path, session_id: str, prompt: str = "", explicit_domain: str | None = None,
                     budget: int = 32 * 1024, refresh: bool = False,
                     domain_only: bool = False,
                     output_format: str = "compact",
                     authority_mode: AuthorityMode = "authoritative",
                     ontology_partitions: Sequence[str] | None = None, selector_config: dict | None = None) -> dict[str, object]:
    """Build one bounded payload per session/snapshot with an atomic receipt."""
    snapshot_id = _snapshot_id(store)
    safe_session = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:24]
    receipts = DeliveryReceipts(Path(root) / "receipts")
    source = StoreRetrievalSource(store)
    if domain_only:
        class DomainOnlySource:
            def retrieval_candidates(self, requested_snapshot_id):
                return tuple(item for item in source.retrieval_candidates(requested_snapshot_id) if item.section == "domain")
        retrieval_source = DomainOnlySource()
    else:
        retrieval_source = source
    # Validate every retrieval invariant before consuming the once-delivery latch.
    engine = RetrievalEngine(
        retrieval_source,
        RetrievalConfig(
            total_budget_bytes=budget,
            allow_higher_budget=budget > 32 * 1024,
            output_format=output_format,
            authority_mode=authority_mode,
        ),
    )
    if domain_only and not explicit_domain:
        raise ValueError("domain_only retrieval requires an explicit selected domain")
    receipt_domain = explicit_domain if domain_only else None
    if authority_mode != "authoritative" or ontology_partitions is not None:
        contract = "\0".join((authority_mode, *(ontology_partitions or ())))
        receipt_domain = "query-" + hashlib.sha256(contract.encode("utf-8")).hexdigest()[:16]
    if not refresh:
        pending, delivered = receipts._paths(safe_session, snapshot_id, receipt_domain)
        if delivered.exists():
            return {"status": "already_delivered", "snapshot_id": snapshot_id, "payload": "", "selected_ids": []}
        if pending.exists():
            cached = receipts._decode_prepared(pending)
            return cached
    result = engine.retrieve(
        snapshot_id=snapshot_id, query=prompt, selected_domain=explicit_domain,
        ontology_partitions=ontology_partitions, authority_mode=authority_mode,
    )
    # Jev is strictly opt-in and fail-open. The deterministic result above is
    # retained for every missing-key, network, parse, or timeout failure.
    if selector_config and selector_config.get("mode") == "jev" and prompt:
        jev = selector_config.get("jev", {})
        picks = JevSelector(
            endpoint=jev.get("endpoint", "https://openrouter.ai/api/alpha/decisions"),
            model=jev.get("model", "typesafe/jev-1.13"),
            api_key_env=jev.get("api_key_env", "OPENROUTER_API_KEY"),
        ).select(prompt, tuple(item for item in source.retrieval_candidates(snapshot_id) if item.record_id in set(result.selected_ids) or True), top=jev.get("top", 20), floor=jev.get("score_floor", 0.55), timeout=jev.get("timeout_seconds", 3), prefilter_keep=jev.get("prefilter_keep", 150))
        if picks:
            chosen = {item.record_id: (item, score, rank) for rank, (item, score) in enumerate(picks, 1)}
            lines = []
            for item, score, rank in (chosen[key] for key in chosen):
                lines.append(f"- {item.ontology_type} ({item.provenance_status}; Jev score={score:.3f}, rank={rank}): {item.text}")
            result = result.__class__(payload="\n".join(lines).encode() + b"\n", selected_ids=tuple(chosen), eligible_count=result.eligible_count, omitted_count=max(0, result.eligible_count-len(chosen)), selected_bytes=len("\n".join(lines).encode())+1, budget_bytes=result.budget_bytes, section_bytes=result.section_bytes, tokenizer_version=result.tokenizer_version, authority_mode=result.authority_mode, requested_partitions=result.requested_partitions, selected_by_partition=result.selected_by_partition)
    response: dict[str, object] = {
        "status": "delivered",
        "snapshot_id": snapshot_id,
        "payload": result.payload.decode("utf-8"),
        "selected_ids": list(result.selected_ids),
        "selected_bytes": result.selected_bytes,
        "budget_bytes": result.budget_bytes,
        "eligible_count": result.eligible_count,
        "omitted_count": result.omitted_count,
        "section_bytes": result.section_bytes,
        "tokenizer_version": result.tokenizer_version,
        "authority_mode": result.authority_mode,
        "requested_partitions": list(result.requested_partitions),
        "selected_by_partition": {
            partition: list(ids) for partition, ids in result.selected_by_partition.items()
        },
        "receipt_scope": receipt_domain,
    }
    if refresh:
        return response
    state, cached = receipts.prepare_delivery(
        safe_session, snapshot_id, receipt_domain, response,
    )
    if state == "delivered":
        return {"status": "already_delivered", "snapshot_id": snapshot_id, "payload": "", "selected_ids": []}
    assert cached is not None
    return cached


def commit_payload_delivery(
    *, root: Path, session_id: str, snapshot_id: str, domain_id: str | None = None,
) -> bool:
    """Commit a prepared delivery only after its caller flushed the payload."""
    safe_session = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:24]
    return DeliveryReceipts(Path(root) / "receipts").commit_delivery(
        safe_session, snapshot_id, domain_id,
    )

__all__ = [
    "BUSINESS_DECLARED_PARTITION",
    "BUSINESS_OBSERVED_PARTITION",
    "commit_payload_delivery",
    "AuthorityMode",
    "DeliveryReceipts",
    "JUDGMENT_PARTITION",
    "ONTOLOGY_PARTITIONS",
    "RetrievalConfig",
    "RetrievalEngine",
    "RetrievalRecord",
    "RetrievalResult",
    "SELF_MODEL_PARTITION",
    "StoreRetrievalSource",
    "retrieve_payload",
]
