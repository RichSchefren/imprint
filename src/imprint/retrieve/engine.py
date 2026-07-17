"""Eligibility, stable ranking, and byte-exact context compilation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, Sequence

from .models import (
    ONTOLOGY_PARTITIONS,
    AuthorityMode,
    RetrievalConfig,
    RetrievalRecord,
    RetrievalResult,
    RetrievalSource,
)
from .tokenizer import TOKENIZER_VERSION, lexical_score

DEFAULT_BUDGET = 32 * 1024
MAX_EXPLICIT_BUDGET = 128 * 1024
_BASE_WEIGHTS = {"core": 1, "general": 2, "domain": 1}
_DIRECT_AUTHORITY = {"captured": 0, "ratified": 0, "extracted": 1}
_TIER_ORDER = {
    "captured_judgment": 0,
    "ratified_knowledge": 0,
    "imported_floor": 2,
}
_ANALYTICAL_TIERS = {"inferred_candidate", "observed_candidate"}


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _recency_bucket(value: str) -> int:
    # Day buckets are deterministic and avoid wall-clock-dependent ranking.
    return int(_parse_time(value).timestamp() // 86400)


def eligible(
    record: RetrievalRecord,
    selected_domain: str | None,
    authority_mode: AuthorityMode = "authoritative",
) -> bool:
    if not record.current or record.rejected or record.tombstoned or record.valid_until is not None:
        return False
    if not record.provenance_complete or not record.evidence_ids:
        return False
    if authority_mode not in {"authoritative", "analytical"}:
        return False
    authoritative = authority_mode == "authoritative"
    allowed_statuses = {"captured", "extracted", "ratified"}
    if not authoritative:
        allowed_statuses.add("inferred")
    if record.provenance_status not in allowed_statuses:
        return False
    allowed_tiers = {
        "captured_judgment",
        "ratified_knowledge",
        "imported_floor",
    }
    if not authoritative:
        allowed_tiers.update(_ANALYTICAL_TIERS)
    if record.authority_tier not in allowed_tiers:
        return False
    if record.authority_tier == "captured_judgment" and record.provenance_status != "captured":
        return False
    if (
        record.provenance_status == "captured"
        and record.ontology_partition != "business_declared"
        and not record.case_ids
    ):
        return False
    if record.authority_tier == "ratified_knowledge" and record.provenance_status != "ratified":
        return False
    if record.authority_tier == "imported_floor" and not record.imported_selected:
        return False
    if record.provenance_status == "inferred" and record.authority_tier != "inferred_candidate":
        return False
    if record.authority_tier == "observed_candidate" and record.provenance_status != "extracted":
        return False
    if record.ontology_partition == "self_model" and authoritative:
        if record.ontology_type != "SelfModelAssertion" or record.provenance_status != "ratified":
            return False
    if record.section == "domain" and (selected_domain is None or record.domain_id != selected_domain):
        return False
    if record.domain_id is not None and record.section != "domain":
        # Domain-bound material cannot escape through a general section label.
        return False
    return True


def _rank_key(record: RetrievalRecord, query: str, selected_domain: str | None, version: str) -> tuple:
    exact_domain = selected_domain is not None and record.domain_id == selected_domain
    return (
        -int(record.pinned),
        -int(exact_domain),
        -lexical_score(query, record.text, version=version),
        _DIRECT_AUTHORITY.get(record.provenance_status, 9),
        _TIER_ORDER.get(record.authority_tier, 9),
        -max(0, record.recurrence_count),
        -_recency_bucket(record.valid_from),
        record.record_id.encode("utf-8"),
    )


def _section_limits(total: int) -> dict[str, int]:
    # Preserve the frozen 1:2:1 split for lower and explicitly higher budgets.
    unit, remainder = divmod(total, 4)
    limits = {"core": unit, "general": unit * 2, "domain": unit}
    # Deterministic remainder allocation follows the downward flow order.
    for name in ("core", "general", "domain")[:remainder]:
        limits[name] += 1
    return limits


def _render_audit(record: RetrievalRecord) -> bytes:
    authority = "imported_floor" if record.authority_tier == "imported_floor" else record.provenance_status
    value = {
        "authority": authority,
        "case_ids": list(record.case_ids),
        "case_referents": list(record.case_referents),
        "evidence_ids": list(record.evidence_ids),
        "ontology": {
            "confidence": record.confidence,
            "disclosure": record.disclosure,
            "partition": record.ontology_partition,
            "path": list(record.ontology_path),
            "type": record.ontology_type,
        },
        "record_id": record.record_id,
        "source_receipt_ids": list(record.source_receipt_ids),
        "text": record.text,
    }
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _render_compact(record: RetrievalRecord) -> bytes:
    """Render useful context, not an internal graph serialization."""
    authority = "imported" if record.authority_tier == "imported_floor" else record.provenance_status
    kind = record.ontology_type if record.ontology_type != "LegacyRecord" else "Judgment"
    parts = [f"- {kind} ({authority}): {_one_line(record.text)}"]
    if record.case_referents:
        parts.append("Case: " + " / ".join(_one_line(value) for value in record.case_referents))
    return (" | ".join(parts) + "\n").encode("utf-8")


def _render(record: RetrievalRecord, output_format: str) -> bytes:
    if output_format == "audit":
        return _render_audit(record)
    return _render_compact(record)


class RetrievalEngine:
    def __init__(self, source: RetrievalSource, config: RetrievalConfig | None = None):
        self.source = source
        self.config = config or RetrievalConfig()
        self._validate_config()

    def _validate_config(self) -> None:
        budget = self.config.total_budget_bytes
        if budget <= 0:
            raise ValueError("retrieval budget must be positive")
        if budget > DEFAULT_BUDGET and not self.config.allow_higher_budget:
            raise ValueError("higher retrieval budget requires explicit opt-in")
        if budget > MAX_EXPLICIT_BUDGET:
            raise ValueError("retrieval budget exceeds explicit hard bound")
        if self.config.tokenizer_version != TOKENIZER_VERSION:
            raise ValueError("unsupported tokenizer version")
        if self.config.authority_mode not in {"authoritative", "analytical"}:
            raise ValueError("unsupported retrieval authority mode")
        if self.config.output_format not in {"compact", "audit"}:
            raise ValueError("unsupported retrieval output format")

    @staticmethod
    def _partitions(
        requested: Sequence[str] | None,
        authority_mode: AuthorityMode,
    ) -> tuple[str, ...]:
        if requested is None:
            if authority_mode == "analytical":
                raise ValueError("analytical retrieval requires explicit ontology partitions")
            return ()
        if isinstance(requested, str):
            raise ValueError("ontology_partitions must be a sequence of partition names")
        partitions = tuple(dict.fromkeys(requested))
        if authority_mode == "analytical" and not partitions:
            raise ValueError("analytical retrieval requires explicit ontology partitions")
        unknown = set(partitions) - ONTOLOGY_PARTITIONS
        if unknown:
            raise ValueError(f"unsupported ontology partitions: {sorted(unknown)}")
        return partitions

    def retrieve(
        self,
        *,
        snapshot_id: str,
        query: str = "",
        selected_domain: str | None = None,
        ontology_partitions: Sequence[str] | None = None,
        authority_mode: AuthorityMode | None = None,
    ) -> RetrievalResult:
        mode = authority_mode or self.config.authority_mode
        if mode not in {"authoritative", "analytical"}:
            raise ValueError("unsupported retrieval authority mode")
        partitions = self._partitions(ontology_partitions, mode)
        candidates = [
            item for item in self.source.retrieval_candidates(snapshot_id)
            if eligible(item, selected_domain, mode)
            and (not partitions or item.ontology_partition in partitions)
        ]
        candidates.sort(
            key=lambda item: _rank_key(
                item, query, selected_domain, self.config.tokenizer_version
            )
        )
        by_section: dict[str, list[RetrievalRecord]] = {"core": [], "general": [], "domain": []}
        for item in candidates:
            by_section[item.section].append(item)

        limits = _section_limits(self.config.total_budget_bytes)
        carry = 0
        selected: list[tuple[str, bytes]] = []
        section_bytes: dict[str, int] = {"core": 0, "general": 0, "domain": 0}
        for section in ("core", "general", "domain"):
            available = limits[section] + carry
            for item in by_section[section]:
                rendered = _render(item, self.config.output_format)
                if len(rendered) <= available - section_bytes[section]:
                    selected.append((item.record_id, rendered))
                    section_bytes[section] += len(rendered)
            carry = available - section_bytes[section]

        payload = b"".join(value for _, value in selected)
        if len(payload) > self.config.total_budget_bytes:  # defensive invariant
            raise RuntimeError("retrieval budget invariant violated")
        selected_ids = tuple(record_id for record_id, _ in selected)
        selected_set = set(selected_ids)
        selected_by_partition: dict[str, tuple[str, ...]] = {}
        for item in candidates:
            if item.record_id in selected_set:
                selected_by_partition.setdefault(item.ontology_partition, tuple())
                selected_by_partition[item.ontology_partition] += (item.record_id,)
        return RetrievalResult(
            payload=payload,
            selected_ids=selected_ids,
            eligible_count=len(candidates),
            omitted_count=len(candidates) - len(selected_ids),
            selected_bytes=len(payload),
            budget_bytes=self.config.total_budget_bytes,
            section_bytes=section_bytes,
            tokenizer_version=self.config.tokenizer_version,
            authority_mode=mode,
            requested_partitions=partitions,
            selected_by_partition=selected_by_partition,
        )
