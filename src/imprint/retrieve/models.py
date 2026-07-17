"""Closed public types for the retrieval boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol, Sequence

Section = Literal["core", "general", "domain"]
AuthorityMode = Literal["authoritative", "analytical"]
OutputFormat = Literal["compact", "audit"]

JUDGMENT_PARTITION = "judgment"
SELF_MODEL_PARTITION = "self_model"
BUSINESS_DECLARED_PARTITION = "business_declared"
BUSINESS_OBSERVED_PARTITION = "business_observed"

ONTOLOGY_PARTITIONS = frozenset({
    JUDGMENT_PARTITION,
    SELF_MODEL_PARTITION,
    BUSINESS_DECLARED_PARTITION,
    BUSINESS_OBSERVED_PARTITION,
})


@dataclass(frozen=True)
class RetrievalRecord:
    """One atomic candidate returned by a read-only store projection."""

    record_id: str
    text: str
    section: Section
    provenance_status: str
    authority_tier: str
    evidence_ids: tuple[str, ...]
    case_ids: tuple[str, ...] = ()
    case_referents: tuple[str, ...] = ()
    source_receipt_ids: tuple[str, ...] = ()
    domain_id: str | None = None
    pinned: bool = False
    recurrence_count: int = 0
    valid_from: str = "1970-01-01T00:00:00Z"
    current: bool = True
    rejected: bool = False
    tombstoned: bool = False
    valid_until: str | None = None
    # A store adapter must affirm this only after the canonical provenance validator passes.
    provenance_complete: bool = False
    imported_selected: bool = False
    # Additive ontology labels keep old source adapters compatible while making
    # every new semantic record self-describing at the retrieval boundary.
    ontology_partition: str = JUDGMENT_PARTITION
    ontology_type: str = "LegacyRecord"
    ontology_path: tuple[str, ...] = ()
    confidence: float | None = None
    disclosure: str = "authority_unclassified"


class RetrievalSource(Protocol):
    """Narrow store-facing protocol; implementations must be read-only."""

    def retrieval_candidates(self, snapshot_id: str) -> Sequence[RetrievalRecord]: ...


@dataclass(frozen=True)
class RetrievalConfig:
    total_budget_bytes: int = 32 * 1024
    allow_higher_budget: bool = False
    tokenizer_version: str = "lexical-v1"
    authority_mode: AuthorityMode = "authoritative"
    # Preserve the low-level engine's structured compatibility. Product-facing
    # retrieval explicitly selects compact output; audit callers select this.
    output_format: OutputFormat = "audit"


@dataclass(frozen=True)
class RetrievalResult:
    payload: bytes
    selected_ids: tuple[str, ...]
    eligible_count: int
    omitted_count: int
    selected_bytes: int
    budget_bytes: int
    section_bytes: dict[str, int] = field(default_factory=dict)
    tokenizer_version: str = "lexical-v1"
    authority_mode: AuthorityMode = "authoritative"
    requested_partitions: tuple[str, ...] = ()
    selected_by_partition: dict[str, tuple[str, ...]] = field(default_factory=dict)
