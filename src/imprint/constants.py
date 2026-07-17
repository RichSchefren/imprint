"""Frozen public contracts for Imprint v3."""

from ._version import __version__

PRODUCT_VERSION = __version__
STORE_SCHEMA_VERSION = "3.0.0"
RECORD_SCHEMA_VERSION = "3.0.0"
# Versioned independently so semantic contracts can evolve without forcing a
# storage-engine migration.  Every semantic export/import must name this value.
ONTOLOGY_SCHEMA_VERSION = "3.1.0"
DEFAULT_CONTEXT_BUDGET = 32 * 1024
MAX_EVENT_BYTES = 1024 * 1024

PROVENANCE = frozenset({"captured", "extracted", "inferred", "ratified"})
AUTHORITY_TIERS = frozenset({
    "captured_judgment",
    "imported_floor",
    "observed_candidate",
    "inferred_candidate",
    "ratified_knowledge",
})
CALL_TYPES = frozenset({"accept", "reject", "correct", "prefer", "refuse"})
REASON_STATUSES = frozenset({"absent", "pending", "supplied", "later_added"})
