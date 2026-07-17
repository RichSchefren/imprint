"""Ontology validation and transition contracts.

Raw capture has exactly one canonical validator, owned by ``imprint.capture``.
This package exposes graph/provenance helpers only, preventing a second raw
schema from silently diverging from the persist-first boundary.
"""

from .contracts import (
    NODE_TYPES, RELATION_REGISTRY, validate_node_contract,
    validate_node_payload, validate_relation_contract,
)
from .schema import make_urn, validate_provenance
from .registries import compile_registry_bundle
from .validators import validate_core_payload, validate_provenance_v2_1
from .producer_coverage import producer_coverage

__all__ = [
    "NODE_TYPES", "RELATION_REGISTRY", "make_urn", "validate_node_contract",
    "validate_node_payload", "validate_provenance", "validate_relation_contract",
    "compile_registry_bundle",
    "validate_core_payload", "validate_provenance_v2_1", "producer_coverage",
]
