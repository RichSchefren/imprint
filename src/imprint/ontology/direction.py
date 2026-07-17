"""Boundary for optional, separately distributed direction extensions.

The public Imprint core does not define a model of a person's future,
aspirations, trade-offs, or comparative direction. Those semantics belong in
an independently installed, namespaced extension with its own disclosure,
versioning, and authority review. Keeping this module as a closed boundary
lets callers fail clearly instead of silently accepting private or opaque
schemas as core Imprint knowledge.
"""

from __future__ import annotations

from typing import Any, Iterable

from imprint.errors import ValidationError


# No direction semantics are registered by the public core.
DIRECTION_NODE_TYPES: frozenset[str] = frozenset()


def validate_direction_payload(
    node_type: str,
    payload: Any,
    provenance: Any,
) -> dict[str, Any]:
    """Reject direction records until a namespaced extension is installed."""
    del node_type, payload, provenance
    raise ValidationError(
        "direction semantics require a separately installed namespaced extension"
    )


def partition_direction_records(
    records: Iterable[tuple[str, dict[str, Any]]],
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Refuse private direction records; an empty public-core input is valid."""
    if any(True for _ in records):
        raise ValidationError(
            "direction semantics require a separately installed namespaced extension"
        )
    return {}
