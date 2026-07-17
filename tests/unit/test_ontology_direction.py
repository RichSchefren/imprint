import pytest

from imprint.errors import ValidationError
from imprint.ontology.direction import (
    DIRECTION_NODE_TYPES,
    partition_direction_records,
    validate_direction_payload,
)


def test_public_core_registers_no_private_direction_semantics():
    assert DIRECTION_NODE_TYPES == frozenset()
    with pytest.raises(ValidationError, match="separately installed namespaced extension"):
        validate_direction_payload(
            "vendor.private.DirectionRecord",
            {"schema_id": "vendor.private.direction/1"},
            {"status": "inferred"},
        )


def test_public_core_refuses_nonempty_private_direction_partitions():
    assert partition_direction_records([]) == {}
    with pytest.raises(ValidationError, match="separately installed namespaced extension"):
        partition_direction_records([
            ("vendor.private.DirectionRecord", {"schema_id": "vendor.private.direction/1"})
        ])
