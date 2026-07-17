from __future__ import annotations

import uuid

import pytest

from imprint.capture.schema import new_urn
from imprint.errors import ValidationError
from imprint.ontology.contracts import require_urn as require_contract_urn
from imprint.urn import make_urn, require_urn


def test_all_public_urn_surfaces_share_canonical_uuid4_contract():
    value = new_urn("verdict")
    assert require_urn(value, "verdict") == value
    assert require_contract_urn(value, "verdict", "verdict_id") == value
    assert uuid.UUID(value.rsplit(":", 1)[1]).version == 4


@pytest.mark.parametrize(
    "value",
    [
        "urn:imprint:event:550E8400-E29B-41D4-A716-446655440000",
        f"urn:imprint:event:{uuid.uuid1()}",
        "urn:imprint:Event:550e8400-e29b-41d4-a716-446655440000",
        "urn:imprint:event:550e8400-e29b-41d4-a716-446655440000:extra",
    ],
)
def test_canonical_urn_validator_rejects_aliases_and_non_uuid4(value):
    with pytest.raises(ValidationError):
        require_urn(value, "event")


def test_urn_kind_is_closed_and_typed():
    with pytest.raises(ValidationError):
        make_urn("Bad Kind")
    with pytest.raises(ValidationError):
        require_urn(make_urn("case"), "verdict")
