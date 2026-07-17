from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from imprint.authority.challenge import (
    ChallengeRequest, build_challenge, canonical_bytes, validate_challenge_shape,
)
from imprint.errors import ValidationError


def base_request():
    return ChallengeRequest(
        operation_id="urn:imprint:operation:known-answer",
        purpose="known answer",
        payload_sha256=hashlib.sha256(b"payload").hexdigest(),
        prior_state_sha256="0" * 64,
        execution_fields_sha256=hashlib.sha256(b"{}").hexdigest(),
        authority_transition="captured_to_ratified",
    )


def test_rfc8785_known_answer_key_order_and_unicode():
    assert canonical_bytes({"z": "é", "a": 1}) == '{"a":1,"z":"é"}'.encode()


@pytest.mark.parametrize("ttl", [0, 121, True])
def test_challenge_rejects_invalid_ttl(ttl):
    with pytest.raises(ValidationError, match="TTL"):
        build_challenge(
            base_request(), operator_id="op", install_id="install", key_id="key",
            store_identity="store", ledger_sequence=1, ttl_seconds=ttl,
        )


def test_nonce_is_32_random_bytes_and_challenges_differ():
    kwargs = dict(
        operator_id="op", install_id="install", key_id="key", store_identity="store",
        ledger_sequence=1, clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    first = build_challenge(base_request(), **kwargs)
    second = build_challenge(base_request(), **kwargs)
    assert first["nonce"] != second["nonce"]
    validate_challenge_shape(first)


def test_unknown_challenge_field_fails_closed():
    value = build_challenge(
        base_request(), operator_id="op", install_id="install", key_id="key",
        store_identity="store", ledger_sequence=1,
    )
    value["caller_authority"] = "ratified"
    with pytest.raises(ValidationError, match="unknown or missing"):
        validate_challenge_shape(value)
