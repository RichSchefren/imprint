from copy import deepcopy

import pytest

from imprint.capture.schema import build_capture_envelope, new_urn, validate_capture_envelope
from imprint.errors import ValidationError


def envelope(**overrides):
    args = dict(
        operator_id=new_urn("operator"), session_id=new_urn("session"), node_id="node-alpha",
        case_description="A synthetic draft used the first layout.",
        raw_operator_text="Use the second layout instead because it is easier to scan.",
        call_type="correct", capture_mechanism="explicit_cli", captured_by="test-hook/3.0.0",
        reason="it is easier to scan", reason_status="supplied",
        chosen_alternatives=["second layout"], rejected_alternatives=["first layout"],
    )
    args.update(overrides)
    return build_capture_envelope(**args)


def test_complete_raw_objects_and_alternatives_survive_validation():
    value = envelope()
    checked = validate_capture_envelope(value)
    assert checked == value and checked is not value
    assert {x["disposition"] for x in checked["alternatives"]} == {"chosen", "rejected"}
    assert checked["verdict"]["chosen_alternative_ids"] == [checked["alternatives"][0]["alternative_id"]]
    assert checked["provenance"]["status"] == "captured"
    assert checked["provenance"]["model"] is None
    assert checked["evidence"][0]["content"] == checked["verdict"]["raw_operator_text"]


def test_null_reason_is_honest_and_not_fabricated():
    value = envelope(reason=None, reason_status="pending")
    assert value["verdict"]["reason"] is None
    with pytest.raises(ValidationError, match="cannot be null"):
        envelope(reason=None, reason_status="supplied")


@pytest.mark.parametrize("mutation, message", [
    (lambda x: x.update(extra="closed"), "unknown top-level"),
    (lambda x: x["evidence"][0].update(content="tampered"), "hash mismatch"),
    (lambda x: x["provenance"].update(status="ratified"), "non-authoritative candidate"),
    (lambda x: x["verdict"]["chosen_alternative_ids"].clear(), "unreferenced alternative"),
])
def test_malformed_or_provenance_corrupt_envelope_fails_closed(mutation, message):
    value = deepcopy(envelope())
    mutation(value)
    with pytest.raises(ValidationError, match=message):
        validate_capture_envelope(value)


def test_namespaced_extension_round_trips_without_aliasing():
    ext = {"org.example.synthetic": {"schema_version": "1.0.0", "payload": {"flag": True}}}
    value = envelope(extensions=ext)
    ext["org.example.synthetic"]["payload"]["flag"] = False
    assert value["extensions"]["org.example.synthetic"]["payload"]["flag"] is True


def test_oversized_operator_input_is_rejected():
    with pytest.raises(ValidationError, match="oversized"):
        envelope(raw_operator_text="x" * (256 * 1024 + 1))
