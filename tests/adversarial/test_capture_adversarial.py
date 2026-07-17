import pytest

from imprint.capture.schema import build_capture_envelope, new_urn, validate_capture_envelope
from imprint.errors import ValidationError


def base(**overrides):
    args = dict(
        operator_id=new_urn("operator"), session_id=new_urn("session"), node_id="safe-node",
        case_description="Synthetic case.", raw_operator_text="No, keep the neutral fixture.",
        call_type="correct", capture_mechanism="explicit_cli", captured_by="adversarial/3.0.0",
    )
    args.update(overrides)
    return args


@pytest.mark.parametrize("node", ["../escape", "UPPER", "a/b", "", "a" * 64])
def test_hostile_node_ids_fail(node):
    with pytest.raises(ValidationError, match="node_id"):
        build_capture_envelope(**base(node_id=node))


def test_non_uuid_stable_id_fails():
    value = build_capture_envelope(**base())
    value["input_event_id"] = "urn:imprint:event:not-a-uuid"
    with pytest.raises(ValidationError, match="invalid UUID"):
        validate_capture_envelope(value)


def test_evidence_cannot_point_to_uncited_object():
    value = build_capture_envelope(**base())
    value["case"]["source_refs"] = [new_urn("evidence")]
    with pytest.raises(ValidationError, match="unknown evidence"):
        validate_capture_envelope(value)
