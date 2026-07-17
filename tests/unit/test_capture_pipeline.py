import pytest

from imprint.capture.pipeline import CapturePersistenceError, CapturePipeline
from imprint.capture.durability import reset_stop_capture_phase, stop_capture_is_durable
from imprint.capture.schema import new_urn


BASE = dict(
    operator_id=new_urn("operator"), session_id=new_urn("session"), node_id="node-beta",
    capture_mechanism="claude_code_stop_hook", captured_by="fixture-hook/3.0.0",
)


class Spool:
    def __init__(self, log, fail=False): self.log, self.fail = log, fail
    def persist(self, envelope):
        self.log.append(("persist", envelope["input_event_id"]))
        if self.fail: raise OSError("synthetic disk failure")
        return "receipt"


class Proposer:
    def __init__(self, log, fail=False): self.log, self.fail = log, fail
    def propose(self, envelope, detection):
        self.log.append(("propose", envelope["input_event_id"]))
        if self.fail: raise RuntimeError("synthetic classifier failure")
        return {"route": detection.route}


def test_raw_spool_always_precedes_proposal():
    log = []
    result = CapturePipeline(Spool(log), proposer=Proposer(log)).capture(
        operator_text="No, use the second synthetic option.", case_description="A draft used option one.", **BASE,
    )
    assert result.persisted and result.receipt == "receipt"
    assert [stage for stage, _ in log] == ["persist", "propose"]


def test_successful_spool_marks_confirmed_durable_publication():
    reset_stop_capture_phase()
    result = CapturePipeline(Spool([])).capture(
        operator_text="No, use the second synthetic option.",
        case_description="A draft used option one.", **BASE,
    )
    assert result.persisted is True
    assert stop_capture_is_durable() is True


def test_classification_failure_retains_raw_capture_and_logs_content_free():
    calls, failures = [], []
    result = CapturePipeline(Spool(calls), proposer=Proposer(calls, fail=True), failure_logger=failures.append).capture(
        operator_text="I prefer the second synthetic option.", case_description="Two options were offered.", **BASE,
    )
    assert result.persisted and result.envelope is not None
    assert result.derivation_error == "RuntimeError"
    assert failures == [{"stage": "proposal", "error_type": "RuntimeError", "input_event_id": result.envelope["input_event_id"], "content_included": False}]


def test_spool_failure_aborts_proposal_and_is_explicit():
    calls, failures = [], []
    reset_stop_capture_phase()
    with pytest.raises(CapturePersistenceError):
        CapturePipeline(Spool(calls, fail=True), proposer=Proposer(calls), failure_logger=failures.append).capture(
            operator_text="Approved. Ship it.", case_description="A synthetic draft was reviewed.", **BASE,
        )
    assert [stage for stage, _ in calls] == ["persist"]
    assert failures[0]["content_included"] is False
    assert stop_capture_is_durable() is False


def test_non_feedback_is_not_spooled():
    calls = []
    result = CapturePipeline(Spool(calls)).capture(
        operator_text="What time is the review?", case_description="Scheduling question.", **BASE,
    )
    assert not result.persisted and calls == []
