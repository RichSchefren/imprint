from imprint.capture.detector import FeedbackDetection
from imprint.capture.schema import build_capture_envelope, new_urn
from imprint.derive.cold_start import finished_deliverable_decision, mark_progress_once
from imprint.derive.orchestrator import ProposalOrchestrator, ReferenceDerivationInvoker
from imprint.derive.proposals import route_capture_to_proposal


def envelope():
    return build_capture_envelope(
        operator_id=new_urn("operator"), session_id=new_urn("session"), node_id="node-delta",
        case_description="A synthetic decision.", raw_operator_text="No, keep the source label.", call_type="correct",
        capture_mechanism="explicit_cli", captured_by="boundary/3.0.0",
    )


class Agent:
    def __init__(self, log, name): self.log, self.name = log, name
    def propose(self, task):
        self.log.append(self.name)
        base = task.get("proposal")
        if base is not None:
            return base
        source = CURRENT[0]
        return route_capture_to_proposal(source, FeedbackDetection(True, "correction", "correct", "direct", 1.0), proposer=self.name)


class Writer:
    def __init__(self, log): self.log = log
    def submit_proposal(self, proposal): self.log.append("writer"); return proposal["proposal_id"]


CURRENT = []


def test_recorder_judge_writer_order_is_enforced():
    log, value = [], envelope()
    CURRENT[:] = [value]
    receipt = ProposalOrchestrator(Agent(log, "recorder"), Agent(log, "judge"), Writer(log)).run(value)
    assert log == ["recorder", "judge", "writer"] and receipt.startswith("urn:imprint:proposal:")


def test_shipped_reference_deriver_is_deterministic_and_writes_one_proposal():
    log, value = [], envelope()
    proposal_id = ReferenceDerivationInvoker(Writer(log)).run(value)
    assert proposal_id.startswith("urn:imprint:proposal:")
    assert log == ["writer"]


def test_finished_deliverables_are_refused():
    assert not finished_deliverable_decision(lifecycle_status="published").accepted
    assert not finished_deliverable_decision(lifecycle_status=None, immutable=True).accepted
    assert finished_deliverable_decision(lifecycle_status="draft").accepted


class MemoryProgress:
    def __init__(self): self.keys = set()
    def contains(self, key): return key in self.keys
    def add(self, key): self.keys.add(key)


def test_progress_marker_is_idempotent():
    store = MemoryProgress()
    assert mark_progress_once(store, "urn:synthetic:source", b"same") is True
    assert mark_progress_once(store, "urn:synthetic:source", b"same") is False
    assert mark_progress_once(store, "urn:synthetic:source", b"changed") is True
