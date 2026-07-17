"""Recorder -> judge -> deterministic writer separation."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from imprint.capture.detector import FeedbackDetection

from .proposals import route_capture_to_proposal, validate_proposal


class ProposalAgent(Protocol):
    def propose(self, task_envelope: Mapping[str, Any]) -> Mapping[str, Any]: ...


class DeterministicProposalWriter(Protocol):
    def submit_proposal(self, proposal: Mapping[str, Any]) -> Any: ...


class ProposalOrchestrator:
    """Models propose and review; only injected validated code submits."""

    def __init__(self, recorder: ProposalAgent, judge: ProposalAgent, writer: DeterministicProposalWriter):
        self._recorder, self._judge, self._writer = recorder, judge, writer

    def run(self, captured_envelope: Mapping[str, Any]) -> Any:
        task = {
            "record_schema_version": captured_envelope["record_schema_version"],
            "source_input_event_id": captured_envelope["input_event_id"],
            "case": captured_envelope["case"],
            "verdict": captured_envelope["verdict"],
            "alternatives": captured_envelope["alternatives"],
            "evidence": captured_envelope["evidence"],
        }
        recorder_proposal = validate_proposal(self._recorder.propose(task))
        judge_task = {"record_schema_version": captured_envelope["record_schema_version"], "proposal": recorder_proposal}
        judged_proposal = validate_proposal(self._judge.propose(judge_task))
        return self._writer.submit_proposal(judged_proposal)


class ReferenceDerivationInvoker:
    """Shipped deterministic capture-to-Proposal path with no model dependency."""

    def __init__(self, writer: DeterministicProposalWriter):
        self._writer = writer

    def run(self, captured_envelope: Mapping[str, Any]) -> str:
        verdict = captured_envelope["verdict"]
        call_type = verdict["call"]["call_type"]
        route = {
            "correct": "correction", "prefer": "preference", "approve": "approval",
            "refuse": "refusal", "standard": "standard",
        }.get(call_type, "non_feedback")
        proposal = route_capture_to_proposal(
            captured_envelope,
            FeedbackDetection(
                route != "non_feedback", route, call_type,
                "deterministic_reference_deriver", 1.0,
            ),
            proposer="imprint-reference-deriver",
        )
        return str(self._writer.submit_proposal(proposal))
