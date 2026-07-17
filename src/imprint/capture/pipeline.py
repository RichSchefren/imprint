"""Persist-first capture orchestration with injected storage and proposal ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from imprint.errors import ImprintError

from .detector import FeedbackDetection, detect_explicit_feedback
from .durability import mark_stop_capture_persisted, mark_stop_capture_persisting
from .schema import build_capture_envelope


class CapturePersistenceError(ImprintError):
    """Raw explicit feedback could not be durably spooled."""


class RawSpool(Protocol):
    def persist(self, envelope: Mapping[str, Any]) -> Any: ...


class ProposalProducer(Protocol):
    def propose(self, envelope: Mapping[str, Any], detection: FeedbackDetection) -> Mapping[str, Any]: ...


FailureLogger = Callable[[Mapping[str, Any]], None]


@dataclass(frozen=True)
class CaptureResult:
    detection: FeedbackDetection
    persisted: bool
    envelope: Mapping[str, Any] | None = None
    receipt: Any = None
    proposal: Mapping[str, Any] | None = None
    derivation_error: str | None = None


class CapturePipeline:
    """Guarantee persistence precedes every optional classification/model call."""

    def __init__(self, spool: RawSpool, *, proposer: ProposalProducer | None = None, failure_logger: FailureLogger | None = None):
        self._spool = spool
        self._proposer = proposer
        self._failure_logger = failure_logger or (lambda _: None)

    def capture(self, *, operator_text: str, case_description: str, prior_operator_text: str | None = None, prior_assistant_output: str | None = None, **envelope_fields: Any) -> CaptureResult:
        detection = detect_explicit_feedback(
            operator_text,
            prior_operator_text=prior_operator_text,
            prior_assistant_output=prior_assistant_output,
        )
        if not detection.is_feedback:
            return CaptureResult(detection=detection, persisted=False)
        envelope = build_capture_envelope(
            raw_operator_text=operator_text,
            case_description=case_description,
            call_type=detection.call_type,
            **envelope_fields,
        )
        try:
            mark_stop_capture_persisting()
            receipt = self._spool.persist(envelope)
            mark_stop_capture_persisted()
        except Exception as exc:
            self._failure_logger({
                "stage": "raw_spool", "error_type": type(exc).__name__,
                "input_event_id": envelope["input_event_id"], "content_included": False,
            })
            raise CapturePersistenceError("explicit feedback was not durably spooled; derivation aborted") from exc
        if self._proposer is None:
            return CaptureResult(detection=detection, persisted=True, envelope=envelope, receipt=receipt)
        try:
            proposal = self._proposer.propose(envelope, detection)
        except Exception as exc:
            self._failure_logger({
                "stage": "proposal", "error_type": type(exc).__name__,
                "input_event_id": envelope["input_event_id"], "content_included": False,
            })
            return CaptureResult(
                detection=detection, persisted=True, envelope=envelope, receipt=receipt,
                derivation_error=type(exc).__name__,
            )
        return CaptureResult(detection=detection, persisted=True, envelope=envelope, receipt=receipt, proposal=proposal)
