"""Evidence-first explicit-feedback capture."""

from .detector import FeedbackDetection, detect_explicit_feedback
from .pipeline import CapturePipeline, CaptureResult
from .schema import build_capture_envelope, validate_capture_envelope
from .transcript import parse_native_stop_transcript

__all__ = [
    "CapturePipeline",
    "CaptureResult",
    "FeedbackDetection",
    "build_capture_envelope",
    "detect_explicit_feedback",
    "validate_capture_envelope",
    "parse_native_stop_transcript",
]
