"""Conservative deterministic explicit-feedback candidate gate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher


@dataclass(frozen=True)
class FeedbackDetection:
    is_feedback: bool
    route: str
    call_type: str | None
    marker: str | None
    confidence: float


_RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("refusal", "reject", "rejection", re.compile(r"\b(?:i reject|reject (?:this|that|it))\b", re.I)),
    ("refusal", "refuse", "refusal", re.compile(r"\b(?:do not|don't|won't)\s+(?:use|include|change|send|publish|do|make)|\b(?:i refuse|no thanks|stop (?:using|doing))\b", re.I)),
    ("preference", "prefer", "preference", re.compile(
        r"\b(?:i prefer|my preference is|favor .+ over"
        r"|(?:i'd|i would) rather\s+(?:use|keep|remove|restore|change|make|publish|send|write))\b", re.I,
    )),
    ("approval", "accept", "approval", re.compile(
        r"(?:^|[.!?]\s*)(?:approved|ship it)(?:[.!?]|$)"
        r"|\b(?:that's right|that is right|(?:this|that|it) is exactly right"
        r"|(?:this|that|it) looks good|this is the one[.!?]*$)\b", re.I,
    )),
    ("standard", "correct", "standard", re.compile(
        r"\b(?:(?:always|never)\s+(?:use|include|remove|change|keep|do|say|write|preserve|avoid)"
        r"|(?:we|you) must\s+(?:use|include|remove|change|keep|do|say|write|preserve|avoid)"
        r"|(?:this|that) must\s+(?:be|use|include|keep|preserve|avoid)"
        r")\b", re.I,
    )),
    ("correction", "correct", "direct", re.compile(
        r"(?:^|[.!?]\s*)(?:no[,.:]|wrong\b|incorrect\b)"
        r"|\b(?:(?:this|that|it) is wrong|that's wrong|not .+[,;:]? (?:use|make|keep)"
        r"|(?:use|make|keep|remove|restore|change)\s+.+\s+instead\b"
        r"|instead[,;:]?\s+(?:use|make|keep|remove|restore|change)\b"
        r"|change (?:it|that|this)|you (?:missed|changed|removed|added))\b", re.I,
    )),
    ("correction", "correct", "question_form", re.compile(r"\b(?:why did you\s+(?:remove|change|add|omit|replace|rewrite)|shouldn't (?:it|this|that)|wouldn't (?:it|this|that) be|can you (?:change|restore|remove|keep)|could you (?:change|restore|remove|keep))\b", re.I)),
    ("correction", "correct", "indirect", re.compile(r"(?:^|[.!?]\s*)not quite\b|\b(?:this feels (?:too|like)|it would be better|what i (?:meant|was looking for)|this isn't landing|this is not landing)\b", re.I)),
)
_POLITE_EDIT = re.compile(r"\b(?:please|could you|would you)\b.*\b(?:change|use|make|keep|remove|restore|avoid|don't)\b", re.I)
_WEAK_REVIEW = re.compile(
    r"(?:^|[.!?]\s*)perfect[.!?]*$|\b(?:needs? to|instead|the standard is|our rule is)\b", re.I,
)


def _normalize(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def detect_explicit_feedback(
    operator_text: str,
    *,
    prior_operator_text: str | None = None,
    prior_assistant_output: str | None = None,
) -> FeedbackDetection:
    """Detect feedback forms without treating silence or ordinary questions as calls."""
    if not isinstance(operator_text, str) or not operator_text.strip():
        return FeedbackDetection(False, "non_feedback", None, None, 1.0)
    for route, call_type, marker, pattern in _RULES:
        if pattern.search(operator_text):
            return FeedbackDetection(True, route, call_type, marker, 0.99)
    if prior_assistant_output and _POLITE_EDIT.search(operator_text):
        return FeedbackDetection(True, "correction", "correct", "polite", 0.96)
    if prior_assistant_output and prior_operator_text:
        current, prior = _normalize(operator_text), _normalize(prior_operator_text)
        if current and prior:
            ratio = SequenceMatcher(None, prior, current).ratio()
            shared = len(set(current.split()) & set(prior.split())) / max(1, len(set(prior.split())))
            if ratio >= 0.88 or (ratio >= 0.72 and shared >= 0.8):
                return FeedbackDetection(True, "correction", "correct", "silent_reask", round(max(ratio, shared), 3))
    if _WEAK_REVIEW.search(operator_text):
        # Ambiguous lexical hints never enter canonical memory.  The route is
        # explicit so a future review queue can consume them without changing
        # this precision boundary.
        return FeedbackDetection(False, "review_candidate", None, "weak_lexical_hint", 0.55)
    return FeedbackDetection(False, "non_feedback", None, None, 0.99)
