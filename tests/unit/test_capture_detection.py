import pytest

from imprint.capture.detector import detect_explicit_feedback


@pytest.mark.parametrize("text, marker, route", [
    ("No, use the compact synthetic card.", "direct", "correction"),
    ("Why did you remove the neutral heading?", "question_form", "correction"),
    ("This is not landing; it feels too broad.", "indirect", "correction"),
    ("I prefer the neutral version over the ornate one.", "preference", "preference"),
    ("We must keep source references on every claim.", "standard", "standard"),
    ("Approved. Ship it.", "approval", "approval"),
    ("I reject this synthetic draft.", "rejection", "refusal"),
    ("Do not publish that synthetic example.", "refusal", "refusal"),
])
def test_explicit_feedback_forms(text, marker, route):
    result = detect_explicit_feedback(text, prior_assistant_output="synthetic output")
    assert result.is_feedback and result.marker == marker and result.route == route


def test_polite_feedback_requires_prior_output():
    text = "Please keep the second heading and remove the first."
    assert detect_explicit_feedback(text).is_feedback is False
    assert detect_explicit_feedback(text, prior_assistant_output="a draft").marker == "polite"


def test_silent_reask_is_an_operator_reask_not_silence():
    result = detect_explicit_feedback(
        "Create a concise neutral summary with source labels.",
        prior_operator_text="Create a concise neutral summary with source labels",
        prior_assistant_output="an unrelated output",
    )
    assert result.is_feedback and result.marker == "silent_reask"
    assert detect_explicit_feedback("", prior_assistant_output="anything").is_feedback is False


@pytest.mark.parametrize("text", [
    "What time is the synthetic review?", "I don't know the answer.",
    "I have never visited that place.", "Could you create a new summary?",
    "Thanks for the update.", "No idea where the fixture lives.",
])
def test_negative_controls(text):
    assert detect_explicit_feedback(text).is_feedback is False


@pytest.mark.parametrize("text", [
    "The quarterly report needs to go to finance.",
    "We must leave for the airport by six.",
    "Perfect.",
    "I used the other entrance instead.",
    "This needs to happen before lunch.",
    "The server must restart after patching.",
    "Instead of coffee, I ordered tea.",
    "My passport needs to be renewed.",
    "It must be raining downtown.",
    "The invoice needs to include tax.",
])
def test_mundane_working_messages_do_not_enter_canonical_feedback(text):
    assert detect_explicit_feedback(text, prior_assistant_output="a prior answer").is_feedback is False


def test_ambiguous_lexical_hint_routes_to_review_without_canonical_capture():
    result = detect_explicit_feedback("This needs to be ready tomorrow.")
    assert result.is_feedback is False
    assert result.route == "review_candidate"
    assert result.confidence < 0.8
