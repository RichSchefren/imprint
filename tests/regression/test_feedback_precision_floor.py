from __future__ import annotations

from imprint.capture.detector import detect_explicit_feedback


POSITIVE = (
    "No, use the compact card.",
    "Wrong. Keep the source label.",
    "I prefer the neutral version over the ornate version.",
    "I'd rather use the shorter headline.",
    "My preference is the evidence-first opening.",
    "Approved. Ship it.",
    "That is exactly right.",
    "This looks good.",
    "Ship it.",
    "I reject this draft.",
    "Do not publish that example.",
    "Never include an uncited number.",
    "Always cite a failed source.",
    "We must preserve the accepted label.",
    "You must use the verified total.",
    "This must be concise.",
    "Why did you remove the evidence note?",
    "Can you restore the original heading?",
    "It would be better with the proof first.",
    "Not quite; the conclusion is too broad.",
)

NEGATIVE = (
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
    "What time is the review?",
    "I have never visited Lisbon.",
    "The museum looks good from here.",
    "The shipping team approved the invoice.",
    "The train was exactly on time.",
    "The report includes a source label.",
    "We can use the north entrance.",
    "The package is not quite here yet.",
    "Why did you call yesterday?",
    "I would rather walk than wait for a cab.",
    "Our rule is printed on the old sign.",
    "The editor said the draft was wrong yesterday.",
    "She changed the appointment to noon.",
    "The release train stops using that platform in August.",
    "No idea where the fixture lives.",
    "This is the one train that runs overnight.",
    "The approval meeting starts at nine.",
    "The standard is stored in the policy binder.",
    "He rejected the package at the loading dock.",
    "The weather would be better tomorrow.",
)


def test_feedback_detector_meets_labeled_precision_and_recall_floor():
    predicted_positive = [
        text for text in (*POSITIVE, *NEGATIVE)
        if detect_explicit_feedback(text, prior_assistant_output="synthetic prior output").is_feedback
    ]
    true_positive = sum(text in POSITIVE for text in predicted_positive)
    false_positive = sum(text in NEGATIVE for text in predicted_positive)
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / len(POSITIVE)
    assert precision >= 0.95, (precision, false_positive, predicted_positive)
    assert recall >= 0.90, (recall, true_positive, predicted_positive)
