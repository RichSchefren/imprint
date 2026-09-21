"""Optional, fail-open Jev relevance selection for retrieval."""
from __future__ import annotations

import json
import math
import os
import re
import urllib.request
from collections import Counter
from typing import Any, Sequence

from .models import RetrievalRecord

_STOP = frozenset(
    "the a an and or of to in on for with is are was be it this that as at by from not no do does "
    "your you we they their our its if then than so can will into out up about have has had all any "
    "more most".split()
)


def _tokens(value: str) -> set[str]:
    return {word for word in re.findall(r"[a-z][a-z'\-]{2,}", value.casefold()) if word not in _STOP}


def prefilter(turn_text: str, entries: Sequence[RetrievalRecord], keep: int = 150) -> list[RetrievalRecord]:
    """Keep the IDF-weighted lexical candidates before sending anything out."""
    if keep <= 0:
        return list(entries)
    query = _tokens(turn_text)
    documents = [_tokens(item.text) for item in entries]
    frequency = Counter(token for document in documents for token in document)
    count = max(1, len(entries))
    ranked = []
    for item, document in zip(entries, documents):
        score = sum(math.log1p(count / frequency[token]) for token in document & query)
        score /= math.sqrt(len(document) + 5)
        ranked.append((score, item.record_id, item))
    ranked.sort(key=lambda value: (-value[0], value[1].encode("utf-8")))
    return [item for _, _, item in ranked[:keep]]


def _score(answer: Any) -> float | None:
    """Read the documented answer shape: ``{"noul": probability}``."""
    if not isinstance(answer, dict):
        return None
    value = answer.get("noul")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


class JevSelector:
    def __init__(self, *, endpoint: str, model: str, api_key_env: str = "OPENROUTER_API_KEY") -> None:
        self.endpoint, self.model, self.api_key_env = endpoint, model, api_key_env

    def _request(self, turn_text: str, candidates: Sequence[RetrievalRecord], timeout: float) -> dict[str, Any]:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise RuntimeError("Jev API key is not configured")
        questions = {
            item.record_id: {
                "type": "noul",
                "instructions": f"Does this principle apply to the current turn? Principle: {item.text[:400]}",
            }
            for item in candidates
        }
        body = {"model": self.model, "state": turn_text[:8000], "questions": questions}
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(body, ensure_ascii=False).encode(),
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read().decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Jev response must be an object")
        return value

    def select(
        self,
        turn_text: str,
        entries: Sequence[RetrievalRecord],
        top: int = 20,
        floor: float = 0.55,
        timeout: float = 3.0,
        prefilter_keep: int = 150,
    ) -> list[tuple[RetrievalRecord, float]] | None:
        """Return ranked picks, or None so the caller can use deterministic retrieval."""
        try:
            candidates = prefilter(turn_text, entries, prefilter_keep)
            if not candidates or not os.environ.get(self.api_key_env):
                return None
            answers = self._request(turn_text, candidates, timeout).get("answers")
            if not isinstance(answers, dict):
                return None
            by_id = {item.record_id: item for item in candidates}
            scored = []
            for record_id, answer in answers.items():
                score = _score(answer)
                if record_id in by_id and score is not None and floor <= score <= 1.0:
                    scored.append((by_id[record_id], score))
            scored.sort(key=lambda value: (-value[1], value[0].record_id.encode("utf-8")))
            return scored[: max(0, top)]
        except Exception:
            return None
