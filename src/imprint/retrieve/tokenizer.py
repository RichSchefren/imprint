"""Versioned lexical tokenizer with platform-independent normalization."""

from __future__ import annotations

import re
import unicodedata

TOKENIZER_VERSION = "lexical-v1"
_TOKEN = re.compile(r"[a-z0-9]+(?:['-][a-z0-9]+)*", re.ASCII)


def tokenize(value: str, *, version: str = TOKENIZER_VERSION) -> tuple[str, ...]:
    if version != TOKENIZER_VERSION:
        raise ValueError("unsupported tokenizer version")
    # NFKD plus ASCII projection avoids locale and Unicode-library ordering drift.
    normalized = unicodedata.normalize("NFKD", value).casefold()
    stable = normalized.encode("ascii", "ignore").decode("ascii")
    return tuple(_TOKEN.findall(stable))


def lexical_score(query: str, text: str, *, version: str = TOKENIZER_VERSION) -> int:
    query_tokens = tokenize(query, version=version)
    if not query_tokens:
        return 0
    candidate = set(tokenize(text, version=version))
    # Multiplicity in the query is retained; candidate occurrence count is deliberately ignored.
    return sum(1 for token in query_tokens if token in candidate)

