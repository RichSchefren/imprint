from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterable

from imprint.retrieve.tokenizer import tokenize

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


@dataclass(frozen=True)
class DomainRule:
    domain_id: str
    public_label: str
    safe_paths: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    frozen: bool = False

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.domain_id):
            raise ValueError("unsafe domain id")
        if not self.public_label.strip():
            raise ValueError("public label is required")
        for prefix in self.safe_paths:
            if not prefix.strip() or "\x00" in prefix:
                raise ValueError("unsafe path rule")


@dataclass(frozen=True)
class DomainSelection:
    domain_id: str | None
    method: str
    diagnostic_code: str | None = None


def _path_parts(value: str) -> tuple[str, ...]:
    normalized = value.replace("\\", "/").strip("/")
    if not normalized or "\x00" in normalized:
        return ()
    parts = tuple(part.casefold() for part in PurePath(normalized).parts if part not in {"/", "\\"})
    if any(part in {".", ".."} for part in parts):
        return ()
    return parts


class DomainRegistry:
    def __init__(self, rules: Iterable[DomainRule]):
        values = tuple(rules)
        ids = [item.domain_id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate domain id")
        self._rules = {item.domain_id: item for item in values}

    @property
    def domain_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._rules))

    def select(
        self,
        *,
        explicit: str | None = None,
        path: str | None = None,
        prompt: str = "",
    ) -> DomainSelection:
        if explicit is not None:
            if not _SAFE_ID.fullmatch(explicit) or explicit not in self._rules:
                return DomainSelection(None, "explicit", "domain_explicit_invalid")
            return DomainSelection(explicit, "explicit")

        if path:
            target = _path_parts(path)
            scored: list[tuple[int, str]] = []
            if target:
                for rule in self._rules.values():
                    best = 0
                    for prefix in rule.safe_paths:
                        parts = _path_parts(prefix)
                        if parts and len(parts) <= len(target) and target[: len(parts)] == parts:
                            best = max(best, len(parts))
                    if best:
                        scored.append((best, rule.domain_id))
            if scored:
                high = max(score for score, _ in scored)
                winners = sorted(domain for score, domain in scored if score == high)
                if len(winners) == 1:
                    return DomainSelection(winners[0], "path")
                return DomainSelection(None, "path", "domain_path_tie")

        query = set(tokenize(prompt))
        scored_keywords: list[tuple[int, str]] = []
        for rule in self._rules.values():
            terms = set(token for keyword in rule.keywords for token in tokenize(keyword))
            score = len(query.intersection(terms))
            if score:
                scored_keywords.append((score, rule.domain_id))
        if scored_keywords:
            high = max(score for score, _ in scored_keywords)
            winners = sorted(domain for score, domain in scored_keywords if score == high)
            if len(winners) == 1:
                return DomainSelection(winners[0], "keyword")
            return DomainSelection(None, "keyword", "domain_keyword_tie")
        return DomainSelection(None, "none", "domain_no_match")


def registry_from_config(config: dict) -> DomainRegistry:
    """Build a closed registry from public config without reading user content."""
    raw = config.get("domains", [])
    if not isinstance(raw, list):
        raise ValueError("domains config must be an array")
    rules = []
    expected = {"domain_id", "public_label", "safe_paths", "keywords", "frozen"}
    for item in raw:
        if not isinstance(item, dict) or set(item) - expected:
            raise ValueError("domain config contains unknown fields")
        if not {"domain_id", "public_label"}.issubset(item):
            raise ValueError("domain config requires domain_id and public_label")
        safe_paths = item.get("safe_paths", [])
        keywords = item.get("keywords", [])
        if not isinstance(safe_paths, list) or not all(isinstance(value, str) for value in safe_paths):
            raise ValueError("domain safe_paths must be strings")
        if not isinstance(keywords, list) or not all(isinstance(value, str) for value in keywords):
            raise ValueError("domain keywords must be strings")
        rules.append(DomainRule(
            domain_id=item["domain_id"], public_label=item["public_label"],
            safe_paths=tuple(safe_paths), keywords=tuple(keywords),
            frozen=bool(item.get("frozen", False)),
        ))
    return DomainRegistry(rules)
