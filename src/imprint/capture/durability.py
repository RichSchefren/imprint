"""Process-local Stop-capture durability phase observed by the hook bridge."""

from __future__ import annotations

_NOT_STARTED = "not_started"
_PERSISTING = "persisting"
_PERSISTED = "persisted"
_phase = _NOT_STARTED


def reset_stop_capture_phase() -> None:
    global _phase
    _phase = _NOT_STARTED


def mark_stop_capture_persisting() -> None:
    global _phase
    _phase = _PERSISTING


def mark_stop_capture_persisted() -> None:
    global _phase
    _phase = _PERSISTED


def stop_capture_is_durable() -> bool:
    return _phase == _PERSISTED


def stop_capture_phase() -> str:
    return _phase
