"""Bounded parsing of native Claude Code transcript JSONL hook input."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from imprint.errors import ValidationError

MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class _TranscriptSnapshot:
    data: bytes
    size: int
    offset: int


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _version(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_native_transcript_snapshot(
    path_value: str, *, tail_limit: int | None = None,
) -> _TranscriptSnapshot:
    """Open once and return a bounded, immutable view of a regular file.

    The path checks, size decision, reads, and final change detection are all
    bound to the same descriptor.  The path identity is checked before and
    after the read so a rename-and-replace cannot silently change the source.
    """
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        raise ValidationError("transcript_path must be an absolute regular non-symlink file")
    try:
        path_before = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValidationError("transcript_path must be an absolute regular non-symlink file") from exc
    if not stat.S_ISREG(path_before.st_mode):
        raise ValidationError("transcript_path must be an absolute regular non-symlink file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValidationError("transcript_path must be an absolute regular non-symlink file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(path_before):
            raise ValidationError("transcript_path changed while it was being opened")
        size = opened.st_size
        if size <= 0:
            raise ValidationError("transcript_path size is outside the supported bound")
        if size > MAX_TRANSCRIPT_BYTES and tail_limit is None:
            raise ValidationError("transcript_path size is outside the supported bound")

        read_size = size if size <= MAX_TRANSCRIPT_BYTES else min(size, tail_limit or 0)
        offset = size - read_size
        os.lseek(descriptor, offset, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = read_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        extra = os.read(descriptor, 1)
        after = os.fstat(descriptor)
        try:
            path_after = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise ValidationError("transcript_path changed during the bounded read") from exc
        if (
            remaining
            or extra
            or _version(after) != _version(opened)
            or not stat.S_ISREG(path_after.st_mode)
            or _identity(path_after) != _identity(opened)
        ):
            raise ValidationError("transcript_path changed during the bounded read")
        return _TranscriptSnapshot(data=b"".join(chunks), size=size, offset=offset)
    finally:
        os.close(descriptor)


def _message_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)
    return ""


def _parse_native_stop_snapshot(snapshot: _TranscriptSnapshot) -> dict[str, Any]:
    messages: list[tuple[str, str]] = []
    skipped_malformed_lines: list[int] = []
    try:
        lines = snapshot.data.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise ValidationError("transcript is not valid UTF-8") from exc
    for number, raw_line in enumerate(lines, start=1):
        complete = raw_line.endswith(("\n", "\r"))
        raw = raw_line.rstrip("\r\n")
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            if not complete and number == len(lines):
                raise ValidationError(f"incomplete transcript line {number}") from exc
            skipped_malformed_lines.append(number)
            continue
        if not isinstance(item, dict) or item.get("type") not in {"user", "assistant"}:
            continue
        message = item.get("message", {})
        if not isinstance(message, dict):
            continue
        text = _message_text(message.get("content"))
        if text.strip():
            messages.append((item["type"], text))
    user_indexes = [index for index, (kind, _) in enumerate(messages) if kind == "user"]
    if not user_indexes:
        raise ValidationError("transcript contains no user message")
    user_index = user_indexes[-1]
    operator_text = messages[user_index][1]
    prior_assistant = next(
        (messages[index][1] for index in range(user_index - 1, -1, -1) if messages[index][0] == "assistant"),
        None,
    )
    locator = "transcript:sha256:" + hashlib.sha256(snapshot.data).hexdigest()
    result: dict[str, Any] = {
        "operator_text": operator_text,
        "prior_assistant_output": prior_assistant,
        "case_description": "Explicit operator feedback witnessed in the Claude Code transcript",
        "source_locator": locator,
    }
    if skipped_malformed_lines:
        result["degradation"] = {
            "schema_version": "1.0.0",
            "payload": {
                "receipt": "historic_malformed_lines_skipped",
                "truncated": False,
                "skipped_malformed_line_count": len(skipped_malformed_lines),
                "skipped_malformed_lines": skipped_malformed_lines,
            },
        }
    return result


def parse_native_stop_transcript(path_value: str) -> dict[str, Any]:
    return _parse_native_stop_snapshot(
        _read_native_transcript_snapshot(path_value),
    )
