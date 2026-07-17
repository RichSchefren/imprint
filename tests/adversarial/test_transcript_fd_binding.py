from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import imprint.capture.transcript as transcript_module
from imprint.capture.transcript import MAX_TRANSCRIPT_BYTES, parse_native_stop_transcript
from imprint.cli import _parse_large_native_transcript
from imprint.errors import ValidationError


def _write_transcript(path: Path, *, large: bool) -> None:
    payload = (
        json.dumps({
            "type": "assistant",
            "message": {"content": "Original assistant context."},
        })
        + "\n"
        + json.dumps({
            "type": "user",
            "message": {"content": "No, preserve the descriptor-bound source."},
        })
        + "\n"
    ).encode()
    with path.open("wb") as handle:
        if large:
            handle.seek(MAX_TRANSCRIPT_BYTES + 1024 - len(payload))
            handle.write(b"\n" + payload)
        else:
            handle.write(payload)


def _parse(path: Path, *, large: bool) -> dict:
    if large:
        return _parse_large_native_transcript(str(path))
    return parse_native_stop_transcript(str(path))


@pytest.mark.parametrize("large", [False, True])
def test_transcript_rejects_growth_during_descriptor_bound_read(
    tmp_path, monkeypatch, large,
):
    path = tmp_path / "transcript.jsonl"
    _write_transcript(path, large=large)
    original_read = os.read
    raced = False

    def grow_then_read(descriptor: int, count: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            with path.open("ab") as handle:
                handle.write(b"post-check growth")
        return original_read(descriptor, count)

    monkeypatch.setattr(transcript_module.os, "read", grow_then_read)
    with pytest.raises(ValidationError, match="changed during the bounded read"):
        _parse(path, large=large)


@pytest.mark.parametrize("large", [False, True])
def test_transcript_rejects_path_swap_during_descriptor_bound_read(
    tmp_path, monkeypatch, large,
):
    path = tmp_path / "transcript.jsonl"
    held = tmp_path / "held-original.jsonl"
    _write_transcript(path, large=large)
    original_read = os.read
    raced = False

    def swap_then_read(descriptor: int, count: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            path.rename(held)
            path.write_text(
                json.dumps({
                    "type": "user",
                    "message": {"content": "Attacker replacement."},
                }) + "\n",
                encoding="utf-8",
            )
        return original_read(descriptor, count)

    monkeypatch.setattr(transcript_module.os, "read", swap_then_read)
    with pytest.raises(ValidationError, match="changed during the bounded read"):
        _parse(path, large=large)


@pytest.mark.parametrize("large", [False, True])
def test_transcript_rejects_symlink_before_open(tmp_path, large):
    target = tmp_path / "target.jsonl"
    link = tmp_path / "transcript.jsonl"
    _write_transcript(target, large=large)
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(
        ValidationError,
        match="absolute regular non-symlink file",
    ):
        _parse(link, large=large)
