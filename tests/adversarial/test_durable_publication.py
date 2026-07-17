from __future__ import annotations

import os
from pathlib import Path

import pytest

import imprint.durable_io as durable_io
from imprint.durable_io import publish_new_private, publish_staged_private, replace_private
from imprint.errors import SafetyError


def test_publish_new_is_create_new_and_private(tmp_path: Path) -> None:
    target = tmp_path / "export.json"
    assert publish_new_private(target, b"first") == target
    assert target.read_bytes() == b"first"
    assert target.stat(follow_symlinks=False).st_nlink == 1
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(SafetyError, match="refusing to replace"):
        publish_new_private(target, b"second")
    assert target.read_bytes() == b"first"


def test_publish_new_never_follows_output_symlink(tmp_path: Path) -> None:
    external = tmp_path / "external.txt"
    external.write_bytes(b"preserve")
    output = tmp_path / "output.txt"
    output.symlink_to(external)
    with pytest.raises(SafetyError, match="refusing to replace"):
        publish_new_private(output, b"secret")
    assert external.read_bytes() == b"preserve"


def test_publish_rejects_linked_parent_chain(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(external, target_is_directory=True)
    with pytest.raises(OSError, match="linked private path component"):
        publish_new_private(linked / "export.txt", b"secret")
    assert list(external.iterdir()) == []


def test_replace_private_preserves_complete_state(tmp_path: Path) -> None:
    target = tmp_path / "owner.json"
    publish_new_private(target, b"old")
    replace_private(target, b"new")
    assert target.read_bytes() == b"new"


def test_staged_publication_uses_fsync_capable_descriptor(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "staged.json"
    target = tmp_path / "published.json"
    source.write_bytes(b"complete")
    real_open = durable_io.os.open
    staged_flags: list[int] = []

    def tracked_open(path, flags, *args, **kwargs):
        if Path(path) == source:
            staged_flags.append(flags)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(durable_io.os, "open", tracked_open)
    publish_staged_private(source, target)
    assert target.read_bytes() == b"complete"
    assert staged_flags
    assert staged_flags[-1] & os.O_ACCMODE == os.O_RDWR


def test_create_link_failure_leaves_no_claimed_publication(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "export.json"
    monkeypatch.setattr(durable_io.os, "link", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("fault")))
    with pytest.raises(OSError, match="fault"):
        publish_new_private(target, b"new")
    assert not target.exists()
    assert not list(tmp_path.glob(".export.json.*.tmp"))


def test_replace_failure_preserves_old_complete_file(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "owner.json"
    publish_new_private(target, b"old")
    monkeypatch.setattr(durable_io.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("fault")))
    with pytest.raises(OSError, match="fault"):
        replace_private(target, b"new")
    assert target.read_bytes() == b"old"


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory fsync contract")
def test_publication_fsyncs_file_and_parent(tmp_path: Path, monkeypatch) -> None:
    calls: list[int] = []
    real_fsync = durable_io.os.fsync

    def tracked(descriptor: int) -> None:
        calls.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(durable_io.os, "fsync", tracked)
    publish_new_private(tmp_path / "durable.json", b"content")
    assert len(calls) >= 2
