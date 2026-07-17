#!/usr/bin/env python3
"""Fail-closed confidentiality policy for public source and distributions."""

from __future__ import annotations

import io
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable


MAX_ARCHIVE_DEPTH = 4
MAX_MEMBER_BYTES = 128 * 1024 * 1024


def _decoded(*values: str) -> tuple[bytes, ...]:
    """Keep the signatures out of the scanner's own public byte stream."""
    return tuple(bytes.fromhex(value).lower() for value in values)


# Exact names, namespaces, branded labels, registry identities, and high-signal
# structural vocabulary. Values are hex-encoded so scanning this policy file
# cannot satisfy its own rules.
_EXACT = _decoded(
    "5a4d4f53",  # four-letter private registry abbreviation
    "7a6d6f732e",  # private namespace prefix
    "70726f6d70743a7a6d6f73",  # private prompt namespace
    "7a6d6f735f70726f706f73616c",  # private proposal mechanism
    "5a656e6974684d696e64",
    "5a656e697468204d696e64",
    "4d696e644f53",
    "5a656e69746850726f",
    "4469676974616c20444e41",
    "6469676974616c2d646e61",
    "6469676974616c5f646e61",
    "4f7065726174696e6720506f727472616974",
    "4d6972726f722053636f7265",
    "6e61727261746976655f636f7265",
    "736861646f775f636f6e7374656c6c6174696f6e",
    "6964656e746974795f617263686974656374757265",
    "726573697374616e63655f70726564696374696f6e",
    "6675747572655f73656c665f6469616c6f677565",
    "6d656e746f725f636f756e63696c",
    "7073796368655f656c656d656e74",
    "736861646f775f656c656d656e74",
    "7361626f746167655f6c6f6f70",
    "6964656e746974795f656c656d656e74",
    "72656c6174696f6e616c5f656c656d656e74",
    "657865637574696f6e5f656c656d656e74",
    "74656d706f72616c5f656c656d656e74",
    "43686f73656e467574757265",
    "44656661756c74467574757265",
    "446972656374696f6e53636f7265",
    "446972656374696f6e53636f726552656365697074",
    "43616e6469646174654d6f7665",
    "4d616e4f6e5265636f726456696577",
    "43686f73656e46757475726550726f706f73616c",
    "66666432383938303561313865306637616335663639336264373739623234363335346665323838323265326365613162356364336431303365613461626233",
)

_SCHEMA_SUFFIXES = _decoded(
    "63686f73656e2d667574757265",
    "64656661756c742d667574757265",
    "646972656374696f6e2d73636f7265",
    "646972656374696f6e2d73636f72652d72656365697074",
    "63616e6469646174652d6d6f7665",
    "6d616e2d6f6e2d7265636f72642d76696577",
    "63686f73656e2d6675747572652d70726f706f73616c",
)
_SCHEMA_PREFIX = bytes.fromhex("696d7072696e742e6e6f64652e").lower()

# A private phase token has a word boundary, one of four encoded family names,
# and either a concrete number or the start of a generator expression. This
# avoids matching generic public fields such as observer_actor_version_id.
_PHASE_FAMILIES = _decoded("676f64", "6f62736572766572", "7565", "716c63")
_PHASE_PATTERNS = tuple(
    re.compile(rb"(?<![a-z0-9])" + family + rb"_(?:0?[0-9]|1[0-4]|\{)", re.IGNORECASE)
    for family in _PHASE_FAMILIES
)

_FIVE_CLASS = frozenset(_decoded(
    "507379636865", "4964656e74697479", "52656c6174696f6e616c",
    "457865637574696f6e", "54656d706f72616c",
))


def scan_content(name: str, content: bytes) -> list[str]:
    """Return content-free findings for one logical file payload."""
    lowered = content.lower()
    findings: list[str] = []
    if any(signature in lowered for signature in _EXACT):
        findings.append(f"private ontology signature: {name}")
    if any(_SCHEMA_PREFIX + suffix in lowered for suffix in _SCHEMA_SUFFIXES):
        findings.append(f"private schema identifier: {name}")
    if any(pattern.search(lowered) for pattern in _PHASE_PATTERNS):
        findings.append(f"private source-phase signature: {name}")
    if all(token.lower() in lowered for token in _FIVE_CLASS):
        findings.append(f"private five-class structure: {name}")
    return findings


def _archive_kind(name: str, content: bytes) -> str | None:
    lowered = name.lower()
    if lowered.endswith((".zip", ".whl")) or content.startswith(b"PK\x03\x04"):
        return "zip"
    if lowered.endswith((".tar.gz", ".tgz", ".tar")):
        return "tar"
    return None


def scan_payload(name: str, content: bytes, *, depth: int = 0) -> list[str]:
    """Scan one payload and recursively inspect supported distribution archives."""
    findings = scan_content(name, content)
    kind = _archive_kind(name, content)
    if kind is None:
        return findings
    if depth >= MAX_ARCHIVE_DEPTH:
        return [*findings, f"archive nesting exceeds policy: {name}"]
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                for member in sorted(archive.infolist(), key=lambda item: item.filename):
                    if member.is_dir():
                        continue
                    child = f"{name}!{member.filename}"
                    findings.extend(scan_content(child + "#path", member.filename.encode()))
                    if member.file_size > MAX_MEMBER_BYTES:
                        findings.append(f"archive member exceeds scan limit: {child}")
                        continue
                    findings.extend(scan_payload(child, archive.read(member), depth=depth + 1))
        else:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
                for member in sorted(archive.getmembers(), key=lambda item: item.name):
                    if member.isdir():
                        continue
                    child = f"{name}!{member.name}"
                    findings.extend(scan_content(child + "#path", member.name.encode()))
                    if not member.isfile():
                        findings.append(f"unsupported archive member: {child}")
                        continue
                    if member.size > MAX_MEMBER_BYTES:
                        findings.append(f"archive member exceeds scan limit: {child}")
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        findings.append(f"unreadable archive member: {child}")
                        continue
                    findings.extend(scan_payload(child, source.read(), depth=depth + 1))
    except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, ValueError):
        findings.append(f"unreadable release archive: {name}")
    return findings


def scan_paths(paths: Iterable[Path], *, root: Path) -> list[str]:
    """Scan exact files using stable relative names."""
    findings: list[str] = []
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        findings.extend(scan_content(relative + "#path", relative.encode()))
        try:
            size = path.stat().st_size
            if size > MAX_MEMBER_BYTES:
                findings.append(f"file exceeds scan limit: {relative}")
                continue
            findings.extend(scan_payload(relative, path.read_bytes()))
        except OSError:
            findings.append(f"unreadable public file: {relative}")
    return findings

