#!/usr/bin/env python3
"""Scan public source for local paths, common secrets, and private runtime data."""

from __future__ import annotations

import re
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from confidentiality import scan_paths

ROOT = Path(__file__).resolve().parents[2]
EXCLUDED = {".git", ".venv", ".pytest_cache", "__pycache__", "build", "dist", "release-artifacts", "imprint_local.egg-info"}
BAD_SUFFIXES = {".db", ".db-wal", ".db-shm", ".log", ".bak", ".pyc"}
PATTERNS = {
    "macOS user path": re.compile(rb"/" + rb"Users" + rb"/[A-Za-z0-9._-]+/"),
    "Windows user path": re.compile(
        rb"[A-Za-z]:\\\\" + rb"Users" + rb"\\\\[^\\\\]+\\\\"
    ),
    "Slack token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic bearer": re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{12,}"),
}


def main() -> int:
    failures = []
    public_files = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED for part in relative.parts) or not path.is_file():
            continue
        if any(path.name.endswith(suffix) for suffix in BAD_SUFFIXES):
            failures.append(f"runtime file: {relative}")
            continue
        public_files.append(path)
        content = path.read_bytes()
        for label, pattern in PATTERNS.items():
            if pattern.search(content):
                failures.append(f"{label}: {relative}")
    failures.extend(scan_paths(public_files, root=ROOT))
    if failures:
        raise RuntimeError("public scan failed:\n" + "\n".join(failures))
    print("public source scan: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
