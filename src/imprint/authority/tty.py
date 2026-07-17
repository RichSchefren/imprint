"""Native terminal ceremonies; secrets never enter argv, env, stdin pipes, or logs."""

from __future__ import annotations

import getpass
import os
import sys
from contextlib import contextmanager
from typing import Iterator, Protocol

from imprint.errors import ValidationError


class CeremonyConsole(Protocol):
    def require_native(self) -> None: ...
    def write(self, value: str) -> None: ...
    def read_line(self, prompt: str) -> str: ...
    def read_secret(self, prompt: str) -> str: ...


class NativeConsole:
    """Open the controlling terminal, never redirected process stdio."""

    @contextmanager
    def _streams(self) -> Iterator[tuple[object, object]]:
        if os.name == "nt":
            input_path, output_path = "CONIN$", "CONOUT$"
        else:
            input_path = output_path = "/dev/tty"
        try:
            reader = open(input_path, "r", encoding="utf-8", errors="strict")
            writer = open(output_path, "w", encoding="utf-8", errors="strict")
        except OSError as exc:
            raise ValidationError("native TTY/console is required for authority operations") from exc
        try:
            if not reader.isatty() or not writer.isatty():
                raise ValidationError("native TTY/console is required for authority operations")
            yield reader, writer
        finally:
            reader.close()
            writer.close()

    def require_native(self) -> None:
        if os.environ.get("IMPRINT_HOOK") == "1" or os.environ.get("IMPRINT_NONINTERACTIVE") == "1":
            raise ValidationError("hooks and non-interactive processes cannot raise authority")
        if not sys.stdin.isatty():
            raise ValidationError("redirected stdin cannot raise authority")
        with self._streams():
            return

    def write(self, value: str) -> None:
        with self._streams() as (_, writer):
            writer.write(value)
            writer.flush()

    def read_line(self, prompt: str) -> str:
        with self._streams() as (reader, writer):
            writer.write(prompt)
            writer.flush()
            value = reader.readline()
        if not value:
            raise ValidationError("native TTY input ended unexpectedly")
        return value.rstrip("\r\n")

    def read_secret(self, prompt: str) -> str:
        self.require_native()
        # getpass itself opens /dev/tty or the native Windows console and
        # disables echo.  Redirected stdin is never its authority boundary.
        try:
            return getpass.getpass(prompt=prompt, stream=None)
        except (EOFError, KeyboardInterrupt) as exc:
            raise ValidationError("authority secret entry was cancelled") from exc


def assert_cli_not_redirected() -> None:
    """Enrollment/approval requires both process stdin and controlling TTY."""
    if os.environ.get("IMPRINT_HOOK") == "1" or os.environ.get("IMPRINT_NONINTERACTIVE") == "1":
        raise ValidationError("hooks and non-interactive processes cannot raise authority")
    NativeConsole().require_native()
