from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

from winpty import PtyProcess


artifact = Path(__file__).resolve().parents[2]
script = artifact / "tests" / "acceptance" / "test_authority_windows.ps1"
pwsh = shutil.which("pwsh.exe")
if pwsh is None:
    raise SystemExit("pwsh.exe was not found")
powershell = (
    "$env:IMPRINT_EXTERNAL_PTY='1'; "
    "$env:IMPRINT_ACCEPTANCE_DEBUG='1'; "
    "$env:PYTHONDONTWRITEBYTECODE='1'; "
    "& '" + str(script).replace("'", "''") + "'"
)
command = [pwsh, "-NoLogo", "-NoProfile", "-Command", powershell]
child = PtyProcess.spawn(command, dimensions=(40, 160))
exact = re.compile(r"Type ([A-Z][A-Z -]*[A-Z]) to [^:\r\n]*: ")
passphrase = re.compile(r"[^\r\n]*passphrase: $", re.IGNORECASE)
secret = "native authority acceptance passphrase"
pending = ""
transcript: list[str] = []
while True:
    try:
        value = child.read(256)
    except EOFError:
        break
    transcript.append(value)
    pending = (pending + value)[-8192:]
    exact_match = exact.search(pending)
    if exact_match is not None:
        child.write(exact_match.group(1) + "\r")
        pending = ""
    elif passphrase.search(pending) is not None:
        child.write(secret + "\r")
        pending = ""
status = child.wait()
output = "".join(transcript)
if secret in output:
    raise SystemExit("native authority secret was echoed into the CI transcript")
sys.stdout.write(output)
if "native Windows authority: PASS" not in output:
    raise SystemExit("standard-user native authority ceremony did not reach PASS")
raise SystemExit(status)
