#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-python3}"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/imprint-real-upgrade.XXXXXX")"
TEST_ROOT="$(cd "${TEST_ROOT}" && pwd -P)"
trap 'rm -rf "${TEST_ROOT}"' EXIT
export HOME="${TEST_ROOT}/home"
export XDG_CONFIG_HOME="${HOME}/config"
export XDG_DATA_HOME="${HOME}/data"
export IMPRINT_LAUNCHER_DIR="${HOME}/bin"
export SHELL=/bin/bash
INSTALL_ROOT="${HOME}/app"
CONFIG="${XDG_CONFIG_HOME}/imprint/config.json"
SETTINGS="${HOME}/.claude/settings.json"
DATA="${XDG_DATA_HOME}/imprint"
mkdir -p "${HOME}"

# A clean public repository deliberately carries no historical tags. Recreate
# the exact ownership boundary an installed v3.0.0 product exposed without
# republishing the old source tree or relying on hidden Git history.
mkdir -p "${INSTALL_ROOT}/venv/bin" "$(dirname "${CONFIG}")" "$(dirname "${SETTINGS}")" "${DATA}"
printf '%s\n' '#!/bin/sh' "printf '%s\\n' '3.0.0'" > "${INSTALL_ROOT}/venv/bin/imprint"
chmod 755 "${INSTALL_ROOT}/venv/bin/imprint"
printf '%s\n' 'imprint-local:3.0.0' > "${INSTALL_ROOT}/.imprint-install-root"
printf '%s\n' '{"config_version":"3.0.0"}' > "${CONFIG}"
printf '%s\n' '{}' > "${SETTINGS}"
"${PYTHON}" - "${INSTALL_ROOT}" <<'PY'
import hashlib
import json
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
entries = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path.name in {".imprint-install-root", ".imprint-owned-files.json"}:
        continue
    relative = path.relative_to(root).as_posix()
    mode = path.lstat().st_mode
    if stat.S_ISDIR(mode):
        entries.append({"path": relative, "type": "directory"})
    elif stat.S_ISREG(mode):
        entries.append({
            "path": relative,
            "type": "file",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    else:
        raise SystemExit(f"unsupported fixture path: {relative}")
payload = {"format": 1, "product": "imprint-local", "version": "3.0.0", "entries": entries}
(root / ".imprint-owned-files.json").write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
test "$(IMPRINT_CONFIG="${CONFIG}" "${INSTALL_ROOT}/venv/bin/imprint" version)" = "3.0.0"
mkdir -p "${DATA}/default"
printf '%s\n' preserved > "${DATA}/default/v300-data-sentinel.txt"

bash "${ROOT}/install/install.sh" \
  --install-root "${INSTALL_ROOT}" --config "${CONFIG}" \
  --settings "${SETTINGS}" --data-root "${DATA}"
test "$(IMPRINT_CONFIG="${CONFIG}" "${INSTALL_ROOT}/venv/bin/imprint" version)" = "3.1.1"
test "$(cat "${DATA}/default/v300-data-sentinel.txt")" = preserved
test -z "$(find "$(dirname "${INSTALL_ROOT}")" -maxdepth 1 -name 'app.imprint-backup.*' -print -quit)"

bash "${ROOT}/install/uninstall.sh" \
  --install-root "${INSTALL_ROOT}" --config "${CONFIG}" --settings "${SETTINGS}"
test ! -e "${INSTALL_ROOT}"
test -f "${DATA}/default/v300-data-sentinel.txt"
echo "real v3.0.0 to v3.1.1 upgrade: PASS"
