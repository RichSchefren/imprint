#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-python3}"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/imprint-real-upgrade.XXXXXX")"
TEST_ROOT="$(cd "${TEST_ROOT}" && pwd -P)"
trap 'rm -rf "${TEST_ROOT}"' EXIT
OLD_SOURCE="${TEST_ROOT}/v300"
mkdir -p "${OLD_SOURCE}"
git -C "${ROOT}" archive v3.0.0 | tar -xf - -C "${OLD_SOURCE}"

"${PYTHON}" -m build --outdir "${OLD_SOURCE}/dist" "${OLD_SOURCE}" >/dev/null
rm -rf "${ROOT}/dist"
"${PYTHON}" -m build --outdir "${ROOT}/dist" "${ROOT}" >/dev/null
PYTHON_EXECUTABLE="$("${PYTHON}" -c 'import sys; print(sys.executable)')"
ln -s "${PYTHON_EXECUTABLE}" "${TEST_ROOT}/python"
export PYTHON="${TEST_ROOT}/python"

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

bash "${OLD_SOURCE}/install/install.sh" \
  --install-root "${INSTALL_ROOT}" --config "${CONFIG}" \
  --settings "${SETTINGS}" --data-root "${DATA}"
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
