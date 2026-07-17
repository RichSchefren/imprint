#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = "Darwin" ] || { echo "macOS only" >&2; exit 77; }
[ -t 0 ] && [ -t 1 ] || { echo "run from a native terminal" >&2; exit 2; }
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/imprint-native-authority.XXXXXX")"
# macOS presents /var as a symlink to /private/var. Feed the authority layer
# the physical path so this acceptance test exercises a safe path chain.
ROOT="$(cd "${ROOT}" && pwd -P)"
CRASH_ROOT="${ROOT}-crash"
LIFECYCLE_ROOT="${ROOT}-lifecycle"
REDIRECTED_ROOT="${ROOT}-redirected"
TRANSCRIPT="${ROOT}.typescript"
CRASH_TRANSCRIPT="${CRASH_ROOT}.typescript"
LIFECYCLE_TRANSCRIPT="${LIFECYCLE_ROOT}.typescript"
trap 'rm -rf "${ROOT}" "${CRASH_ROOT}" "${LIFECYCLE_ROOT}" "${LIFECYCLE_ROOT}-offline" "${LIFECYCLE_ROOT}-restored" "${LIFECYCLE_ROOT}-paired" "${REDIRECTED_ROOT}" "${TRANSCRIPT}" "${CRASH_TRANSCRIPT}" "${LIFECYCLE_TRANSCRIPT}"' EXIT
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${REPO}/.venv/bin/python"
OPERATOR="urn:imprint:operator:11111111-1111-4111-8111-111111111111"
if [ "${IMPRINT_EXTERNAL_PTY:-0}" != "1" ]; then
  echo 'For every secret prompt, use the test-only passphrase: native authority acceptance passphrase'
fi
if printf 'redirected\n' | "${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" full --root "${REDIRECTED_ROOT}" --operator "${OPERATOR}" >/dev/null 2>&1; then
  echo 'Redirected stdin was accepted' >&2; exit 1
fi
if [ "${IMPRINT_EXTERNAL_PTY:-0}" = "1" ]; then
  "${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" full --root "${ROOT}" --operator "${OPERATOR}"
else
  script -q "${TRANSCRIPT}" "${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" full --root "${ROOT}" --operator "${OPERATOR}"
  ! grep -q 'native authority acceptance passphrase' "${TRANSCRIPT}"
fi
BLOB="$(find "${ROOT}/authority/keys" -type f -name '*.blob' -print -quit)"
chmod 0644 "${BLOB}"
"${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" verify-unsafe --root "${ROOT}" --operator "${OPERATOR}"
[ "$(stat -f '%Lp' "${BLOB}")" = "644" ]
if [ "${IMPRINT_EXTERNAL_PTY:-0}" = "1" ]; then
  "${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" crash-reconcile --root "${CRASH_ROOT}" --operator "${OPERATOR}"
else
  script -q "${CRASH_TRANSCRIPT}" "${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" crash-reconcile --root "${CRASH_ROOT}" --operator "${OPERATOR}"
  ! grep -q 'native authority acceptance passphrase' "${CRASH_TRANSCRIPT}"
fi
if [ "${IMPRINT_EXTERNAL_PTY:-0}" = "1" ]; then
  "${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" lifecycle --root "${LIFECYCLE_ROOT}" --operator "${OPERATOR}"
else
  script -q "${LIFECYCLE_TRANSCRIPT}" "${PYTHON}" "${REPO}/tests/acceptance/native_authority.py" lifecycle --root "${LIFECYCLE_ROOT}" --operator "${OPERATOR}"
  ! grep -q 'native authority acceptance passphrase' "${LIFECYCLE_TRANSCRIPT}"
fi
echo "native macOS authority: PASS"
