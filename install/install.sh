#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_ROOT="${IMPRINT_INSTALL_ROOT:-${HOME}/.local/lib/imprint-local}"
CONFIG_PATH="${IMPRINT_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/imprint/config.json}"
SETTINGS_PATH="${CLAUDE_SETTINGS_PATH:-${HOME}/.claude/settings.json}"
DATA_ROOT="${IMPRINT_DATA_ROOT:-${XDG_DATA_HOME:-${HOME}/.local/share}/imprint}"
LAUNCHER_DIR="${IMPRINT_LAUNCHER_DIR:-${HOME}/.local/bin}"
SHELL_PROFILE="${IMPRINT_SHELL_PROFILE:-}"
OPERATOR="default"
REGISTER_HOOKS=1
PYTHON="${PYTHON:-python3}"
SUCCESS=0
BACKUP_ROOT=""
STATE_ROOT=""
PRODUCT_VERSION="$("${PYTHON}" - "${ARTIFACT_ROOT}/src/imprint/_version.py" <<'PY'
import runpy, sys
print(runpy.run_path(sys.argv[1])["__version__"])
PY
)"

usage() {
  echo "Usage: install.sh [--install-root PATH] [--config PATH] [--settings PATH] [--data-root PATH] [--launcher-dir PATH] [--shell-profile PATH] [--operator SLUG] [--python PATH] [--no-hooks]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-root) INSTALL_ROOT="$2"; shift 2 ;;
    --config) CONFIG_PATH="$2"; shift 2 ;;
    --settings) SETTINGS_PATH="$2"; shift 2 ;;
    --data-root) DATA_ROOT="$2"; shift 2 ;;
    --launcher-dir) LAUNCHER_DIR="$2"; shift 2 ;;
    --shell-profile) SHELL_PROFILE="$2"; shift 2 ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    --no-hooks) REGISTER_HOOKS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "${SHELL_PROFILE}" ]; then
  case "${SHELL:-}" in
    */zsh) SHELL_PROFILE="${HOME}/.zprofile" ;;
    */bash) SHELL_PROFILE="${HOME}/.bash_profile" ;;
    *) SHELL_PROFILE="${HOME}/.profile" ;;
  esac
fi

"${PYTHON}" -c 'import platform,sys,sysconfig; ok=platform.python_implementation()=="CPython" and (3,10)<=sys.version_info[:2]<=(3,14) and not sysconfig.get_config_var("Py_GIL_DISABLED"); raise SystemExit(0 if ok else "Imprint requires standard GIL-enabled CPython 3.10 through 3.14")'
case "${OPERATOR}" in *[!a-z0-9-]*|'') echo "Operator must use lowercase letters, digits, and hyphens." >&2; exit 2 ;; esac

INSTALL_ROOT="$("${PYTHON}" - "${INSTALL_ROOT}" <<'PY'
import sys
from pathlib import Path
print(Path(sys.argv[1]).expanduser().resolve())
PY
)"
HOME_ROOT="$(cd "${HOME}" && pwd -P)"
if [ "${INSTALL_ROOT}" = "/" ] || [ "${INSTALL_ROOT}" = "${HOME_ROOT}" ] || [ -L "${INSTALL_ROOT}" ]; then
  echo "Refusing an unsafe install root: ${INSTALL_ROOT}" >&2
  exit 2
fi
MARKER="${INSTALL_ROOT}/.imprint-install-root"
LAUNCHER_PATH="${LAUNCHER_DIR}/imprint"
EXISTING_VERSION=""
if [ -d "${INSTALL_ROOT}" ] && [ -n "$(find "${INSTALL_ROOT}" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  if [ ! -f "${MARKER}" ]; then
    echo "Refusing a non-empty install root not owned by Imprint: ${INSTALL_ROOT}" >&2
    exit 2
  fi
  case "$(cat "${MARKER}")" in
    imprint-local:3.0.0) EXISTING_VERSION="3.0.0" ;;
    imprint-local:3.0.1) EXISTING_VERSION="3.0.1" ;;
    imprint-local:3.1.0) EXISTING_VERSION="3.1.0" ;;
    imprint-local:3.1.1) EXISTING_VERSION="3.1.1" ;;
    *) echo "Refusing an unsupported Imprint install version: $(cat "${MARKER}")" >&2; exit 2 ;;
  esac
  "${PYTHON}" "${ARTIFACT_ROOT}/tools/install/install_ownership.py" verify \
    --root "${INSTALL_ROOT}" --expected-version "${EXISTING_VERSION}"
fi

case "$(uname -s):$(uname -m)" in
  Darwin:x86_64|Darwin:arm64) WHEEL_LANE="macos" ;;
  Linux:x86_64|Linux:aarch64) WHEEL_LANE="linux" ;;
  *) echo "Unsupported Imprint platform/architecture: $(uname -s)/$(uname -m)" >&2; exit 2 ;;
esac
echo "Before extraction or execution, verify this complete archive with the full GitHub attestation policy documented for v3.1.1. Internal hashes establish component integrity only, not public provenance." >&2
VERIFIER="${ARTIFACT_ROOT}/tools/install/verify_wheelhouse.py"
EXPECTED_VERIFIER_SHA256="783a44343f848e969869242e488d14485dfd851c9e2018debe18c2eeab8ff9d5"
MANIFEST_DIGEST_FILE="${ARTIFACT_ROOT}/release/wheelhouse/manifest.sha256"
if [ ! -f "${VERIFIER}" ] || [ ! -f "${MANIFEST_DIGEST_FILE}" ]; then
  echo "The release artifact is missing its pinned offline verifier or manifest digest." >&2; exit 2
fi
ACTUAL_VERIFIER_SHA256="$("${PYTHON}" - "${VERIFIER}" <<'PY'
import hashlib,sys
print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())
PY
)"
if [ "${ACTUAL_VERIFIER_SHA256}" != "${EXPECTED_VERIFIER_SHA256}" ]; then echo "Offline verifier digest mismatch." >&2; exit 2; fi
MANIFEST_SHA256="$(tr -d '[:space:]' < "${MANIFEST_DIGEST_FILE}")"
"${PYTHON}" "${VERIFIER}" --root "${ARTIFACT_ROOT}" --lane "${WHEEL_LANE}" --manifest-sha256 "${MANIFEST_SHA256}"
WHEELHOUSE="${ARTIFACT_ROOT}/release/wheelhouse/${WHEEL_LANE}"
RUNTIME_LOCK="${ARTIFACT_ROOT}/requirements/runtime-${WHEEL_LANE}.lock"

STATE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/imprint-install-state.XXXXXX")"
BACKUP_ROOT="${INSTALL_ROOT}.imprint-backup.$$"
if [ -e "${BACKUP_ROOT}" ] || [ -L "${BACKUP_ROOT}" ]; then
  echo "Refusing to overwrite stale install backup: ${BACKUP_ROOT}" >&2
  exit 2
fi

snapshot_file() {
  local source="$1" name="$2"
  if [ -f "${source}" ]; then cp -p "${source}" "${STATE_ROOT}/${name}"; else : > "${STATE_ROOT}/${name}.absent"; fi
}
restore_file() {
  local destination="$1" name="$2"
  if [ -f "${STATE_ROOT}/${name}.absent" ]; then rm -f -- "${destination}"; else mkdir -p "$(dirname "${destination}")"; cp -p "${STATE_ROOT}/${name}" "${destination}"; fi
}
snapshot_mode() {
  local source="$1" name="$2"
  if [ -e "${source}" ] && [ ! -L "${source}" ]; then
    "${PYTHON}" - "${source}" > "${STATE_ROOT}/${name}.mode" <<'PY'
import stat, sys
from pathlib import Path
print(f"{stat.S_IMODE(Path(sys.argv[1]).stat().st_mode):04o}")
PY
  else
    : > "${STATE_ROOT}/${name}.absent"
  fi
}
restore_mode() {
  local destination="$1" name="$2"
  if [ -f "${STATE_ROOT}/${name}.mode" ] && [ -e "${destination}" ] && [ ! -L "${destination}" ]; then
    chmod "$(cat "${STATE_ROOT}/${name}.mode")" "${destination}"
  elif [ -f "${STATE_ROOT}/${name}.absent" ] && [ -d "${destination}" ] && [ ! -L "${destination}" ]; then
    rmdir "${destination}" 2>/dev/null || true
  fi
}
remove_new_root() {
  if [ -d "${INSTALL_ROOT}" ] && [ ! -L "${INSTALL_ROOT}" ]; then
    "${PYTHON}" - "${INSTALL_ROOT}" <<'PY'
import shutil, sys
from pathlib import Path
root = Path(sys.argv[1])
if root == Path(root.anchor) or root == Path.home().resolve() or root.is_symlink():
    raise SystemExit("unsafe rollback root")
shutil.rmtree(root)
PY
  fi
}
rollback() {
  local status=$?
  if [ "${SUCCESS}" -ne 1 ]; then
    remove_new_root || true
    if [ -d "${BACKUP_ROOT}" ]; then mv "${BACKUP_ROOT}" "${INSTALL_ROOT}"; fi
    restore_file "${CONFIG_PATH}" config || true
    restore_file "${SETTINGS_PATH}" settings || true
    restore_file "${LAUNCHER_PATH}" launcher || true
    restore_file "${SHELL_PROFILE}" shell_profile || true
    restore_mode "${CONFIG_PATH}" config_acl || true
    restore_mode "$(dirname "${CONFIG_PATH}")" config_parent || true
    restore_mode "${DATA_ROOT}" data_root || true
  fi
  [ -n "${STATE_ROOT}" ] && rm -rf -- "${STATE_ROOT}"
  exit "${status}"
}
snapshot_file "${CONFIG_PATH}" config
snapshot_file "${SETTINGS_PATH}" settings
snapshot_file "${LAUNCHER_PATH}" launcher
snapshot_file "${SHELL_PROFILE}" shell_profile
snapshot_mode "${CONFIG_PATH}" config_acl
snapshot_mode "$(dirname "${CONFIG_PATH}")" config_parent
snapshot_mode "${DATA_ROOT}" data_root
trap rollback EXIT

if [ -d "${INSTALL_ROOT}" ]; then
  if [ -n "${EXISTING_VERSION}" ]; then mv "${INSTALL_ROOT}" "${BACKUP_ROOT}"; else rmdir "${INSTALL_ROOT}"; fi
fi
CONFIG_PARENT="$(dirname "${CONFIG_PATH}")"
CONFIG_PARENT_CREATED=0
DATA_ROOT_CREATED=0
[ -d "${CONFIG_PARENT}" ] || CONFIG_PARENT_CREATED=1
[ -d "${DATA_ROOT}" ] || DATA_ROOT_CREATED=1
"${PYTHON}" - "${CONFIG_PARENT}" "${DATA_ROOT}" "${EXISTING_VERSION}" <<'PY'
import os, stat, sys
from pathlib import Path
verified_upgrade = bool(sys.argv[3])
for raw in sys.argv[1:3]:
    path = Path(raw)
    if not path.exists():
        continue
    info = path.lstat()
    unsafe_identity = path.is_symlink() or not path.is_dir() or info.st_uid != os.getuid()
    unsafe_mode = stat.S_IMODE(info.st_mode) != 0o700
    if unsafe_identity or (unsafe_mode and not verified_upgrade):
        raise SystemExit(f"Refusing to adopt a non-private pre-existing Imprint directory: {path}")
PY
mkdir -p "${INSTALL_ROOT}" "${CONFIG_PARENT}" "${DATA_ROOT}"
if [ -n "${EXISTING_VERSION}" ]; then
  chmod 700 "${CONFIG_PARENT}" "${DATA_ROOT}"
else
  if [ "${CONFIG_PARENT_CREATED}" -eq 1 ]; then chmod 700 "${CONFIG_PARENT}"; fi
  if [ "${DATA_ROOT_CREATED}" -eq 1 ]; then chmod 700 "${DATA_ROOT}"; fi
fi
"${PYTHON}" -m venv "${INSTALL_ROOT}/venv"
"${INSTALL_ROOT}/venv/bin/python" -m pip install --disable-pip-version-check --no-index --find-links "${WHEELHOUSE}" --require-hashes --only-binary=:all: --force-reinstall -r "${RUNTIME_LOCK}"
cp -R "${ARTIFACT_ROOT}/hooks" "${INSTALL_ROOT}/hooks"
mkdir -p "${INSTALL_ROOT}/tools"
cp "${ARTIFACT_ROOT}/tools/install/manage_hooks.py" "${INSTALL_ROOT}/tools/manage_hooks.py"
cp "${ARTIFACT_ROOT}/tools/install/install_ownership.py" "${INSTALL_ROOT}/tools/install_ownership.py"

"${INSTALL_ROOT}/venv/bin/python" - "${CONFIG_PATH}" "${DATA_ROOT}" "${OPERATOR}" "${INSTALL_ROOT}/hooks" <<'PY'
import json, os, sys
from pathlib import Path
path, root, operator, hooks_dir = Path(sys.argv[1]), str(Path(sys.argv[2]).expanduser().resolve()), sys.argv[3], str(Path(sys.argv[4]).resolve())
value = {}
if path.exists():
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict): raise SystemExit("Existing config must contain a JSON object")
value.update({"config_version":"3.1.1", "data_root":root, "operator_slug":operator, "hooks_dir":hooks_dir})
value.setdefault("node_id", "primary")
value.setdefault("compiler", True)
value.setdefault("context_budget_bytes", 32768)
value.pop("experimental", None)
tmp = path.with_suffix(path.suffix + ".imprint-tmp")
tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(tmp, path)
os.chmod(path, 0o600)
PY

if [ "${REGISTER_HOOKS}" -eq 1 ]; then
  "${INSTALL_ROOT}/venv/bin/python" "${INSTALL_ROOT}/tools/manage_hooks.py" register \
    --settings "${SETTINGS_PATH}" --python "${INSTALL_ROOT}/venv/bin/python" --hooks-dir "${INSTALL_ROOT}/hooks"
fi
if [ -e "${LAUNCHER_PATH}" ] || [ -L "${LAUNCHER_PATH}" ]; then
  if [ ! -f "${LAUNCHER_PATH}" ] || ! grep -Fx '# imprint-local-owned-launcher' "${LAUNCHER_PATH}" >/dev/null; then
    echo "Refusing to replace an unowned launcher: ${LAUNCHER_PATH}" >&2
    exit 2
  fi
fi
mkdir -p "${LAUNCHER_DIR}"
"${PYTHON}" - "${LAUNCHER_PATH}" "${INSTALL_ROOT}/venv/bin/imprint" "${CONFIG_PATH}" <<'PY'
import os, shlex, sys
from pathlib import Path
path, executable, config = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
temporary = path.with_name(path.name + ".imprint-tmp")
temporary.write_text(
    "#!/bin/sh\n# imprint-local-owned-launcher\n"
    f"IMPRINT_CONFIG={shlex.quote(config)}\nexport IMPRINT_CONFIG\n"
    f"exec {shlex.quote(executable)} \"$@\"\n",
    encoding="utf-8",
)
os.chmod(temporary, 0o755)
os.replace(temporary, path)
PY
"${PYTHON}" - "${SHELL_PROFILE}" "${LAUNCHER_DIR}" <<'PY'
import re, shlex, sys
from pathlib import Path
path, launcher_dir = Path(sys.argv[1]), sys.argv[2]
prior = path.read_text(encoding="utf-8") if path.exists() else ""
prior = re.sub(
    r"# >>> imprint-local-owned-path(?::[^ ]+)? >>>\n.*?\n"
    r"# <<< imprint-local-owned-path(?::[^ ]+)? <<<\n?",
    "", prior, flags=re.DOTALL,
)
start = "# >>> imprint-local-owned-path >>>"
end = "# <<< imprint-local-owned-path <<<"
block = f'{start}\nexport PATH={shlex.quote(launcher_dir)}:"$PATH"\n{end}\n'
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(prior + ("\n" if prior and not prior.endswith("\n") else "") + block, encoding="utf-8")
PY
printf '%s\n' "${SHELL_PROFILE}" > "${INSTALL_ROOT}/.imprint-shell-profile"
printf '%s\n' "${LAUNCHER_DIR}" > "${INSTALL_ROOT}/.imprint-launcher-dir"
IMPRINT_CONFIG="${CONFIG_PATH}" "${INSTALL_ROOT}/venv/bin/imprint" version | grep -Fx "${PRODUCT_VERSION}" >/dev/null
PATH="${LAUNCHER_DIR}:${PATH}" imprint version | grep -Fx "${PRODUCT_VERSION}" >/dev/null
"${INSTALL_ROOT}/venv/bin/python" "${INSTALL_ROOT}/tools/install_ownership.py" record --root "${INSTALL_ROOT}"
if [ -d "${BACKUP_ROOT}" ]; then
  "${INSTALL_ROOT}/venv/bin/python" "${INSTALL_ROOT}/tools/install_ownership.py" uninstall --root "${BACKUP_ROOT}" \
    --expected-version "${EXISTING_VERSION}"
fi
printf 'imprint-local:%s\n' "${PRODUCT_VERSION}" > "${MARKER}.tmp"
mv "${MARKER}.tmp" "${MARKER}"
SUCCESS=1
rm -rf -- "${STATE_ROOT}"
STATE_ROOT=""
trap - EXIT
echo "Imprint ${PRODUCT_VERSION} installed. Launcher: ${LAUNCHER_PATH}. Data root: ${DATA_ROOT}. No telemetry is enabled."
