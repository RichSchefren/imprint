from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_posix_installer_rejects_unsafe_adoption_and_only_chmods_created_roots():
    source = _read("install/install.sh")
    assert "Refusing to adopt a non-private pre-existing Imprint directory" in source
    assert 'if [ "${CONFIG_PARENT_CREATED}" -eq 1 ]; then chmod 700' in source
    assert 'if [ "${DATA_ROOT_CREATED}" -eq 1 ]; then chmod 700' in source


def test_windows_installer_rejects_unsafe_adoption_and_only_acls_created_roots():
    source = _read("install/install.ps1")
    assert "Refusing to adopt a non-private pre-existing Imprint directory" in source
    assert "if ($ConfigParentCreated) { Set-PrivateAcl $ConfigParent }" in source
    assert "if ($DataRootCreated) { Set-PrivateAcl $DataRoot }" in source


def test_launchers_and_path_blocks_are_version_agnostic_and_location_is_recorded():
    posix_install = _read("install/install.sh")
    posix_uninstall = _read("install/uninstall.sh")
    windows_install = _read("install/install.ps1")
    windows_uninstall = _read("install/uninstall.ps1")
    assert "# imprint-local-owned-launcher" in posix_install
    assert "# imprint-local-owned-launcher:" not in posix_install
    assert "# >>> imprint-local-owned-path >>>" in posix_install
    assert ".imprint-launcher-dir" in posix_install and ".imprint-launcher-dir" in posix_uninstall
    assert "rem imprint-local-owned-launcher" in windows_install
    assert ".imprint-launcher-dir" in windows_install and ".imprint-launcher-dir" in windows_uninstall
    assert "--expected-version" in posix_uninstall and "--expected-version" in windows_uninstall
