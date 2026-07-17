from __future__ import annotations

import runpy
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility.
    import tomli as tomllib

from imprint import __version__
from imprint.constants import PRODUCT_VERSION


ROOT = Path(__file__).resolve().parents[2]


def test_runtime_and_build_metadata_share_one_version_source():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "imprint._version.__version__"
    }
    assert PRODUCT_VERSION == __version__ == "3.1.1"


def test_release_and_install_tools_consume_authoritative_version():
    for relative, name in (
        ("tools/release/package.py", "VERSION"),
        ("tools/release/build_wheelhouse.py", "PRODUCT_VERSION"),
        ("tools/release/verify_artifacts.py", "VERSION"),
        ("tools/install/verify_wheelhouse.py", "PRODUCT_VERSION"),
        ("tools/install/install_ownership.py", "VERSION"),
    ):
        values = runpy.run_path(str(ROOT / relative), run_name=f"test_{relative}")
        assert values[name] == __version__
