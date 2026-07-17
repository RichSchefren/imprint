from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hx(value: str) -> bytes:
    return bytes.fromhex(value)


def test_confidentiality_policy_allows_generic_public_ontology() -> None:
    policy = load("release_confidentiality_generic", "tools/release/confidentiality.py")
    payload = b"""
    imprint.node.decision-episode/1.0.0
    imprint.node.evidence-artifact/1.0.0
    SelfModelAssertion Observation Outcome Principle Verdict
    identity execution temporal relational evidence provenance authority
    observer_actor_version_id operator_authored approved_import
    """
    assert policy.scan_payload("generic-ontology.txt", payload) == []


@pytest.mark.parametrize("payload", [
    _hx("5a4d4f53"),
    _hx("5a656e697468204d696e64"),
    _hx("4469676974616c20444e41"),
    _hx("4f7065726174696e6720506f727472616974"),
    _hx("4d6972726f722053636f7265"),
    _hx("696d7072696e742e6e6f64652e63686f73656e2d6675747572652f312e302e30"),
    _hx("6f627365727665725f3132"),
    _hx("736861646f775f636f6e7374656c6c6174696f6e"),
])
def test_confidentiality_policy_rejects_each_private_signature(payload: bytes) -> None:
    policy = load("release_confidentiality_exact", "tools/release/confidentiality.py")
    assert policy.scan_payload("candidate.txt", payload)


def test_confidentiality_policy_rejects_private_five_class_structure() -> None:
    policy = load("release_confidentiality_structure", "tools/release/confidentiality.py")
    payload = b" ".join(_hx(value) for value in (
        "507379636865", "4964656e74697479", "52656c6174696f6e616c",
        "457865637574696f6e", "54656d706f72616c",
    ))
    assert policy.scan_payload("registry.py", payload) == [
        "private five-class structure: registry.py"
    ]


def test_confidentiality_policy_recurses_into_wheel_and_sdist() -> None:
    policy = load("release_confidentiality_archives", "tools/release/confidentiality.py")
    private_payload = _hx("7a6d6f732e7073796368652e6e61727261746976655f636f7265")

    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("imprint/ontology/extension.py", private_payload)
    wheel_findings = policy.scan_payload("candidate.whl", wheel.getvalue())
    assert any("candidate.whl!imprint/ontology/extension.py" in item for item in wheel_findings)

    sdist = io.BytesIO()
    with tarfile.open(fileobj=sdist, mode="w:gz") as archive:
        item = tarfile.TarInfo("package/src/imprint/ontology/extension.py")
        item.size = len(private_payload)
        archive.addfile(item, io.BytesIO(private_payload))
    sdist_findings = policy.scan_payload("candidate.tar.gz", sdist.getvalue())
    assert any("candidate.tar.gz!package/src/imprint/ontology/extension.py" in item for item in sdist_findings)


def test_confidentiality_policy_does_not_match_its_encoded_rules() -> None:
    policy_path = ROOT / "tools" / "release" / "confidentiality.py"
    policy = load("release_confidentiality_self", "tools/release/confidentiality.py")
    assert policy.scan_payload(policy_path.name, policy_path.read_bytes()) == []


def test_release_builder_runs_recursive_confidentiality_gate() -> None:
    script = (ROOT / "tools" / "release" / "package.py").read_text(encoding="utf-8")
    assert "confidentiality_failures = scan_paths(" in script
    assert "release confidentiality scan failed" in script
    allowlist = (ROOT / "release" / "allowlist.txt").read_text(encoding="utf-8").splitlines()
    assert "tools/release/confidentiality.py" in allowlist
    assert "tools/release/scan_public.py" in allowlist


def test_zip_symlink_is_rejected_by_verifier_and_extractor(tmp_path: Path) -> None:
    verifier = load("verify_artifacts_for_zip", "tools/release/verify_artifacts.py")
    extractor = load("extract_safe_for_zip", "tools/release/extract_safe.py")
    archive = tmp_path / "hostile.zip"
    with zipfile.ZipFile(archive, "w") as output:
        item = zipfile.ZipInfo("imprint-3.1.1/link")
        item.create_system = 3
        item.external_attr = (stat.S_IFLNK | 0o777) << 16
        output.writestr(item, "../../outside")
    with pytest.raises(RuntimeError, match="link or special"):
        verifier.inspect_zip(archive)
    with pytest.raises(RuntimeError, match="link or special"):
        extractor.extract_zip(archive, tmp_path / "zip-output")
    assert not (tmp_path / "outside").exists()


def test_tar_link_and_traversal_are_rejected(tmp_path: Path) -> None:
    extractor = load("extract_safe_for_tar", "tools/release/extract_safe.py")
    link_archive = tmp_path / "link.tar.gz"
    with tarfile.open(link_archive, "w:gz") as output:
        item = tarfile.TarInfo("imprint-3.1.1/link")
        item.type = tarfile.SYMTYPE
        item.linkname = "../../outside"
        output.addfile(item)
    with pytest.raises(RuntimeError, match="link or special"):
        extractor.extract_tar(link_archive, tmp_path / "tar-link-output")

    traversal_archive = tmp_path / "traversal.tar.gz"
    with tarfile.open(traversal_archive, "w:gz") as output:
        payload = b"escape"
        item = tarfile.TarInfo("../outside")
        item.size = len(payload)
        output.addfile(item, io.BytesIO(payload))
    with pytest.raises(RuntimeError, match="unsafe archive path"):
        extractor.extract_tar(traversal_archive, tmp_path / "tar-traversal-output")
    assert not (tmp_path / "outside").exists()


def test_ownership_manifest_refuses_unknown_or_mutated_files(tmp_path: Path) -> None:
    ownership = load("install_ownership_for_test", "tools/install/install_ownership.py")
    root = tmp_path / "install"
    root.mkdir()
    owned = root / "owned.txt"
    owned.write_text("original", encoding="utf-8")
    ownership.record(root)
    (root / ownership.MARKER).write_text("imprint-local:3.1.1\n", encoding="ascii")
    unknown = root / "unknown.txt"
    unknown.write_text("leave me", encoding="utf-8")
    with pytest.raises(SystemExit, match="unowned paths"):
        ownership.verify(root)
    assert unknown.read_text(encoding="utf-8") == "leave me"
    unknown.unlink()
    owned.write_text("changed", encoding="utf-8")
    with pytest.raises(SystemExit, match="changed since installation"):
        ownership.verify(root)


def test_ownership_manifest_ignores_and_removes_runtime_bytecode(tmp_path: Path) -> None:
    ownership = load("install_ownership_for_runtime_cache", "tools/install/install_ownership.py")
    root = tmp_path / "install"
    cache = root / "hooks" / "__pycache__"
    cache.mkdir(parents=True)
    (root / "hooks" / "bridge.py").write_text("pass\n", encoding="utf-8")
    bytecode = cache / "bridge.cpython-314.pyc"
    bytecode.write_bytes(b"before")
    ownership.record(root)
    (root / ownership.MARKER).write_text("imprint-local:3.1.1\n", encoding="ascii")

    entries = json.loads((root / ownership.MANIFEST).read_text(encoding="utf-8"))["entries"]
    assert not any("__pycache__" in entry["path"] for entry in entries)
    bytecode.write_bytes(b"after ordinary hook execution")
    ownership.uninstall(root)
    assert not root.exists()


def test_ownership_tool_accepts_only_closed_upgrade_versions(tmp_path: Path) -> None:
    ownership = load("install_ownership_for_upgrade", "tools/install/install_ownership.py")
    root = tmp_path / "legacy-install"
    root.mkdir()
    (root / "owned.txt").write_text("legacy", encoding="utf-8")
    ownership.record(root)
    manifest = root / ownership.MANIFEST
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["version"] = "3.0.0"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    (root / ownership.MARKER).write_text("imprint-local:3.0.0\n", encoding="ascii")
    ownership.verify(root, "3.0.0")
    with pytest.raises(SystemExit, match="unsupported install ownership version"):
        ownership.verify(root, "2.9.9")


def test_v300_recorded_runtime_bytecode_may_change_before_upgrade(tmp_path: Path) -> None:
    ownership = load("install_ownership_v300_cache", "tools/install/install_ownership.py")
    root = tmp_path / "install"
    cache = root / "hooks" / "__pycache__"
    cache.mkdir(parents=True)
    source = root / "hooks" / "bridge.py"
    source.write_text("pass\n", encoding="utf-8")
    bytecode = cache / "bridge.cpython-311.pyc"
    bytecode.write_bytes(b"recorded-v300-cache")
    ownership.record(root)
    manifest_path = root / ownership.MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "3.0.0"
    manifest["entries"].extend([
        ownership._entry(cache, root),
        ownership._entry(bytecode, root),
    ])
    manifest["entries"].sort(key=lambda item: item["path"])
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / ownership.MARKER).write_text("imprint-local:3.0.0\n", encoding="ascii")

    bytecode.write_bytes(b"changed-by-ordinary-hook-use")
    ownership.uninstall(root, "3.0.0")
    assert not root.exists()


def test_embedded_provenance_validates_revision_and_dist_hashes() -> None:
    verifier = load("verify_artifacts_for_provenance", "tools/release/verify_artifacts.py")
    wheel = b"wheel-bytes"
    sdist = b"sdist-bytes"
    revision = "a" * 40
    provenance = {
        "format": 1,
        "product": "imprint-local",
        "version": "3.1.1",
        "source_revision": revision,
        "source_tree_sha256": "b" * 64,
        "python_distributions": [
            {
                "fileName": "imprint_local-3.1.1-py3-none-any.whl",
                "sha256": hashlib.sha256(wheel).hexdigest(),
                "size": len(wheel),
            },
            {
                "fileName": "imprint_local-3.1.1.tar.gz",
                "sha256": hashlib.sha256(sdist).hexdigest(),
                "size": len(sdist),
            },
        ],
    }
    files = {
        "imprint-3.1.1/dist/imprint_local-3.1.1-py3-none-any.whl": wheel,
        "imprint-3.1.1/dist/imprint_local-3.1.1.tar.gz": sdist,
        "imprint-3.1.1/release/BUILD-PROVENANCE.json": json.dumps(provenance).encode(),
    }
    verifier.validate_provenance(files, revision, "b" * 64)
    with pytest.raises(RuntimeError, match="expected revision"):
        verifier.validate_provenance(files, "c" * 40)
    with pytest.raises(RuntimeError, match="source digest"):
        verifier.validate_provenance(files, revision, "c" * 64)
    files["imprint-3.1.1/dist/imprint_local-3.1.1-py3-none-any.whl"] = b"tampered"
    with pytest.raises(RuntimeError, match="digest mismatch"):
        verifier.validate_provenance(files, revision)


def test_windows_uninstaller_stages_cleanup_outside_owned_venv() -> None:
    script = (ROOT / "install" / "uninstall.ps1").read_text(encoding="utf-8")
    assert "sys._base_executable" in script
    assert "cleanup interpreter is inside the owned install root" in script
    stage_tool = script.index("Copy-Item $Ownership $StagedOwnership")
    stage_version = script.index("Copy-Item $VersionSource $StagedVersion")
    external_verify = script.index("& $BasePython -I -S $StagedOwnership verify --root $InstallRoot")
    unregister = script.index("$Manager unregister")
    uninstall = script.index("& $BasePython -I -S $StagedOwnership uninstall --root $InstallRoot")
    assert stage_tool < stage_version < external_verify < unregister < uninstall
    assert "& $Python $Ownership uninstall --root $InstallRoot" not in script


def test_staged_ownership_tool_uses_copied_authoritative_version_without_distribution_metadata(tmp_path: Path) -> None:
    ownership = load("install_ownership_for_staging", "tools/install/install_ownership.py")
    root = tmp_path / "install"
    root.mkdir()
    (root / "owned.txt").write_text("owned\n", encoding="utf-8")
    ownership.record(root)
    (root / ownership.MARKER).write_text(f"imprint-local:{ownership.VERSION}\n", encoding="ascii")

    staging = tmp_path / "external-cleanup"
    staging.mkdir()
    staged_tool = staging / "install_ownership.py"
    staged_version = staging / "_version.py"
    staged_tool.write_bytes((ROOT / "tools" / "install" / "install_ownership.py").read_bytes())
    staged_version.write_bytes((ROOT / "src" / "imprint" / "_version.py").read_bytes())

    verify = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(staged_tool),
            "verify",
            "--root",
            str(root),
            "--expected-version",
            ownership.VERSION,
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
    )
    assert verify.returncode == 0, verify.stderr

    rejected = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(staged_tool),
            "verify",
            "--root",
            str(root),
            "--expected-version",
            "9.9.9",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
    )
    assert rejected.returncode != 0
    assert "invalid choice" in rejected.stderr

    removed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(staged_tool),
            "uninstall",
            "--root",
            str(root),
            "--expected-version",
            ownership.VERSION,
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
    )
    assert removed.returncode == 0, removed.stderr
    assert not root.exists()


def test_windows_installer_sets_exact_private_acl_after_owner() -> None:
    script = (ROOT / "install" / "install.ps1").read_text(encoding="utf-8")
    owner = script.index('/setowner "*$Sid"')
    protection = script.index("SetAccessRuleProtection($true, $false)")
    purge = script.index("RemoveAccessRuleSpecific")
    grants = script.index("FileSystemAccessRule]::new")
    apply_acl = script.index("Set-Acl -LiteralPath $Path -AclObject $Acl")
    assert owner < protection < purge < grants < apply_acl


def test_windows_install_and_authority_paths_never_request_elevation() -> None:
    """Hosted CI may be elevated; shipped Imprint must never elevate itself."""
    paths = (
        ROOT / "install" / "install.ps1",
        ROOT / "install" / "uninstall.ps1",
        ROOT / "tests" / "acceptance" / "test_authority_windows.ps1",
        ROOT / "src" / "imprint" / "authority" / "tty.py",
        ROOT / "src" / "imprint" / "authority" / "service.py",
    )
    text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    forbidden = (
        "-verb runas",
        "runas.exe",
        "shellexecuteex",
        "requireadministrator",
        "net localgroup administrators",
        "start-process -credential",
    )
    assert all(value not in text for value in forbidden)


def test_windows_native_authority_ci_uses_ephemeral_standard_user_conpty() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    acceptance = (ROOT / "tests" / "acceptance" / "test_authority_windows.ps1").read_text(
        encoding="utf-8"
    )
    driver = (ROOT / "tools" / "ci" / "windows_authority_driver.py").read_text(
        encoding="utf-8"
    )
    assert "New-LocalUser" in workflow
    assert "Add-LocalGroupMember -Group 'Users'" in workflow
    assert "Remove-LocalUser -Name $User" in workflow
    created = workflow.index("New-LocalUser")
    cleanup_scope = workflow.index("try {", created)
    added = workflow.index("Add-LocalGroupMember", cleanup_scope)
    removed = workflow.index("Remove-LocalUser -Name $User", added)
    assert created < cleanup_scope < added < removed
    assert "Start-Process -FilePath $Python" in workflow
    assert "-Credential $Credential" in workflow
    assert "-Environment $StandardEnvironment" in workflow
    assert "APPDATA = $Result; LOCALAPPDATA = $Result" in workflow
    assert 'command = [pwsh, "-NoLogo", "-NoProfile", "-Command", powershell]' in driver
    assert "PtyProcess.spawn(command" in driver
    assert 'child.write(exact_match.group(1) + "\\r")' in driver
    assert 'child.write(secret + "\\r")' in driver
    assert 'child.write(secret + "\\r\\n")' not in driver
    assert "runas.exe" not in workflow
    assert "windows_authority_driver.py" in workflow
    assert 'if "native Windows authority: PASS" not in output:' in driver
    assert "Acceptance must run non-admin" in acceptance
    assert "$acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])" in acceptance


def test_windows_acl_inspection_is_utf8_and_fail_closed() -> None:
    script = (ROOT / "src" / "imprint" / "permissions.py").read_text(encoding="utf-8")
    assert "def _secure_windows_paths" in script
    assert "$existingAcl.GetOwner([Security.Principal.SecurityIdentifier])" in script
    assert "[Security.AccessControl.DirectorySecurity]::new()" in script
    assert "[Security.AccessControl.FileSecurity]::new()" in script
    assert "RemoveAccessRuleSpecific" not in script
    assert "[IO.FileSystemAclExtensions]::SetAccessControl(" in script
    assert "Set-Acl -LiteralPath $path" not in script
    assert "refusing private state not owned by the current user" in script
    assert "$owner.Value -eq 'S-1-5-32-544'" in script
    assert "$isAdmin -and $owner.Value" in script
    assert "$acl.SetOwner($current)" in script
    assert "$acl.SetAccessRuleProtection($true, $false)" in script
    assert "if target.parent.absolute() not in _WINDOWS_HARDENED_DIRECTORIES" in script
    assert "_secure_windows_paths([*parents, *targets])" in script
    assert "Exact leaves must" in script
    assert "candidates.extend(sorted(target.iterdir()" in script
    assert "_secure_windows_paths(candidates)" in script
    assert "_cache_hardened_windows_directories(paths)" in script
    assert 'shutil.which("pwsh.exe") or shutil.which("powershell.exe")' in script
    assert '[Console]::InputEncoding = $utf8' in script
    assert '[Console]::OutputEncoding = $utf8' in script
    assert 'encoding="utf-8"' in script
    assert 'return ("<acl-inspection-failed>",)' in script

    authority = (ROOT / "src" / "imprint" / "authority" / "service.py").read_text(
        encoding="utf-8"
    )
    reconcile = authority.index("def reconcile(")
    inspect_permissions = authority.index("unsafe_private_permissions(keys_dir)", reconcile)
    prepare_missing = authority.index("keys_dir = prepare_key_directory", reconcile)
    quarantine = authority.index("quarantine = secure_directory", reconcile)
    assert reconcile < inspect_permissions < prepare_missing < quarantine


def test_release_provenance_covers_every_shipped_and_build_input() -> None:
    package = load("package_for_provenance_test", "tools/release/package.py")
    verifier = load("verify_source_tree_digest", "tools/release/verify_artifacts.py")
    allowlist = verifier.git_allowlist(ROOT, "HEAD")
    relative = {path.relative_to(ROOT).as_posix() for path in package.release_inputs(allowlist)}
    assert set(allowlist) <= relative
    assert {".gitignore", "pyproject.toml", "tools/release/package.py"} <= relative
    assert {path.relative_to(ROOT).as_posix() for path in (ROOT / "src").rglob("*.py")} <= relative
    script = (ROOT / "tools" / "release" / "package.py").read_text(encoding="utf-8")
    assert "refusing a release build from a dirty worktree" in script
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT, text=True, capture_output=True, check=True,
    )
    if status.stdout.strip():
        # Digests are deliberately bound to committed blobs; the packaging
        # entry point separately refuses every dirty worktree.
        assert verifier.source_tree_digest(ROOT) == package.source_digest(allowlist)
        with pytest.raises(RuntimeError, match="dirty worktree"):
            package.source_revision()
    else:
        assert verifier.source_tree_digest(ROOT) == package.source_digest(allowlist)


def _git_bound_release_files(verifier) -> dict[str, bytes]:
    prefix = "imprint-3.1.1/"
    files = {
        prefix + relative: verifier.git_blob(ROOT, "HEAD", relative)
        for relative in verifier.git_allowlist(ROOT, "HEAD")
    }
    sources = {
        relative.removeprefix("src/"): verifier.git_blob(ROOT, "HEAD", relative)
        for relative in verifier.git_source_paths(ROOT, "HEAD")
    }
    wheel_output = io.BytesIO()
    dist_info = "imprint_local-3.1.1.dist-info/"
    with zipfile.ZipFile(wheel_output, "w") as wheel:
        def add(name: str, content: bytes | str) -> None:
            item = zipfile.ZipInfo(name)
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | 0o644) << 16
            wheel.writestr(item, content)
        for name, content in sources.items():
            add(name, content)
        add(dist_info + "licenses/LICENSE", verifier.git_blob(ROOT, "HEAD", "LICENSE"))
        add(dist_info + "METADATA", "Metadata-Version: 2.4\nName: imprint-local\nVersion: 3.1.1\nRequires-Python: <3.15,>=3.10\n")
        add(dist_info + "WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        add(dist_info + "entry_points.txt", "[console_scripts]\nimprint = imprint.cli:main\n")
        add(dist_info + "top_level.txt", "imprint\n")
        add(dist_info + "RECORD", "")
    files[prefix + "dist/imprint_local-3.1.1-py3-none-any.whl"] = wheel_output.getvalue()

    sdist_output = io.BytesIO()
    sdist_prefix = "imprint_local-3.1.1/"
    sdist_payload = {
        **{sdist_prefix + "src/" + name: content for name, content in sources.items()},
        **{sdist_prefix + name: verifier.git_blob(ROOT, "HEAD", name) for name in ("LICENSE", "README.md", "pyproject.toml")},
        sdist_prefix + "PKG-INFO": b"Metadata-Version: 2.4\nName: imprint-local\nVersion: 3.1.1\nRequires-Python: <3.15,>=3.10\n",
        sdist_prefix + "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n\n",
    }
    for name in ("PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "requires.txt", "top_level.txt"):
        sdist_payload[sdist_prefix + "src/imprint_local.egg-info/" + name] = b""
    with tarfile.open(fileobj=sdist_output, mode="w:gz") as sdist:
        for name, content in sorted(sdist_payload.items()):
            item = tarfile.TarInfo(name)
            item.size = len(content)
            sdist.addfile(item, io.BytesIO(content))
    files[prefix + "dist/imprint_local-3.1.1.tar.gz"] = sdist_output.getvalue()
    files[prefix + "release/BUILD-PROVENANCE.json"] = b"{}"
    files[prefix + "release/SBOM.spdx.json"] = b"{}"
    return files


def test_git_binding_accepts_exact_independent_source_payloads() -> None:
    verifier = load("verify_git_bound_baseline", "tools/release/verify_artifacts.py")
    verifier.validate_source_bindings(_git_bound_release_files(verifier), ROOT, "HEAD")


@pytest.mark.parametrize("relative", ["hooks/_bridge.py", "install/install.sh"])
def test_git_binding_rejects_mutated_public_hook_or_installer(relative: str) -> None:
    verifier = load("verify_git_bound_outer", "tools/release/verify_artifacts.py")
    files = _git_bound_release_files(verifier)
    files["imprint-3.1.1/" + relative] += b"\nmalicious mutation\n"
    with pytest.raises(RuntimeError, match="differs from Git blob"):
        verifier.validate_source_bindings(files, ROOT, "HEAD")


def test_git_binding_rejects_mutated_wheel_python_payload() -> None:
    verifier = load("verify_git_bound_wheel", "tools/release/verify_artifacts.py")
    files = _git_bound_release_files(verifier)
    key = "imprint-3.1.1/dist/imprint_local-3.1.1-py3-none-any.whl"
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(files[key])) as source, zipfile.ZipFile(output, "w") as target:
        for item in source.infolist():
            content = source.read(item)
            if item.filename == "imprint/backup.py":
                content += b"\n# malicious wheel mutation\n"
            target.writestr(item, content)
    files[key] = output.getvalue()
    with pytest.raises(RuntimeError, match="wheel Python payload"):
        verifier.validate_source_bindings(files, ROOT, "HEAD")


def test_git_binding_rejects_mutated_sdist_python_payload() -> None:
    verifier = load("verify_git_bound_sdist", "tools/release/verify_artifacts.py")
    files = _git_bound_release_files(verifier)
    key = "imprint-3.1.1/dist/imprint_local-3.1.1.tar.gz"
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(files[key]), mode="r:gz") as source:
        records = []
        for item in source.getmembers():
            extracted = source.extractfile(item) if item.isfile() else None
            content = extracted.read() if extracted is not None else None
            if item.name.endswith("/src/imprint/backup.py"):
                content = (content or b"") + b"\n# malicious sdist mutation\n"
                item.size = len(content)
            records.append((item, content))
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        for item, content in records:
            target.addfile(item, io.BytesIO(content) if content is not None else None)
    files[key] = output.getvalue()
    with pytest.raises(RuntimeError, match="sdist payload"):
        verifier.validate_source_bindings(files, ROOT, "HEAD")
