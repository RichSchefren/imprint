[CmdletBinding()]
param(
    [string]$InstallRoot = $(if ($env:IMPRINT_INSTALL_ROOT) { $env:IMPRINT_INSTALL_ROOT } else { Join-Path $env:LOCALAPPDATA "ImprintApp\app" }),
    [string]$Config = $(if ($env:IMPRINT_CONFIG) { $env:IMPRINT_CONFIG } else { Join-Path $env:APPDATA "Imprint\config.json" }),
    [string]$Settings = $(if ($env:CLAUDE_SETTINGS_PATH) { $env:CLAUDE_SETTINGS_PATH } else { Join-Path $env:USERPROFILE ".claude\settings.json" }),
    [string]$DataRoot = $(if ($env:IMPRINT_DATA_ROOT) { $env:IMPRINT_DATA_ROOT } else { Join-Path $env:LOCALAPPDATA "Imprint" }),
    [string]$LauncherDir = $(if ($env:IMPRINT_LAUNCHER_DIR) { $env:IMPRINT_LAUNCHER_DIR } else { Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps" }),
    [string]$Operator = "default",
    [string]$Python = "python",
    [switch]$NoHooks
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArtifactRoot = Split-Path -Parent $ScriptDir

function Set-PrivateAcl([string]$Path) {
    $Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $Item = Get-Item $Path -Force
    & icacls.exe $Path /setowner "*$Sid" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to set the private Imprint path owner: $Path" }
    $Acl = Get-Acl -LiteralPath $Path
    $Acl.SetAccessRuleProtection($true, $false)
    foreach ($Rule in @($Acl.Access)) { [void]$Acl.RemoveAccessRuleSpecific($Rule) }
    $Inheritance = if ($Item.PSIsContainer) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($AllowedSid in @($Sid, "S-1-5-18")) {
        $Identity = [Security.Principal.SecurityIdentifier]::new($AllowedSid)
        $Grant = [Security.AccessControl.FileSystemAccessRule]::new(
            $Identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $Inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$Acl.AddAccessRule($Grant)
    }
    Set-Acl -LiteralPath $Path -AclObject $Acl
}

function Assert-SafePathChain([string]$Path) {
    $Full = [IO.Path]::GetFullPath($Path)
    $Current = [IO.Path]::GetPathRoot($Full)
    foreach ($Part in $Full.Substring($Current.Length).Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)) {
        $Current = Join-Path $Current $Part
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -Force -LiteralPath $Current
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing a reparse-point path component before mutation: $Current"
            }
        }
    }
}

if ($Operator -notmatch '^[a-z0-9][a-z0-9-]*$') { throw "Operator must use lowercase letters, digits, and hyphens." }
& $Python -c "import platform,sys,sysconfig; raise SystemExit(0 if platform.python_implementation() == 'CPython' and (3,10) <= sys.version_info[:2] <= (3,14) and not sysconfig.get_config_var('Py_GIL_DISABLED') else 2)"
if ($LASTEXITCODE -ne 0) { throw "Standard GIL-enabled CPython 3.10 through 3.14 is required." }
$ProductVersion = (& $Python -c "import runpy,sys; print(runpy.run_path(sys.argv[1])['__version__'])" (Join-Path $ArtifactRoot "src\imprint\_version.py")).Trim()
if ($LASTEXITCODE -ne 0 -or $ProductVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Unable to read the authoritative Imprint version." }
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$VolumeRoot = [IO.Path]::GetPathRoot($InstallRoot)
if ($InstallRoot -eq $VolumeRoot -or $InstallRoot -eq [IO.Path]::GetFullPath($env:USERPROFILE)) { throw "Refusing an unsafe install root: $InstallRoot" }
$Marker = Join-Path $InstallRoot ".imprint-install-root"
$Launcher = Join-Path ([IO.Path]::GetFullPath($LauncherDir)) "imprint.cmd"
foreach ($Candidate in @($InstallRoot, $Config, $Settings, $DataRoot, $Launcher)) { Assert-SafePathChain $Candidate }
$ExistingVersion = $null
if (Test-Path $InstallRoot) {
    $item = Get-Item $InstallRoot -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing a reparse-point install root: $InstallRoot" }
    $children = @(Get-ChildItem $InstallRoot -Force)
    if ($children.Count -gt 0) {
        if (-not (Test-Path $Marker -PathType Leaf)) { throw "Refusing a non-empty install root not owned by Imprint: $InstallRoot" }
        $MarkerText = Get-Content -Raw $Marker
        if ($MarkerText -eq "imprint-local:3.0.0`n") { $ExistingVersion = "3.0.0" }
        elseif ($MarkerText -eq "imprint-local:3.0.1`n") { $ExistingVersion = "3.0.1" }
        elseif ($MarkerText -eq "imprint-local:3.1.0`n") { $ExistingVersion = "3.1.0" }
        elseif ($MarkerText -eq "imprint-local:3.1.1`n") { $ExistingVersion = "3.1.1" }
        else { throw "Refusing an unsupported Imprint install version: $MarkerText" }
        & $Python (Join-Path $ArtifactRoot "tools\install\install_ownership.py") verify --root $InstallRoot --expected-version $ExistingVersion
        if ($LASTEXITCODE -ne 0) { throw "Existing installation ownership verification failed." }
    }
}
Write-Warning "Before extraction or execution, verify this complete archive with the full GitHub attestation policy documented for v3.1.1. Internal hashes establish component integrity only, not public provenance."
$Verifier = Join-Path $ArtifactRoot "tools\install\verify_wheelhouse.py"
$ExpectedVerifierSha256 = "783a44343f848e969869242e488d14485dfd851c9e2018debe18c2eeab8ff9d5"
$ManifestDigestFile = Join-Path $ArtifactRoot "release\wheelhouse\manifest.sha256"
if (-not (Test-Path $Verifier -PathType Leaf) -or -not (Test-Path $ManifestDigestFile -PathType Leaf)) { throw "The release artifact is missing its pinned offline verifier or manifest digest." }
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Verifier).Hash.ToLowerInvariant() -ne $ExpectedVerifierSha256) { throw "Offline verifier digest mismatch." }
$ManifestSha256 = (Get-Content -Raw -LiteralPath $ManifestDigestFile).Trim()
& $Python $Verifier --root $ArtifactRoot --lane windows --manifest-sha256 $ManifestSha256
if ($LASTEXITCODE -ne 0) { throw "Offline wheelhouse verification failed." }
$Wheelhouse = Join-Path $ArtifactRoot "release\wheelhouse\windows"
$RuntimeLock = Join-Path $ArtifactRoot "requirements\runtime-windows.lock"

$StateRoot = Join-Path ([IO.Path]::GetTempPath()) ("imprint-install-state-" + [guid]::NewGuid())
$BackupRoot = "$InstallRoot.imprint-backup.$PID"
if (Test-Path $BackupRoot) { throw "Refusing to overwrite stale install backup: $BackupRoot" }
New-Item -ItemType Directory -Path $StateRoot | Out-Null
function Save-StateFile([string]$Path, [string]$Name) {
    if (Test-Path $Path -PathType Leaf) { Copy-Item $Path (Join-Path $StateRoot $Name) }
    else { New-Item -ItemType File -Path (Join-Path $StateRoot "$Name.absent") | Out-Null }
}
function Restore-StateFile([string]$Path, [string]$Name) {
    if (Test-Path (Join-Path $StateRoot "$Name.absent")) { Remove-Item $Path -Force -ErrorAction SilentlyContinue }
    else { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null; Copy-Item -Force (Join-Path $StateRoot $Name) $Path }
}
function Save-PathAcl([string]$Path, [string]$Name) {
    if (Test-Path $Path) { [IO.File]::WriteAllText((Join-Path $StateRoot "$Name.acl.sddl"), (Get-Acl -LiteralPath $Path).Sddl, [Text.Encoding]::ASCII) }
    else { New-Item -ItemType File -Path (Join-Path $StateRoot "$Name.acl.absent") | Out-Null }
}
function Restore-PathAcl([string]$Path, [string]$Name) {
    $Saved = Join-Path $StateRoot "$Name.acl.sddl"
    if ((Test-Path $Saved -PathType Leaf) -and (Test-Path $Path)) {
        $Acl = Get-Acl -LiteralPath $Path
        $Acl.SetSecurityDescriptorSddlForm([IO.File]::ReadAllText($Saved, [Text.Encoding]::ASCII))
        Set-Acl -LiteralPath $Path -AclObject $Acl
    } elseif ((Test-Path (Join-Path $StateRoot "$Name.acl.absent") -PathType Leaf) -and (Test-Path $Path -PathType Container)) {
        Remove-Item $Path -ErrorAction SilentlyContinue
    }
}
Save-StateFile $Config "config"
Save-StateFile $Settings "settings"
Save-StateFile $Launcher "launcher"
Save-PathAcl $Config "config"
Save-PathAcl (Split-Path -Parent $Config) "config-parent"
Save-PathAcl $DataRoot "data-root"
$Succeeded = $false
try {
    if (Test-Path $InstallRoot) {
        if ($ExistingVersion) { Move-Item $InstallRoot $BackupRoot } else { Remove-Item $InstallRoot }
    }
    $ConfigParent = Split-Path -Parent $Config
    $ConfigParentCreated = -not (Test-Path $ConfigParent)
    $DataRootCreated = -not (Test-Path $DataRoot)
    foreach ($PrivateRoot in @($ConfigParent, $DataRoot)) {
        if (Test-Path $PrivateRoot) {
            $PrivateItem = Get-Item -Force -LiteralPath $PrivateRoot
            $PrivateAcl = Get-Acl -LiteralPath $PrivateRoot
            $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $OwnerSid = $PrivateAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            $ForeignAllow = @($PrivateAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
                $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $_.IdentityReference.Value -notin @($CurrentSid, 'S-1-5-18')
            })
            $UnsafeIdentity = (($PrivateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $OwnerSid -ne $CurrentSid)
            $UnsafeAcl = ($ForeignAllow.Count -gt 0)
            if ($UnsafeIdentity -or ($UnsafeAcl -and -not $ExistingVersion)) {
                throw "Refusing to adopt a non-private pre-existing Imprint directory: $PrivateRoot"
            }
        }
    }
    New-Item -ItemType Directory -Force -Path $InstallRoot, $ConfigParent, $DataRoot | Out-Null
    if ($ExistingVersion) {
        Set-PrivateAcl $ConfigParent
        Set-PrivateAcl $DataRoot
    } else {
        if ($ConfigParentCreated) { Set-PrivateAcl $ConfigParent }
        if ($DataRootCreated) { Set-PrivateAcl $DataRoot }
    }
    & $Python -m venv (Join-Path $InstallRoot "venv")
    if ($LASTEXITCODE -ne 0) { throw "Unable to create the isolated Imprint environment." }
    $VenvPython = Join-Path $InstallRoot "venv\Scripts\python.exe"
    & $VenvPython -m pip install --disable-pip-version-check --no-index --find-links $Wheelhouse --require-hashes --only-binary=:all: --force-reinstall -r $RuntimeLock
    if ($LASTEXITCODE -ne 0) { throw "Unable to install the Imprint wheel." }

    $HookTarget = Join-Path $InstallRoot "hooks"
    $ToolTarget = Join-Path $InstallRoot "tools"
    Copy-Item (Join-Path $ArtifactRoot "hooks") $HookTarget -Recurse
    New-Item -ItemType Directory -Force -Path $ToolTarget | Out-Null
    Copy-Item (Join-Path $ArtifactRoot "tools\install\manage_hooks.py") (Join-Path $ToolTarget "manage_hooks.py")
    Copy-Item (Join-Path $ArtifactRoot "tools\install\install_ownership.py") (Join-Path $ToolTarget "install_ownership.py")

    $ConfigValue = @{}
    if (Test-Path $Config) {
        $parsed = Get-Content -Raw $Config | ConvertFrom-Json -AsHashtable
        if ($parsed) { $ConfigValue = $parsed }
    }
    $ConfigValue["config_version"] = "3.1.1"
    $ConfigValue["data_root"] = [IO.Path]::GetFullPath($DataRoot)
    $ConfigValue["operator_slug"] = $Operator
    $ConfigValue["hooks_dir"] = [IO.Path]::GetFullPath($HookTarget)
    if (-not $ConfigValue.ContainsKey("node_id")) { $ConfigValue["node_id"] = "primary" }
    if (-not $ConfigValue.ContainsKey("compiler")) { $ConfigValue["compiler"] = $true }
    if (-not $ConfigValue.ContainsKey("context_budget_bytes")) { $ConfigValue["context_budget_bytes"] = 32768 }
    [void]$ConfigValue.Remove("experimental")
    $TempConfig = "$Config.imprint-tmp"
    $ConfigValue | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $TempConfig
    Move-Item -Force $TempConfig $Config
    Set-PrivateAcl $Config

    if (-not $NoHooks) {
        & $VenvPython (Join-Path $ToolTarget "manage_hooks.py") register --settings $Settings --python $VenvPython --hooks-dir $HookTarget
        if ($LASTEXITCODE -ne 0) { throw "Managed hook registration failed." }
    }
    if (Test-Path $Launcher) {
        $LauncherItem = Get-Item $Launcher -Force
        $LauncherText = if ($LauncherItem.PSIsContainer) { "" } else { Get-Content -Raw $Launcher }
        if (($LauncherItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $LauncherText -notmatch '(?m)^rem imprint-local-owned-launcher\r?$') {
            throw "Refusing to replace an unowned launcher: $Launcher"
        }
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Launcher) | Out-Null
    $env:IMPRINT_CONFIG = $Config
    $Imprint = Join-Path $InstallRoot "venv\Scripts\imprint.exe"
    $LauncherBody = "@echo off`r`nrem imprint-local-owned-launcher`r`nset `"IMPRINT_CONFIG=$Config`"`r`n`"$Imprint`" %*`r`n"
    [IO.File]::WriteAllText($Launcher, $LauncherBody, [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText((Join-Path $InstallRoot ".imprint-launcher-dir"), ([IO.Path]::GetFullPath($LauncherDir) + "`n"), [Text.Encoding]::UTF8)
    $Version = & $Imprint version
    if ($LASTEXITCODE -ne 0 -or $Version -ne $ProductVersion) { throw "Installed Imprint failed its version check." }
    $Version = & $Launcher version
    if ($LASTEXITCODE -ne 0 -or $Version -ne $ProductVersion) { throw "Installed launcher failed its version check." }
    $Ownership = Join-Path $ToolTarget "install_ownership.py"
    & $VenvPython $Ownership record --root $InstallRoot
    if ($LASTEXITCODE -ne 0) { throw "Unable to record installed-file ownership." }
    if (Test-Path $BackupRoot) {
        & $VenvPython $Ownership uninstall --root $BackupRoot --expected-version $ExistingVersion
        if ($LASTEXITCODE -ne 0) { throw "Unable to remove the verified previous installation." }
    }
    [IO.File]::WriteAllText($Marker, "imprint-local:$ProductVersion`n", [Text.Encoding]::ASCII)
    $Succeeded = $true
    Write-Host "Imprint $ProductVersion installed. Launcher: $Launcher. Data root: $DataRoot. No telemetry is enabled."
} catch {
    if (Test-Path $InstallRoot) { Remove-Item $InstallRoot -Recurse -Force }
    if (Test-Path $BackupRoot) { Move-Item $BackupRoot $InstallRoot }
    Restore-StateFile $Config "config"
    Restore-StateFile $Settings "settings"
    Restore-StateFile $Launcher "launcher"
    Restore-PathAcl $Config "config"
    Restore-PathAcl (Split-Path -Parent $Config) "config-parent"
    Restore-PathAcl $DataRoot "data-root"
    throw
} finally {
    Remove-Item $StateRoot -Recurse -Force -ErrorAction SilentlyContinue
}
