[CmdletBinding()]
param(
    [string]$InstallRoot = $(if ($env:IMPRINT_INSTALL_ROOT) { $env:IMPRINT_INSTALL_ROOT } else { Join-Path $env:LOCALAPPDATA "ImprintApp\app" }),
    [string]$Config = $(if ($env:IMPRINT_CONFIG) { $env:IMPRINT_CONFIG } else { Join-Path $env:APPDATA "Imprint\config.json" }),
    [string]$Settings = $(if ($env:CLAUDE_SETTINGS_PATH) { $env:CLAUDE_SETTINGS_PATH } else { Join-Path $env:USERPROFILE ".claude\settings.json" }),
    [string]$LauncherDir = $(if ($env:IMPRINT_LAUNCHER_DIR) { $env:IMPRINT_LAUNCHER_DIR } else { Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps" }),
    [switch]$PurgeConfig
)
$ErrorActionPreference = "Stop"
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$VolumeRoot = [IO.Path]::GetPathRoot($InstallRoot)
if ($InstallRoot -eq $VolumeRoot -or $InstallRoot -eq [IO.Path]::GetFullPath($env:USERPROFILE)) { throw "Refusing an unsafe install root: $InstallRoot" }
if (-not (Test-Path $InstallRoot -PathType Container)) { throw "Imprint install root does not exist: $InstallRoot" }
$RootItem = Get-Item $InstallRoot -Force
if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing a reparse-point install root: $InstallRoot" }
$Marker = Join-Path $InstallRoot ".imprint-install-root"
$MarkerText = if (Test-Path $Marker -PathType Leaf) { (Get-Content -Raw $Marker).Trim() } else { "" }
if ($MarkerText -notmatch '^imprint-local:(\d+\.\d+\.\d+)$') { throw "Refusing to remove an install root without Imprint's ownership marker: $InstallRoot" }
$InstalledVersion = $Matches[1]
$Python = Join-Path $InstallRoot "venv\Scripts\python.exe"
$Manager = Join-Path $InstallRoot "tools\manage_hooks.py"
$Ownership = Join-Path $InstallRoot "tools\install_ownership.py"
$VersionSource = Join-Path $InstallRoot "venv\Lib\site-packages\imprint\_version.py"
$LauncherRecord = Join-Path $InstallRoot ".imprint-launcher-dir"
if (Test-Path $LauncherRecord -PathType Leaf) { $LauncherDir = (Get-Content -Raw $LauncherRecord).Trim() }
$Launcher = Join-Path ([IO.Path]::GetFullPath($LauncherDir)) "imprint.cmd"
if (-not (Test-Path $Python -PathType Leaf) -or
    -not (Test-Path $Ownership -PathType Leaf) -or
    -not (Test-Path $VersionSource -PathType Leaf)) {
    throw "Refusing uninstall because ownership tooling or authoritative version metadata is missing."
}
$BasePython = (& $Python -I -S -c "import sys; print(sys._base_executable)").Trim()
if ($LASTEXITCODE -ne 0 -or -not $BasePython -or -not (Test-Path $BasePython -PathType Leaf)) { throw "Unable to locate the external Python interpreter required for safe removal." }
$BasePython = [IO.Path]::GetFullPath($BasePython)
$InstallBoundary = $InstallRoot.TrimEnd([char[]]@('\', '/'))
if ($BasePython.Equals($InstallBoundary, [StringComparison]::OrdinalIgnoreCase) -or $BasePython.StartsWith($InstallBoundary + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing uninstall because the cleanup interpreter is inside the owned install root."
}
& $Python $Ownership verify --root $InstallRoot --expected-version $InstalledVersion
if ($LASTEXITCODE -ne 0) { throw "Installed-file ownership verification failed; installation was left intact." }
$RemovalState = Join-Path ([IO.Path]::GetTempPath()) ("imprint-uninstall-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $RemovalState | Out-Null
try {
    $StagedOwnership = Join-Path $RemovalState "install_ownership.py"
    $StagedVersion = Join-Path $RemovalState "_version.py"
    Copy-Item $Ownership $StagedOwnership
    Copy-Item $VersionSource $StagedVersion
    & $BasePython -I -S $StagedOwnership verify --root $InstallRoot --expected-version $InstalledVersion
    if ($LASTEXITCODE -ne 0) { throw "External ownership verification failed; installation was left intact." }
    if (Test-Path $Manager) {
        & $Python $Manager unregister --settings $Settings --python $Python --hooks-dir (Join-Path $InstallRoot "hooks")
        if ($LASTEXITCODE -ne 0) { throw "Managed hook removal failed; installation was left intact." }
    }
    if (Test-Path $Launcher -PathType Leaf) {
        $LauncherItem = Get-Item $Launcher -Force
        $LauncherText = Get-Content -Raw $Launcher
        if (($LauncherItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $LauncherText -match '(?m)^rem imprint-local-owned-launcher\r?$' -and
            $LauncherText.Contains((Join-Path $InstallRoot "venv\Scripts\imprint.exe"))) {
            Remove-Item $Launcher -Force
        } else {
            Write-Warning "Leaving unowned or modified launcher intact: $Launcher"
        }
    }
    # Windows locks a running executable. Use the venv's external base
    # interpreter so the owned venv\Scripts\python.exe can be removed safely.
    & $BasePython -I -S $StagedOwnership uninstall --root $InstallRoot --expected-version $InstalledVersion
    if ($LASTEXITCODE -ne 0) { throw "Conservative installed-file removal failed." }
} finally {
    Remove-Item $RemovalState -Recurse -Force -ErrorAction SilentlyContinue
}
if ($PurgeConfig -and (Test-Path $Config)) { Remove-Item $Config -Force }
Write-Host "Imprint code and managed hooks removed. Captured data was preserved."
