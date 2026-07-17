$ErrorActionPreference = 'Stop'
if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { throw 'Run from a native Windows console' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Acceptance must run non-admin' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$python = Join-Path $repo '.venv/Scripts/python.exe'
$root = Join-Path ([IO.Path]::GetTempPath()) ("imprint-native-authority-" + [Guid]::NewGuid())
$crashRoot = $root + '-crash'
$lifecycleRoot = $root + '-lifecycle'
$redirectedRoot = $root + '-redirected'
$transcript = $root + '.transcript.txt'
$transcriptStarted = $false
$operator = 'urn:imprint:operator:11111111-1111-4111-8111-111111111111'
try {
  if ($env:IMPRINT_EXTERNAL_PTY -ne '1') {
    'For every secret prompt, use the test-only passphrase: native authority acceptance passphrase'
  }
  'redirected' | & $python (Join-Path $repo 'tests/acceptance/native_authority.py') full --root $redirectedRoot --operator $operator 2>$null
  if ($LASTEXITCODE -eq 0) { throw 'redirected stdin was accepted' }
  Start-Transcript -Path $transcript -Force | Out-Null
  $transcriptStarted = $true
  & $python (Join-Path $repo 'tests/acceptance/native_authority.py') full --root $root --operator $operator
  if ($LASTEXITCODE -ne 0) { throw 'native full ceremony failed' }
  $blob = Get-ChildItem -LiteralPath (Join-Path $root 'authority/keys') -Filter '*.blob' | Select-Object -First 1
  & icacls.exe $blob.FullName /grant '*S-1-1-0:(R)' | Out-Null
  & $python (Join-Path $repo 'tests/acceptance/native_authority.py') verify-unsafe --root $root --operator $operator
  if ($LASTEXITCODE -ne 0) { throw 'unsafe ACL was accepted' }
  $acl = Get-Acl -LiteralPath $blob.FullName
  $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
  if (-not ($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' })) { throw 'read repaired the unsafe ACL' }
  & $python (Join-Path $repo 'tests/acceptance/native_authority.py') crash-reconcile --root $crashRoot --operator $operator
  if ($LASTEXITCODE -ne 0) { throw 'crash reconciliation failed' }
  & $python (Join-Path $repo 'tests/acceptance/native_authority.py') lifecycle --root $lifecycleRoot --operator $operator
  if ($LASTEXITCODE -ne 0) { throw 'native lifecycle ceremony failed' }
  Stop-Transcript | Out-Null
  $transcriptStarted = $false
  if (Select-String -LiteralPath $transcript -SimpleMatch 'native authority acceptance passphrase' -Quiet) { throw 'secret was echoed into transcript' }
  'native Windows authority: PASS'
} finally {
  if ($transcriptStarted) { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null }
  Remove-Item -LiteralPath $root,$crashRoot,$lifecycleRoot,($lifecycleRoot + '-offline'),($lifecycleRoot + '-restored'),($lifecycleRoot + '-paired'),$redirectedRoot,$transcript -Recurse -Force -ErrorAction SilentlyContinue
}
