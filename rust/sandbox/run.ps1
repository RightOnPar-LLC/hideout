<#
  Host side: start a throwaway Windows Sandbox (networking OFF) with the `wsb` command
  line, run inside.ps1 in it, collect its reports, and stop it. The repo is mapped in
  READ-ONLY; only -Out is writable.

    powershell -File rust\sandbox\run.ps1 -Mode clean -Out <folder>
    powershell -File rust\sandbox\run.ps1 -Mode dirty -Out <folder>

  Build first: powershell -File rust\build-release.ps1
  Needs Windows Sandbox with its command line (wsb), Windows 11 24H2 or later.
  ASCII-only.
#>
param([ValidateSet('clean', 'dirty')][string]$Mode = 'clean', [Parameter(Mandatory)][string]$Out)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
foreach ($f in 'rust\target\release\hideout.exe', 'rust\target\release\hideout-parity.exe', 'hideout.ps1') {
  if (-not (Test-Path (Join-Path $repo $f))) { throw "missing $f - build the release binaries first" }
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
Remove-Item -LiteralPath (Join-Path $Out "$Mode-done.txt") -ErrorAction SilentlyContinue

$esc = { param($s) [Security.SecurityElement]::Escape($s) }
$cfg = "<Configuration><Networking>Disable</Networking><ClipboardRedirection>Disable</ClipboardRedirection><PrinterRedirection>Disable</PrinterRedirection>" +
  "<MappedFolders><MappedFolder><HostFolder>$(& $esc $repo)</HostFolder><SandboxFolder>C:\hideout</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>" +
  "<MappedFolder><HostFolder>$(& $esc $Out)</HostFolder><SandboxFolder>C:\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders></Configuration>"

Write-Host "starting Windows Sandbox ($Mode, networking off)..."
$start = (& wsb start --raw -c $cfg) | Out-String
$id = ($start | ConvertFrom-Json).Id
if (-not $id) { throw "wsb start gave no id: $start" }
Write-Host "sandbox $id"
try {
  # The logged-in session takes a moment to exist; retry until exec is accepted.
  $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\hideout\rust\sandbox\inside.ps1 -Mode $Mode -Out C:\out -NoShutdown"
  $ok = $false
  foreach ($i in 1..60) {
    $r = (& wsb exec --raw --id $id -r ExistingLogin -c $cmd 2>&1) | Out-String
    if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    Start-Sleep -Seconds 5
  }
  if (-not $ok) { throw "could not run the test inside the sandbox: $r" }
  Write-Host $r
  Get-Content -LiteralPath (Join-Path $Out "$Mode-log.txt")
} finally {
  & wsb stop --id $id | Out-Null
  Write-Host "sandbox $id stopped"
}
