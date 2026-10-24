<#
  Host side: start a throwaway Windows Sandbox (networking OFF), run inside.ps1 in it,
  and wait for its reports. The repo is mapped in READ-ONLY; only -Out is writable.

    powershell -File rust\sandbox\run.ps1 -Mode clean -Out <folder>
    powershell -File rust\sandbox\run.ps1 -Mode dirty -Out <folder>

  Build first: cargo build --release -p hideout -p hideout-parity (in rust\).
  ASCII-only.
#>
param([ValidateSet('clean', 'dirty')][string]$Mode = 'clean', [Parameter(Mandatory)][string]$Out, [int]$TimeoutMinutes = 20)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
foreach ($f in 'rust\target\release\hideout.exe', 'rust\target\release\hideout-parity.exe', 'hideout.ps1') {
  if (-not (Test-Path (Join-Path $repo $f))) { throw "missing $f - build the release binaries first" }
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
Remove-Item -LiteralPath (Join-Path $Out "$Mode-done.txt") -ErrorAction SilentlyContinue

$esc = { param($s) [Security.SecurityElement]::Escape($s) }
$wsb = @"
<Configuration>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <MappedFolders>
    <MappedFolder><HostFolder>$(& $esc $repo)</HostFolder><SandboxFolder>C:\hideout</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$(& $esc $Out)</HostFolder><SandboxFolder>C:\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\hideout\rust\sandbox\inside.ps1 -Mode $Mode -Out C:\out</Command></LogonCommand>
</Configuration>
"@
$cfg = Join-Path $env:TEMP "hideout-$Mode.wsb"
Set-Content -LiteralPath $cfg -Value $wsb -Encoding UTF8
Write-Host "starting Windows Sandbox ($Mode, networking off)..."
Start-Process -FilePath "$env:WINDIR\System32\WindowsSandbox.exe" -ArgumentList "`"$cfg`""
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
while (-not (Test-Path (Join-Path $Out "$Mode-done.txt"))) {
  if ((Get-Date) -gt $deadline) { throw "sandbox run did not finish in $TimeoutMinutes minutes" }
  Start-Sleep -Seconds 5
}
Write-Host "sandbox $Mode finished:"
Get-Content -LiteralPath (Join-Path $Out "$Mode-log.txt")
Remove-Item -LiteralPath $cfg -ErrorAction SilentlyContinue
