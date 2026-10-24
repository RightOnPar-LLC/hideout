<#
  Runs INSIDE Windows Sandbox (a throwaway VM with networking off). Never run it on a
  real PC: in "dirty" mode it plants persistence on purpose.

    clean  - a fresh Windows as it comes: parity on the whole PC + the planted fixtures
    dirty  - first plants the real-case replica the way real malware would (logon task,
             service, Run keys incl. one named "PS...", a hidden file in Startup), then
             the same runs; both engines must flag it, and agree

  Reports land in -Out, which the host maps back out. ASCII-only.
#>
param([ValidateSet('clean', 'dirty')][string]$Mode = 'clean', [string]$Out = 'C:\out')
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$log = Join-Path $Out "$Mode-log.txt"
function Say([string]$m) { "$(Get-Date -Format s) $m" | Add-Content -LiteralPath $log; Write-Host $m }

try {
  Say "mode=$Mode os=$([Environment]::OSVersion.Version) admin=$(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators'))"
  # Work from a local copy: the mapped repo is read-only, and the harness writes temp files.
  $work = 'C:\hideout-work'
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  Copy-Item -LiteralPath 'C:\hideout\hideout.ps1', 'C:\hideout\hunt.ps1', 'C:\hideout\report.html' -Destination $work
  Copy-Item -LiteralPath 'C:\hideout\rust\target\release\hideout.exe', 'C:\hideout\rust\target\release\hideout-parity.exe' -Destination $work
  $hideout = Join-Path $work 'hideout.exe'
  $parity = Join-Path $work 'hideout-parity.exe'

  if ($Mode -eq 'dirty') {
    # A signed program to plant: Defender's own command-line tool (embedded-signed).
    $src = Get-ChildItem "$env:ProgramFiles\Windows Defender\*.exe" | Where-Object { (Get-AuthenticodeSignature $_.FullName).SignatureType -eq 'Authenticode' -and (Get-AuthenticodeSignature $_.FullName).Status -eq 'Valid' } | Select-Object -First 1
    if (-not $src) { $src = Get-ChildItem "$env:ProgramFiles\Windows Defender\*.dll" | Where-Object { (Get-AuthenticodeSignature $_.FullName).SignatureType -eq 'Authenticode' } | Select-Object -First 1 }
    Say "planting from $($src.Name)"
    $bad = 'C:\ProgramData\qXkRzTwP4m'
    New-Item -ItemType Directory -Force -Path $bad | Out-Null
    Copy-Item -LiteralPath $src.FullName -Destination "$bad\Player.exe"
    $b = [IO.File]::ReadAllBytes($src.FullName); $b[[int]($b.Length / 2)] = $b[[int]($b.Length / 2)] -bxor 0xFF
    [IO.File]::WriteAllBytes("$bad\codec.dll", $b)
    $r = New-Object Random 7
    foreach ($n in 'helper.dll', 'render.dll', 'net.dll') { $x = New-Object byte[] 4096; $r.NextBytes($x); [IO.File]::WriteAllBytes("$bad\$n", $x) }
    $x = New-Object byte[] (200KB); $r.NextBytes($x); [IO.File]::WriteAllBytes("$bad\intro.wav", $x)
    $x = New-Object byte[] (300KB); $r.NextBytes($x); [IO.File]::WriteAllBytes("$bad\data.raw", $x)
    # Persistence, four ways.
    $act = New-ScheduledTaskAction -Execute "$bad\Player.exe"
    Register-ScheduledTask -TaskName 'MediaPlayerUpdate' -Action $act -Trigger (New-ScheduledTaskTrigger -AtLogOn) | Out-Null
    New-Service -Name 'PlayerSvc' -BinaryPathName "`"$bad\Player.exe`" -svc" -StartupType Manual | Out-Null
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'PlayerTray' -Value "`"$bad\Player.exe`" /tray" -Force | Out-Null
    # Named to hide from hideout.ps1's PS* filter.
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'PSUpdater' -Value "`"$bad\Player.exe`" /u" -Force | Out-Null
    # A hidden program in the Startup folder.
    $startup = [Environment]::GetFolderPath('Startup')
    Copy-Item -LiteralPath "$bad\Player.exe" -Destination "$startup\svchelper.exe"
    (Get-Item "$startup\svchelper.exe" -Force).Attributes = 'Hidden'
    Say 'planted: task, service, 2 Run values, hidden Startup file'
  }

  Push-Location $work
  $t0 = Get-Date
  & $parity quick --rust $hideout --repo $work --report (Join-Path $Out "$Mode-thispc.json") *> (Join-Path $Out "$Mode-thispc.txt")
  Say "parity this-pc exit=$LASTEXITCODE ($([int]((Get-Date) - $t0).TotalSeconds)s)"
  & $parity fixtures --rust $hideout --repo $work --report (Join-Path $Out "$Mode-fixtures.json") *> (Join-Path $Out "$Mode-fixtures.txt")
  Say "parity fixtures exit=$LASTEXITCODE"
  # The Rust engine's own report, as a person would see it.
  & $hideout scan --json > (Join-Path $Out "$Mode-rust-scan.json")
  # Timing: three cold quick scans.
  $times = foreach ($i in 1..3) { $s = Get-Date; & $hideout scan --json | Out-Null; [math]::Round(((Get-Date) - $s).TotalSeconds, 2) }
  Say "rust quick scan seconds: $($times -join ', ')"
  Pop-Location
} catch {
  Say "ERROR: $($_.Exception.Message)"
} finally {
  Set-Content -LiteralPath (Join-Path $Out "$Mode-done.txt") -Value (Get-Date -Format s)
  Stop-Computer -Force
}
