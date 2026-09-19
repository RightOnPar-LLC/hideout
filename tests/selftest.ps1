<#
  Hideout selftest. Builds a fake sideloading folder in %TEMP% from REAL signed files
  (one copy with a single byte flipped, so its signature is a true HashMismatch), runs
  the engine against it as a child process, and checks the verdicts, the report's
  escaping, and that the engine stays read-only.

    pwsh -File tests\selftest.ps1                     (also: powershell -File ...)
    pwsh -File tests\selftest.ps1 -Engine <path>      (negative control: test another build)

  ASCII-only, same reason as the engine.
#>
param([string]$Engine)
$ErrorActionPreference = 'Stop'
$App = Split-Path $PSScriptRoot -Parent
if (-not $Engine) { $Engine = Join-Path $App 'hideout.ps1' }
$Host_ = (Get-Process -Id $PID).Path

$pass = 0; $fail = 0
function Check([string]$name, [bool]$ok, [string]$detail = '') {
  if ($ok) { $script:pass++; Write-Host "  ok    $name" } else { $script:fail++; Write-Host "  FAIL  $name  $detail" -ForegroundColor Red }
}

# ---------------------------------------------------------------- static
$src = Get-Content -LiteralPath $Engine -Raw
$code = [regex]::Replace($src, '(?s)<#.*?#>', '')
$code = [regex]::Replace($code, '(?m)#.*$', '')
$forbidden = 'Remove-Item', 'Move-Item', 'Rename-Item', 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty',
             'Disable-ScheduledTask', 'Unregister-ScheduledTask', 'Stop-Process', 'Stop-Service', 'Set-Service',
             'Start-Process', 'Invoke-WebRequest', 'Invoke-RestMethod', 'WebClient', 'schtasks', 'sc.exe', 'reg delete', 'Invoke-Expression'
$hits = @($forbidden | Where-Object { $code -match [regex]::Escape($_) })
Check 'S1 engine is read-only (no delete/move/disable/stop/run/download commands)' ($hits.Count -eq 0) ($hits -join ', ')
Check 'S2 engine is ASCII-only (Windows PowerShell 5.1 safe)' (-not ($src -match '[^\x00-\x7F]'))
Check 'S3 selftest is ASCII-only' (-not ((Get-Content -LiteralPath $PSCommandPath -Raw) -match '[^\x00-\x7F]'))
# The hunt runs ELEVATED, so its read-only promise matters most of all.
$huntSrc = Get-Content -LiteralPath (Join-Path $App 'hunt.ps1') -Raw
$huntCode = [regex]::Replace([regex]::Replace($huntSrc, '(?s)<#.*?#>', ''), '(?m)#.*$', '')
# Single-quoted strings are DATA (the hunt's own list of suspicious words, e.g. the
# pattern that flags 'invoke-webrequest'), not commands it runs.
$huntCmds = [regex]::Replace($huntCode, "'[^']*'", "''")
$huntHits = @($forbidden | Where-Object { $huntCmds -match [regex]::Escape($_) })
Check 'S8 hunt is read-only (no delete/move/disable/stop/run/download commands)' ($huntHits.Count -eq 0) ($huntHits -join ', ')
Check 'S9 hunt is ASCII-only' (-not ($huntSrc -match '[^\x00-\x7F]'))
# Every `snippet = ...` must be Get-Redacted, or pass along a snippet that already was.
$snips = @([regex]::Matches($huntCode, 'snippet\s*=\s*([^;}\r\n]+)') | ForEach-Object { $_.Groups[1].Value.Trim() })
$raw = @($snips | Where-Object { $_ -notmatch '^(Get-Redacted\b|\$\w+\.snippet\b)' })
Check 'S10 hunt never copies a command line whole (every snippet is redacted)' ($snips.Count -ge 4 -and $raw.Count -eq 0) ("unredacted: " + ($raw -join ' | '))
$tpl = Get-Content -LiteralPath (Join-Path $App 'report.html') -Raw
$tplCode = [regex]::Replace($tpl, '(?m)//.*$', '')
Check 'S4 report never builds HTML from data (no innerHTML / insertAdjacentHTML / document.write / eval)' (-not ($tplCode -match 'innerHTML|insertAdjacentHTML|document\.write|eval\(|new Function'))
Check 'S5 report loads nothing from the network (CSP default-src none)' ($tpl -match "default-src 'none'" -and -not ($tpl -match 'https?://'))

# Test-RandomName, lifted out of the engine and run on known names.
$fn = [regex]::Match($src, '(?s)function Test-RandomName.*?\n}\r?\n').Value
. ([scriptblock]::Create($fn))
$randomYes = 'kLmQzRtPx8', 'qXkRzTwP4m', 'deadbeefcafebabe0123'
$randomNo  = 'CustomCursor', 'OneDrive', 'iCloudDrive', 'MediaPlayer', 'Tailscale', 'ZohoMeeting', 'nodejs'
Check 'S6 random-name test flags machine-made names' (@($randomYes | Where-Object { -not (Test-RandomName $_) }).Count -eq 0) ($randomYes -join ',')
Check 'S7 random-name test leaves real product names alone' (@($randomNo | Where-Object { Test-RandomName $_ }).Count -eq 0) (@($randomNo | Where-Object { Test-RandomName $_ }) -join ',')

# ---------------------------------------------------------------- fixture
$root = Join-Path ([IO.Path]::GetTempPath()) ('hideout-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$bad = Join-Path $root 'qXkRzTwP4m'; $clean = Join-Path $root 'PlainApp'
New-Item -ItemType Directory -Path $bad, $clean | Out-Null
try {
  # A small, embedded-signed PE from this machine (catalog-signed Windows files will not do).
  $signed = $null
  $dirs = "$env:ProgramFiles\Windows Defender", "$env:ProgramFiles\Git\mingw64\bin", "$env:ProgramFiles\nodejs", "$env:ProgramFiles\Microsoft OneDrive", "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
  foreach ($d in $dirs) {
    if ($signed -or -not (Test-Path $d)) { continue }
    foreach ($f in (Get-ChildItem -Path (Join-Path $d '*') -File -Include *.dll, *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 50KB -and $_.Length -lt 8MB } | Select-Object -First 40)) {
      if ((Get-AuthenticodeSignature -LiteralPath $f.FullName).Status -eq 'Valid') { $signed = $f.FullName; break }
    }
  }
  if (-not $signed) { $n = (Get-Command node -ErrorAction SilentlyContinue).Source; if ($n -and (Get-AuthenticodeSignature $n).Status -eq 'Valid') { $signed = $n } }
  Check 'F0 found a signed file to build the fixture from' ([bool]$signed) 'no embedded-signed PE found'
  if (-not $signed) { throw 'cannot build fixture' }

  Copy-Item -LiteralPath $signed -Destination (Join-Path $bad 'Player.exe')
  Copy-Item -LiteralPath $signed -Destination (Join-Path $clean 'Player.exe')
  $bytes = [IO.File]::ReadAllBytes($signed); $mid = [int]($bytes.Length / 2); $bytes[$mid] = $bytes[$mid] -bxor 0xFF
  [IO.File]::WriteAllBytes((Join-Path $bad 'codec.dll'), $bytes)
  $rnd = New-Object byte[] 4096; (New-Object Random 7).NextBytes($rnd); [IO.File]::WriteAllBytes((Join-Path $bad 'helper.dll'), $rnd)
  $blob = New-Object byte[] (200KB); (New-Object Random 9).NextBytes($blob); [IO.File]::WriteAllBytes((Join-Path $bad 'intro.wav'), $blob)
  Set-Content -LiteralPath (Join-Path $bad 'run.vbs') -Value 'WScript.Echo 1'
  Check 'F1 the flipped byte really breaks the signature' ((Get-AuthenticodeSignature -LiteralPath (Join-Path $bad 'codec.dll')).Status -eq 'HashMismatch')

  $targets = @(
    @{ kind = 'Scheduled task'; name = 'Evil <img src=x onerror=alert(1)> task'; state = 'Ready'; exe = (Join-Path $bad 'Player.exe') },
    @{ kind = 'Scheduled task'; name = 'Clean app'; state = 'Ready'; exe = (Join-Path $clean 'Player.exe') },
    @{ kind = 'Startup folder'; name = 'a script'; state = 'Enabled'; exe = (Join-Path $bad 'run.vbs') },
    @{ kind = 'Service'; name = 'system program'; state = 'Running'; exe = "$env:WINDIR\System32\svchost.exe" }
  )
  $tt = Join-Path $root 'targets.json'
  $targets | ConvertTo-Json | Set-Content -LiteralPath $tt

  $json = & $Host_ -NoProfile -ExecutionPolicy Bypass -File $Engine -Json -TestTargets $tt | Out-String
  $r = $json | ConvertFrom-Json
  $f = @($r.findings)
  Check 'E1 exactly one finding' ($f.Count -eq 1) "got $($f.Count)"
  $hit = $f | Where-Object { $_.program -eq 'Player.exe' -and $_.folder -like '*qXkRzTwP4m' }
  Check 'E2 the sideloading folder is a HIGH threat' ($hit -and $hit.severity -eq 'high') "severity=$($hit.severity)"
  $tags = @($hit.reasons | ForEach-Object { $_.tag })
  foreach ($want in 'Tampered file', 'Unsigned DLLs', 'Random folder', 'Hidden payload') {
    Check "E3 reason: $want" ($tags -contains $want) ($tags -join ', ')
  }
  Check 'E4 the clean folder is not reported' (-not ($f | Where-Object { $_.folder -like '*PlainApp' }))
  Check 'E5 scripts and system programs are not treated as sideloading targets' ($r.checked.inUserFolders -eq 2) "inUserFolders=$($r.checked.inUserFolders)"
  Check 'E6 nothing silently skipped (couldNotCheck empty)' (@($r.checked.couldNotCheck).Count -eq 0)

  $out = Join-Path $root 'report.html'
  & $Host_ -NoProfile -ExecutionPolicy Bypass -File $Engine -TestTargets $tt -Out $out | Out-Null
  $html = Get-Content -LiteralPath $out -Raw -Encoding UTF8
  Check 'R1 report written with the data in place' ($html -notmatch '/\*__HIDEOUT_DATA__\*/null' -and $html -match 'Player\.exe')
  Check 'R2 a malicious task name cannot inject markup' ($html -notmatch '<img src=x' -and $html -match '\\u003cimg src=x')
}
finally {
  if ($root -like '*hideout-selftest-*') { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
if ($fail) { Write-Host "hideout selftest: $pass passed, $fail FAILED" -ForegroundColor Red; exit 1 }
Write-Host "hideout selftest: $pass passed, 0 failed" -ForegroundColor Green
