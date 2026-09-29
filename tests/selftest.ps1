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

# ---------------------------------------------------------------- doors (read-only, ASCII, mirrored helpers)
$doorsPath = Join-Path $App 'doors.ps1'
$doorsSrc = Get-Content -LiteralPath $doorsPath -Raw
$doorsCodeRaw = [regex]::Replace([regex]::Replace($doorsSrc, '(?s)<#.*?#>', ''), '(?m)#.*$', '')
$doorsCode = [regex]::Replace($doorsCodeRaw, "'[^']*'", "''")
$doorsHits = @($forbidden | Where-Object { $doorsCode -match [regex]::Escape($_) })
Check 'S11 doors is read-only (same forbidden list as hunt/hideout)' ($doorsHits.Count -eq 0) ($doorsHits -join ', ')
Check 'S12 doors is ASCII-only' (-not ($doorsSrc -match '[^\x00-\x7F]'))

# publicRepoGuards item 5: the doors-specific forbidden list, over the code with single-quoted
# STRING LITERALS blanked (the firewall group id and comments discussing these words as
# things doors.ps1 must never do are data, not commands).
$doorsForbidden = 'Start-Job', 'Start-MpScan', 'Set-MpPreference', 'Disable-LocalUser', 'Enable-LocalUser', 'Remove-LocalUser', 'Set-LocalUser',
                  'Enable-BitLocker', 'manage-bde', 'Suspend-BitLocker', 'Register-ScheduledTask', 'powercfg /set', '/change', '/setactive', '/h',
                  'wevtutil sl', 'Set-NetFirewallRule', 'dsregcmd', 'qwinsta', 'CurrentClockSpeed', 'CommandLine', 'RecoveryPassword', 'DisplayGroup'
$doorsForbiddenHits = @($doorsForbidden | Where-Object { $doorsCode -match [regex]::Escape($_) })
Check 'S13 doors carries none of the doors-specific forbidden strings (write cmdlets, BitLocker mutators, clock-speed, full command lines, recovery keys, locale-bound firewall matching)' ($doorsForbiddenHits.Count -eq 0) ($doorsForbiddenHits -join ', ')
Check 'S14 doors uses the locale-proof Remote Desktop firewall group id' ($doorsSrc -match [regex]::Escape('@FirewallAPI.dll,-28752'))
# Negative control: the guard above must actually fire on a planted violation, or it is
# checking nothing (publicRepoGuards item 5's own requirement).
$negPath = Join-Path ([IO.Path]::GetTempPath()) ('doors-negctrl-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
try {
  Set-Content -LiteralPath $negPath -Value ($doorsSrc + "`nStart-MpScan | Out-Null`n") -Encoding ascii
  $negSrc = Get-Content -LiteralPath $negPath -Raw
  $negCode = [regex]::Replace([regex]::Replace($negSrc, '(?s)<#.*?#>', ''), '(?m)#.*$', '')
  $negCode = [regex]::Replace($negCode, "'[^']*'", "''")
  $negHits = @($doorsForbidden | Where-Object { $negCode -match [regex]::Escape($_) })
  Check 'S13n negative control: a planted Start-MpScan makes S13''s own check go red' ($negHits.Count -gt 0)
} finally { Remove-Item -LiteralPath $negPath -Force -ErrorAction SilentlyContinue }

# publicRepoGuards item 4 / the risk about factoring Section/Get-Redacted into a shared file:
# doors.ps1 mirrors hunt.ps1's two helpers byte-for-byte instead, and this is the check that
# keeps that promise true - drift here means the helper quietly grew two homes.
function Get-MirroredBlock([string]$src, [string]$pattern) {
  $m = [regex]::Match($src, $pattern)
  if ($m.Success) { return $m.Value } else { return $null }
}
$redactedPattern = '\$redactor = \[System\.Text\.RegularExpressions\.MatchEvaluator\][\s\S]*?\nfunction Get-Redacted\(\[string\]\$s\)[\s\S]*?\r?\n\}\r?\n'
$sectionPattern = '\$report = \[ordered\]@\{\}\r?\nfunction Section\(\[string\]\$name, \[scriptblock\]\$body\)[\s\S]*?\r?\n\}\r?\n'
$huntRedacted = Get-MirroredBlock $huntSrc $redactedPattern
$doorsRedacted = Get-MirroredBlock $doorsSrc $redactedPattern
$huntSection = Get-MirroredBlock $huntSrc $sectionPattern
$doorsSection = Get-MirroredBlock $doorsSrc $sectionPattern
Check 'S15 doors'' Get-Redacted (+ $redactor) is byte-identical to hunt''s' ($huntRedacted -and $doorsRedacted -and ($huntRedacted -ceq $doorsRedacted)) 'blocks differ or one was not found'
Check 'S16 doors'' Section helper is byte-identical to hunt''s' ($huntSection -and $doorsSection -and ($huntSection -ceq $doorsSection)) 'blocks differ or one was not found'

# The recovery-key guard on hunt.ps1's new 'bitlocker' Section (engineChecks doors.diskEncryption,
# publicRepoGuards item 6): lift the shaping function out and run it against a fixture volume
# carrying a FAKE 48-digit recovery key, with a negative control proving the test itself is not
# vacuous (the raw, unshaped fixture DOES match the same regex).
$shapeFn = [regex]::Match($huntSrc, '(?s)function Get-BitlockerShape.*?\n\}\r?\n').Value
Check 'F2 found Get-BitlockerShape to lift out of hunt.ps1' ([bool]$shapeFn)
if ($shapeFn) {
  . ([scriptblock]::Create($shapeFn))
  $fakeVolume = [pscustomobject]@{
    MountPoint = 'C:'; VolumeStatus = 'FullyEncrypted'; ProtectionStatus = 'On'; EncryptionPercentage = 100
    KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword'; RecoveryPassword = '123456-234567-345678-456789-567890-678901-789012-890123' })
  }
  $shaped = Get-BitlockerShape @($fakeVolume) | ConvertTo-Json -Depth 6
  $keyRegex = '\d{6}(-\d{6}){7}'
  Check 'F3 the shaped bitlocker section never serializes a recovery-key-shaped string' (-not ($shaped -match $keyRegex)) $shaped
  $rawShaped = @($fakeVolume) | ConvertTo-Json -Depth 6
  Check 'F3n negative control: the SAME fixture, unshaped, does match the key regex (proves F3 is not vacuous)' ($rawShaped -match $keyRegex)
}

# ---------------------------------------------------------------- doors live shape run (quick pass only - seconds, no fixture)
$doorsOut = Join-Path ([IO.Path]::GetTempPath()) ('doors-shape-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
try {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  & $Host_ -NoProfile -ExecutionPolicy Bypass -File $doorsPath -Pass quick -Out $doorsOut | Out-Null
  $sw.Stop()
  # Budget set generously for a CI box, not tuned to this one - the spec's own per-check
  # measurements here were 0.3-1.1s each across 8 quick-pass sections.
  Check 'D1 doors -Pass quick exits 0' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
  Check 'D2 doors -Pass quick finishes well inside its seconds-not-minutes budget' ($sw.Elapsed.TotalSeconds -lt 20) "$($sw.Elapsed.TotalSeconds)s"
  $doorsJsonText = Get-Content -LiteralPath $doorsOut -Raw
  Check 'D3 doors output never carries the 5.1 slash-Date wrapper' (-not ($doorsJsonText -match '\\/Date\('))
  $doorsResult = $doorsJsonText | ConvertFrom-Json
  Check 'D4 doors output is the quick pass' ($doorsResult.pass -eq 'quick')
  $quickSections = 'remoteDesktopRegistry', 'extraAccount', 'diskEncryption', 'remoteSupportInstalled', 'restartWaiting', 'diskSpace', 'sleepTimers', 'battery'
  $missing = @($quickSections | Where-Object { -not $doorsResult.sections.PSObject.Properties.Name.Contains($_) })
  Check 'D5 every quick-pass section is present' ($missing.Count -eq 0) ($missing -join ', ')
  $badShape = @($quickSections | Where-Object {
      $sec = $doorsResult.sections.$_
      -not ($sec -and $sec.items -and $sec.items.Count -eq 1 -and ($null -ne $sec.items[0].checked) -and ($null -ne $sec.items[0].control))
    })
  Check 'D6 every quick-pass Section returns exactly one item shaped {checked, control, facts}' ($badShape.Count -eq 0) ($badShape -join ', ')
  # Every date-ish field anywhere in the payload matches ISO-8601 or is the empty string.
  $dateFields = @([regex]::Matches($doorsJsonText, '"(\w*(?:Date|Time|LastSet|LastLogon|LastBoot|Started)\w*)"\s*:\s*"([^"]*)"', 'IgnoreCase'))
  $badDates = @($dateFields | Where-Object { $_.Groups[2].Value -ne '' -and $_.Groups[2].Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' })
  Check 'D7 every date field in the live run is ISO-8601 or empty' ($dateFields.Count -gt 0 -and $badDates.Count -eq 0) ($badDates | ForEach-Object { $_.Value })
} finally { Remove-Item -LiteralPath $doorsOut -Force -ErrorAction SilentlyContinue }

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
