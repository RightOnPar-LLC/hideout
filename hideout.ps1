<#
  Hideout - finds where malware hides on a Windows PC. READ-ONLY.

  It looks at everything that starts by itself (scheduled tasks, Run keys, Startup
  folders, services), keeps the programs that live in user-writable folders
  (ProgramData, AppData, Temp, Downloads, Public), and checks each program's folder
  for the "signed-binary sideloading" pattern:

    - a DLL or EXE whose signature no longer matches (altered after signing)
    - unsigned DLLs sitting beside a signed program
    - the program itself unsigned
    - signed by a vendor that has nothing installed on this PC
    - a random-looking folder name
    - large data files dressed as media (.raw, .wav, .dat ...) next to DLLs

  Born from a real find: a genuinely signed vendor EXE in C:\ProgramData\<random>,
  one sibling DLL "HashMismatch", three unsigned DLLs, payloads named .raw/.wav, a
  logon task - which the antivirus had not flagged in four months.

  It NEVER deletes, moves, disables, runs or uploads anything, and never prints a
  full command line (those can carry passwords and tokens). The only file it writes
  is the report.

  Run:   Hideout.cmd                      (scan, write the report, open it)
         pwsh -File hideout.ps1 -Json     (findings as JSON)
  Tests: pwsh -File tests\selftest.ps1

  Keep this file ASCII-only: Windows PowerShell 5.1 misreads non-ASCII as parse errors.
#>
[CmdletBinding()]
param(
  [switch]$Json,
  [switch]$Open,
  [string]$Out,
  [string]$TestTargets
)
$ErrorActionPreference = 'SilentlyContinue'

$UserWritable = '^[A-Za-z]:\\(ProgramData|Users\\Public|Windows\\Temp|Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents))\\'
$PayloadExt   = '\.(raw|wav|dat|bin|tmp|log|db|png|jpg|jpeg|bmp|mp3|ico|cab|pak)$'
$BadSig       = @('HashMismatch')
$NoSig        = @('NotSigned', 'UnknownError', 'NotSupportedFileFormat')

function Get-ProgramPath([string]$cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); if ($end -gt 1) { return $c.Substring(1, $end - 1) } }
  if ($c -match '^(.+?\.(exe|dll|com|scr|cpl|ocx))(\s|,|$)') { return $matches[1] }
  return $null
}

# Hosts that run a DLL or script handed to them - the real target is in the arguments.
$Hosts = '\\(rundll32|regsvr32|mshta|wscript|cscript)\.exe$'
function Get-TargetFromArgs([string]$argText) {
  if (-not $argText) { return $null }
  $a = [Environment]::ExpandEnvironmentVariables($argText)
  if ($a -match '([A-Za-z]:\\[^"]+?\.(dll|exe|ocx|cpl))') { return $matches[1] }
  return $null
}

function Get-Targets {
  $list = New-Object System.Collections.Generic.List[object]
  $add = { param($kind, $name, $state, $exe) if ($exe) { $list.Add([pscustomobject]@{ kind = $kind; name = $name; state = $state; exe = $exe }) } }

  foreach ($t in (Get-ScheduledTask)) {
    foreach ($a in $t.Actions) {
      $p = Get-ProgramPath "$($a.Execute)"
      if ($p -and $p -match $Hosts) { $inner = Get-TargetFromArgs "$($a.Arguments)"; if ($inner) { $p = $inner } }
      & $add 'Scheduled task' $t.TaskName "$($t.State)" $p
    }
  }
  $runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
  foreach ($k in $runKeys) {
    $props = Get-ItemProperty $k
    if (-not $props) { continue }
    foreach ($pp in $props.PSObject.Properties) {
      if ($pp.Name -like 'PS*') { continue }
      $p = Get-ProgramPath "$($pp.Value)"
      if ($p -and $p -match $Hosts) { $inner = Get-TargetFromArgs "$($pp.Value)"; if ($inner) { $p = $inner } }
      & $add 'Startup (registry)' $pp.Name 'Enabled' $p
    }
  }
  $shell = New-Object -ComObject WScript.Shell
  foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    foreach ($f in (Get-ChildItem $d -File)) {
      $p = if ($f.Extension -eq '.lnk') { $shell.CreateShortcut($f.FullName).TargetPath } else { $f.FullName }
      & $add 'Startup folder' $f.Name 'Enabled' $p
    }
  }
  foreach ($s in (Get-CimInstance Win32_Service)) {
    & $add 'Service' $s.Name "$($s.State)" (Get-ProgramPath "$($s.PathName)")
  }
  return $list
}

$installedCache = $null
$installLocations = $null
function Initialize-Installed {
  if ($null -ne $script:installedCache) { return }
  $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
  $entries = @(Get-ItemProperty $keys)
  $script:installedCache = ($entries | ForEach-Object { "$($_.DisplayName) | $($_.Publisher)" }) -join "`n"
  $script:installLocations = @($entries | ForEach-Object { "$($_.InstallLocation)".Trim().Trim('"').TrimEnd('\') } | Where-Object { $_.Length -gt 3 })
}
function Test-VendorInstalled([string]$org) {
  if (-not $org) { return $true }
  Initialize-Installed
  $word = ($org -split '[\s,(]')[0]
  if ($word.Length -lt 3) { return $true }
  return $script:installedCache -match [regex]::Escape($word)
}
# A folder that a registered installer claims (Uninstall InstallLocation = this folder or
# a parent) is an app, and apps ship unsigned helper DLLs, installer art and odd names all
# the time. Those weak signals are ignored there; a TAMPERED file never is.
function Test-RegisteredInstall([string]$dir) {
  Initialize-Installed
  $d = $dir.TrimEnd('\')
  foreach ($loc in $script:installLocations) {
    if ($d -ieq $loc -or $d.StartsWith($loc + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
  }
  return $false
}
# Machine-made names flip case over and over (kLmQzRtPx8); human names are words
# (CustomCursor, OneDrive, iCloudDrive). Needs 4+ case flips AND (4+ capitals or a digit).
function Test-RandomName([string]$n) {
  if ($n -match '^[0-9a-f]{16,}$') { return $true }
  if ($n -notmatch '^[A-Za-z0-9]{8,14}$') { return $false }
  $flips = 0; $upper = 0
  for ($i = 0; $i -lt $n.Length; $i++) {
    $c = $n[$i]
    if ([char]::IsUpper($c)) { $upper++ }
    if ($i -gt 0 -and [char]::IsLetter($c) -and [char]::IsLetter($n[$i - 1]) -and ([char]::IsUpper($c) -ne [char]::IsUpper($n[$i - 1]))) { $flips++ }
  }
  return ($flips -ge 4 -and ($upper -ge 4 -or $n -match '\d'))
}

function Get-Org($cert) {
  if (-not $cert) { return '' }
  if ($cert.Subject -match 'O="?([^",]+)') { return $matches[1].Trim() }
  if ($cert.Subject -match 'CN="?([^",]+)') { return $matches[1].Trim() }
  return ''
}

function Test-Folder($target, $folderCache) {
  $exe = $target.exe
  $dir = Split-Path $exe -Parent
  if ($folderCache.ContainsKey($dir)) { return $folderCache[$dir] }

  $score = 0; $reasons = New-Object System.Collections.Generic.List[object]
  $es = Get-AuthenticodeSignature -LiteralPath $exe
  $signer = Get-Org $es.SignerCertificate
  $exeSigned = ("$($es.Status)" -eq 'Valid')

  $bins = Get-ChildItem -Path (Join-Path $dir '*') -File -Include *.dll, *.exe, *.ocx, *.cpl
  $tampered = @(); $unsigned = @()
  foreach ($b in $bins) {
    $st = "$((Get-AuthenticodeSignature -LiteralPath $b.FullName).Status)"
    if ($BadSig -contains $st) { $tampered += $b.Name } elseif ($NoSig -contains $st) { $unsigned += $b.Name }
  }
  if ($tampered.Count) { $score += 5; $reasons.Add(@{ tag = 'Tampered file'; text = "Changed after it was signed: $($tampered -join ', ')" }) }
  if (-not $exeSigned -and ($tampered -notcontains (Split-Path $exe -Leaf))) {
    $score += 3; $reasons.Add(@{ tag = 'Unsigned program'; text = "The program itself has no valid signature ($($es.Status))." })
  }
  $registered = Test-RegisteredInstall $dir
  $unsignedOthers = @($unsigned | Where-Object { $_ -ne (Split-Path $exe -Leaf) })
  if ($exeSigned -and $unsignedOthers.Count -and -not $registered) { $score += 2; $reasons.Add(@{ tag = 'Unsigned DLLs'; text = "Unsigned files beside a signed program: $($unsignedOthers -join ', ')" }) }
  if ($exeSigned -and $signer -and -not (Test-VendorInstalled $signer)) {
    $score += 2; $reasons.Add(@{ tag = 'No matching install'; text = "Signed by $signer, but nothing from $signer is installed." })
  }
  $leaf = Split-Path $dir -Leaf
  if ((Test-RandomName $leaf) -and -not $registered) {
    $score += 1; $reasons.Add(@{ tag = 'Random folder'; text = "Folder name looks machine-generated: $leaf" })
  }
  if ($bins.Count -and -not $registered) {
    $blobs = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -match $PayloadExt -and $_.Length -gt 100KB })
    if ($blobs.Count) { $score += 1; $reasons.Add(@{ tag = 'Hidden payload'; text = "Large data files beside program code: $(($blobs | ForEach-Object { $_.Name }) -join ', ')" }) }
  }

  $sev = if ($score -ge 5) { 'high' } elseif ($score -ge 3) { 'medium' } elseif ($score -ge 2) { 'low' } else { '' }
  $created = (Get-Item -LiteralPath $dir).CreationTime
  $arrived = ''; if ($created) { $arrived = $created.ToString('yyyy-MM-dd HH:mm') }
  # Build with plain assignments: an `if` expression or a generic List inside this
  # literal throws "Argument types do not match", which the silent error mode used to
  # turn into NO finding - a crash that looked exactly like a clean PC.
  $r = [pscustomobject]@{ score = $score; severity = $sev; signer = $signer; reasons = $reasons.ToArray(); folder = $dir; arrived = $arrived }
  $folderCache[$dir] = $r
  return $r
}

# ---------------------------------------------------------------- scan
$targets = if ($TestTargets) { Get-Content -LiteralPath $TestTargets -Raw | ConvertFrom-Json } else { Get-Targets }
$counts = @{}
foreach ($t in $targets) { $counts[$t.kind] = 1 + [int]$counts[$t.kind] }

$folderCache = @{}
$findings = New-Object System.Collections.Generic.List[object]
$unchecked = New-Object System.Collections.Generic.List[object]
$inUserFolders = 0
foreach ($t in $targets) {
  if (-not $t.exe -or $t.exe -notmatch $UserWritable -or -not (Test-Path -LiteralPath $t.exe)) { continue }
  # Programs only: scripts (.vbs/.cmd/.ps1) are never code-signed, so every check below
  # would fire on them - that is noise, not evidence. Store-app execution aliases
  # (0-byte redirects to protected Program Files\WindowsApps) cannot be opened at all.
  if ($t.exe -notmatch '\.(exe|dll|ocx|cpl|scr|com)$') { continue }
  if ($t.exe -match '\\AppData\\Local\\Microsoft\\WindowsApps\\') { continue }
  $inUserFolders++
  $f = $null
  try { $f = Test-Folder $t $folderCache } catch { $f = $null }
  # Test-Folder always returns an object when it works (score 0 included). Nothing
  # back means the check itself failed - report it, never count it as clean.
  if ($null -eq $f) { $unchecked.Add([pscustomobject]@{ kind = $t.kind; name = $t.name; program = (Split-Path $t.exe -Leaf) }); continue }
  if (-not $f.severity) { continue }
  $findings.Add([pscustomobject]@{
    severity = $f.severity; score = $f.score; kind = $t.kind; name = $t.name; state = $t.state
    program = (Split-Path $t.exe -Leaf); folder = $f.folder; signer = $f.signer; arrived = $f.arrived; reasons = $f.reasons
  })
}

$def = $null
try {
  $m = Get-MpComputerStatus -ErrorAction Stop
  $def = [pscustomobject]@{
    realtime = [bool]$m.RealTimeProtectionEnabled
    signatureAgeDays = $m.AntivirusSignatureAge
    lastQuickScan = if ($m.QuickScanEndTime) { $m.QuickScanEndTime.ToString('yyyy-MM-dd') } else { '' }
    lastFullScan = if ($m.FullScanEndTime) { $m.FullScanEndTime.ToString('yyyy-MM-dd') } else { '' }
  }
} catch {}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$result = [pscustomobject]@{
  app = 'Hideout'; version = 1
  scannedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm'); computer = $env:COMPUTERNAME; admin = $isAdmin
  checked = [pscustomobject]@{ startItems = @($targets).Count; inUserFolders = $inUserFolders; byKind = $counts; couldNotCheck = $unchecked.ToArray() }
  defender = $def
  findings = @($findings | Sort-Object -Property score -Descending)
}

if ($Json) { $result | ConvertTo-Json -Depth 6; return }

# ---------------------------------------------------------------- report
if (-not $Out) { $Out = Join-Path $PSScriptRoot 'out\report.html' }
$outDir = Split-Path $Out -Parent
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$data = $result | ConvertTo-Json -Depth 6 -Compress
# Names and paths come from the machine being scanned - malware chooses them. Escape
# everything that could close the <script> tag or start markup; the page itself only
# ever renders with textContent.
$data = $data.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
$template = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'report.html') -Raw -Encoding UTF8
$html = $template.Replace('/*__HIDEOUT_DATA__*/null', $data)
[IO.File]::WriteAllText($Out, $html, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Hideout: $($findings.Count) finding(s) - report: $Out"
if ($Open) { Invoke-Item -LiteralPath $Out }
