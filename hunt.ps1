<#
  Hideout hunt - a read-only evidence snapshot of everywhere malware usually hides,
  for a deep review (human or agent). Run it ELEVATED to see everything; it still
  works without admin and says which sections needed it.

  Collects: Hideout's own verdicts, every scheduled task, services (incl. svchost
  ServiceDlls), drivers, registry autoruns (Run/RunOnce for every loaded user, Winlogon,
  IFEO debuggers, SilentProcessExit, AppInit, AppCert, LSA packages, Active Setup,
  user-hive COM overrides), Startup folders for every user, WMI event subscriptions,
  Defender status + exclusions + detections, root certificates, listening and
  outbound connections, running programs from user folders or unsigned, executables
  and scripts created in user-writable folders in the last 180 days, PowerShell
  profiles, browser extensions, hosts file, proxy settings, local accounts.

  NEVER deletes, moves, disables, runs or uploads anything. Command lines are NOT
  copied whole: each gets behaviour flags (encoded-command, download, hidden-window
  ...), the URL hosts it names, and a snippet with every long token-like run replaced
  by [redacted N chars] - command lines carry passwords and API keys often enough.
  File CONTENTS are never copied (profiles: size, date, hash, flags only).

  Run:  "Hideout Hunt (admin).cmd"   (asks Windows for admin, then runs this)
        pwsh -File hunt.ps1 [-Out <file.json>] [-Days 180]
  ASCII-only (Windows PowerShell 5.1).
#>
[CmdletBinding()]
param([string]$Out, [int]$Days = 180)
$ErrorActionPreference = 'SilentlyContinue'
$started = Get-Date
$UserWritable = '^[A-Za-z]:\\(ProgramData|Users\\Public|Windows\\Temp|Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents))\\'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------- helpers
$sigCache = @{}
function Get-Sig([string]$path) {
  if (-not $path) { return $null }
  if ($sigCache.ContainsKey($path)) { return $sigCache[$path] }
  $r = $null
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    # Some files throw a TERMINATING error here (Store-app aliases: "cannot be accessed
    # by the system"), which SilentlyContinue does not stop - one such file used to wipe
    # out a whole section. Record it as Unreadable and carry on.
    try {
      $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
      $org = ''
      if ($s.SignerCertificate) {
        if ($s.SignerCertificate.Subject -match 'O="?([^",]+)') { $org = $matches[1].Trim() }
        elseif ($s.SignerCertificate.Subject -match 'CN="?([^",]+)') { $org = $matches[1].Trim() }
      }
      $r = [pscustomobject]@{ status = "$($s.Status)"; signer = $org; osBinary = [bool]$s.IsOSBinary }
    } catch { $r = [pscustomobject]@{ status = 'Unreadable'; signer = ''; osBinary = $false } }
  } else { $r = [pscustomobject]@{ status = 'FileMissing'; signer = ''; osBinary = $false } }
  $sigCache[$path] = $r
  return $r
}
function Get-Sha([string]$path) {
  if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return '' }
  try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return 'unreadable' }
}
function Get-ProgramPath([string]$cmd) {
  if (-not $cmd) { return $null }
  $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
  $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:WINDIR\" -replace '^(?i)system32\\', "$env:WINDIR\System32\"
  if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); if ($end -gt 1) { return $c.Substring(1, $end - 1) } }
  if ($c -match '^(.+?\.(exe|dll|sys|com|scr|cpl|ocx))(\s|,|$)') { return $matches[1] }
  return $c
}
function Get-Flags([string]$s) {
  $f = @()
  if (-not $s) { return $f }
  if ($s -match '(?i)(^|\s)-(e|en|enc|enco|encod|encodedcommand)\s') { $f += 'encoded-command' }
  if ($s -match '(?i)https?://') { $f += 'url' }
  if ($s -match '(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|start-bitstransfer|bitsadmin|certutil.*urlcache|curl(\.exe)?\s|wget\s') { $f += 'download' }
  if ($s -match '(?i)-(ep|exec|executionpolicy)\s+bypass') { $f += 'policy-bypass' }
  if ($s -match '(?i)-(w|win|windowstyle)\s+h(idden)?\b') { $f += 'hidden-window' }
  if ($s -match '(?i)frombase64string|\biex\b|invoke-expression') { $f += 'eval' }
  if ($s -match '[A-Za-z0-9+/=]{120,}') { $f += 'long-base64' }
  if ($s -match '(?i)\\(appdata|programdata|temp|users\\public)\\') { $f += 'user-folder-path' }
  if ($s -match '(?i)\b(rundll32|regsvr32|mshta|wscript|cscript|msiexec|installutil|regasm|regsvcs|cmstp)\b') { $f += 'lolbin' }
  return $f
}
function Get-UrlHosts([string]$s) {
  if (-not $s) { return @() }
  return @([regex]::Matches($s, '(?i)https?://([^/\s"'':]+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
}
$redactor = [System.Text.RegularExpressions.MatchEvaluator] { param($m) "[redacted $($m.Value.Length) chars]" }
function Get-Redacted([string]$s) {
  if (-not $s) { return '' }
  $r = [regex]::Replace($s, '[A-Za-z0-9+/=_\-\.%]{28,}', $redactor)
  if ($r.Length -gt 240) { $r = $r.Substring(0, 240) + '...' }
  return $r
}
function Describe-Command([string]$exe, [string]$argText) {
  $all = "$exe $argText"
  $p = Get-ProgramPath $exe
  $o = [ordered]@{ program = $p; userFolder = [bool]($p -match $UserWritable) }
  $sig = Get-Sig $p
  if ($sig) { $o.sig = $sig.status; $o.signer = $sig.signer }
  $fl = @(Get-Flags $all)
  if ($fl.Count) { $o.flags = $fl; $o.snippet = Get-Redacted $argText }
  $h = @(Get-UrlHosts $all); if ($h.Count) { $o.urlHosts = $h }
  return [pscustomobject]$o
}
$report = [ordered]@{}
function Section([string]$name, [scriptblock]$body) {
  $t0 = Get-Date
  $s = [ordered]@{ ok = $true; items = @() }
  try { $s.items = @(& $body) } catch { $s.ok = $false; $s.error = "$($_.Exception.Message)" }
  $s.seconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
  $script:report[$name] = [pscustomobject]$s
  Write-Host ("  {0,-22} {1,5} item(s)  {2}s{3}" -f $name, @($s.items).Count, $s.seconds, $(if ($s.ok) { '' } else { "  ERROR: $($s.error)" }))
}
$users = @(Get-ChildItem 'C:\Users' -Directory -Force | Where-Object { $_.Name -notin @('Default', 'Default User', 'All Users', 'Public') -and (Test-Path (Join-Path $_.FullName 'AppData')) })

Write-Host "Hideout hunt - $env:COMPUTERNAME - admin=$isAdmin"

# ---------------------------------------------------------------- sections
Section 'hideout' {
  $h = & (Join-Path $PSScriptRoot 'hideout.ps1') -Json | Out-String | ConvertFrom-Json
  $h.findings
}

Section 'scheduledTasks' {
  foreach ($t in (Get-ScheduledTask)) {
    $i = $t | Get-ScheduledTaskInfo
    $acts = @(foreach ($a in $t.Actions) {
      if ($a.Execute) { Describe-Command "$($a.Execute)" "$($a.Arguments)" }
      elseif ($a.ClassId) { [pscustomobject]@{ comHandler = "$($a.ClassId)" } }
    })
    [pscustomobject]@{
      path = $t.TaskPath; name = $t.TaskName; state = "$($t.State)"; author = $t.Author; registered = $t.Date
      hidden = [bool]$t.Settings.Hidden; runAs = $t.Principal.UserId; runLevel = "$($t.Principal.RunLevel)"
      triggers = @($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task|Trigger', '' })
      lastRun = if ($i) { "$($i.LastRunTime)" } else { '' }; lastResult = if ($i) { $i.LastTaskResult } else { '' }
      actions = $acts
    }
  }
}

Section 'services' {
  foreach ($s in (Get-CimInstance Win32_Service)) {
    $d = Describe-Command "$($s.PathName)" ''
    $o = [ordered]@{ name = $s.Name; display = $s.DisplayName; state = "$($s.State)"; start = "$($s.StartMode)"; account = $s.StartName; program = $d.program; sig = $d.sig; signer = $d.signer; userFolder = $d.userFolder }
    if ($s.PathName -match '(?i)svchost\.exe') {
      $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters").ServiceDll
      if ($dll) { $dp = Get-ProgramPath $dll; $o.serviceDll = $dp; $ds = Get-Sig $dp; if ($ds) { $o.serviceDllSig = $ds.status; $o.serviceDllSigner = $ds.signer } }
    }
    [pscustomobject]$o
  }
}

Section 'drivers' {
  foreach ($d in (Get-CimInstance Win32_SystemDriver)) {
    $p = Get-ProgramPath "$($d.PathName)"
    $sg = Get-Sig $p
    $normalPlace = $p -match '(?i)\\Windows\\System32\\(drivers|DriverStore)\\'
    if ($sg -and $sg.status -eq 'Valid' -and $normalPlace) { continue }
    [pscustomobject]@{ name = $d.Name; state = "$($d.State)"; start = "$($d.StartMode)"; path = $p; sig = if ($sg) { $sg.status } else { '' }; signer = if ($sg) { $sg.signer } else { '' } }
  }
}

Section 'registryAutoruns' {
  $hives = @('HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')
  foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) { $hives += "Registry::HKEY_USERS\$($sid.PSChildName)\SOFTWARE" }
  foreach ($h in $hives) {
    foreach ($k in 'Run', 'RunOnce', 'RunServices', 'RunServicesOnce', 'Policies\Explorer\Run') {
      $key = "$h\Microsoft\Windows\CurrentVersion\$k"
      $props = Get-ItemProperty $key
      if (-not $props) { continue }
      foreach ($pp in $props.PSObject.Properties) {
        if ($pp.Name -like 'PS*') { continue }
        $d = Describe-Command "$($pp.Value)" "$($pp.Value)"
        [pscustomobject]@{ where = $key; name = $pp.Name; program = $d.program; sig = $d.sig; signer = $d.signer; userFolder = $d.userFolder; flags = $d.flags; snippet = $d.snippet; urlHosts = $d.urlHosts }
      }
    }
    foreach ($v in 'Shell', 'Userinit', 'Taskman') {
      $val = (Get-ItemProperty "$h\Microsoft\Windows NT\CurrentVersion\Winlogon").$v
      if ($val) { [pscustomobject]@{ where = "$h\...\Winlogon"; name = $v; value = Get-Redacted "$val" } }
    }
  }
  foreach ($base in 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node') {
    foreach ($ifeo in (Get-ChildItem "$base\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")) {
      $p = Get-ItemProperty $ifeo.PSPath
      if ($p.Debugger) { [pscustomobject]@{ where = 'IFEO Debugger'; name = $ifeo.PSChildName; value = Get-Redacted "$($p.Debugger)" } }
      if ($p.GlobalFlag -and ([int]$p.GlobalFlag -band 0x200)) { [pscustomobject]@{ where = 'IFEO GlobalFlag 0x200 (silent exit monitor)'; name = $ifeo.PSChildName } }
    }
    foreach ($spe in (Get-ChildItem "$base\Microsoft\Windows NT\CurrentVersion\SilentProcessExit")) {
      $m = (Get-ItemProperty $spe.PSPath).MonitorProcess
      if ($m) { [pscustomobject]@{ where = 'SilentProcessExit'; name = $spe.PSChildName; value = Get-Redacted "$m" } }
    }
    $w = Get-ItemProperty "$base\Microsoft\Windows NT\CurrentVersion\Windows"
    if ($w.AppInit_DLLs) { [pscustomobject]@{ where = "$base AppInit_DLLs"; name = "LoadAppInit=$($w.LoadAppInit_DLLs)"; value = "$($w.AppInit_DLLs)" } }
  }
  $ac = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
  if ($ac) { foreach ($pp in $ac.PSObject.Properties) { if ($pp.Name -notlike 'PS*') { [pscustomobject]@{ where = 'AppCertDlls'; name = $pp.Name; value = "$($pp.Value)" } } } }
  $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  foreach ($v in 'Authentication Packages', 'Security Packages', 'Notification Packages') { [pscustomobject]@{ where = 'LSA'; name = $v; value = (@($lsa.$v) -join ', ') } }
  foreach ($c in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
    $sp = (Get-ItemProperty $c.PSPath).StubPath
    if ($sp -and $sp -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\|\\Program Files') { [pscustomobject]@{ where = 'Active Setup StubPath'; name = $c.PSChildName; value = Get-Redacted "$sp"; flags = @(Get-Flags "$sp") } }
  }
  foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+_Classes$' })) {
    foreach ($clsid in (Get-ChildItem "Registry::HKEY_USERS\$($sid.PSChildName)\CLSID")) {
      $srv = (Get-ItemProperty "$($clsid.PSPath)\InprocServer32").'(default)'
      if (-not $srv) { $srv = (Get-ItemProperty "$($clsid.PSPath)\LocalServer32").'(default)' }
      if ($srv) { $p = Get-ProgramPath "$srv"; $sg = Get-Sig $p; [pscustomobject]@{ where = 'User-hive COM override'; name = $clsid.PSChildName; program = $p; sig = if ($sg) { $sg.status } else { '' }; signer = if ($sg) { $sg.signer } else { '' } } }
    }
  }
}

Section 'startupFolders' {
  $shell = New-Object -ComObject WScript.Shell
  $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") + @($users | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
  foreach ($d in $dirs) {
    foreach ($f in (Get-ChildItem -LiteralPath $d -File -Force)) {
      $target = if ($f.Extension -eq '.lnk') { $sc = $shell.CreateShortcut($f.FullName); "$($sc.TargetPath)|$($sc.Arguments)" } else { $f.FullName }
      $parts = $target -split '\|', 2
      $dsc = Describe-Command $parts[0] $(if ($parts.Count -gt 1) { $parts[1] } else { '' })
      [pscustomobject]@{ folder = $d; file = $f.Name; created = $f.CreationTime.ToString('s'); program = $dsc.program; sig = $dsc.sig; signer = $dsc.signer; flags = $dsc.flags; snippet = $dsc.snippet }
    }
  }
}

Section 'wmiSubscriptions' {
  foreach ($f in (Get-CimInstance -Namespace root/subscription -ClassName __EventFilter)) { [pscustomobject]@{ type = 'filter'; name = $f.Name; query = Get-Redacted "$($f.Query)" } }
  foreach ($c in (Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer)) {
    $cmd = "$($c.CommandLineTemplate) $($c.ExecutablePath) $($c.ScriptText)"
    [pscustomobject]@{ type = "consumer:$($c.CimClass.CimClassName)"; name = $c.Name; flags = @(Get-Flags $cmd); snippet = Get-Redacted $cmd; urlHosts = @(Get-UrlHosts $cmd) }
  }
  foreach ($b in (Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding)) { [pscustomobject]@{ type = 'binding'; filter = "$($b.Filter)"; consumer = "$($b.Consumer)" } }
}

Section 'defender' {
  $m = Get-MpComputerStatus
  $p = Get-MpPreference
  [pscustomobject]@{
    type = 'status'; realtime = $m.RealTimeProtectionEnabled; antivirus = $m.AntivirusEnabled; tamperProtected = $m.IsTamperProtected
    signatureAgeDays = $m.AntivirusSignatureAge; lastQuick = "$($m.QuickScanEndTime)"; lastFull = "$($m.FullScanEndTime)"
    disableRealtime = $p.DisableRealtimeMonitoring; disableBehavior = $p.DisableBehaviorMonitoring; disableIOAV = $p.DisableIOAVProtection
    exclusionPaths = @($p.ExclusionPath); exclusionProcesses = @($p.ExclusionProcess); exclusionExtensions = @($p.ExclusionExtension); exclusionIPs = @($p.ExclusionIpAddress)
  }
  foreach ($d in (Get-MpThreatDetection)) { [pscustomobject]@{ type = 'detection'; when = "$($d.InitialDetectionTime)"; threatId = $d.ThreatID; resources = @($d.Resources); actionSuccess = $d.ActionSuccess } }
  foreach ($t in (Get-MpThreat)) { [pscustomobject]@{ type = 'threat'; name = $t.ThreatName; severity = $t.SeverityID; active = $t.IsActive; resources = @($t.Resources) } }
}

Section 'rootCertificates' {
  foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\AuthRoot') {
    foreach ($c in (Get-ChildItem $store)) { [pscustomobject]@{ store = $store; subject = $c.Subject; issuer = $c.Issuer; notBefore = $c.NotBefore.ToString('yyyy-MM-dd'); notAfter = $c.NotAfter.ToString('yyyy-MM-dd'); thumbprint = $c.Thumbprint } }
  }
}

Section 'network' {
  $procs = @{}; foreach ($p in (Get-CimInstance Win32_Process)) { $procs[[int]$p.ProcessId] = $p }
  $private = '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.0\.0\.0|::1$|::$|fe80:|fd)'
  foreach ($c in (Get-NetTCPConnection -State Listen, Established)) {
    if ($c.State -eq 'Established' -and $c.RemoteAddress -match $private) { continue }
    $pr = $procs[[int]$c.OwningProcess]
    $path = if ($pr) { $pr.ExecutablePath } else { '' }
    $sg = Get-Sig $path
    [pscustomobject]@{ state = "$($c.State)"; local = "$($c.LocalAddress):$($c.LocalPort)"; remote = if ($c.State -eq 'Established') { "$($c.RemoteAddress):$($c.RemotePort)" } else { '' }; process = if ($pr) { $pr.Name } else { "pid $($c.OwningProcess)" }; path = $path; sig = if ($sg) { $sg.status } else { '' }; signer = if ($sg) { $sg.signer } else { '' } }
  }
}

Section 'processes' {
  $all = @(Get-CimInstance Win32_Process)
  $byId = @{}; foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }
  foreach ($p in $all) {
    if (-not $p.ExecutablePath) { continue }
    $sg = Get-Sig $p.ExecutablePath
    $odd = ($p.ExecutablePath -match $UserWritable) -or ($sg -and $sg.status -ne 'Valid')
    $fl = @(Get-Flags "$($p.CommandLine)")
    if (-not $odd -and -not ($fl -contains 'encoded-command' -or $fl -contains 'download' -or $fl -contains 'eval' -or $fl -contains 'long-base64')) { continue }
    $parent = $byId[[int]$p.ParentProcessId]
    $o = [ordered]@{ name = $p.Name; pid = $p.ProcessId; path = $p.ExecutablePath; sig = $sg.status; signer = $sg.signer; started = "$($p.CreationDate)"; parent = if ($parent) { $parent.Name } else { "pid $($p.ParentProcessId) (gone)" } }
    if ($fl.Count) { $o.flags = $fl; $o.snippet = Get-Redacted "$($p.CommandLine)" }
    if ($sg.status -ne 'Valid') { $o.sha256 = Get-Sha $p.ExecutablePath }
    [pscustomobject]$o
  }
}

Section 'recentFiles' {
  $cut = (Get-Date).AddDays(-$Days)
  $exts = '.exe', '.dll', '.scr', '.sys', '.ocx', '.cpl', '.msi', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.bat', '.cmd', '.lnk', '.jar'
  $skip = '(?i)\\(node_modules|\.git|INetCache|Packages|WinSxS|npm-cache|_npx|pip\\cache|Code Cache|GPUCache|Service Worker|CacheStorage|User Data\\[^\\]+\\(Cache|Code Cache))\\|\\Temp\\claude\\|\\Microsoft\\WindowsApps\\'
  $roots = @(@{ p = "$env:ProgramData"; d = 3 }, @{ p = "$env:WINDIR\Temp"; d = 2 }, @{ p = "$env:PUBLIC"; d = 3 })
  foreach ($u in $users) {
    $roots += @{ p = (Join-Path $u.FullName 'AppData\Roaming'); d = 4 }, @{ p = (Join-Path $u.FullName 'AppData\Local'); d = 3 },
              @{ p = (Join-Path $u.FullName 'AppData\LocalLow'); d = 3 }, @{ p = (Join-Path $u.FullName 'Downloads'); d = 2 }, @{ p = (Join-Path $u.FullName 'Desktop'); d = 1 }
  }
  $n = 0
  foreach ($r in $roots) {
    foreach ($f in (Get-ChildItem -LiteralPath $r.p -Recurse -Depth $r.d -File -Force)) {
      if ($f.CreationTime -lt $cut -or $exts -notcontains $f.Extension.ToLower() -or $f.FullName -match $skip) { continue }
      if (++$n -gt 5000) { break }
      $isPE = $f.Extension -match '(?i)^\.(exe|dll|scr|sys|ocx|cpl)$'
      if ($isPE) {
        $sg = Get-Sig $f.FullName
        if ($sg.status -eq 'Valid') { continue }
        [pscustomobject]@{ kind = 'program'; path = $f.FullName; created = $f.CreationTime.ToString('s'); size = $f.Length; sig = $sg.status; sha256 = Get-Sha $f.FullName }
      } else {
        [pscustomobject]@{ kind = 'script-or-shortcut'; path = $f.FullName; created = $f.CreationTime.ToString('s'); size = $f.Length }
      }
    }
  }
}

Section 'powershellProfiles' {
  $cands = @("$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1", "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:WINDIR\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1")
  foreach ($u in $users) { foreach ($sub in 'Documents\WindowsPowerShell', 'Documents\PowerShell', 'OneDrive\Documents\WindowsPowerShell', 'OneDrive\Documents\PowerShell') { $cands += (Join-Path (Join-Path $u.FullName $sub) '*profile.ps1') } }
  foreach ($c in $cands) {
    foreach ($f in (Get-ChildItem -Path $c -File -Force)) {
      $txt = Get-Content -LiteralPath $f.FullName -Raw
      [pscustomobject]@{ path = $f.FullName; size = $f.Length; modified = $f.LastWriteTime.ToString('s'); sha256 = Get-Sha $f.FullName; flags = @(Get-Flags "$txt"); urlHosts = @(Get-UrlHosts "$txt") }
    }
  }
}

Section 'browserExtensions' {
  $risky = '<all_urls>', 'webRequest', 'webRequestBlocking', 'cookies', 'debugger', 'nativeMessaging', 'proxy', 'declarativeNetRequest', 'history', 'clipboardRead', 'management', 'scripting'
  foreach ($u in $users) {
    foreach ($b in 'Google\Chrome', 'Microsoft\Edge', 'BraveSoftware\Brave-Browser', 'Vivaldi') {
      $ud = Join-Path $u.FullName "AppData\Local\$b\User Data"
      foreach ($prof in (Get-ChildItem -LiteralPath $ud -Directory -Force | Where-Object { Test-Path (Join-Path $_.FullName 'Extensions') })) {
        foreach ($ext in (Get-ChildItem -LiteralPath (Join-Path $prof.FullName 'Extensions') -Directory -Force)) {
          $mf = Get-ChildItem -LiteralPath $ext.FullName -Directory | Sort-Object Name -Descending | Select-Object -First 1
          if (-not $mf) { continue }
          $m = $null; try { $m = Get-Content -LiteralPath (Join-Path $mf.FullName 'manifest.json') -Raw | ConvertFrom-Json } catch {}
          if (-not $m) { continue }
          $perms = @($m.permissions) + @($m.host_permissions) + @($m.optional_permissions) | ForEach-Object { "$_" }
          [pscustomobject]@{ user = $u.Name; browser = $b; profile = $prof.Name; id = $ext.Name; name = "$($m.name)"; version = "$($m.version)"; updateUrl = "$($m.update_url)"; riskyPermissions = @($perms | Where-Object { $risky -contains $_ -or $_ -match '^\*://\*/\*$|^https?://\*/\*$' } | Select-Object -Unique) }
        }
      }
    }
  }
}

Section 'hostsAndProxy' {
  foreach ($l in (Get-Content "$env:WINDIR\System32\drivers\etc\hosts")) { if ($l.Trim() -and -not $l.Trim().StartsWith('#')) { [pscustomobject]@{ type = 'hosts'; line = $l.Trim() } } }
  $hk = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings')
  foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) { $hk += "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Internet Settings" }
  foreach ($k in ($hk | Select-Object -Unique)) {
    $p = Get-ItemProperty $k
    if ($p.ProxyEnable -or $p.ProxyServer -or $p.AutoConfigURL) { [pscustomobject]@{ type = 'proxy'; where = $k; enabled = $p.ProxyEnable; server = "$($p.ProxyServer)"; autoConfigUrl = "$($p.AutoConfigURL)" } }
  }
}

Section 'accounts' {
  foreach ($u in (Get-LocalUser)) { [pscustomobject]@{ type = 'user'; name = $u.Name; enabled = $u.Enabled; lastLogon = "$($u.LastLogon)"; passwordSet = "$($u.PasswordLastSet)"; description = $u.Description } }
  foreach ($m in (Get-LocalGroupMember -Group 'Administrators')) { [pscustomobject]@{ type = 'administrator'; name = $m.Name; source = "$($m.PrincipalSource)" } }
}

# ---------------------------------------------------------------- write
$result = [pscustomobject]@{
  app = 'Hideout hunt'; version = 1; computer = $env:COMPUTERNAME; admin = $isAdmin
  started = $started.ToString('s'); seconds = [math]::Round(((Get-Date) - $started).TotalSeconds)
  osBuild = [Environment]::OSVersion.Version.ToString(); recentDays = $Days
  sections = [pscustomobject]$report
}
if (-not $Out) { $Out = Join-Path $PSScriptRoot ("out\hunt-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm')) }
$outDir = Split-Path $Out -Parent
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
[IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Hideout hunt done in $($result.seconds)s - $Out"
