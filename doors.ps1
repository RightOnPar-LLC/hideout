<#
  Hideout doors & power - RAW FACTS only, read-only. Collects every way into this PC that
  might be standing open (Remote Desktop, an admin account that may have no password, disk
  encryption, remote-support programs, antivirus) and why it might keep dying (sudden
  shutdowns, battery and charger health, sleep timers, a restart waiting, disk space, an
  opt-in speed check). Every Section below returns ONE item shaped {checked, control, facts}:
  checked is whether the read itself succeeded, control is an independent observation that
  proves the read actually answered (never trust an empty result on its own), and facts are
  the raw numbers - no verdict, no judgement. Every verdict lives in JS (app/src/doors/
  summarize.mjs and decode.mjs); this script never decides "open" or "shut".

  Two entry points via -Pass:
    quick  - registry keys, the Explorer BitLocker property, Win32_Battery, fixed disks,
             process names, Get-LocalUser/ADSI. Seconds.
    slow   - event logs, scheduled tasks, firewall, Defender status. Several seconds to a
             couple of minutes; meant to run once per launch in the background, never from
             inside a single request.
    speed  - OPT-IN only. A 6s in-process CPU load plus counter samples. Never automatic and
             never launched by the guide.

  NEVER changes a setting, enables/disables an account, flips Remote Desktop, turns
  encryption on or off, starts or stops an antivirus scan, or registers/removes a scheduled
  task. Behind an admin prompt (a future PR) it still only reads.

  Run:   pwsh -File doors.ps1 -Pass quick
  Tests: pwsh -File tests\selftest.ps1

  Keep this file ASCII-only: Windows PowerShell 5.1 misreads non-ASCII as parse errors.
#>
[CmdletBinding()]
param(
  [ValidateSet('quick', 'slow', 'speed')][string]$Pass = 'quick',
  [string]$Out
)
$ErrorActionPreference = 'SilentlyContinue'
$started = Get-Date

# ISO dates everywhere: Windows PowerShell 5.1's ConvertTo-Json renders a bare DateTime as
# the string "\/Date(...)\/ ", never a clean timestamp - measured this session. Iso() is the
# single place every date passes through, so a summarizer can always match ^\d{4}-\d{2}-\d{2}T
# or treat '' as "no date". A MinValue / 1601 date (never set) is also treated as ''.
function Iso($d) {
  if (-not $d) { return '' }
  try {
    $v = $d -as [DateTime]
    if ($v -and $v.Year -gt 1601) { return $v.ToString('s') }
  } catch {}
  return ''
}

# ---------------------------------------------------------------- Section / Get-Redacted
# Byte-identical to hunt.ps1's own copies (an engine test asserts this) - the helper has one
# home (hunt.ps1, which runs elevated and stays self-contained on purpose) and this is a
# checked mirror, not drift. Get-Redacted exists here for any future action-snippet reading
# doors.ps1 grows into; today no Section below reads a full command line at all.
$redactor = [System.Text.RegularExpressions.MatchEvaluator] { param($m) "[redacted $($m.Value.Length) chars]" }
function Get-Redacted([string]$s) {
  if (-not $s) { return '' }
  $r = [regex]::Replace($s, '[A-Za-z0-9+/=_\-\.%]{28,}', $redactor)
  if ($r.Length -gt 240) { $r = $r.Substring(0, 240) + '...' }
  return $r
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

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Managed-PC flag, shared by remoteDesktop and extraAccount: a registry read only, never a
# domain-join console tool and never a session-enumeration console tool.
function Get-ManagedFlag {
  $partOfDomain = $false
  try { $partOfDomain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
  $entraJoined = $false
  try { $entraJoined = [bool](Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo') } catch {}
  [pscustomobject]@{ partOfDomain = $partOfDomain; entraJoined = $entraJoined }
}

# ================================================================== QUICK PASS
if ($Pass -eq 'quick') {

  Section 'remoteDesktopRegistry' {
    $regOk = $true
    $fDeny = $null
    try { $fDeny = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections } catch { $regOk = $false }
    $nla = $null
    try { $nla = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop).UserAuthentication } catch {}
    $sessions = @()
    try {
      $sessions = @(Get-CimInstance Win32_LogonSession -Filter 'LogonType=10' -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ startTime = Iso($_.StartTime) } })
    } catch {}
    $termPresent = $false
    try { $termPresent = [bool](Get-Service -Name TermService -ErrorAction Stop) } catch {}
    $managed = Get-ManagedFlag
    [pscustomobject]@{
      checked = $regOk
      control = [pscustomobject]@{ registryReadable = $regOk; termServicePresent = $termPresent }
      facts   = [pscustomobject]@{
        fDenyTSConnections = $fDeny; userAuthenticationNLA = $nla; remoteSessions = $sessions
        partOfDomain = $managed.partOfDomain; entraJoined = $managed.entraJoined
      }
    }
  }

  Section 'extraAccount' {
    $usersOk = $true
    $users = @()
    try {
      $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
          [pscustomobject]@{
            name = $_.Name; enabled = [bool]$_.Enabled; passwordRequired = [bool]$_.PasswordRequired
            passwordLastSet = Iso($_.PasswordLastSet); principalSource = "$($_.PrincipalSource)"
          }
        })
    } catch { $usersOk = $false }
    $adminSource = 'group-member'
    $admins = @()
    try {
      $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ name = "$($_.Name)"; source = "$($_.PrincipalSource)" } })
    } catch {
      $adminSource = 'adsi'
      try {
        $grp = [ADSI]'WinNT://./Administrators,group'
        $admins = @($grp.psbase.Invoke('Members') | ForEach-Object {
            $n = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
            [pscustomobject]@{ name = "$n"; source = 'Local' }
          })
      } catch {}
    }
    $builtins = 'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount'
    $builtinsPresent = @($users | Where-Object { $builtins -contains $_.name }).Count -gt 0
    $managed = Get-ManagedFlag
    [pscustomobject]@{
      checked = $usersOk
      control = [pscustomobject]@{ usersReadable = $usersOk; builtinsPresent = $builtinsPresent }
      facts   = [pscustomobject]@{
        users = $users; administrators = $admins; adminSource = $adminSource
        partOfDomain = $managed.partOfDomain; entraJoined = $managed.entraJoined
      }
    }
  }

  Section 'diskEncryption' {
    $disks = @()
    try { $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | Where-Object { $_.Size -ge 32GB }) } catch {}
    $shell = New-Object -ComObject Shell.Application
    # The Win32_EncryptableVolume CIM class (a documented second source when it answers) is
    # deliberately NOT read here: measured on this machine, non-admin, it took 5.1s to fail
    # with "Access to a CIM resource was not available to the client" for ONE drive - a cost
    # that breaks the quick pass's "seconds, no prompt" contract for a read that fails for
    # almost everyone anyway. The Shell property alone answered in well under a second and is
    # the sole quick-pass source; the admin hunt.ps1 'bitlocker' Section is the authoritative
    # second source once elevated (a future PR wires it in - see doors.diskEncryption).
    $drives = @(foreach ($d in $disks) {
        $prop = $null
        try { $prop = $shell.NameSpace("$($d.DeviceID)\").Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch {}
        [pscustomobject]@{ drive = $d.DeviceID; sizeBytes = $d.Size; shellProperty = $prop }
      })
    $sysDrive = "$env:SystemDrive"
    $sysAnswered = @($drives | Where-Object { $_.drive -eq $sysDrive -and $null -ne $_.shellProperty -and $_.shellProperty -ne '' }).Count -gt 0
    $osCaption = ''
    $osSku = $null
    try { $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $osCaption = "$($osInfo.Caption)"; $osSku = $osInfo.OperatingSystemSKU } catch {}
    [pscustomobject]@{
      checked = ($disks.Count -gt 0)
      control = [pscustomobject]@{ systemDriveAnswered = $sysAnswered }
      facts   = [pscustomobject]@{ drives = $drives; osCaption = $osCaption; osSku = $osSku }
    }
  }

  Section 'remoteSupportInstalled' {
    $procOk = $true
    $procs = @()
    try { $procs = @(Get-Process -ErrorAction Stop | Select-Object -ExpandProperty ProcessName -Unique) } catch { $procOk = $false }
    $knownProcessSeen = @($procs | Where-Object { $_ -match '^(explorer|svchost)$' }).Count -gt 0
    [pscustomobject]@{
      checked = $procOk
      control = [pscustomobject]@{ processListReadable = $procOk; knownProcessSeen = $knownProcessSeen }
      facts   = [pscustomobject]@{ processNames = $procs }
    }
  }

  Section 'restartWaiting' {
    $rebootRequired = [bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    $cbsPending = [bool](Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    $pfro = $false
    try { $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations; $pfro = [bool]$v } catch {}
    $uxOk = $true
    $hoursStart = $null; $hoursEnd = $null
    try {
      $ux = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction Stop
      $hoursStart = $ux.ActiveHoursStart; $hoursEnd = $ux.ActiveHoursEnd
    } catch { $uxOk = $false }
    $boot = ''; $uptimeSeconds = $null
    try {
      $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
      $boot = Iso($osInfo.LastBootUpTime)
      $uptimeSeconds = [math]::Round(((Get-Date) - $osInfo.LastBootUpTime).TotalSeconds)
    } catch {}
    [pscustomobject]@{
      checked = $uxOk
      control = [pscustomobject]@{ uxKeyReadable = $uxOk }
      facts   = [pscustomobject]@{
        rebootRequired = $rebootRequired; cbsRebootPending = $cbsPending; pendingFileRename = $pfro
        activeHoursStart = $hoursStart; activeHoursEnd = $hoursEnd; lastBootUpTime = $boot; uptimeSeconds = $uptimeSeconds
      }
    }
  }

  Section 'diskSpace' {
    $drives = @()
    $ok = $true
    try {
      $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | Where-Object { $_.Size -ge 32GB } | ForEach-Object {
          [pscustomobject]@{ drive = $_.DeviceID; sizeBytes = $_.Size; freeBytes = $_.FreeSpace }
        })
    } catch { $ok = $false }
    $sysDrive = "$env:SystemDrive"
    $sysPresent = @($drives | Where-Object { $_.drive -eq $sysDrive }).Count -gt 0
    $memTotal = $null; $memFree = $null
    try { $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $memTotal = $osInfo.TotalVisibleMemorySize; $memFree = $osInfo.FreePhysicalMemory } catch {}
    [pscustomobject]@{
      checked = $ok
      control = [pscustomobject]@{ systemDrivePresent = $sysPresent }
      facts   = [pscustomobject]@{ drives = $drives; memoryTotalKb = $memTotal; memoryFreeKb = $memFree }
    }
  }

  Section 'sleepTimers' {
    $SUB_SLEEP = '238C9FA8-0AAD-41ED-83F4-97BE242C8F20'
    $SUB_VIDEO = '7516B95F-F776-4464-8C53-06167F40CC99'
    $STANDBYIDLE = '29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA'
    $VIDEOIDLE = '3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E'
    $VIDEOCONLOCK = '8EC4B3A5-6868-48c2-BE75-4F3044BE88A7'
    $active = $null
    try { $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -Name ActivePowerScheme -ErrorAction Stop).ActivePowerScheme } catch {}
    function Get-PowerIndex($scheme, $subgroup, $setting) {
      if (-not $scheme) { return $null }
      $per = $null
      try { $per = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$scheme\$subgroup\$setting" -ErrorAction Stop } catch {}
      if ($per) { return [pscustomobject]@{ ac = $per.ACSettingIndex; dc = $per.DCSettingIndex; source = 'per-scheme' } }
      $def = $null
      try { $def = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$subgroup\$setting\DefaultPowerSchemeValues\$scheme" -ErrorAction Stop } catch {}
      if ($def) { return [pscustomobject]@{ ac = $def.ACSettingIndex; dc = $def.DCSettingIndex; source = 'default' } }
      return $null
    }
    $standby = Get-PowerIndex $active $SUB_SLEEP $STANDBYIDLE
    $videoIdle = Get-PowerIndex $active $SUB_VIDEO $VIDEOIDLE
    $videoConLock = Get-PowerIndex $active $SUB_VIDEO $VIDEOCONLOCK
    $model = ''
    try { $model = (powercfg /a | Out-String) } catch {}
    $qh = ''
    try { $qh = (powercfg /qh | Out-String) } catch {}
    $modelListed = [bool]($model -match 'S0 Low Power Idle' -or $model -match 'Standby \(S1')
    $registryOk = [bool]($standby -or $videoIdle)
    [pscustomobject]@{
      checked = $registryOk
      control = [pscustomobject]@{ modelListed = $modelListed }
      facts   = [pscustomobject]@{
        activeScheme = $active; standbyIdle = $standby; videoIdle = $videoIdle; videoConLock = $videoConLock
        modelText = $model; qhText = $qh
      }
    }
  }

  Section 'battery' {
    $battOk = $true
    $charge = $null; $status = $null
    try {
      $b = Get-CimInstance Win32_Battery -ErrorAction Stop | Select-Object -First 1
      if ($b) { $charge = $b.EstimatedChargeRemaining; $status = $b.BatteryStatus }
    } catch { $battOk = $false }
    $hasBattery = $null -ne $charge -or $null -ne $status
    $full = $null
    try { $full = (Get-CimInstance -Namespace 'root/wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1).FullChargedCapacity } catch {}
    $design = $null
    try { $design = (Get-CimInstance -Namespace 'root/wmi' -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1).DesignedCapacity } catch {}
    [pscustomobject]@{
      checked = $battOk
      control = [pscustomobject]@{ win32BatteryAnswered = $battOk }
      facts   = [pscustomobject]@{ hasBattery = $hasBattery; estimatedChargeRemaining = $charge; batteryStatus = $status; fullChargedCapacity = $full; designedCapacity = $design }
    }
  }
}

# ================================================================== SLOW PASS
if ($Pass -eq 'slow') {

  Section 'remoteDesktopFirewall' {
    $ok = $true
    $rules = @()
    try { $rules = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ enabled = [bool]($_.Enabled -eq 1) } }) } catch { $ok = $false }
    $groupPresent = $ok
    [pscustomobject]@{
      checked = $ok
      control = [pscustomobject]@{ firewallReadable = $ok; groupPresent = $groupPresent }
      facts   = [pscustomobject]@{ enabledRuleCount = @($rules | Where-Object { $_.enabled }).Count; ruleCount = $rules.Count }
    }
  }

  Section 'antivirus' {
    $ok = $true
    $m = $null
    try { $m = Get-MpComputerStatus -ErrorAction Stop } catch { $ok = $false }
    $hasMode = [bool]($m -and $m.AMRunningMode)
    [pscustomobject]@{
      checked = $ok
      control = [pscustomobject]@{ statusReadable = $ok; hasRunningMode = $hasMode }
      facts   = [pscustomobject]@{
        amRunningMode = if ($m) { "$($m.AMRunningMode)" } else { '' }
        realTimeProtectionEnabled = if ($m) { [bool]$m.RealTimeProtectionEnabled } else { $null }
        antivirusEnabled = if ($m) { [bool]$m.AntivirusEnabled } else { $null }
        isTamperProtected = if ($m) { [bool]$m.IsTamperProtected } else { $null }
        signatureAgeDays = if ($m) { $m.AntivirusSignatureAge } else { $null }
        quickScanEndTime = if ($m) { Iso($m.QuickScanEndTime) } else { '' }
        fullScanEndTime = if ($m) { Iso($m.FullScanEndTime) } else { '' }
      }
    }
  }

  Section 'suddenShutdowns' {
    $days = 30
    $since = (Get-Date).AddDays(-$days)
    $ctrlOk = $true
    $ctrlCount = 0
    try { $ctrlCount = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $since } -ErrorAction Stop).Count } catch { $ctrlOk = $false }
    $kp41 = @()
    try {
      $kp41 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41; ProviderName = 'Microsoft-Windows-Kernel-Power'; StartTime = $since } -ErrorAction Stop | ForEach-Object {
          $xml = [xml]$_.ToXml()
          $data = @{}
          foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
          [pscustomobject]@{ timeCreated = Iso($_.TimeCreated); bugcheckCode = $data.BugcheckCode; powerButtonTimestamp = $data.PowerButtonTimestamp }
        })
    } catch {}
    $c6008 = 0
    try { $c6008 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6008; StartTime = $since } -ErrorAction Stop).Count } catch {}
    $c1001 = 0
    try { $c1001 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since } -ErrorAction Stop).Count } catch {}
    $cWhea = 0
    try { $cWhea = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } -ErrorAction Stop).Count } catch {}
    $dumps = @()
    try { $dumps = @(Get-ChildItem "$env:WINDIR\Minidump" -File -ErrorAction Stop | Where-Object { $_.CreationTime -ge $since } | ForEach-Object { Iso($_.CreationTime) }) } catch {}
    $memDump = $false
    try { $memDump = [bool](Test-Path "$env:WINDIR\MEMORY.DMP") } catch {}
    $crashDumpEnabled = $null
    try { $crashDumpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -ErrorAction Stop).CrashDumpEnabled } catch {}
    [pscustomobject]@{
      checked = $ctrlOk
      control = [pscustomobject]@{ systemLogReadable = $ctrlOk; sampleCountWithoutIdFilter = $(if ($ctrlOk) { $ctrlCount } else { $null }) }
      facts   = [pscustomobject]@{
        windowDays = $days; kp41 = $kp41; count6008 = $c6008; count1001 = $c1001; countWhea = $cWhea
        minidumps = $dumps; memoryDmp = $memDump; crashDumpEnabled = $crashDumpEnabled
      }
    }
  }

  Section 'batteryAndCharger' {
    $days = 30
    $since = (Get-Date).AddDays(-$days)
    $ctrlOk = $true
    $kp105 = @()
    try {
      $kp105 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 105; ProviderName = 'Microsoft-Windows-Kernel-Power'; StartTime = $since } -ErrorAction Stop | ForEach-Object {
          $xml = [xml]$_.ToXml()
          $data = @{}
          foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
          [pscustomobject]@{ timeCreated = Iso($_.TimeCreated); acOnline = $data.AcOnline }
        })
    } catch { $ctrlOk = $false }
    $kp524 = @()
    try {
      $kp524 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 524; ProviderName = 'Microsoft-Windows-Kernel-Power'; StartTime = $since } -ErrorAction Stop | ForEach-Object { Iso($_.TimeCreated) })
    } catch {}
    [pscustomobject]@{
      checked = $ctrlOk
      control = [pscustomobject]@{ systemLogReadable = $ctrlOk }
      facts   = [pscustomobject]@{ windowDays = $days; kp105 = $kp105; kp524 = $kp524 }
    }
  }

  Section 'startupHealth' {
    $ctrlOk = $true
    $tasks = @()
    try {
      $all = @(Get-ScheduledTask -ErrorAction Stop)
      $ctrlOk = @($all | Where-Object { $_.TaskPath -match '^\\Microsoft\\' }).Count -gt 0
      $tasks = @($all | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } | ForEach-Object {
          $i = $null; try { $i = $_ | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
          [pscustomobject]@{
            path = $_.TaskPath; name = $_.TaskName; state = "$($_.State)"
            lastTaskResult = if ($i) { $i.LastTaskResult } else { $null }
            disallowStartIfOnBatteries = [bool]$_.Settings.DisallowStartIfOnBatteries
          }
        })
    } catch { $ctrlOk = $false }
    $vbsStartup = @()
    try {
      $shell = New-Object -ComObject WScript.Shell
      foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        foreach ($f in (Get-ChildItem -LiteralPath $d -File -Filter *.lnk -ErrorAction SilentlyContinue)) {
          $target = $shell.CreateShortcut($f.FullName).TargetPath
          if ($target -match '(?i)\.vbs$') { $vbsStartup += $f.Name }
        }
      }
    } catch {}
    $days = 30
    $since = (Get-Date).AddDays(-$days)
    $vbsCtrlOk = $true
    try { $null = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since } -ErrorAction Stop -MaxEvents 1 } catch { $vbsCtrlOk = $false }
    $vbsCount = 0
    try {
      $vbsCount = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 4096; StartTime = $since } -ErrorAction Stop | Where-Object { $_.ProviderName -eq 'VBScriptDeprecationAlert' }).Count
    } catch {}
    [pscustomobject]@{
      checked = $ctrlOk
      control = [pscustomobject]@{ microsoftTaskSeen = $ctrlOk; vbsLogReadable = $vbsCtrlOk }
      facts   = [pscustomobject]@{ tasks = $tasks; vbsStartupEntries = $vbsStartup; vbsDeprecationCount = $vbsCount }
    }
  }
}

# ================================================================== SPEED PASS (opt-in only)
if ($Pass -eq 'speed') {
  Section 'speedCap' {
    $n = [Environment]::ProcessorCount
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $jobs = @(for ($i = 0; $i -lt $n; $i++) {
        $ps = [powershell]::Create()
        [void]$ps.AddScript({ param($budget) $t = [Diagnostics.Stopwatch]::StartNew(); while ($t.Elapsed.TotalSeconds -lt $budget) { } }).AddArgument(6)
        [pscustomobject]@{ ps = $ps; handle = $ps.BeginInvoke() }
      })
    $ctrOk = $true
    $perf = @(); $util = @()
    try {
      for ($i = 0; $i -lt 4; $i++) {
        $p = (Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop).CounterSamples[0].CookedValue
        $u = (Get-Counter '\Processor Information(_Total)\% Processor Utility' -ErrorAction Stop).CounterSamples[0].CookedValue
        if ($i -gt 0) { $perf += [math]::Round($p, 1); $util += [math]::Round($u, 1) }
        Start-Sleep -Seconds 1
      }
    } catch { $ctrOk = $false }
    foreach ($j in $jobs) { try { $null = $j.ps.EndInvoke($j.handle) } catch {}; $j.ps.Dispose() }
    $sw.Stop()
    $firmwareLimits = 0
    try { $firmwareLimits = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop).Count } catch {}
    [pscustomobject]@{
      checked = $ctrOk
      control = [pscustomobject]@{ counterReadable = $ctrOk }
      facts   = [pscustomobject]@{ perf = $perf; util = $util; firmwareLimitEvents = $firmwareLimits; loadSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) }
    }
  }
}

# ---------------------------------------------------------------- write
$result = [pscustomobject]@{
  app = 'Hideout doors'; version = 1; pass = $Pass
  computer = $env:COMPUTERNAME; admin = $isAdmin
  started = Iso($started); seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
  sections = [pscustomobject]$report
}
if ($Out) {
  $outDir = Split-Path $Out -Parent
  if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
  [IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "Hideout doors ($Pass) done in $($result.seconds)s - $Out"
} else {
  $result | ConvertTo-Json -Depth 8
}
