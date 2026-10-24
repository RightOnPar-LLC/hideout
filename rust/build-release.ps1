<#
  The release build. Use this, not a bare `cargo build --release`, for anything that
  leaves this machine.

  Rust records source-file locations for panic messages. Without remapping, those are
  the build machine's own paths - its home folder and user name - inside a binary that
  ships to strangers. This build remaps every build-machine prefix to a neutral name,
  links the C runtime statically (one self-contained exe), and then re-reads the
  finished binaries: if the home folder, the user name or the machine name is still in
  there, the build FAILS.

    powershell -File rust\build-release.ps1                 (hideout + hideout-parity)
    powershell -File rust\build-release.ps1 -Packages hideout
  ASCII-only.
#>
param([string[]]$Packages = @('hideout', 'hideout-parity'), [switch]$SelfTest)
$ErrorActionPreference = 'Stop'
$ws = $PSScriptRoot
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $env:USERPROFILE '.rustup' }
$needles = @($env:USERPROFILE, $env:USERNAME, $env:COMPUTERNAME, $cargoHome, $rustupHome, $ws) | Where-Object { $_ -and $_.Length -ge 4 } | Select-Object -Unique

function Find-Leaks([string]$file) {
  $bytes = [IO.File]::ReadAllBytes($file)
  $hits = @()
  foreach ($text in [Text.Encoding]::ASCII.GetString($bytes), [Text.Encoding]::Unicode.GetString($bytes)) {
    foreach ($n in $needles) { if ($text.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits += $n } }
  }
  return @($hits | Select-Object -Unique)
}

if ($SelfTest) {
  # Negative control: the check must catch a planted home path (ASCII and UTF-16) and
  # must pass a file without one.
  $t = Join-Path $env:TEMP "hideout-leakcheck-$PID.bin"
  [IO.File]::WriteAllBytes($t, [Text.Encoding]::ASCII.GetBytes("panic at $($env:USERPROFILE)\x.rs"))
  $a = (Find-Leaks $t).Count -gt 0
  [IO.File]::WriteAllBytes($t, [Text.Encoding]::Unicode.GetBytes("path $($env:USERPROFILE)"))
  $w = (Find-Leaks $t).Count -gt 0
  [IO.File]::WriteAllBytes($t, [Text.Encoding]::ASCII.GetBytes('panic at hideout\crates\x.rs'))
  $c = (Find-Leaks $t).Count -eq 0
  Remove-Item $t
  "leak check self-test: ascii caught=$a utf16 caught=$w clean passes=$c"
  if ($a -and $w -and $c) { exit 0 } else { exit 1 }
}
$flags = @(
  '-C', 'target-feature=+crt-static',
  "--remap-path-prefix=$cargoHome=cargo",
  "--remap-path-prefix=$rustupHome=rustup",
  "--remap-path-prefix=$ws=hideout",
  "--remap-path-prefix=$($env:USERPROFILE)=home"
)
# The encoded form keeps paths with spaces intact (fields separated by 0x1F).
$env:CARGO_ENCODED_RUSTFLAGS = ($flags -join [char]0x1f)
Push-Location $ws
try {
  $pk = foreach ($p in $Packages) { '-p'; $p }
  & cargo build --release @pk
  if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
} finally { Pop-Location; Remove-Item Env:\CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue }

# Re-read what was built. ASCII and UTF-16 both, case-insensitive.
$bad = @()
foreach ($p in $Packages) {
  $exe = Join-Path $ws "target\release\$p.exe"
  if (-not (Test-Path $exe)) { continue }
  foreach ($n in (Find-Leaks $exe)) { $bad += "$p.exe contains '$n'" }
  $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
  Write-Host ("{0,-20} {1,10:N0} bytes  sha256 {2}" -f "$p.exe", (Get-Item $exe).Length, $hash)
}
if ($bad.Count) { $bad | Select-Object -Unique | ForEach-Object { Write-Host "FAIL $_" -ForegroundColor Red }; exit 1 }
Write-Host 'build-release: no build-machine paths, user or machine names in the binaries'
