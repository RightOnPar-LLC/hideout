# build-exe.ps1 - packages the Hideout app as ONE double-click Windows .exe (dist\Hideout.exe).
# Every test suite must pass first; then esbuild bundles the app + the Claude SDK into one
# CJS file (fetched on demand via npx, never a dependency), Node's SEA tooling embeds it plus
# the app's static files, and postject injects the blob into a copy of node.exe.
# The PowerShell engine (hideout.ps1, hunt.ps1) ships INSIDE the exe as assets and is
# written to %LOCALAPPDATA%\Hideout\engine on start. No key or .env is ever an asset.
#
# Optional, per builder (neither is in the repo):
#   gateway URL  - $env:HIDEOUT_GATEWAY_URL, or the first line of app\gateway-url.txt
#                  (git-ignored). Without one the guide needs ANTHROPIC_API_KEY at run time.
#   memory engine - $env:HIDEOUT_BRAIN_EXE, or a cognitive-mcp release build beside this
#                  repo's parent folder. Without one Hideout runs with memory off.
# ASCII-only on purpose (Windows PowerShell 5.1 misparses non-ASCII in scripts).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$dist = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null

Write-Host "running self-tests (app + money + doors + engine + gateway)..."
& node (Join-Path $PSScriptRoot 'tests\selftest.mjs')
if ($LASTEXITCODE -ne 0) { throw "app selftest failed - build aborted" }
& node (Join-Path $PSScriptRoot 'tests\money.selftest.mjs')
if ($LASTEXITCODE -ne 0) { throw "money selftest failed - build aborted" }
& node (Join-Path $PSScriptRoot 'tests\doors.selftest.mjs')
if ($LASTEXITCODE -ne 0) { throw "doors selftest failed - build aborted" }
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot '..\tests\selftest.ps1')
if ($LASTEXITCODE -ne 0) { throw "engine selftest failed - build aborted" }
& node (Join-Path $PSScriptRoot '..\gateway\tests\selftest.mjs')
if ($LASTEXITCODE -ne 0) { throw "gateway selftest failed - build aborted" }

$assets = [ordered]@{
  'version.txt' = 'dist/version.txt'
  'ui/index.html' = 'ui/index.html'
  'data/merchants.json' = 'data/merchants.json'
  'engine/hideout.ps1' = '../hideout.ps1'
  'engine/hunt.ps1' = '../hunt.ps1'
  'engine/report.html' = '../report.html'
}

# The guide talks to a cloud gateway (which holds the Claude key) - never a key in the exe.
$gatewayUrl = $env:HIDEOUT_GATEWAY_URL
$gwFile = Join-Path $PSScriptRoot 'gateway-url.txt'
if (-not $gatewayUrl -and (Test-Path $gwFile)) { $gatewayUrl = (Get-Content $gwFile -TotalCount 1).Trim() }
if ($gatewayUrl) {
  if ($gatewayUrl -notmatch '^https://[^/\s]+/?$') { throw "gateway URL must be https://host - got '$gatewayUrl'" }
  @{ url = $gatewayUrl } | ConvertTo-Json -Compress | Set-Content (Join-Path $dist 'gateway.json') -Encoding ascii -NoNewline
  $assets['gateway.json'] = 'dist/gateway.json'
  Write-Host "guide gateway: $gatewayUrl"
} else { Write-Host "no gateway URL - the guide will need ANTHROPIC_API_KEY at run time" }

# The private brain's engine (cognitive-mcp) ships inside the exe when it is available.
$brainExe = if ($env:HIDEOUT_BRAIN_EXE) { $env:HIDEOUT_BRAIN_EXE } else { Join-Path $PSScriptRoot '..\..\..\cognitive-mcp\rust\target\release\cognitive-mcp.exe' }
if (Test-Path $brainExe) {
  Copy-Item $brainExe (Join-Path $dist 'cognitive-mcp.exe') -Force
  $assets['brain/cognitive-mcp.exe'] = 'dist/cognitive-mcp.exe'
} else { Write-Host "memory engine not found at $brainExe - building with memory off" }

$hash = (git rev-parse --short HEAD 2>$null); if (-not $hash) { $hash = 'nogit' }
"$(Get-Date -Format 'yyyy-MM-dd') $hash" | Set-Content (Join-Path $dist 'version.txt') -Encoding ascii -NoNewline

Write-Host "bundling (esbuild, fetched on demand)..."
$nodeExe = (Get-Command node).Source
$npx = Join-Path (Split-Path $nodeExe) 'npx.cmd'
& $npx --yes esbuild src/main.mjs --bundle --platform=node --format=cjs --target=node22 --outfile="$dist/hideout-bundle.cjs" --log-level=warning
if ($LASTEXITCODE -ne 0) { throw "esbuild bundling failed ($LASTEXITCODE)" }

[ordered]@{ main = 'dist/hideout-bundle.cjs'; output = 'dist/sea-prep.blob'; disableExperimentalSEAWarning = $true; assets = $assets } | ConvertTo-Json -Depth 4 | Set-Content sea-config.json -Encoding ascii

node --experimental-sea-config sea-config.json
if ($LASTEXITCODE -ne 0) { throw "SEA blob build failed ($LASTEXITCODE)" }

$exe = Join-Path $dist 'Hideout.exe'
# A running Hideout.exe can't be overwritten, but Windows lets it be renamed: the open window
# keeps running from the old file and the next launch gets the new build.
if (Test-Path $exe) {
  try { Remove-Item $exe -Force -ErrorAction Stop }
  catch { $old = "Hideout.previous-$(Get-Date -Format 'yyyyMMdd-HHmmss').exe"; Rename-Item $exe $old; Write-Host "Hideout.exe was open - kept it running as $old" }
}
Copy-Item $nodeExe $exe -Force
& $npx --yes postject "$exe" NODE_SEA_BLOB "$dist\sea-prep.blob" --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
if ($LASTEXITCODE -ne 0) { throw "postject failed ($LASTEXITCODE)" }

Remove-Item "$dist\sea-prep.blob", "$dist\hideout-bundle.cjs", "$dist\cognitive-mcp.exe", "$dist\gateway.json" -Force -ErrorAction SilentlyContinue
$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Built dist\Hideout.exe ($size MB) - double-click to run. Unsigned: sign it before giving it to anyone else."
