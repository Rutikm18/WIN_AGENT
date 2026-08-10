<#
.SYNOPSIS
    Build AttackLens Agent EXEs via PyInstaller (onedir, Windows Service safe).

.DESCRIPTION
    Produces two onedir distributions in dist\:
      dist\attacklens-agent\      - agent binary + _internal dependencies
      dist\attacklens-watchdog\   - watchdog binary + _internal dependencies

    OneDIR is required for Windows Services: --onefile extracts to a temp path
    each run, causing the SCM to lose track of the registered executable PID.

    The spec files (attacklens-agent.spec, attacklens-watchdog.spec) embed the
    correct hidden imports and pathex settings — do not use --onefile.

    Optionally Authenticode-signs both top-level EXEs.

.PARAMETER SignIdentity
    Authenticode certificate thumbprint or CN= subject name for signtool.exe.
    Leave empty to skip signing (dev builds).

.PARAMETER SkipWatchdog
    Build only the agent EXE; skip the watchdog.

.PARAMETER Clean
    Delete the build\ work directory before building (forces a full rebuild).

.EXAMPLE
    # Unsigned dev build
    .\build_exe.ps1

.EXAMPLE
    # Signed release build
    .\build_exe.ps1 -SignIdentity "CN=AttackLens Inc"

.EXAMPLE
    # Agent only, clean rebuild
    .\build_exe.ps1 -SkipWatchdog -Clean
#>
param(
    [string] $SignIdentity = "",
    [switch] $SkipWatchdog = $false,
    [switch] $Clean        = $false
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ── Path resolution ───────────────────────────────────────────────────────────
# This script lives at: <ROOT>/agent/os/windows/pkg/build_exe.ps1
$pkg  = $PSScriptRoot
$ROOT = (Resolve-Path (Join-Path $pkg "..\..\..\..")).Path
$dist = Join-Path $pkg "dist"

function Banner([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function OK([string]$m)     { Write-Host "  [OK] $m"   -ForegroundColor Green }
function Info([string]$m)   { Write-Host "  $m" }

function Resolve-Python313 {
    $candidates = @(
        $env:ATTACKLENS_PYTHON
        if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe" }
        if ($env:ProgramFiles) { Join-Path $env:ProgramFiles "Python313\python.exe" }
        (Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and $candidate -notmatch '\\WindowsApps\\' -and
                (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "Python 3.13 not found. Set ATTACKLENS_PYTHON to python.exe."
}
$pythonExe = Resolve-Python313

Write-Host ""
Write-Host "  AttackLens EXE Builder (onedir)" -ForegroundColor Cyan
Write-Host "  Root : $ROOT" -ForegroundColor DarkGray
Write-Host "  Dist : $dist" -ForegroundColor DarkGray
Write-Host ""

# ── Clean ─────────────────────────────────────────────────────────────────────
if ($Clean) {
    Banner "Clean"
    $buildDir = Join-Path $pkg "build"
    if (Test-Path $buildDir) {
        Remove-Item $buildDir -Recurse -Force
        OK "Removed build\"
    }
}

New-Item -ItemType Directory -Force -Path $dist | Out-Null

# ── Check PyInstaller ─────────────────────────────────────────────────────────
Banner "Checking PyInstaller"
& $pythonExe -m PyInstaller --version 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "PyInstaller is unavailable for Python 3.13" }
OK "PyInstaller available"

# ── Build attacklens-agent (onedir) ──────────────────────────────────────────
Banner "Building attacklens-agent"
Push-Location $ROOT
& $pythonExe -m PyInstaller `
    --distpath  $dist `
    --workpath  (Join-Path $pkg "build\agent") `
    --noconfirm `
    (Join-Path $pkg "attacklens-agent.spec")
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "PyInstaller failed for attacklens-agent" }
Pop-Location
OK "attacklens-agent built"

# ── Build attacklens-watchdog (onedir) ────────────────────────────────────────
if (-not $SkipWatchdog) {
    Banner "Building attacklens-watchdog"
    Push-Location $ROOT
    & $pythonExe -m PyInstaller `
        --distpath  $dist `
        --workpath  (Join-Path $pkg "build\watchdog") `
        --noconfirm `
        (Join-Path $pkg "attacklens-watchdog.spec")
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "PyInstaller failed for attacklens-watchdog" }
    Pop-Location
    OK "attacklens-watchdog built"
}

# ── Verify outputs ────────────────────────────────────────────────────────────
Banner "Verifying outputs"
$agentExe    = Join-Path $dist "attacklens-agent\attacklens-agent.exe"
$watchdogExe = Join-Path $dist "attacklens-watchdog\attacklens-watchdog.exe"

if (-not (Test-Path $agentExe))    { throw "Missing: $agentExe" }
if (-not $SkipWatchdog -and -not (Test-Path $watchdogExe)) { throw "Missing: $watchdogExe" }

$targets = @($agentExe)
if (-not $SkipWatchdog) { $targets += $watchdogExe }

foreach ($exe in $targets) {
    $mb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    OK "$([IO.Path]::GetFileName($exe))  ($mb MB)"
}

# ── Authenticode signing ──────────────────────────────────────────────────────
<#
if (-not $SignIdentity) {
    Info "Signing skipped (no -SignIdentity)"
} else {
    Banner "Authenticode signing"
    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits" `
                -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty FullName
    if (-not $signtool) {
        $st2 = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($st2) { $signtool = $st2.Source }
    }
    if ($signtool) {
        foreach ($exe in $targets) {
            Info "Signing $([IO.Path]::GetFileName($exe))..."
            & $signtool sign /sha1 $SignIdentity /fd sha256 `
                /tr http://timestamp.digicert.com /td sha256 $exe
            if ($LASTEXITCODE -eq 0) { OK "Signed" }
            else { Write-Warning "signtool returned $LASTEXITCODE for $exe" }
        }
    } else {
        Write-Warning "signtool.exe not found — EXEs not signed"
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
#>

if (-not $SignIdentity) {
    Info "Signing skipped (no -SignIdentity)"
} else {
    Banner "Authenticode signing"
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        Write-Warning "signtool.exe not found; EXEs not signed"
    } else {
        foreach ($exe in $targets) {
            Info "Signing $([IO.Path]::GetFileName($exe))..."
            & $signtool.Source sign /sha1 $SignIdentity /fd sha256 `
                /tr "http://timestamp.digicert.com" /td sha256 $exe
            if ($LASTEXITCODE -ne 0) {
                throw "signtool returned $LASTEXITCODE for $exe"
            }
            OK "Signed"
        }
    }
}

Banner "DONE"
Write-Host ""
Write-Host "  Output directory: $dist" -ForegroundColor Yellow
Write-Host ""
Write-Host "  To install the MSI (includes EXEs):" -ForegroundColor Cyan
Write-Host "    .\build_msi.ps1 -SkipBuild -ManagerUrl 'https://manager.example.com'"
Write-Host ""
Write-Host "  To register the agent service manually (no MSI):" -ForegroundColor Cyan
Write-Host "    $agentExe install"
Write-Host "    $watchdogExe install"
Write-Host "    net start AttackLensWatchdog"
Write-Host "    net start AttackLensAgent"
Write-Host ""
