<#
.SYNOPSIS
    Build the AttackLens Agent Windows MSI package (WiX v4, Python source-based).

.DESCRIPTION
    Legacy source-based developer builder retained for compatibility. Production
    and verified development packages must use ..\build_windows_msi.ps1, which
    freezes both services, runs the complete gate, scans artifacts, validates
    WiX ICE rules, and verifies the compiled MSI payload.

    Full pipeline:
      1. Pre-flight checks (WiX, Python, source tree)
      2. Copy Python source to build\src\ (robocopy, excludes __pycache__, tests, .git)
      3. Write bootstrap launchers: build\bin\run_agent.py + run_watchdog.py
      4. Harvest Python source tree → build\src_files.wxs  (wix harvest dir)
      5. Compile: wix build product.wxs build\src_files.wxs → dist\attacklens-agent-<ver>-x64.msi
      6. Optionally Authenticode-sign the MSI

    Output: installer\dist\attacklens-agent-<Version>-x64.msi

.PARAMETER Version
    Semantic version embedded in MSI metadata. Default: 2.0.25

.PARAMETER SignIdentity
    Authenticode certificate thumbprint or CN= subject name.
    Leave empty to produce an unsigned MSI (development builds).

.PARAMETER SkipSource
    Skip the robocopy step — reuse an existing build\src\ tree.

.PARAMETER WixPath
    Override path to the WiX bin directory.
    If omitted, the script searches PATH, then dotnet global tools, then
    offers to auto-install WiX v4 via `dotnet tool install --global wix`.

.PARAMETER SourceRoot
    Root of the Python agent source tree (default: four levels up from this script,
    i.e. the repo root that contains the `agent\` package).

.EXAMPLE
    # Signed release build
    ..\build_windows_msi.ps1 -Version "2.0.25" -Release -SignThumbprint "<thumbprint>"

.EXAMPLE
    # Quick unsigned dev build
    .\build_msi.ps1 -SkipSource

.EXAMPLE
    # Silent install after build:
    msiexec /i dist\attacklens-agent-2.0.25-x64.msi /qn ACCEPT_EULA=1 `
        MANAGER_URL="http://34.224.174.38:8080" `
        AGENT_NAME="WORKSTATION-01"
#>

param(
    [string] $Version      = "2.0.25",
    [string] $SignIdentity = "",
    [switch] $SkipSource   = $false,
    [string] $WixPath      = "",
    [string] $SourceRoot   = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve paths ─────────────────────────────────────────────────────────────
$ScriptDir   = $PSScriptRoot
$BuildDir    = Join-Path $ScriptDir "build"
$BuildSrcDir = Join-Path $BuildDir  "src"
$BuildBinDir = Join-Path $BuildDir  "bin"
$DistDir     = Join-Path $ScriptDir "dist"
$WxsFile     = Join-Path $ScriptDir "product.wxs"
$SrcFilesWxs = Join-Path $BuildDir  "src_files.wxs"
$MsiOut      = Join-Path $DistDir   "attacklens-agent-$Version-x64.msi"

# Repo root: installer\ → windows\ → os\ → agent\ → (repo root)
if (-not $SourceRoot) {
    $SourceRoot = Split-Path (Split-Path (Split-Path (Split-Path $ScriptDir)))
}
$AgentSrcDir = Join-Path $SourceRoot "agent"

Write-Host ""
Write-Host "  AttackLens Agent MSI Builder" -ForegroundColor Cyan
Write-Host "  Version : $Version"           -ForegroundColor Cyan
Write-Host "  Source  : $AgentSrcDir"       -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Pre-flight ────────────────────────────────────────────────────────
Write-Host "  [1/5] Pre-flight checks..." -ForegroundColor Yellow

if (-not (Test-Path $WxsFile)) {
    Write-Error "product.wxs not found at: $WxsFile"
}
if (-not (Test-Path $AgentSrcDir)) {
    Write-Error "Agent source not found at: $AgentSrcDir`n  Set -SourceRoot to the repo root."
}

# Verify Python 3.11+
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Error "python.exe not found in PATH.`n  Install Python 3.11+ and ensure it is in PATH."
}
$pyVer = & python.exe --version 2>&1
if ($pyVer -match "(\d+)\.(\d+)") {
    $pyMajor = [int]$Matches[1]; $pyMinor = [int]$Matches[2]
    if ($pyMajor -lt 3 -or ($pyMajor -eq 3 -and $pyMinor -lt 11)) {
        Write-Warning "Python $pyVer detected — Python 3.11+ recommended."
    } else {
        Write-Host "    Python $pyVer found: $($python.Source)" -ForegroundColor Green
    }
}

# ── Step 2: Locate WiX ────────────────────────────────────────────────────────
Write-Host "  [2/5] Locating WiX Toolset..." -ForegroundColor Yellow

$WixVersion = 0  # 0=not found, 3=v3, 4=v4
$WixExe     = $null
$HeatExe    = $null
$CandleExe  = $null
$LightExe   = $null

function Find-Exe([string]$name) {
    if ($WixPath) {
        $p = Join-Path $WixPath $name
        if (Test-Path $p) { return $p }
    }
    $found = Get-Command $name -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    # Check dotnet global tools
    $toolsDir = Join-Path $env:USERPROFILE ".dotnet\tools"
    $p2 = Join-Path $toolsDir $name
    if (Test-Path $p2) { return $p2 }
    return $null
}

$WixExe = Find-Exe "wix.exe"
if (-not $WixExe) { $WixExe = Find-Exe "wix" }

if ($WixExe) {
    $WixVersion = 4
    Write-Host "    WiX v4: $WixExe" -ForegroundColor Green
} else {
    # Check WiX v3
    $CandleExe = Find-Exe "candle.exe"
    $LightExe  = Find-Exe "light.exe"
    $HeatExe   = Find-Exe "heat.exe"
    if ($CandleExe -and $LightExe -and $HeatExe) {
        $WixVersion = 3
        Write-Host "    WiX v3: $CandleExe" -ForegroundColor Green
    }
}

if ($WixVersion -eq 0) {
    Write-Host "    WiX not found — installing WiX v4 via dotnet tool..." -ForegroundColor Yellow
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnet) {
        Write-Error @"
Neither WiX Toolset nor .NET SDK found.
Install WiX v4:  dotnet tool install --global wix
Install .NET SDK: https://dotnet.microsoft.com/download
"@
    }
    & dotnet tool install --global wix 2>&1 | Out-Null
    $toolsDir = Join-Path $env:USERPROFILE ".dotnet\tools"
    $env:PATH = "$toolsDir;$env:PATH"
    $WixExe = Join-Path $toolsDir "wix.exe"
    if (-not (Test-Path $WixExe)) { $WixExe = Join-Path $toolsDir "wix" }
    if (Test-Path $WixExe) {
        $WixVersion = 4
        Write-Host "    WiX v4 installed: $WixExe" -ForegroundColor Green
    } else {
        Write-Error "WiX installation failed. Install manually: dotnet tool install --global wix"
    }
}

# ── Step 3: Copy Python source ────────────────────────────────────────────────
if (-not $SkipSource) {
    Write-Host "  [3/5] Copying Python source to build\src\..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $BuildSrcDir | Out-Null

    # robocopy: /MIR mirror, /XD excludes dirs, /XF excludes files, /NP no progress
    $roboCopyArgs = @(
        $AgentSrcDir, $BuildSrcDir,
        "/MIR",
        "/XD", "__pycache__", ".git", "dist", "build", "*.egg-info",
               "tests", ".venv", "venv", "node_modules",
        "/XF", "*.pyc", "*.pyo", "*.pyd", ".DS_Store",
        "/NP", "/NFL", "/NDL", "/NJH"
    )
    $rc = (Start-Process robocopy -ArgumentList $roboCopyArgs -Wait -PassThru).ExitCode
    # robocopy exit codes: 0=no change, 1=files copied, 2=extra, 3=both — all OK
    if ($rc -ge 8) {
        Write-Error "robocopy failed with exit code $rc"
    }
    Write-Host "    Source copied: $BuildSrcDir" -ForegroundColor Green
} else {
    Write-Host "  [3/5] Skipping source copy (-SkipSource)" -ForegroundColor DarkGray
    if (-not (Test-Path $BuildSrcDir)) {
        Write-Error "build\src\ not found. Run without -SkipSource first."
    }
}

# ── Step 4: Write bootstrap launchers ────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $BuildBinDir | Out-Null

$RunAgentContent = @'
"""
AttackLens Agent — Windows Service bootstrap launcher.
Generated by build_msi.ps1 at build time. Do not edit directly.

Sets sys.path to src\, points ATTACKLENS_CONFIG to agent.toml in ProgramData,
then dispatches to the AttackLensAgentService SCM service class.
"""
import os, sys

# Add src\ to path so `agent.*` imports resolve correctly
_INSTALL = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SRC = os.path.join(_INSTALL, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# Point the service wrapper at the AttackLens config location
_DATA_DIR = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
_CONFIG   = os.path.join(_DATA_DIR, "AttackLens", "config", "agent.toml")
os.environ.setdefault("ATTACKLENS_CONFIG", _CONFIG)

try:
    import win32serviceutil, servicemanager
    from agent.os.windows.service import AttackLensAgentService as BaseAttackLensAgentService, _add_root_to_path

    class AttackLensAgentService(BaseAttackLensAgentService):
        _svc_name_         = "AttackLensAgent"
        _svc_display_name_ = "AttackLens Agent"
        _svc_description_  = (
            "AttackLens endpoint telemetry agent — collects system metrics, "
            "security posture, and software inventory."
        )

    def main():
        _add_root_to_path()
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AttackLensAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        elif len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
            sys.argv = ["agent", "--config", _CONFIG]
            from agent.os.windows.win_agent import main as _main
            _main()
        else:
            win32serviceutil.HandleCommandLine(AttackLensAgentService)

    main()

except ImportError as _e:
    print(f"[run_agent] pywin32 unavailable ({_e}) — running agent in foreground")
    sys.argv = ["agent", "--config", _CONFIG]
    from agent.os.windows.win_agent import main as _main
    _main()
'@

$RunWatchdogContent = @'
"""
AttackLens Watchdog — Windows Service bootstrap launcher.
Generated by build_msi.ps1 at build time. Do not edit directly.
"""
import os, sys

_INSTALL = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SRC = os.path.join(_INSTALL, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

try:
    import win32serviceutil, servicemanager
    # Patch the agent service name BEFORE importing WatchdogCore
    import agent.os.windows.watchdog_svc as _wd_mod
    _wd_mod.AGENT_SERVICE_NAME = "AttackLensAgent"
    from agent.os.windows.watchdog_svc import AttackLensWatchdogService as BaseAttackLensWatchdogService, WatchdogCore

    class AttackLensWatchdogService(BaseAttackLensWatchdogService):
        _svc_name_         = "AttackLensWatchdog"
        _svc_display_name_ = "AttackLens Watchdog"
        _svc_description_  = (
            "Monitors the AttackLens Agent service and restarts it if it stops."
        )
        _svc_deps_         = []

    def main():
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AttackLensWatchdogService)
            servicemanager.StartServiceCtrlDispatcher()
        elif len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
            import threading
            stop = threading.Event()
            try:
                WatchdogCore(stop_event=stop).run()
            except KeyboardInterrupt:
                stop.set()
        else:
            win32serviceutil.HandleCommandLine(AttackLensWatchdogService)

    main()

except ImportError as _e:
    print(f"[run_watchdog] pywin32 unavailable ({_e})")
    sys.exit(1)
'@

[System.IO.File]::WriteAllText(
    (Join-Path $BuildBinDir "run_agent.py"),
    $RunAgentContent,
    [System.Text.Encoding]::UTF8
)
[System.IO.File]::WriteAllText(
    (Join-Path $BuildBinDir "run_watchdog.py"),
    $RunWatchdogContent,
    [System.Text.Encoding]::UTF8
)
Write-Host "  [3b] Bootstrap launchers written to build\bin\" -ForegroundColor Green

# ── Step 4b: Harvest Python source tree ──────────────────────────────────────
Write-Host "  [4/5] Harvesting Python source tree..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

if ($WixVersion -eq 4) {
    & $WixExe harvest dir $BuildSrcDir `
        -ag `
        -srd `
        -dr SRCDIR `
        -cg SourceGroup `
        -out $SrcFilesWxs
    if ($LASTEXITCODE -ne 0) { Write-Error "wix harvest failed (exit $LASTEXITCODE)" }
} else {
    # WiX v3: heat.exe
    & $HeatExe dir $BuildSrcDir `
        -ag `
        -srd `
        -dr SRCDIR `
        -cg SourceGroup `
        -out $SrcFilesWxs
    if ($LASTEXITCODE -ne 0) { Write-Error "heat.exe failed (exit $LASTEXITCODE)" }
}
Write-Host "    Harvested: $SrcFilesWxs" -ForegroundColor Green

# ── Step 5: Build MSI ─────────────────────────────────────────────────────────
Write-Host "  [5/5] Building MSI..." -ForegroundColor Yellow

# WiX variable definitions passed at compile time
$WixVars = @(
    "Version=$Version",
    "BuildBinDir=$BuildBinDir",
    "ScriptsDir=$ScriptDir"
)

# WiX v4 extension DLL paths (adjust if extension version differs)
$UtilExt = $null
$extSearch = Join-Path $env:USERPROFILE ".wix\extensions"
if (Test-Path $extSearch) {
    $UtilExt = Get-ChildItem $extSearch -Recurse -Filter "WixToolset.Util.wixext.dll" |
        Select-Object -First 1 -ExpandProperty FullName
}

if ($WixVersion -eq 4) {
    $WixArgs = @("build", $WxsFile, $SrcFilesWxs, "-o", $MsiOut)
    foreach ($v in $WixVars) { $WixArgs += @("-d", $v) }
    if ($UtilExt) { $WixArgs += @("-ext", $UtilExt) }

    Write-Host "    wix $($WixArgs -join ' ')" -ForegroundColor DarkGray
    & $WixExe @WixArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "wix build failed (exit $LASTEXITCODE)" }

} else {
    # WiX v3: candle + light
    $ObjDir    = Join-Path $BuildDir "obj"
    New-Item -ItemType Directory -Force -Path $ObjDir | Out-Null

    $CandleArgs = @($WxsFile, $SrcFilesWxs, "-out", "$ObjDir\", "-ext", "WixUtilExtension")
    foreach ($v in $WixVars) { $CandleArgs += "-d$v" }
    & $CandleExe @CandleArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "candle.exe failed (exit $LASTEXITCODE)" }

    $LightArgs = @(
        (Join-Path $ObjDir "product.wixobj"),
        (Join-Path $ObjDir "src_files.wixobj"),
        "-out", $MsiOut,
        "-ext", "WixUtilExtension",
        "-cultures:en-US"
    )
    & $LightExe @LightArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "light.exe failed (exit $LASTEXITCODE)" }
}

Write-Host "    MSI: $MsiOut" -ForegroundColor Green

# ── Authenticode signing ──────────────────────────────────────────────────────
if ($SignIdentity) {
    Write-Host "  Signing MSI..." -ForegroundColor Yellow

    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits" `
        -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $signtool) {
        $st2 = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($st2) { $signtool = $st2.Source }
    }

    if ($signtool) {
        & $signtool sign /sha1 $SignIdentity /fd sha256 `
            /tr http://timestamp.digicert.com /td sha256 $MsiOut
        if ($LASTEXITCODE -eq 0) { Write-Host "    Signed." -ForegroundColor Green }
        else { Write-Warning "Signing failed (exit $LASTEXITCODE) — unsigned MSI retained" }
    } else {
        Write-Warning "signtool.exe not found — MSI not signed"
    }
} else {
    Write-Host "  Signing skipped (no -SignIdentity)" -ForegroundColor DarkGray
}

# ── Summary ───────────────────────────────────────────────────────────────────
$info = Get-Item $MsiOut
$mb   = [math]::Round($info.Length / 1MB, 1)

Write-Host ""
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Output  : $MsiOut  ($mb MB)"
Write-Host ""
Write-Host "  Install commands:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  # Interactive install:"
Write-Host "    msiexec /i `"$MsiOut`""
Write-Host ""
Write-Host "  # Silent install:"
Write-Host "    msiexec /i `"$MsiOut`" /qn ``"
Write-Host "        MANAGER_URL=`"http://34.224.174.38:8080`" ``"
Write-Host "        AGENT_NAME=`"WORKSTATION-01`" ``"
Write-Host "        /l*v install.log"
Write-Host ""
Write-Host "  # Silent uninstall:"
Write-Host "    msiexec /x `"$MsiOut`" /qn"
Write-Host ""
