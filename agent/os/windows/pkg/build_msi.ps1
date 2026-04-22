<#
.SYNOPSIS
    Build the Jarvis Agent Windows MSI package.

.DESCRIPTION
    Full pipeline:
      1. Build standalone EXEs via PyInstaller  (build_exe.ps1)
      2. Locate or download WiX Toolset (v4 preferred, v3 fallback)
      3. Compile jarvis-agent.wxs → jarvis-agent.msi
      4. Optionally sign the MSI with Authenticode

    Output: agent\os\windows\pkg\dist\jarvis-agent-<version>.msi

.PARAMETER Version
    Semantic version string embedded in MSI and EXEs. Default: 1.0.0

.PARAMETER SignIdentity
    Authenticode certificate thumbprint or subject name.
    Leave empty to skip signing (dev builds).

.PARAMETER SkipBuildExe
    Skip the PyInstaller step (use existing dist\*.exe files).

.PARAMETER WixPath
    Path to the WiX toolset bin directory.
    If omitted the script searches PATH, then common install locations,
    then falls back to downloading WiX v4 via dotnet tool install.

.EXAMPLE
    # Full signed release build
    .\build_msi.ps1 -Version "1.2.0" -SignIdentity "CN=ACME Corp"

.EXAMPLE
    # Quick unsigned dev build (reuse existing EXEs)
    .\build_msi.ps1 -SkipBuildExe

.EXAMPLE
    # Silent install after build:
    msiexec /i dist\jarvis-agent-1.0.0.msi /qn `
        MANAGER_URL="https://manager.corp.example:8443" `
        ENROLL_TOKEN="sk-enroll-abc123"
#>

param(
    [string] $Version       = "1.0.0",
    [string] $SignIdentity  = "",
    [switch] $SkipBuildExe  = $false,
    [string] $WixPath       = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir      = $PSScriptRoot
$DistDir        = "$ScriptDir\dist"
$AgentExe       = "$DistDir\jarvis-agent.exe"
$WatchdogExe    = "$DistDir\jarvis-watchdog.exe"
$WxsFile        = "$ScriptDir\jarvis-agent.wxs"
$GenCfgPs1      = "$ScriptDir\generate_config.ps1"
$MgmtPs1        = "$ScriptDir\manage_services.ps1"
$MsiOut         = "$DistDir\jarvis-agent-$Version.msi"

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  mac_intel Agent MSI Builder" -ForegroundColor Cyan
Write-Host "  Version: $Version" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Build EXEs via PyInstaller ───────────────────────────────────────
if (-not $SkipBuildExe) {
    Write-Host "  [1/4] Building EXEs via PyInstaller..." -ForegroundColor Yellow
    & "$ScriptDir\build_exe.ps1" -Version $Version -SignIdentity $SignIdentity
    if ($LASTEXITCODE -ne 0) {
        Write-Error "build_exe.ps1 failed (exit $LASTEXITCODE)"
    }
} else {
    Write-Host "  [1/4] Skipping EXE build (SkipBuildExe set)" -ForegroundColor DarkGray
}

# Verify EXEs exist
foreach ($exe in @($AgentExe, $WatchdogExe, $GenCfgPs1, $MgmtPs1)) {
    if (-not (Test-Path $exe)) {
        Write-Error "Required EXE not found: $exe`n  Run without -SkipBuildExe or run build_exe.ps1 first."
    }
}

# ── Step 2: Locate WiX Toolset ────────────────────────────────────────────────
Write-Host "  [2/4] Locating WiX Toolset..." -ForegroundColor Yellow

$WixVersion = 0   # 0=not found, 3=v3, 4=v4

function Find-WixTool([string]$name) {
    # Check explicit path
    if ($WixPath) {
        $p = Join-Path $WixPath $name
        if (Test-Path $p) { return $p }
    }
    # Check PATH
    $found = Get-Command $name -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    return $null
}

# Check WiX v4 (dotnet tool: wix)
$WixV4 = Find-WixTool "wix.exe"
if (-not $WixV4) { $WixV4 = Find-WixTool "wix" }

if ($WixV4) {
    $WixVersion = 4
    Write-Host "    WiX v4 found: $WixV4" -ForegroundColor Green
} else {
    # Check WiX v3 (candle + light)
    $CandleExe = Find-WixTool "candle.exe"
    $LightExe  = Find-WixTool "light.exe"

    if ($CandleExe -and $LightExe) {
        $WixVersion = 3
        Write-Host "    WiX v3 found: $CandleExe" -ForegroundColor Green
    }
}

# Auto-install WiX v4 as dotnet global tool if not found
if ($WixVersion -eq 0) {
    Write-Host "    WiX not found - installing WiX v4 via dotnet tool..." -ForegroundColor Yellow

    $dotnet = Get-Command "dotnet" -ErrorAction SilentlyContinue
    if (-not $dotnet) {
        Write-Error @"
Neither WiX Toolset nor .NET SDK found.

To install WiX Toolset v4 (recommended):
  dotnet tool install --global wix

To install WiX Toolset v3:
  Download from https://wixtoolset.org/docs/wix3/

Or install .NET SDK 6+ from https://dotnet.microsoft.com/download
then re-run this script.
"@
    }

    dotnet tool install --global wix 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # May already be installed but not in PATH - try to add dotnet tools dir
        $toolsDir = Join-Path $env:USERPROFILE ".dotnet\tools"
        $env:PATH = "$toolsDir;$env:PATH"
    }

    $WixV4 = Find-WixTool "wix"
    if (-not $WixV4) {
        # Add dotnet tools to PATH for this session
        $toolsDir = Join-Path $env:USERPROFILE ".dotnet\tools"
        $WixV4 = Join-Path $toolsDir "wix.exe"
    }

    if (Test-Path $WixV4) {
        $WixVersion = 4
        Write-Host "    WiX v4 installed: $WixV4" -ForegroundColor Green
    } else {
        Write-Error "WiX installation failed. Install manually and retry."
    }
}

# ── Step 3: Build MSI ─────────────────────────────────────────────────────────
Write-Host "  [3/4] Building MSI..." -ForegroundColor Yellow

if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}

$WxsVars = @(
    "AgentExe=$AgentExe",
    "WatchdogExe=$WatchdogExe",
    "Version=$Version",
    "GenerateConfigPs1=$GenCfgPs1",
    "ManageServicesPs1=$MgmtPs1"
)

if ($WixVersion -eq 4) {
    # ── WiX v4: single 'wix build' command ───────────────────────────────────
    $WixArgs = @(
        "build",
        $WxsFile,
        "-o", $MsiOut,
        "-ext", (Join-Path $env:USERPROFILE ".wix\extensions\WixToolset.Util.wixext\4.0.5\wixext4\WixToolset.Util.wixext.dll")
    )
    foreach ($v in $WxsVars) {
        $WixArgs += @("-d", $v)
    }

    Write-Host "    wix $($WixArgs -join ' ')"
    & $WixV4 @WixArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "WiX build failed (exit $LASTEXITCODE)"
    }

} else {
    # ── WiX v3: candle + light ────────────────────────────────────────────────
    $WixObjFile = "$ScriptDir\jarvis-agent.wixobj"

    $CandleArgs = @($WxsFile, "-out", $WixObjFile, "-ext", "WixUtilExtension")
    foreach ($v in $WxsVars) {
        $CandleArgs += "-d$v"
    }
    Write-Host "    candle $($CandleArgs -join ' ')"
    & $CandleExe @CandleArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "candle failed (exit $LASTEXITCODE)"
    }

    $LightArgs = @($WixObjFile, "-out", $MsiOut, "-ext", "WixUtilExtension", "-cultures:en-US")
    Write-Host "    light $($LightArgs -join ' ')"
    & $LightExe @LightArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "light failed (exit $LASTEXITCODE)"
    }

    Remove-Item $WixObjFile -ErrorAction SilentlyContinue
}

Write-Host "    MSI built: $MsiOut" -ForegroundColor Green

# ── Step 4: Sign MSI ──────────────────────────────────────────────────────────
if ($SignIdentity) {
    Write-Host "  [4/4] Signing MSI..." -ForegroundColor Yellow

    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits" `
        -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName

    if (-not $signtool) {
        $signtool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty Source
    }

    if ($signtool) {
        & $signtool sign `
            /sha1 $SignIdentity `
            /fd sha256 `
            /tr http://timestamp.digicert.com `
            /td sha256 `
            $MsiOut

        if ($LASTEXITCODE -eq 0) {
            Write-Host "    MSI signed successfully" -ForegroundColor Green
        } else {
            Write-Warning "MSI signing failed (exit $LASTEXITCODE) - unsigned MSI retained"
        }
    } else {
        Write-Warning "signtool.exe not found - MSI not signed"
    }
} else {
    Write-Host "  [4/4] Signing skipped (no SignIdentity)" -ForegroundColor DarkGray
}

# ── Summary ───────────────────────────────────────────────────────────────────
$msiInfo = Get-Item $MsiOut
$msiMB   = [math]::Round($msiInfo.Length / 1MB, 1)

Write-Host ""
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Output: $MsiOut  ($msiMB MB)" -ForegroundColor White
Write-Host ""
Write-Host "  Install commands:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  # Interactive (GUI wizard):"
Write-Host "    msiexec /i `"$MsiOut`""
Write-Host ""
Write-Host "  # Silent with enrollment token:"
Write-Host "    msiexec /i `"$MsiOut`" /qn ``"
Write-Host "        MANAGER_URL=`"https://manager.corp.example:8443`" ``"
Write-Host "        ENROLL_TOKEN=`"sk-enroll-<token>`" ``"
Write-Host "        AGENT_NAME=`"WORKSTATION-01`" ``"
Write-Host "        TLS_VERIFY=`"true`""
Write-Host ""
Write-Host "  # Silent with pre-shared API key (skip enrollment):"
Write-Host "    msiexec /i `"$MsiOut`" /qn ``"
Write-Host "        MANAGER_URL=`"https://manager.corp.example:8443`" ``"
Write-Host "        MANAGER_API_KEY=`"<64-hex-key>`" ``"
Write-Host "        AGENT_NAME=`"WORKSTATION-01`""
Write-Host ""
Write-Host "  # Silent uninstall:"
Write-Host "    msiexec /x `"$MsiOut`" /qn"
Write-Host ""
Write-Host "  # Deploy via Group Policy / Intune:"
Write-Host "    Upload $MsiOut to your MDM/GPO software distribution"
Write-Host "    Set properties: MANAGER_URL, ENROLL_TOKEN, TLS_VERIFY"
Write-Host ""
