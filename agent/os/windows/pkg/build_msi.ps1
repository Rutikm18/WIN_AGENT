<#
.SYNOPSIS
    Build the AttackLens Agent MSI (self-contained, all dependencies included).

.DESCRIPTION
    Produces:  pkg\dist\attacklens-agent-<Version>-x64.msi

    The manager URL, enrollment token, and TLS settings are NO LONGER baked
    into the MSI at build time.  They are supplied at install time as public
    MSI properties (MANAGER_IP, ENROLL_TOKEN, etc.).

    Install (after build):
      msiexec /i dist\attacklens-agent-2.0.25-x64.msi /qn ACCEPT_EULA=1 ^
          MANAGER_URL="http://72.61.228.62:8080" ^
          ALLOW_INSECURE_TRANSPORT="true" ^
          /l*v install.log

.PARAMETER Version
    MSI version string. Default: 2.0.25

.PARAMETER SkipBuild
    Skip PyInstaller rebuild — reuse existing binaries in dist\.

.EXAMPLE
    .\build_msi.ps1
    .\build_msi.ps1 -Version "2.1.0"
    .\build_msi.ps1 -SkipBuild
#>
param(
    [string] $Version   = "2.0.25",
    [switch] $SkipBuild = $false
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Off

# ── Path resolution ───────────────────────────────────────────────────────────
# This script lives at: <ROOT>/agent/os/windows/pkg/build_msi.ps1
$pkg         = $PSScriptRoot
$ROOT        = (Resolve-Path (Join-Path $pkg "..\..\..\..")).Path
$dist        = Join-Path $pkg "dist"
$agentDir    = Join-Path $dist "attacklens-agent"
$watchdogDir = Join-Path $dist "attacklens-watchdog"
$agentIntDir = Join-Path $agentDir "_internal"
$wdIntDir    = Join-Path $watchdogDir "_internal"

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
            $resolved = (Resolve-Path -LiteralPath $candidate).Path
            $detectedVersion = & $resolved -c `
                "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
            if ($LASTEXITCODE -eq 0 -and $detectedVersion -eq "3.13") {
                return $resolved
            }
        }
    }
    throw "Python 3.13 not found. Set ATTACKLENS_PYTHON to python.exe."
}
$pythonExe = Resolve-Python313

New-Item -ItemType Directory -Force -Path $dist | Out-Null

# ── Step 1: Build PyInstaller EXEs (onedir) ───────────────────────────────────
Banner "Step 1: PyInstaller build"
if ($SkipBuild) {
    Info "Skipped (-SkipBuild)"
} else {
    Push-Location $ROOT
    Info "Building attacklens-agent..."
    & $pythonExe -m PyInstaller --distpath $dist --workpath (Join-Path $pkg "build\agent") `
        --noconfirm (Join-Path $pkg "attacklens-agent.spec")
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "PyInstaller failed for agent" }

    Info "Building attacklens-watchdog..."
    & $pythonExe -m PyInstaller --distpath $dist --workpath (Join-Path $pkg "build\watchdog") `
        --noconfirm (Join-Path $pkg "attacklens-watchdog.spec")
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "PyInstaller failed for watchdog" }
    Pop-Location
}

if (-not (Test-Path (Join-Path $agentDir    "attacklens-agent.exe")))    { throw "Missing agent EXE" }
if (-not (Test-Path (Join-Path $watchdogDir "attacklens-watchdog.exe"))) { throw "Missing watchdog EXE" }
OK "Binaries verified"

$manifestPath = Join-Path $pkg "build\install-manifest.json"
$manifestFiles = [ordered]@{}
foreach ($bundle in @(
    @{ InstallPrefix = "bin/attacklens-agent"; SourceRoot = $agentDir },
    @{ InstallPrefix = "bin/attacklens-watchdog"; SourceRoot = $watchdogDir }
)) {
    $sourceRoot = (Resolve-Path -LiteralPath $bundle.SourceRoot).Path.TrimEnd('\')
    $sourcePrefix = $sourceRoot + '\'
    $bundleFiles = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File |
        Sort-Object FullName)
    if ($bundleFiles.Count -eq 0) {
        throw "No packaged files found under $sourceRoot"
    }
    foreach ($item in $bundleFiles) {
        if (-not $item.FullName.StartsWith(
                $sourcePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Packaged file escapes its source root: $($item.FullName)"
        }
        $relativeWithinBundle = $item.FullName.Substring($sourcePrefix.Length).Replace('\', '/')
        $relative = "$($bundle.InstallPrefix)/$relativeWithinBundle"
        $manifestFiles[$relative] = [ordered]@{
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = [int64]$item.Length
        }
    }
}
$manifest = [ordered]@{
    schema = 1
    generated_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    algorithm = "sha256"
    files = $manifestFiles
}
New-Item -ItemType Directory -Path (Split-Path $manifestPath -Parent) -Force | Out-Null
[IO.File]::WriteAllText(
    $manifestPath,
    ($manifest | ConvertTo-Json -Depth 6 -Compress),
    (New-Object Text.UTF8Encoding($false))
)
OK "Install manifest generated ($($manifestFiles.Count) files)"

# ── Step 2: Encode gen_config.ps1 as UTF-16 LE Base64 ────────────────────────
# Scripts are installed as MSI files; runtime values still arrive through
# %MsiCustomActionData% in the deferred custom actions.
Banner "Step 2: Verify installer scripts"
$genPs1Path = Join-Path $pkg "gen_config.ps1"
if (-not (Test-Path $genPs1Path)) { throw "gen_config.ps1 not found: $genPs1Path" }
$purgePs1Path = Join-Path $pkg "purge_state.ps1"
if (-not (Test-Path $purgePs1Path)) { throw "purge_state.ps1 not found: $purgePs1Path" }
$editPs1Path = Join-Path $pkg "edit-agent-config.ps1"
if (-not (Test-Path $editPs1Path)) { throw "edit-agent-config.ps1 not found: $editPs1Path" }
$bridgeJsPath = Join-Path $pkg "prepare_config_data.js"
if (-not (Test-Path $bridgeJsPath)) { throw "prepare_config_data.js not found: $bridgeJsPath" }
OK "Installer scripts verified"

# Resolve matching WiX 4.x extension DLLs explicitly.  A newer damaged cache
# entry can otherwise shadow the valid extension when only its short ID is
# passed to wix.exe.
$wixExtRoot = Join-Path $ROOT ".wix\extensions"
$utilExt = Get-ChildItem $wixExtRoot -Recurse -File -Filter "WixToolset.Util.wixext.dll" `
           -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
$uiExt = Get-ChildItem $wixExtRoot -Recurse -File -Filter "WixToolset.UI.wixext.dll" `
         -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $utilExt -or -not $uiExt) {
    throw "Matching WiX extension DLLs were not found under $wixExtRoot"
}
OK "WiX extensions resolved"

# ── Step 3: Generate WiX fragment files for _internal directories ─────────────
Banner "Step 3: Generate WiX _internal fragments"

function New-WixGuid([string]$seed) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($seed)
    $hash  = [Security.Cryptography.MD5]::Create().ComputeHash($bytes)
    $hex   = [BitConverter]::ToString($hash).Replace("-","").ToLower()
    return "{$($hex.Substring(0,8))-$($hex.Substring(8,4))-$($hex.Substring(12,4))-$($hex.Substring(16,4))-$($hex.Substring(20,12))}"
}

function Safe-Id([string]$s) {
    $clean = ($s -replace '[^a-zA-Z0-9_]','_') -replace '^([0-9])','_$1'
    if ($clean.Length -le 60) { return $clean }
    $bytes = [Text.Encoding]::UTF8.GetBytes($s)
    $hash  = [Security.Cryptography.MD5]::Create().ComputeHash($bytes)
    $short = [BitConverter]::ToString($hash).Replace("-","").ToLower().Substring(0,8)
    return $clean.Substring(0,52) + "_$short"
}

function Build-Fragment {
    param([string]$RootDir, [string]$RootDirId, [string]$Prefix, [string]$GroupId)
    $sb      = [Text.StringBuilder]::new()
    $dirIdMap = @{ '' = $RootDirId }
    $sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>') | Out-Null
    $sb.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">') | Out-Null
    $sb.AppendLine('  <Fragment>') | Out-Null

    $allDirs = Get-ChildItem $RootDir -Recurse -Directory | Sort-Object FullName
    foreach ($dir in $allDirs) {
        $rel       = $dir.FullName.Substring($RootDir.Length).TrimStart('\')
        $parentRel = if ($rel -match '\\') {
            $rel.Substring(0, $rel.LastIndexOf('\'))
        } else {
            ''
        }
        if (-not $dirIdMap.ContainsKey($parentRel)) {
            throw "WiX fragment parent directory was not mapped: $parentRel"
        }
        $parentId = $dirIdMap[$parentRel]
        $dirId    = "${Prefix}_d_$(Safe-Id ($rel -replace '\\','_'))"
        $dirIdMap[$rel] = $dirId
        $sb.AppendLine("    <DirectoryRef Id=`"$parentId`">") | Out-Null
        $sb.AppendLine("      <Directory Id=`"$dirId`" Name=`"$($dir.Name)`" />") | Out-Null
        $sb.AppendLine("    </DirectoryRef>") | Out-Null
    }

    $sb.AppendLine("    <ComponentGroup Id=`"$GroupId`">") | Out-Null
    $idx = 0
    foreach ($file in (Get-ChildItem $RootDir -Recurse -File | Sort-Object FullName)) {
        $rel    = $file.FullName.Substring($RootDir.Length).TrimStart('\')
        $dirRel = if ($rel -match '\\') { $rel.Substring(0,$rel.LastIndexOf('\')) } else { '' }
        $dirId  = if ($dirIdMap.ContainsKey($dirRel)) { $dirIdMap[$dirRel] } else { $RootDirId }
        $safe   = Safe-Id ($rel -replace '\\','_')
        $guid   = New-WixGuid "al:${Prefix}:${rel}:$idx"
        $sb.AppendLine("      <Component Id=`"${Prefix}_c_$safe`" Directory=`"$dirId`" Guid=`"$guid`">") | Out-Null
        $sb.AppendLine("        <File Id=`"${Prefix}_f_$safe`" Name=`"$($file.Name)`" Source=`"$($file.FullName)`" KeyPath=`"yes`" />") | Out-Null
        $sb.AppendLine("      </Component>") | Out-Null
        $idx++
    }
    $sb.AppendLine("    </ComponentGroup>") | Out-Null
    $sb.AppendLine("  </Fragment>") | Out-Null
    $sb.AppendLine("</Wix>") | Out-Null
    return $sb.ToString()
}

$agentFragPath = Join-Path $pkg "attacklens-agent-internal.wxs"
$wdFragPath    = Join-Path $pkg "attacklens-watchdog-internal.wxs"

[IO.File]::WriteAllText($agentFragPath,
    (Build-Fragment -RootDir $agentIntDir -RootDirId "AGENTINTERNALDIR"    -Prefix "agt" -GroupId "AgentInternalFiles"),
    [Text.Encoding]::UTF8)
[IO.File]::WriteAllText($wdFragPath,
    (Build-Fragment -RootDir $wdIntDir    -RootDirId "WATCHDOGINTERNALDIR" -Prefix "wd"  -GroupId "WatchdogInternalFiles"),
    [Text.Encoding]::UTF8)

OK "Agent _internal:    $((Get-ChildItem $agentIntDir -Recurse -File).Count) files"
OK "Watchdog _internal: $((Get-ChildItem $wdIntDir    -Recurse -File).Count) files"

# ── Step 4: Build MSI ────────────────────────────────────────────────────────
Banner "Step 4: wix build"
$outMsi  = Join-Path $dist "attacklens-agent-$Version-x64.msi"
$wixArgs = @(
    "build", "-arch", "x64",
    "-d", "Version=$Version",
    "-d", "AgentExeDir=$agentDir",
    "-d", "WatchdogExeDir=$watchdogDir",
    "-d", "ScriptDir=$pkg",
    "-d", "ManifestPath=$manifestPath",
    (Join-Path $pkg "attacklens.wxs"),
    (Join-Path $pkg "attacklens-ui.wxs"),
    $agentFragPath,
    $wdFragPath,
    "-ext", $utilExt,
    "-ext", $uiExt,
    "-o", $outMsi
)
# The embedded PowerShell payloads can make the direct Windows command line
# exceed its length limit.  WiX accepts one argument per line in a response
# file, preserving paths and large -d values without truncation.
$wixRsp = [IO.Path]::GetTempFileName()
try {
    $wixResponseArgs = foreach ($arg in [string[]]$wixArgs) {
        if ($arg -match '[\s"]') { '"' + ($arg -replace '"', '\\"') + '"' }
        else { $arg }
    }
    [IO.File]::WriteAllLines($wixRsp, [string[]]$wixResponseArgs)
    & wix "@$wixRsp"
    $wixExit = $LASTEXITCODE
} finally {
    Remove-Item -LiteralPath $wixRsp -Force -ErrorAction SilentlyContinue
}
if ($wixExit -ne 0) { throw "wix build failed (exit $wixExit)" }

$sizeMb = [math]::Round((Get-Item $outMsi).Length / 1MB, 1)

Banner "DONE"
Write-Host "  MSI : $outMsi  ($sizeMb MB)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Install (minimum):" -ForegroundColor Cyan
Write-Host "  msiexec /i `"$outMsi`" /qn ACCEPT_EULA=1 MANAGER_URL=`"http://72.61.228.62:8080`" ALLOW_INSECURE_TRANSPORT=`"true`" /l*v install.log"
Write-Host ""
Write-Host "Uninstall:" -ForegroundColor Cyan
Write-Host "  msiexec /x `"$outMsi`" /qn"
Write-Host ""
