<#
.SYNOPSIS
    Build Jarvis Agent Windows binaries via PyInstaller.

.DESCRIPTION
    Produces two standalone .exe files:
      dist\jarvis-agent.exe    - main agent (runs as Windows Service or CLI)
      dist\jarvis-watchdog.exe - watchdog (runs as Windows Service)

    Optionally signs them with a code-signing certificate.
    Output directory: agent\os\windows\pkg\dist\

.PARAMETER Version
    Version string embedded in the EXE version info. Default: 1.0.0

.PARAMETER SignIdentity
    Code-signing thumbprint or subject name for signtool.exe.
    Leave empty to skip signing (dev builds).

.PARAMETER Arch
    Target architecture: x64 (default) or arm64.

.EXAMPLE
    .\build_exe.ps1 -Version "1.2.0" -SignIdentity "CN=ACME Corp"
    .\build_exe.ps1 -Version "1.0.0"                              # unsigned
#>

param(
    [string] $Version      = "1.0.0",
    [string] $SignIdentity = "",
    [string] $Arch         = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Locate project root ───────────────────────────────────────────────────────
$ScriptDir  = $PSScriptRoot
$WindowsDir = Split-Path $ScriptDir -Parent
$AgentOsDir = Split-Path $WindowsDir -Parent
$AgentDir   = Split-Path $AgentOsDir -Parent
$Root       = Split-Path $AgentDir -Parent
$DistDir    = "$ScriptDir\dist"
$AgentExe   = "$DistDir\jarvis-agent.exe"
$WdExe      = "$DistDir\jarvis-watchdog.exe"

Write-Host ""
Write-Host "  mac_intel Windows Binary Builder" -ForegroundColor Cyan
Write-Host "  Version: $Version  Arch: $Arch" -ForegroundColor Cyan
Write-Host ""

# ── Install PyInstaller if missing ────────────────────────────────────────────
Write-Host "  Checking PyInstaller..." -NoNewline
pip install pyinstaller --quiet
Write-Host " OK" -ForegroundColor Green

# ── Write version info file ───────────────────────────────────────────────────
$VerParts = $Version.Split(".")
while ($VerParts.Count -lt 4) { $VerParts += "0" }
$VerTuple = $VerParts[0..3] -join ", "

$VersionFile = "$ScriptDir\version_info.txt"
@"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=($VerTuple),
    prodvers=($VerTuple),
    mask=0x3f,
    flags=0x0,
    OS=0x4,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(u'040904B0', [
        StringStruct(u'CompanyName',      u'Jarvis'),
        StringStruct(u'FileDescription',  u'Jarvis Endpoint Agent'),
        StringStruct(u'FileVersion',      u'$Version'),
        StringStruct(u'InternalName',     u'jarvis-agent'),
        StringStruct(u'LegalCopyright',   u'Copyright 2026 Jarvis'),
        StringStruct(u'OriginalFilename', u'jarvis-agent.exe'),
        StringStruct(u'ProductName',      u'Jarvis Agent'),
        StringStruct(u'ProductVersion',   u'$Version'),
      ])
    ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"@ | Out-File -FilePath $VersionFile -Encoding utf8

# ── Build agent EXE ───────────────────────────────────────────────────────────
Write-Host "  Building jarvis-agent.exe..." -NoNewline
Push-Location $Root

pyinstaller `
    --onefile `
    --clean `
    --name jarvis-agent `
    --distpath "$DistDir" `
    --workpath "$ScriptDir\build\agent" `
    --specpath "$ScriptDir" `
    --version-file "$VersionFile" `
    --hidden-import agent.agent.collectors `
    --hidden-import agent.agent.crypto `
    --hidden-import agent.agent.sender `
    --hidden-import agent.agent.enrollment `
    --hidden-import agent.agent.keystore `
    --hidden-import agent.agent.normalizer `
    --hidden-import agent.agent.circuit_breaker `
    --hidden-import agent.os.windows.win_agent `
    --hidden-import agent.os.windows.tls_transport `
    --hidden-import agent.os.windows.service `
    --hidden-import agent.os.windows.keystore `
    --hidden-import agent.os.windows.normalizer `
    --hidden-import agent.os.windows.collectors `
    --hidden-import agent.os.windows.collectors.volatile `
    --hidden-import agent.os.windows.collectors.network `
    --hidden-import agent.os.windows.collectors.system `
    --hidden-import agent.os.windows.collectors.posture `
    --hidden-import agent.os.windows.collectors.inventory `
    --hidden-import agent.os.windows.collectors.eventlog `
    --hidden-import win32service `
    --hidden-import win32serviceutil `
    --hidden-import win32event `
    --hidden-import win32evtlog `
    --hidden-import servicemanager `
    --hidden-import win32crypt `
    --hidden-import pywintypes `
    --hidden-import psutil `
    --hidden-import cryptography `
    --hidden-import cryptography.hazmat.primitives.ciphers.aead `
    --hidden-import requests `
    --hidden-import urllib3 `
    agent\os\windows\agent_win_entry.py

if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "PyInstaller failed for agent"
}
Write-Host " done" -ForegroundColor Green

# ── Build watchdog EXE ────────────────────────────────────────────────────────
Write-Host "  Building jarvis-watchdog.exe..." -NoNewline

$WdVersionFile = "$ScriptDir\version_info_wd.txt"
(Get-Content $VersionFile) -replace 'jarvis-agent', 'jarvis-watchdog' `
    -replace 'Endpoint Agent', 'Watchdog' | Out-File $WdVersionFile -Encoding utf8

pyinstaller `
    --onefile `
    --clean `
    --name jarvis-watchdog `
    --distpath "$DistDir" `
    --workpath "$ScriptDir\build\watchdog" `
    --specpath "$ScriptDir" `
    --version-file "$WdVersionFile" `
    --hidden-import win32service `
    --hidden-import win32serviceutil `
    --hidden-import win32event `
    --hidden-import servicemanager `
    --hidden-import pywintypes `
    agent\os\windows\watchdog_svc.py

if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "PyInstaller failed for watchdog"
}
Write-Host " done" -ForegroundColor Green

Pop-Location

# ── Authenticode signing ──────────────────────────────────────────────────────
if ($SignIdentity) {
    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits" `
        -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName

    if (-not $signtool) {
        Write-Warning "signtool.exe not found - skipping signing"
    } else {
        foreach ($exe in @("jarvis-agent.exe", "jarvis-watchdog.exe")) {
            $exePath = "$DistDir\$exe"
            Write-Host "  Signing $exe..." -NoNewline
            & $signtool sign /sha1 $SignIdentity /fd sha256 /tr http://timestamp.digicert.com /td sha256 $exePath
            if ($LASTEXITCODE -eq 0) {
                Write-Host " signed" -ForegroundColor Green
            } else {
                Write-Warning "Signing $exe failed (exit $LASTEXITCODE)"
            }
        }
    }
} else {
    Write-Host "  Signing skipped (no SignIdentity)" -ForegroundColor Yellow
}

# ── Cleanup temp files ────────────────────────────────────────────────────────
Remove-Item $VersionFile, $WdVersionFile -ErrorAction SilentlyContinue

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "  Output directory: $DistDir"
Get-ChildItem $DistDir -Filter "*.exe" | ForEach-Object {
    $size = [math]::Round($_.Length / 1MB, 1)
    Write-Host "    $($_.Name) - ${size} MB"
}
Write-Host ""
Write-Host "  To install (Run as Administrator):" -ForegroundColor Cyan
Write-Host "    cd $DistDir"
Write-Host "    .\install.ps1 -ManagerUrl https://YOUR_MANAGER:8443"
Write-Host "    # With agent name:"
Write-Host "    .\install.ps1 -ManagerUrl https://YOUR_MANAGER:8443 -AgentName 'Alice Laptop' -TlsVerify `$false"
Write-Host ""
