#Requires -RunAsAdministrator
<#
.SYNOPSIS
    mac_intel Agent — Windows uninstaller

.DESCRIPTION
    Stops and removes MacIntelAgent and MacIntelWatchdog services,
    deletes binaries, optionally wipes config and key material.

.PARAMETER InstallDir
    Root installation directory. Default: C:\Program Files (x86)\Jarvis

.PARAMETER DataDir
    Data/config directory. Defaults to InstallDir (single-tree install).

.PARAMETER KeepConfig
    Preserve agent.toml and the enrolled API key (for re-install). Default: $false

.EXAMPLE
    .\uninstall.ps1                       # full wipe
    .\uninstall.ps1 -KeepConfig $true     # preserve config + key
#>

param(
    [string] $InstallDir  = "C:\Program Files (x86)\Jarvis",
    [string] $DataDir     = "",
    [bool]   $KeepConfig  = $false
)

if (-not $DataDir) { $DataDir = $InstallDir }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  mac_intel Agent Uninstaller" -ForegroundColor Cyan
Write-Host "  ───────────────────────────" -ForegroundColor Cyan
Write-Host ""

# ── Stop and remove services ──────────────────────────────────────────────────
foreach ($svc in @("MacIntelWatchdog", "MacIntelAgent")) {
    $existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Stopping $svc..." -NoNewline
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Write-Host " stopped" -ForegroundColor Green
        Write-Host "  Removing $svc service..." -NoNewline
        & sc.exe delete $svc | Out-Null
        Write-Host " removed" -ForegroundColor Green
    } else {
        Write-Host "  $svc not installed — skipping"
    }
}

Start-Sleep -Seconds 1

# ── Remove binaries ───────────────────────────────────────────────────────────
Write-Host "  Removing binaries from $InstallDir..." -NoNewline
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host " done" -ForegroundColor Green
} else {
    Write-Host " not found"
}

# ── Remove data ───────────────────────────────────────────────────────────────
if ($KeepConfig) {
    Write-Host "  Keeping $DataDir (KeepConfig=true)"
} else {
    Write-Host "  Removing data directory $DataDir..." -NoNewline
    if (Test-Path $DataDir) {
        # Restore ACLs so we can delete (service may have locked them down)
        icacls $DataDir /reset /T /Q 2>&1 | Out-Null
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
        Write-Host " done" -ForegroundColor Green
    } else {
        Write-Host " not found"
    }
}

# ── Remove from Windows Credential Manager ────────────────────────────────────
Write-Host "  Removing stored credentials..." -NoNewline
try {
    $creds = cmdkey /list | Select-String "macintel"
    if ($creds) {
        cmdkey /delete:"com.macintel.agent" 2>&1 | Out-Null
    }
    Write-Host " done" -ForegroundColor Green
} catch {
    Write-Host " (none found)"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Uninstall complete." -ForegroundColor Green
if ($KeepConfig) {
    Write-Host "  Config preserved at: $DataDir\agent.toml"
}
Write-Host ""
