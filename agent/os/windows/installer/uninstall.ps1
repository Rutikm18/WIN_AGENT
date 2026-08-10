#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AttackLens Windows Agent — uninstaller.

.DESCRIPTION
    Stops and removes the AttackLensAgent and AttackLensWatchdog services,
    removes binaries and registry keys, and optionally preserves data/config
    so the key survives a reinstall.

.PARAMETER InstallDir
    Root installation directory. Default: C:\Program Files\AttackLens

.PARAMETER DataDir
    Root data directory. Default: C:\ProgramData\AttackLens

.PARAMETER KeepData
    $true  — preserve C:\ProgramData\AttackLens\ (config + enrolled key + spool)
              Use when reinstalling: the agent will skip enrollment on next start.
    $false — full wipe including config, logs, spool, and security keys.
    Default: $false

.EXAMPLE
    .\uninstall.ps1                    # full wipe

.EXAMPLE
    .\uninstall.ps1 -KeepData $true   # preserve config + API key (for reinstall)
#>

param(
    [string] $InstallDir = "C:\Program Files\AttackLens",
    [string] $DataDir    = "C:\ProgramData\AttackLens",
    [bool]   $KeepData   = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$AGENT_SVC    = "AttackLensAgent"
$WATCHDOG_SVC = "AttackLensWatchdog"
$REG_INSTALL  = "HKLM:\SOFTWARE\AttackLens"
$REG_SVC_PARAMS = "HKLM:\SYSTEM\CurrentControlSet\Services\$AGENT_SVC\Parameters"

function Write-Ok  ([string]$m) { Write-Host "  [OK]  $m" -ForegroundColor Green  }
function Write-Warn([string]$m) { Write-Host "  [!!]  $m" -ForegroundColor Yellow }
function Write-Skip([string]$m) { Write-Host "  [--]  $m" -ForegroundColor DarkGray }

Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  AttackLens Windows Agent Uninstaller ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install dir : $InstallDir"
Write-Host "  Data dir    : $DataDir"
Write-Host "  Keep data   : $KeepData"
Write-Host ""

# ── Stop and remove services (watchdog first so it can't restart agent) ───────
Write-Host "  Stopping services..." -ForegroundColor Cyan

foreach ($svc in @($WATCHDOG_SVC, $AGENT_SVC)) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if (-not $s) { Write-Skip "$svc not installed"; continue }

    if ($s.Status -ne "Stopped") {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        # Wait up to 10 s for the service to stop
        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Service -Name $svc -EA SilentlyContinue).Status -ne "Stopped" -and
               (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 300
        }
    }
    & sc.exe delete $svc 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Removed service: $svc"
    } else {
        Write-Warn "Could not remove $svc (exit $LASTEXITCODE) — may need manual cleanup"
    }
}

Start-Sleep -Milliseconds 500

# ── Remove service Parameters registry key ────────────────────────────────────
if (Test-Path $REG_SVC_PARAMS) {
    Remove-Item -Path $REG_SVC_PARAMS -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Removed registry: $REG_SVC_PARAMS"
}

# ── Remove install info registry key ─────────────────────────────────────────
if (Test-Path $REG_INSTALL) {
    Remove-Item -Path $REG_INSTALL -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Removed registry: $REG_INSTALL"
}

# ── Remove Windows Credential Manager entry ───────────────────────────────────
$credTarget = "com.attacklens.agent"
$credList = & cmdkey /list 2>&1
if ($credList -match [regex]::Escape($credTarget)) {
    & cmdkey /delete:$credTarget 2>&1 | Out-Null
    Write-Ok "Removed Credential Manager entry: $credTarget"
} else {
    Write-Skip "No Credential Manager entry found for $credTarget"
}

# ── Remove binaries ───────────────────────────────────────────────────────────
if (Test-Path $InstallDir) {
    # Reset ACLs first so inherited restrictions do not block deletion
    & icacls $InstallDir /reset /T /Q 2>&1 | Out-Null
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $InstallDir)) {
        Write-Ok "Removed install directory: $InstallDir"
    } else {
        Write-Warn "Could not fully remove $InstallDir — some files may be locked. Reboot and retry."
    }
} else {
    Write-Skip "Install directory not found: $InstallDir"
}

# ── Remove data directory (unless -KeepData) ─────────────────────────────────
if ($KeepData) {
    Write-Skip "Data directory preserved (KeepData=true): $DataDir"
    Write-Host "  The enrolled API key and config will be reused on reinstall." -ForegroundColor DarkGray
} else {
    if (Test-Path $DataDir) {
        # Reset ACLs before deleting (security\ is locked down)
        & icacls $DataDir /reset /T /Q 2>&1 | Out-Null
        Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $DataDir)) {
            Write-Ok "Removed data directory: $DataDir"
        } else {
            Write-Warn "Could not fully remove $DataDir — check for open log file handles and retry."
        }
    } else {
        Write-Skip "Data directory not found: $DataDir"
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Uninstall complete." -ForegroundColor Green
if ($KeepData) {
    Write-Host "  Config + key preserved at: $DataDir" -ForegroundColor DarkGray
    Write-Host "  Reinstall with:  .\install.ps1 -ManagerIP <IP>" -ForegroundColor DarkGray
} else {
    Write-Host "  All AttackLens files and keys have been removed." -ForegroundColor DarkGray
}
Write-Host ""
