#Requires -RunAsAdministrator
<#
.SYNOPSIS
    mac_intel Agent — Windows installer

.DESCRIPTION
    Installs the mac_intel agent and watchdog as Windows Services.
    Copies binaries, creates directory structure with proper ACLs, writes
    agent.toml, and registers both services with the Service Control Manager.

.PARAMETER InstallDir
    Root installation directory. Default: C:\Program Files (x86)\Jarvis
    All subdirectories (bin, config, data, logs, security, spool) are created here.

.PARAMETER DataDir
    Writable data directory root. Defaults to InstallDir (single-tree install).

.PARAMETER ManagerUrl
    Manager HTTPS URL, e.g. https://192.168.1.100:8443

.PARAMETER EnrollToken
    One-time enrollment token from the manager operator.

.PARAMETER AgentId
    Unique agent identifier (default: hostname).

.PARAMETER AgentName
    Human-readable name shown on the dashboard (default: hostname).

.PARAMETER TlsVerify
    Set to $false only for self-signed certs in dev. Default: $true

.PARAMETER ServiceAccount
    Windows account to run the agent service. Default: NT AUTHORITY\NetworkService

.EXAMPLE
    .\install.ps1 `
        -ManagerUrl    "https://10.0.0.5:8443" `
        -EnrollToken   "sk-enroll-abc123" `
        -AgentId       "laptop-001"
#>

param(
    # REQUIRED: manager HTTPS URL
    [string] $ManagerUrl     = "",
    # OPTIONAL: friendly name shown on dashboard (defaults to computer name)
    [string] $AgentName      = $env:COMPUTERNAME,
    # Advanced overrides — safe to leave at defaults
    [string] $InstallDir     = "C:\Program Files (x86)\Jarvis",
    [string] $DataDir        = "",
    [string] $EnrollToken    = "",          # only if manager requires token-mode
    [bool]   $TlsVerify      = $true,       # set $false for self-signed certs
    [string] $ServiceAccount = "NT AUTHORITY\NetworkService"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Consolidate everything under $InstallDir when no separate DataDir given
if (-not $DataDir) { $DataDir = $InstallDir }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  mac_intel Agent Installer" -ForegroundColor Cyan
Write-Host "  ─────────────────────────" -ForegroundColor Cyan
Write-Host ""

# ── Validate ──────────────────────────────────────────────────────────────────
if (-not (Test-Path ".\jarvis-agent.exe")) {
    Write-Error "jarvis-agent.exe not found in current directory."
}
if (-not (Test-Path ".\jarvis-watchdog.exe")) {
    Write-Error "jarvis-watchdog.exe not found in current directory."
}
if ($ManagerUrl -like "*YOUR_MANAGER*") {
    Write-Warning "ManagerUrl still set to placeholder. Edit agent.toml after install."
}

# ── Create directories ────────────────────────────────────────────────────────
$BinDir      = "$InstallDir\bin"
$ConfigDir   = "$DataDir\config"
$LogDir      = "$DataDir\logs"
$SecurityDir = "$DataDir\security"
$SpoolDir    = "$DataDir\spool"
$SubDataDir  = "$DataDir\data"
$ConfigFile  = "$ConfigDir\agent.toml"

Write-Host "  Creating directories..." -NoNewline
foreach ($dir in @($BinDir, $ConfigDir, $LogDir, $SecurityDir, $SpoolDir, $SubDataDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Host " done" -ForegroundColor Green

# ── Lock down data directory (SYSTEM + Admins only) ──────────────────────────
Write-Host "  Applying ACLs to $DataDir..." -NoNewline
icacls $DataDir    /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" `
                                  /grant:r "BUILTIN\Administrators:(OI)(CI)(F)" 2>&1 | Out-Null
icacls $SecurityDir /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" 2>&1 | Out-Null
Write-Host " done" -ForegroundColor Green

# ── Copy binaries ─────────────────────────────────────────────────────────────
Write-Host "  Installing binaries to $BinDir..." -NoNewline
Copy-Item ".\jarvis-agent.exe"   -Destination $BinDir -Force
Copy-Item ".\jarvis-watchdog.exe" -Destination $BinDir -Force
# Restrict write access on binaries (read + execute only for service account)
icacls "$BinDir\jarvis-agent.exe"    /inheritance:r `
    /grant:r "NT AUTHORITY\SYSTEM:(RX)" `
    /grant:r "BUILTIN\Administrators:(RX)" 2>&1 | Out-Null
icacls "$BinDir\jarvis-watchdog.exe" /inheritance:r `
    /grant:r "NT AUTHORITY\SYSTEM:(RX)" `
    /grant:r "BUILTIN\Administrators:(RX)" 2>&1 | Out-Null
Write-Host " done" -ForegroundColor Green

# ── Write agent.toml ──────────────────────────────────────────────────────────
Write-Host "  Writing $ConfigFile..." -NoNewline
$TlsVerifyStr = if ($TlsVerify) { "true" } else { "false" }
$ConfigContent = @"
# mac_intel Agent Configuration — managed by installer
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

[agent]
id          = "$AgentId"
name        = "$AgentName"
description = "Windows endpoint"

[manager]
url        = "$ManagerUrl"
tls_verify = $TlsVerifyStr
timeout_sec = 30
retry_attempts = 3
retry_delay_sec = 5
max_queue_size = 500

[enrollment]
token    = "$EnrollToken"
keystore = "keychain"

[watchdog]
enabled            = true
check_interval_sec = 30
max_restarts       = 5
restart_window_sec = 300

[paths]
install_dir  = "$($BinDir -replace '\\', '\\')"
config_dir   = "$($ConfigDir -replace '\\', '\\')"
log_dir      = "$($LogDir -replace '\\', '\\')"
data_dir     = "$($SubDataDir -replace '\\', '\\')"
security_dir = "$($SecurityDir -replace '\\', '\\')"
spool_dir    = "$($SpoolDir -replace '\\', '\\')"
pid_file     = "$($InstallDir -replace '\\', '\\')\\jarvis-agent.pid"

[binaries]
agent    = "$($BinDir -replace '\\', '\\')\\jarvis-agent.exe"
watchdog = "$($BinDir -replace '\\', '\\')\\jarvis-watchdog.exe"

[collection]
enabled  = true
tick_sec = 5

[collection.sections.metrics]
enabled = true; interval_sec = 10; send = true
[collection.sections.connections]
enabled = true; interval_sec = 10; send = true
[collection.sections.processes]
enabled = true; interval_sec = 10; send = true
[collection.sections.ports]
enabled = true; interval_sec = 30; send = true
[collection.sections.network]
enabled = true; interval_sec = 120; send = true
[collection.sections.battery]
enabled = true; interval_sec = 120; send = true
[collection.sections.openfiles]
enabled = true; interval_sec = 120; send = true
[collection.sections.services]
enabled = true; interval_sec = 120; send = true
[collection.sections.users]
enabled = true; interval_sec = 120; send = true
[collection.sections.hardware]
enabled = true; interval_sec = 120; send = true
[collection.sections.containers]
enabled = true; interval_sec = 120; send = true
[collection.sections.arp]
enabled = true; interval_sec = 120; send = true
[collection.sections.mounts]
enabled = true; interval_sec = 120; send = true
[collection.sections.storage]
enabled = true; interval_sec = 600; send = true
[collection.sections.tasks]
enabled = true; interval_sec = 600; send = true
[collection.sections.security]
enabled = true; interval_sec = 3600; send = true
[collection.sections.sysctl]
enabled = true; interval_sec = 3600; send = true
[collection.sections.configs]
enabled = true; interval_sec = 3600; send = true
[collection.sections.apps]
enabled = true; interval_sec = 86400; send = true
[collection.sections.packages]
enabled = true; interval_sec = 86400; send = true
[collection.sections.binaries]
enabled = false; interval_sec = 86400; send = false
[collection.sections.sbom]
enabled = true; interval_sec = 86400; send = true

[logging]
level   = "INFO"
file    = "$($LogDir -replace '\\', '\\')\\agent.log"
max_mb  = 10
backups = 3
"@
$ConfigContent | Out-File -FilePath $ConfigFile -Encoding UTF8 -Force

# Config: only SYSTEM and Admins can read (key material stored separately)
icacls $ConfigFile /inheritance:r `
    /grant:r "NT AUTHORITY\SYSTEM:(R)" `
    /grant:r "BUILTIN\Administrators:(R)" 2>&1 | Out-Null
Write-Host " done" -ForegroundColor Green

# ── Register Windows Services ─────────────────────────────────────────────────
Write-Host "  Registering Windows Services..." -NoNewline

# Remove stale services if present
foreach ($svc in @("MacIntelAgent", "MacIntelWatchdog")) {
    $existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.Status -eq "Running") {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        }
        & sc.exe delete $svc | Out-Null
        Start-Sleep -Milliseconds 500
    }
}

# Agent service
& sc.exe create MacIntelAgent `
    binpath= "`"$BinDir\jarvis-agent.exe`"" `
    DisplayName= "mac_intel Agent" `
    start= auto `
    obj= $ServiceAccount | Out-Null
& sc.exe description MacIntelAgent "Endpoint telemetry agent (mac_intel)" | Out-Null
# Failure action: restart after 60s, 3 times, then wait 600s
& sc.exe failure MacIntelAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

# Watchdog service
& sc.exe create MacIntelWatchdog `
    binpath= "`"$BinDir\jarvis-watchdog.exe`"" `
    DisplayName= "mac_intel Watchdog" `
    start= auto `
    depend= MacIntelAgent | Out-Null
& sc.exe description MacIntelWatchdog "Monitors and restarts the mac_intel Agent service" | Out-Null

# Set config path via environment
& sc.exe config MacIntelAgent start= delayed-auto | Out-Null

Write-Host " done" -ForegroundColor Green

# ── Start services ────────────────────────────────────────────────────────────
Write-Host "  Starting MacIntelAgent..." -NoNewline
Start-Service -Name MacIntelAgent -ErrorAction SilentlyContinue
$agentStatus = (Get-Service -Name MacIntelAgent).Status
Write-Host " $agentStatus" -ForegroundColor $(if ($agentStatus -eq "Running") { "Green" } else { "Yellow" })

Write-Host "  Starting MacIntelWatchdog..." -NoNewline
Start-Service -Name MacIntelWatchdog -ErrorAction SilentlyContinue
$wdStatus = (Get-Service -Name MacIntelWatchdog).Status
Write-Host " $wdStatus" -ForegroundColor $(if ($wdStatus -eq "Running") { "Green" } else { "Yellow" })

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Agent ID   : $AgentId"
Write-Host "  Manager URL: $ManagerUrl"
Write-Host "  Config     : $ConfigFile"
Write-Host "  Logs       : $LogDir\agent.log"
Write-Host "  Services   : MacIntelAgent, MacIntelWatchdog"
Write-Host ""
if (-not $EnrollToken) {
    Write-Host "  WARNING: No enrollment token set." -ForegroundColor Yellow
    Write-Host "  Edit $ConfigFile and set [enrollment] token," -ForegroundColor Yellow
    Write-Host "  then restart: Restart-Service MacIntelAgent" -ForegroundColor Yellow
    Write-Host ""
}
