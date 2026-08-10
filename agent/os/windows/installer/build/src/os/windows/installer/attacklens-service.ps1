<#
.SYNOPSIS
    AttackLens Agent service management CLI.

.DESCRIPTION
    Operator tool for managing the AttackLens Agent and Watchdog Windows Services.

    Commands
    ────────
      status        Show service status, config summary, and last log lines
      start         Start both services (requires elevation)
      stop          Stop both services (requires elevation)
      restart       Stop then start both services
      reload        Signal agent to reload config (restart services)
      logs          Tail agent log in real-time (Ctrl+C to stop)
      config        Print agent.toml to stdout
      version       Show installed version, Python info, and OS build
      diagnose      Connectivity + install health check (all green = healthy)
      set-manager   Update manager URL in agent.toml and restart
      enroll        Delete stored API key and force re-enrollment on next start
      update-config Regenerate agent.toml (preserves agent id and name)
      help          Show this help

    Most commands require elevation (Run as Administrator).

.PARAMETER Command
    One of the commands listed above.

.PARAMETER Arg
    Argument for commands that take one (e.g. set-manager <IP_OR_URL>).

.PARAMETER Lines
    Number of log lines to show with 'logs' command. Default: 50.

.PARAMETER Follow
    With 'logs': tail continuously (Get-Content -Wait). Default: $true.

.EXAMPLE
    attacklens-service status
    attacklens-service start
    attacklens-service logs -Lines 100
    attacklens-service set-manager 34.224.174.38
    attacklens-service set-manager http://34.224.174.38:8080
    attacklens-service diagnose
    attacklens-service enroll
#>

param(
    [Parameter(Position=0)]
    [string] $Command = "status",

    [Parameter(Position=1)]
    [string] $Arg = "",

    [int]    $Lines  = 50,
    [bool]   $Follow = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ── Constants ─────────────────────────────────────────────────────────────────
$AGENT_SVC    = "AttackLensAgent"
$WATCHDOG_SVC = "AttackLensWatchdog"
$REG_KEY      = "HKLM:\SOFTWARE\AttackLens\Agent"
$PRODUCT      = "AttackLens Agent"

# ── Resolve install paths from registry ───────────────────────────────────────
function Get-Reg([string]$name) {
    try { return (Get-ItemProperty -Path $REG_KEY -Name $name -ErrorAction Stop).$name }
    catch { return $null }
}

$InstallDir  = Get-Reg "InstallDir"
$DataDir     = Get-Reg "DataDir"
$BinDir      = Get-Reg "BinDir"
$ScriptsDir  = Get-Reg "ScriptsDir"
$Version     = Get-Reg "Version"
$PythonExe   = Get-Reg "PythonExe"

if (-not $DataDir)    { $DataDir   = Join-Path $env:PROGRAMDATA "AttackLens" }
if (-not $InstallDir) { $InstallDir= "C:\Program Files\AttackLens" }
if (-not $BinDir)     { $BinDir    = Join-Path $InstallDir "bin" }
if (-not $ScriptsDir) { $ScriptsDir= Join-Path $InstallDir "scripts" }

$ConfigPath  = Join-Path $DataDir "agent.toml"
$LogFile     = Join-Path $DataDir "logs\agent.log"
$SecurityDir = Join-Path $DataDir "security"

# ── Colour helpers ─────────────────────────────────────────────────────────────
function ok  ([string]$m) { Write-Host "  [OK]  $m" -ForegroundColor Green  }
function warn([string]$m) { Write-Host "  [!!]  $m" -ForegroundColor Yellow }
function err ([string]$m) { Write-Host "  [ERR] $m" -ForegroundColor Red    }
function hdr ([string]$m) { Write-Host "`n  $m"     -ForegroundColor Cyan   }
function dot ([string]$m) { Write-Host "  ·  $m"    -ForegroundColor DarkGray }

# ── Elevation check ────────────────────────────────────────────────────────────
function Require-Admin {
    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host ""
        err "This command requires Administrator privileges."
        Write-Host "  Run: Start-Process powershell -Verb RunAs -ArgumentList `"attacklens-service $Command $Arg`"" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
}

# ── Service helpers ────────────────────────────────────────────────────────────
function Get-SvcStatus([string]$name) {
    try { return (Get-Service -Name $name -ErrorAction Stop).Status }
    catch { return "NotInstalled" }
}

function Wait-Svc([string]$name, [string]$target, [int]$timeoutSec = 30) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        if ((Get-SvcStatus $name) -eq $target) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Svc-StatusLine([string]$name) {
    $st = Get-SvcStatus $name
    $col = switch ($st) {
        "Running"      { "Green"  }
        "Stopped"      { "Red"    }
        "NotInstalled" { "Yellow" }
        default        { "Gray"   }
    }
    Write-Host ("  {0,-28} {1}" -f "$name`:", $st) -ForegroundColor $col
}

# ══════════════════════════════════════════════════════════════════════════════
#  COMMAND DISPATCH
# ══════════════════════════════════════════════════════════════════════════════

switch ($Command.ToLower()) {

    # ── status ─────────────────────────────────────────────────────────────────
    { $_ -in "status", "st" } {
        hdr "$PRODUCT — Status"
        Svc-StatusLine $AGENT_SVC
        Svc-StatusLine $WATCHDOG_SVC

        hdr "Configuration"
        Write-Host "  Config file  : $ConfigPath"
        Write-Host "  Data dir     : $DataDir"
        Write-Host "  Log file     : $LogFile"
        Write-Host "  Security dir : $SecurityDir"
        if ($Version) { Write-Host "  Version      : $Version" }
        if ($PythonExe) { Write-Host "  Python       : $PythonExe" }

        if (Test-Path $ConfigPath) {
            hdr "Manager (from config)"
            Select-String -Path $ConfigPath -Pattern '^\s*url\s*=' |
                Select-Object -First 1 | ForEach-Object { Write-Host "  $($_.Line.Trim())" }
        } else {
            warn "agent.toml not found: $ConfigPath"
        }

        hdr "Agent Identity (client.key)"
        $ck = Join-Path $SecurityDir "client.key"
        if (Test-Path $ck) {
            Get-Content $ck | Where-Object { $_ -match '^\s*(agent_name|agent_number|issued_at)\s*=' } |
                ForEach-Object { Write-Host "  $($_.Trim())" }
            $tok = Get-Content $ck | Where-Object { $_ -match '^\s*token\s*=' }
            if ($tok) {
                $val = ($tok -replace '.*=\s*"?([^"]+)"?.*', '$1')
                Write-Host "  token        : $($val.Substring(0, [Math]::Min(16, $val.Length)))..." -ForegroundColor DarkGray
            }
        } else {
            warn "client.key not found — agent has not enrolled yet"
        }

        hdr "Recent log (last 10 lines)"
        if (Test-Path $LogFile) {
            Get-Content $LogFile -Tail 10 | ForEach-Object { dot $_ }
        } else {
            warn "Log file not found: $LogFile"
        }
        Write-Host ""
    }

    # ── start ──────────────────────────────────────────────────────────────────
    "start" {
        Require-Admin
        hdr "Starting $PRODUCT services"

        foreach ($svc in @($WATCHDOG_SVC, $AGENT_SVC)) {
            $st = Get-SvcStatus $svc
            if ($st -eq "Running")      { ok "$svc already running"; continue }
            if ($st -eq "NotInstalled") { warn "$svc not installed"; continue }
            Write-Host "  Starting $svc..." -NoNewline
            Start-Service -Name $svc
            if (Wait-Svc $svc "Running") { ok "started" }
            else { err "timed out"; exit 1 }
        }
        Write-Host ""
    }

    # ── stop ───────────────────────────────────────────────────────────────────
    "stop" {
        Require-Admin
        hdr "Stopping $PRODUCT services"

        foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
            $st = Get-SvcStatus $svc
            if ($st -eq "Stopped")      { ok "$svc already stopped"; continue }
            if ($st -eq "NotInstalled") { warn "$svc not installed"; continue }
            Write-Host "  Stopping $svc..." -NoNewline
            Stop-Service -Name $svc -Force
            if (Wait-Svc $svc "Stopped") { ok "stopped" }
            else { err "timed out waiting for $svc to stop" }
        }
        Write-Host ""
    }

    # ── restart ────────────────────────────────────────────────────────────────
    { $_ -in "restart", "rs" } {
        Require-Admin
        & $MyInvocation.MyCommand.Path stop
        Start-Sleep -Seconds 2
        & $MyInvocation.MyCommand.Path start
    }

    # ── reload ─────────────────────────────────────────────────────────────────
    "reload" {
        Require-Admin
        hdr "Reloading $PRODUCT (restart)"
        Write-Host "  Windows Services do not support SIGHUP — restarting services instead."
        & $MyInvocation.MyCommand.Path restart
    }

    # ── logs ───────────────────────────────────────────────────────────────────
    { $_ -in "logs", "log" } {
        if (-not (Test-Path $LogFile)) {
            warn "Log file not found: $LogFile"
            exit 0
        }
        hdr "$PRODUCT Log  ($LogFile)"
        Write-Host ""
        if ($Follow) {
            Write-Host "  Tailing log (Ctrl+C to stop)..." -ForegroundColor DarkGray
            Get-Content $LogFile -Tail $Lines -Wait
        } else {
            Get-Content $LogFile -Tail $Lines | ForEach-Object { Write-Host $_ }
        }
        Write-Host ""
    }

    # ── config ─────────────────────────────────────────────────────────────────
    "config" {
        if (-not (Test-Path $ConfigPath)) {
            err "Config not found: $ConfigPath"
            Write-Host "  Run: attacklens-service update-config" -ForegroundColor Yellow
            exit 1
        }
        Write-Host ""
        Get-Content $ConfigPath | ForEach-Object { Write-Host $_ }
        Write-Host ""
    }

    # ── version ────────────────────────────────────────────────────────────────
    "version" {
        Write-Host ""
        Write-Host "  $PRODUCT" -ForegroundColor Cyan
        Write-Host "  Version    : $Version"
        Write-Host "  Install dir: $InstallDir"
        Write-Host "  Data dir   : $DataDir"
        if ($PythonExe -and (Test-Path $PythonExe)) {
            $pyVer = & $PythonExe --version 2>&1
            Write-Host "  Python     : $pyVer  ($PythonExe)"
        }
        Write-Host "  OS Build   : $([System.Environment]::OSVersion.VersionString)"
        $osBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        Write-Host "  Windows    : Build $osBuild"
        Write-Host ""
    }

    # ── diagnose ───────────────────────────────────────────────────────────────
    { $_ -in "diagnose", "diag", "check" } {
        hdr "$PRODUCT — Diagnostic"
        $pass = 0; $fail = 0

        function Check([string]$label, [bool]$result, [string]$hint = "") {
            if ($result) { ok $label; $script:pass++ }
            else {
                err $label
                if ($hint) { Write-Host "        $hint" -ForegroundColor DarkGray }
                $script:fail++
            }
        }

        # OS version
        $osv = [System.Environment]::OSVersion.Version
        Check "Windows 10/11 or Server 2019/2022" ($osv.Major -ge 10) `
            "Windows 10 (Build 19041+) is required."

        # Python
        $pyFound = $PythonExe -and (Test-Path $PythonExe)
        Check "Python 3.11+ found" $pyFound "Install Python: https://www.python.org/downloads/"
        if ($pyFound) {
            $pyV = & $PythonExe --version 2>&1
            dot $pyV
        }

        # Required packages
        if ($pyFound) {
            foreach ($pkg in @("psutil", "cryptography", "requests", "keyring", "win32service")) {
                $ok = (& $PythonExe -c "import $pkg" 2>&1) -eq ""
                Check "Python package: $pkg" $ok "pip install $pkg"
            }
        }

        # Install dir
        Check "Install dir exists" (Test-Path $InstallDir) "Reinstall AttackLens Agent."
        Check "agent.toml exists"  (Test-Path $ConfigPath)  "Run: attacklens-service update-config"
        Check "run_agent.py exists" (Test-Path (Join-Path $BinDir "run_agent.py")) "Reinstall."

        # Config validity
        if (Test-Path $ConfigPath) {
            $urlLine = Select-String -Path $ConfigPath -Pattern '^\s*url\s*=\s*"([^"]+)"' |
                Select-Object -First 1
            if ($urlLine) {
                $managerUrl = $urlLine.Matches[0].Groups[1].Value
                Check "Manager URL not placeholder" ($managerUrl -notlike "*YOUR_MANAGER*") `
                    "Run: attacklens-service set-manager <IP>"
                dot "Manager URL: $managerUrl"

                # TCP connectivity
                if ($managerUrl -match "https?://([^:/]+)(?::(\d+))?") {
                    $host2 = $Matches[1]
                    $port2 = if ($Matches[2]) { [int]$Matches[2] } else { 80 }
                    $tcp = Test-NetConnection -ComputerName $host2 -Port $port2 -ErrorAction SilentlyContinue
                    Check "TCP $host2`:$port2 reachable" ($tcp.TcpTestSucceeded -eq $true) `
                        "Check firewall / VPN / manager is running."

                    # HTTP /health
                    try {
                        $resp = Invoke-WebRequest -Uri "$managerUrl/health" -TimeoutSec 5 -ErrorAction Stop
                        Check "Manager /health responded $($resp.StatusCode)" ($resp.StatusCode -lt 400)
                    } catch {
                        warn "Manager /health: $($_.Exception.Message)"
                        $fail++
                    }
                }
            } else {
                err "Manager URL missing from agent.toml"; $fail++
            }
        }

        # Services
        foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
            $st = Get-SvcStatus $svc
            Check "Service $svc installed" ($st -ne "NotInstalled") "Reinstall AttackLens Agent."
            Check "Service $svc running"   ($st -eq "Running")      "Run: attacklens-service start"
        }

        # Credential Manager / client.key
        $ck = Join-Path $SecurityDir "client.key"
        Check "client.key present (enrolled)" (Test-Path $ck) `
            "Run: attacklens-service enroll  — or wait for auto-enrollment on first start."

        # Event log (last 5 errors)
        $evts = Get-WinEvent -FilterHashtable @{LogName="Application"; Source="AttackLensAgent"; Level=2} `
            -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($evts) {
            warn "Recent errors in Windows Event Log:"
            $evts | ForEach-Object { dot "$($_.TimeCreated)  $($_.Message.Substring(0,[Math]::Min(120,$_.Message.Length)))" }
        }

        Write-Host ""
        Write-Host "  ─────────────────────────────────────" -ForegroundColor Cyan
        if ($fail -eq 0) {
            Write-Host "  All $pass checks passed." -ForegroundColor Green
        } else {
            Write-Host "  $pass passed  /  $fail failed." -ForegroundColor Yellow
        }
        Write-Host ""
    }

    # ── set-manager ────────────────────────────────────────────────────────────
    "set-manager" {
        Require-Admin
        if (-not $Arg) {
            err "Usage: attacklens-service set-manager <IP_OR_URL>"
            Write-Host "  Examples:"
            Write-Host "    attacklens-service set-manager 34.224.174.38"
            Write-Host "    attacklens-service set-manager http://34.224.174.38:8080"
            Write-Host "    attacklens-service set-manager https://manager.corp.example:443"
            exit 1
        }
        if (-not (Test-Path $ConfigPath)) {
            err "agent.toml not found: $ConfigPath"
            exit 1
        }

        # Normalise to full URL
        $NewUrl = $Arg
        if ($NewUrl -notmatch "^https?://") {
            $NewUrl = "http://$NewUrl`:8080"
        }
        $tlsVal = if ($NewUrl.StartsWith("https://")) { "true" } else { "false" }

        hdr "Updating manager URL → $NewUrl"

        # In-place update via Python regex (preserves all other config)
        if (-not $PythonExe) { $PythonExe = "python.exe" }
        & $PythonExe -c @"
import re, sys
path = r'$($ConfigPath.Replace("'","''"))'
url  = sys.argv[1]
tls  = sys.argv[2]
with open(path, encoding='utf-8') as f: c = f.read()
c = re.sub(r'^url\s*=\s*"[^"]*"',   f'url        = "{url}"', c, flags=re.MULTILINE)
c = re.sub(r'^tls_verify\s*=\s*\S+', f'tls_verify = {tls}',  c, flags=re.MULTILINE)
with open(path, 'w', encoding='utf-8') as f: f.write(c)
"@ $NewUrl $tlsVal
        if ($LASTEXITCODE -ne 0) { err "Failed to update agent.toml"; exit 1 }
        ok "agent.toml updated"

        # Remove client.key so agent re-enrolls with new manager
        $ck = Join-Path $SecurityDir "client.key"
        if (Test-Path $ck) { Remove-Item $ck -Force; ok "client.key removed (will re-enroll)" }

        # Remove DPAPI key files
        Get-ChildItem $SecurityDir -Filter "*.dpapi" -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item $_.FullName -Force; ok "Removed: $($_.Name)" }

        & $MyInvocation.MyCommand.Path restart
    }

    # ── enroll ─────────────────────────────────────────────────────────────────
    "enroll" {
        Require-Admin
        hdr "Force re-enrollment"
        Write-Host "  Stops agent, deletes client.key and DPAPI keys, restarts agent."

        & $MyInvocation.MyCommand.Path stop
        Start-Sleep -Seconds 2

        $ck = Join-Path $SecurityDir "client.key"
        if (Test-Path $ck) { Remove-Item $ck -Force; ok "client.key deleted" }
        else { warn "client.key not found (not yet enrolled)" }

        Get-ChildItem $SecurityDir -Filter "*.dpapi" -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item $_.FullName -Force; ok "Removed DPAPI key: $($_.Name)" }

        # Clear Windows Credential Manager entry
        & cmdkey /delete:"com.attacklens.agent" 2>&1 | Out-Null
        ok "Credential Manager entry removed (if present)"

        & $MyInvocation.MyCommand.Path start
        Write-Host ""
        ok "Agent restarted — will auto-enroll on next collection cycle."
    }

    # ── update-config ──────────────────────────────────────────────────────────
    "update-config" {
        Require-Admin
        hdr "Regenerating agent.toml"
        $genScript = Join-Path $ScriptsDir "generate_config.ps1"
        if (-not (Test-Path $genScript)) {
            err "generate_config.ps1 not found: $genScript"
            exit 1
        }
        # Preserve manager URL from existing config
        $existingUrl = "http://YOUR_MANAGER_IP:8080"
        if (Test-Path $ConfigPath) {
            $match = Select-String -Path $ConfigPath -Pattern '^\s*url\s*=\s*"([^"]+)"' |
                Select-Object -First 1
            if ($match) { $existingUrl = $match.Matches[0].Groups[1].Value }
        }
        & powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass `
            -File $genScript `
            -InstallDir $InstallDir `
            -DataDir    $DataDir `
            -ManagerUrl $existingUrl
        if ($LASTEXITCODE -eq 0) {
            ok "agent.toml regenerated"
            Write-Host "  Run: attacklens-service restart  to apply changes."
        } else {
            err "generate_config.ps1 failed (exit $LASTEXITCODE)"
        }
        Write-Host ""
    }

    # ── help ───────────────────────────────────────────────────────────────────
    { $_ -in "help", "--help", "-h", "-?" } {
        Get-Help $MyInvocation.MyCommand.Path -Full
    }

    default {
        err "Unknown command: $Command"
        Write-Host "  Run: attacklens-service help" -ForegroundColor Yellow
        exit 1
    }
}
