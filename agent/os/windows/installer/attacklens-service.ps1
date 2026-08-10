#Requires -RunAsAdministrator
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
      version       Show installed version and OS build
      diagnose      Connectivity + install health check (all green = healthy)
      repair        Auto-fix common problems (services, ACLs, config, enrollment)
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
    attacklens-service set-manager https://34.224.174.38:8443
    attacklens-service diagnose
    attacklens-service repair
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

if (-not $DataDir)    { $DataDir    = Join-Path $env:PROGRAMDATA "AttackLens" }
if (-not $InstallDir) { $InstallDir = "C:\Program Files\AttackLens" }
if (-not $BinDir)     { $BinDir     = Join-Path $InstallDir "bin" }
if (-not $ScriptsDir) { $ScriptsDir = Join-Path $InstallDir "scripts" }

$ConfigPath  = Join-Path $DataDir "config\agent.toml"
$LogFile     = Join-Path $DataDir "logs\agent.log"
$SecurityDir = Join-Path $DataDir "security"
$AgentExe    = Join-Path $BinDir "attacklens-agent\attacklens-agent.exe"

# ── Colour helpers ─────────────────────────────────────────────────────────────
function ok  ([string]$m) { Write-Host "  [OK]  $m" -ForegroundColor Green    }
function warn([string]$m) { Write-Host "  [!!]  $m" -ForegroundColor Yellow   }
function err ([string]$m) { Write-Host "  [ERR] $m" -ForegroundColor Red      }
function hdr ([string]$m) { Write-Host "`n  $m"     -ForegroundColor Cyan     }
function dot ([string]$m) { Write-Host "  ·  $m"    -ForegroundColor DarkGray }
function fix ([string]$m) { Write-Host "  [FIX] $m" -ForegroundColor Magenta  }

# ── Shield logo ────────────────────────────────────────────────────────────────
function Show-Logo {
    param([string]$Subtitle = "")
    Write-Host ""
    Write-Host "       ___________________________"   -ForegroundColor Cyan
    Write-Host "      |                           |"  -ForegroundColor Cyan
    Write-Host "      |      A T T A C K          |"  -ForegroundColor Cyan
    Write-Host "      |        L E N S            |"  -ForegroundColor Cyan
    Write-Host "      |   ─────────────────────   |"  -ForegroundColor Cyan
    Write-Host "      |     Windows  Agent        |"  -ForegroundColor Cyan
    Write-Host "      |___________________________|"  -ForegroundColor Cyan
    Write-Host "       \                         /"   -ForegroundColor Cyan
    Write-Host "        \                       /"    -ForegroundColor Cyan
    Write-Host "         \_______________________/"   -ForegroundColor Cyan
    Write-Host "                   | |"               -ForegroundColor Cyan
    Write-Host "                  [===]"              -ForegroundColor Cyan
    if ($Subtitle) { Write-Host ""; Write-Host "        $Subtitle" -ForegroundColor White }
    Write-Host ""
}

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
    $st  = Get-SvcStatus $name
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
        Show-Logo "Service Status"

        hdr "Services"
        Svc-StatusLine $AGENT_SVC
        Svc-StatusLine $WATCHDOG_SVC

        hdr "Configuration"
        Write-Host "  Config file  : $ConfigPath"
        Write-Host "  Data dir     : $DataDir"
        Write-Host "  Log file     : $LogFile"
        Write-Host "  Security dir : $SecurityDir"
        if ($Version) { Write-Host "  Version      : $Version" }

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
            Start-Service -Name $svc -ErrorAction SilentlyContinue
            if (Wait-Svc $svc "Running") { ok "started" }
            else { err "timed out — check Event Log and agent.log"; exit 1 }
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
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
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
        Write-Host "  Version    : $(if ($Version) { $Version } else { '(unknown)' })"
        Write-Host "  Install dir: $InstallDir"
        Write-Host "  Data dir   : $DataDir"
        Write-Host "  OS         : $([System.Environment]::OSVersion.VersionString)"
        $osBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).CurrentBuildNumber
        if ($osBuild) { Write-Host "  Windows    : Build $osBuild" }
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
                if ($hint) { Write-Host "        Hint: $hint" -ForegroundColor DarkGray }
                $script:fail++
            }
        }

        # OS version
        $osv = [System.Environment]::OSVersion.Version
        Check "Windows 10/11 or Server 2016+" ($osv.Major -ge 10) `
            "Windows 10 Build 19041+ is required."

        # Install dirs
        Check "Install dir exists"  (Test-Path $InstallDir)  "Reinstall AttackLens Agent."
        Check "agent binary exists" (Test-Path $AgentExe)    "Reinstall AttackLens Agent (binary missing)."
        Check "agent.toml exists"   (Test-Path $ConfigPath)  "Run: attacklens-service update-config"
        Check "security dir exists" (Test-Path $SecurityDir) "Reinstall AttackLens Agent."

        # Config validity
        if (Test-Path $ConfigPath) {
            $urlLine = Select-String -Path $ConfigPath -Pattern '^\s*url\s*=\s*"([^"]+)"' |
                Select-Object -First 1
            if ($urlLine) {
                $managerUrl = $urlLine.Matches[0].Groups[1].Value
                Check "Manager URL configured" ($managerUrl -notlike "*YOUR_MANAGER*") `
                    "Run: attacklens-service set-manager <IP>"
                dot "Manager URL: $managerUrl"

                # TCP connectivity
                if ($managerUrl -match "https?://([^:/]+)(?::(\d+))?") {
                    $mHost = $Matches[1]
                    $mPort = if ($Matches[2]) { [int]$Matches[2] } else { 443 }
                    Write-Host "  Checking TCP $mHost`:$mPort..." -NoNewline -ForegroundColor DarkGray
                    $tcp = Test-NetConnection -ComputerName $mHost -Port $mPort -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                    Check " TCP $mHost`:$mPort reachable" ($tcp.TcpTestSucceeded -eq $true) `
                        "Check firewall / VPN / verify manager is running."

                    # HTTPS /health
                    try {
                        $resp = Invoke-WebRequest -Uri "$managerUrl/health" -TimeoutSec 5 `
                            -SkipCertificateCheck -UseBasicParsing -ErrorAction Stop
                        Check "Manager /health HTTP $($resp.StatusCode)" ($resp.StatusCode -lt 400)
                    } catch {
                        warn "Manager /health unreachable: $($_.Exception.Message)"
                        $script:fail++
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

        # Enrollment
        $ck = Join-Path $SecurityDir "client.key"
        Check "client.key present (enrolled)" (Test-Path $ck) `
            "Run: attacklens-service enroll  — or wait for auto-enrollment on first start."

        # Disk space (warn if data drive < 200 MB free)
        $drive = Split-Path -Qualifier $DataDir
        $dFree = (Get-PSDrive -Name ($drive.TrimEnd(':')) -ErrorAction SilentlyContinue).Free
        if ($dFree -ne $null) {
            Check "Data drive free space >= 200 MB" ($dFree -gt 200MB) `
                "Spool and logs may fill up — free disk space on $drive."
        }

        # Recent errors in Windows Event Log
        $evts = Get-WinEvent -FilterHashtable @{LogName="Application"; Source=$AGENT_SVC; Level=2} `
            -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($evts) {
            warn "Recent errors in Windows Event Log ($($evts.Count)):"
            $evts | ForEach-Object {
                dot "$($_.TimeCreated)  $($_.Message.Substring(0,[Math]::Min(120,$_.Message.Length)))"
            }
        }

        Write-Host ""
        Write-Host "  ─────────────────────────────────────" -ForegroundColor Cyan
        if ($fail -eq 0) {
            Write-Host "  All $pass checks passed." -ForegroundColor Green
        } else {
            Write-Host "  $pass passed  /  $fail failed." -ForegroundColor Yellow
            Write-Host "  Run: attacklens-service repair   to attempt automatic fixes." -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # ── repair ─────────────────────────────────────────────────────────────────
    { $_ -in "repair", "fix" } {
        Require-Admin
        Show-Logo "Auto-Repair"
        Write-Host "  Scanning for problems and applying fixes..." -ForegroundColor Cyan
        Write-Host ""

        $fixed   = 0
        $skipped = 0
        $failed  = 0

        # ── 1. Agent binary present? ───────────────────────────────────────────
        if (-not (Test-Path $AgentExe)) {
            err "Agent binary missing: $AgentExe"
            Write-Host "  Cannot repair — reinstall is required:" -ForegroundColor Yellow
            Write-Host "    .\install.ps1 -ManagerIP <IP>" -ForegroundColor Yellow
            exit 1
        }
        ok "Agent binary present"

        # ── 2. Config file ─────────────────────────────────────────────────────
        if (-not (Test-Path $ConfigPath)) {
            fix "agent.toml missing — regenerating"
            $genScript = Join-Path $ScriptsDir "generate_config.ps1"
            if (Test-Path $genScript) {
                & powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass `
                    -File $genScript -InstallDir $InstallDir -DataDir $DataDir `
                    -ManagerUrl "https://YOUR_MANAGER_IP:8443" 2>&1 | Out-Null
                if (Test-Path $ConfigPath) { ok "agent.toml regenerated (update manager: attacklens-service set-manager <IP>)"; $fixed++ }
                else { err "Failed to regenerate agent.toml"; $failed++ }
            } else {
                err "generate_config.ps1 not found — reinstall required"; $failed++
            }
        } else {
            dot "agent.toml present — skipping"
            $skipped++
        }

        # ── 3. Security directory ACLs ─────────────────────────────────────────
        if (Test-Path $SecurityDir) {
            fix "Resetting ACLs on security directory"
            & icacls $SecurityDir /inheritance:r /T /Q 2>&1 | Out-Null
            & icacls $SecurityDir /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" /T /Q 2>&1 | Out-Null
            & icacls $SecurityDir /grant:r "BUILTIN\Administrators:(OI)(CI)(F)" /T /Q 2>&1 | Out-Null
            ok "ACLs reset on: $SecurityDir"; $fixed++
        }

        # ── 4. Logs directory ──────────────────────────────────────────────────
        $logsDir = Join-Path $DataDir "logs"
        if (-not (Test-Path $logsDir)) {
            fix "Logs directory missing — creating"
            New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
            if (Test-Path $logsDir) { ok "Logs directory created: $logsDir"; $fixed++ }
            else { err "Failed to create logs directory"; $failed++ }
        } else {
            dot "Logs directory present — skipping"
            $skipped++
        }

        # ── 5. Spool directory ─────────────────────────────────────────────────
        $spoolDir = Join-Path $DataDir "spool"
        if (-not (Test-Path $spoolDir)) {
            fix "Spool directory missing — creating"
            New-Item -ItemType Directory -Path $spoolDir -Force | Out-Null
            if (Test-Path $spoolDir) { ok "Spool directory created: $spoolDir"; $fixed++ }
            else { err "Failed to create spool directory"; $failed++ }
        } else {
            # Clean up orphaned .draining files (partial drain from previous crash)
            $draining = Get-ChildItem $spoolDir -Filter "*.draining" -ErrorAction SilentlyContinue
            if ($draining) {
                fix "Found $($draining.Count) orphaned .draining file(s) — removing"
                $draining | Remove-Item -Force -ErrorAction SilentlyContinue
                ok "Orphaned spool drain files removed"; $fixed++
            } else {
                dot "Spool directory clean — skipping"
                $skipped++
            }
        }

        # ── 6. Registry keys ───────────────────────────────────────────────────
        $regBase = "HKLM:\SOFTWARE\AttackLens\Agent"
        if (-not (Test-Path $regBase)) {
            fix "Registry key missing — recreating install info"
            New-Item -Path "HKLM:\SOFTWARE\AttackLens\Agent" -Force | Out-Null
            Set-ItemProperty -Path $regBase -Name "InstallDir" -Value $InstallDir
            Set-ItemProperty -Path $regBase -Name "DataDir"    -Value $DataDir
            Set-ItemProperty -Path $regBase -Name "BinDir"     -Value $BinDir
            Set-ItemProperty -Path $regBase -Name "ScriptsDir" -Value $ScriptsDir
            ok "Registry keys recreated"; $fixed++
        } else {
            dot "Registry keys present — skipping"
            $skipped++
        }

        # ── 7. MACINTEL_CONFIG registry value for service.py ──────────────────
        $svcParamsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$AGENT_SVC\Parameters"
        $cfgRegVal    = (Get-ItemProperty -Path $svcParamsKey -Name "MACINTEL_CONFIG" -ErrorAction SilentlyContinue).MACINTEL_CONFIG
        if (-not $cfgRegVal -or $cfgRegVal -ne $ConfigPath) {
            if (Get-Service -Name $AGENT_SVC -ErrorAction SilentlyContinue) {
                fix "MACINTEL_CONFIG registry value missing or wrong — setting to $ConfigPath"
                if (-not (Test-Path $svcParamsKey)) {
                    New-Item -Path $svcParamsKey -Force | Out-Null
                }
                Set-ItemProperty -Path $svcParamsKey -Name "MACINTEL_CONFIG" -Value $ConfigPath
                ok "MACINTEL_CONFIG set"; $fixed++
            } else {
                dot "Service not installed — skipping MACINTEL_CONFIG"; $skipped++
            }
        } else {
            dot "MACINTEL_CONFIG correct — skipping"
            $skipped++
        }

        # ── 8. Services installed and running ──────────────────────────────────
        foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
            $st = Get-SvcStatus $svc
            if ($st -eq "NotInstalled") {
                err "Service $svc not installed — reinstall required"
                $failed++
                continue
            }
            if ($st -ne "Running") {
                fix "Service $svc is $st — starting"
                Start-Service -Name $svc -ErrorAction SilentlyContinue
                if (Wait-Svc $svc "Running" 20) {
                    ok "Service $svc started"; $fixed++
                } else {
                    $lastLog = if (Test-Path $LogFile) {
                        (Get-Content $LogFile -Tail 3 -ErrorAction SilentlyContinue) -join " | "
                    } else { "(no log)" }
                    err "Service $svc failed to start. Last log: $lastLog"
                    $failed++
                }
            } else {
                dot "Service $svc already running — skipping"
                $skipped++
            }
        }

        # ── 9. Verify enrollment ───────────────────────────────────────────────
        $ck = Join-Path $SecurityDir "client.key"
        if (-not (Test-Path $ck)) {
            $agentRunning = (Get-SvcStatus $AGENT_SVC) -eq "Running"
            if ($agentRunning) {
                fix "client.key absent — agent is running, waiting up to 30s for enrollment"
                $enrolled = $false
                for ($i = 0; $i -lt 6; $i++) {
                    Start-Sleep -Seconds 5
                    if (Test-Path $ck) { $enrolled = $true; break }
                }
                if ($enrolled) { ok "Enrollment completed — client.key present"; $fixed++ }
                else {
                    warn "client.key still absent after 30s"
                    Write-Host "  Check manager connectivity: attacklens-service diagnose" -ForegroundColor DarkGray
                    $skipped++
                }
            } else {
                warn "client.key absent and service is not running — start services first"
                $skipped++
            }
        } else {
            dot "client.key present — skipping"
            $skipped++
        }

        # ── Summary ────────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host ("  Fixed: {0,-4} Skipped: {1,-4} Failed: {2}" -f $fixed, $skipped, $failed)
        if ($failed -eq 0) {
            Write-Host "  Repair complete." -ForegroundColor Green
        } else {
            Write-Host "  $failed item(s) could not be repaired automatically." -ForegroundColor Yellow
            Write-Host "  For persistent issues: see TROUBLESHOOTING.md" -ForegroundColor DarkGray
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
            Write-Host "    attacklens-service set-manager 34.224.174.38:8443"
            Write-Host "    attacklens-service set-manager https://manager.corp.example:443"
            exit 1
        }
        if (-not (Test-Path $ConfigPath)) {
            err "agent.toml not found: $ConfigPath"
            exit 1
        }

        # Normalise to full HTTPS URL
        $NewUrl = $Arg
        if ($NewUrl -notmatch "^https?://") {
            # bare IP or IP:port — default to https:// and port 8443 if no port given
            if ($NewUrl -match "^[^:]+:\d+$") {
                $NewUrl = "https://$NewUrl"
            } else {
                $NewUrl = "https://$NewUrl`:8443"
            }
        }
        $tlsVal = if ($NewUrl.StartsWith("https://")) { "false" } else { "false" }

        hdr "Updating manager URL -> $NewUrl"

        # In-place update preserving all other config values
        $cfg = Get-Content $ConfigPath -Raw -ErrorAction Stop
        $cfg = [regex]::Replace($cfg, '(?m)^url\s*=\s*"[^"]*"',   "url        = `"$NewUrl`"")
        $cfg = [regex]::Replace($cfg, '(?m)^tls_verify\s*=\s*\S+', "tls_verify = $tlsVal")
        Set-Content -Path $ConfigPath -Value $cfg -Encoding UTF8 -NoNewline
        ok "agent.toml updated"

        # Remove stored keys so agent re-enrolls with the new manager
        $ck = Join-Path $SecurityDir "client.key"
        if (Test-Path $ck) { Remove-Item $ck -Force; ok "client.key removed (will re-enroll)" }

        Get-ChildItem $SecurityDir -Filter "*.dpapi" -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item $_.FullName -Force; ok "Removed DPAPI key: $($_.Name)" }

        & $MyInvocation.MyCommand.Path restart
    }

    # ── enroll ─────────────────────────────────────────────────────────────────
    "enroll" {
        Require-Admin
        hdr "Force re-enrollment"
        Write-Host "  Stops agent, clears stored API key and DPAPI keys, restarts agent."

        & $MyInvocation.MyCommand.Path stop
        Start-Sleep -Seconds 2

        $ck = Join-Path $SecurityDir "client.key"
        if (Test-Path $ck) { Remove-Item $ck -Force; ok "client.key deleted" }
        else { warn "client.key not found (not yet enrolled)" }

        Get-ChildItem $SecurityDir -Filter "*.dpapi" -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-Item $_.FullName -Force; ok "Removed DPAPI key: $($_.Name)" }

        & cmdkey /delete:"com.attacklens.agent" 2>&1 | Out-Null
        ok "Credential Manager entry removed (if present)"

        & $MyInvocation.MyCommand.Path start
        Write-Host ""
        ok "Agent restarted — will auto-enroll on next start."
        Write-Host ""
    }

    # ── update-config ──────────────────────────────────────────────────────────
    "update-config" {
        Require-Admin
        hdr "Regenerating agent.toml"
        $genScript = Join-Path $ScriptsDir "generate_config.ps1"
        if (-not (Test-Path $genScript)) {
            # Fall back to pkg\ location if scripts\ not populated yet
            $genScript = Join-Path $InstallDir "..\agent\os\windows\pkg\gen_config.ps1"
        }
        if (-not (Test-Path $genScript)) {
            err "generate_config.ps1 not found: $genScript"
            exit 1
        }

        # Preserve existing manager URL
        $existingUrl = "https://YOUR_MANAGER_IP:8443"
        if (Test-Path $ConfigPath) {
            $m = Select-String -Path $ConfigPath -Pattern '^\s*url\s*=\s*"([^"]+)"' | Select-Object -First 1
            if ($m) { $existingUrl = $m.Matches[0].Groups[1].Value }
        }

        & powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass `
            -File $genScript `
            -InstallDir $InstallDir `
            -DataDir    $DataDir `
            -ManagerUrl $existingUrl
        if ($LASTEXITCODE -eq 0) {
            ok "agent.toml regenerated"
            Write-Host "  Run: attacklens-service restart  to apply changes." -ForegroundColor DarkGray
        } else {
            err "generate_config.ps1 failed (exit $LASTEXITCODE)"
        }
        Write-Host ""
    }

    # ── help ───────────────────────────────────────────────────────────────────
    { $_ -in "help", "--help", "-h", "-?" } {
        Show-Logo "Management CLI"
        Get-Help $MyInvocation.MyCommand.Path -Full
    }

    default {
        err "Unknown command: $Command"
        Write-Host "  Available commands: status start stop restart logs config version diagnose repair set-manager enroll update-config help" -ForegroundColor Yellow
        Write-Host "  Run: attacklens-service help" -ForegroundColor Yellow
        exit 1
    }
}
