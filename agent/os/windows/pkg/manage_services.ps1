<#
.SYNOPSIS
    AttackLens Agent service management CLI.

.DESCRIPTION
    Operator tool for managing the AttackLensAgent and AttackLensWatchdog Windows Services
    installed by the MSI.

    Commands
    ────────
      status    - Show service status, config, and last 20 log lines
      start     - Start both services (Watchdog first)
      stop      - Stop both services (Agent first, then Watchdog)
      restart   - Stop then start both services
      logs      - Tail the agent log (default: last 50 lines)
      enroll    - Delete stored API key and restart agent (triggers re-enrollment)
      reenroll  - Alias for enroll
      config    - Open agent.toml in the default editor
      harden    - Move services from LocalSystem to NetworkService + Event Log Readers
      version   - Show installed version from registry

    Must be run as Administrator.

.PARAMETER Command
    One of: status, start, stop, restart, logs, enroll, reenroll, config, harden, version

.PARAMETER LogLines
    Number of log lines to show with the 'logs' command. Default: 50

.PARAMETER Force
    Skip confirmation prompts (useful for automation).

.EXAMPLE
    # Check health
    .\manage_services.ps1 status

.EXAMPLE
    # Restart after changing agent.toml
    .\manage_services.ps1 restart

.EXAMPLE
    # Watch logs live (Ctrl+C to stop)
    .\manage_services.ps1 logs -LogLines 100

.EXAMPLE
    # Re-enroll with a new token (after key rotation on manager)
    .\manage_services.ps1 reenroll

.EXAMPLE
    # Harden service account (NetworkService instead of LocalSystem)
    .\manage_services.ps1 harden
#>

param(
    [Parameter(Position=0)]
    [ValidateSet("status","start","stop","restart","logs","enroll","reenroll","config","harden","version","help")]
    [string] $Command = "status",

    [int]    $LogLines = 50,
    [switch] $Force    = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ──────────────────────────────────────────────────────────────────
$AGENT_SVC    = "AttackLensAgent"
$WATCHDOG_SVC = "AttackLensWatchdog"
$REG_KEY      = "HKLM:\SOFTWARE\AttackLens\Agent"

# ── Privilege check ────────────────────────────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "manage_services.ps1 must be run as Administrator.`n  Right-click PowerShell and choose 'Run as Administrator'."
}

# ── Registry helpers ───────────────────────────────────────────────────────────
function Get-AttackLensRegValue([string]$Name) {
    try { return (Get-ItemProperty -Path $REG_KEY -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

$InstallDir  = Get-AttackLensRegValue "InstallDir"
$DataDir     = Get-AttackLensRegValue "DataDir"
$ConfigFile  = Get-AttackLensRegValue "ConfigFile"
$BinDir      = Get-AttackLensRegValue "BinDir"

# Fallback to environment defaults if registry keys are absent
if (-not $DataDir)    { $DataDir   = Join-Path $env:PROGRAMDATA "AttackLens" }
if (-not $ConfigFile) { $ConfigFile= Join-Path $DataDir "config\agent.toml" }
if (-not $BinDir)     { $BinDir    = Join-Path $env:ProgramFiles "AttackLens\bin" }

$LogFile     = Join-Path $DataDir "logs\agent.log"
$SecurityDir = Join-Path $DataDir "security"

# ── Colour helpers ─────────────────────────────────────────────────────────────
function ok  ([string]$msg) { Write-Host "  [OK]  $msg" -ForegroundColor Green  }
function warn([string]$msg) { Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function err ([string]$msg) { Write-Host "  [ERR] $msg" -ForegroundColor Red    }
function hdr ([string]$msg) { Write-Host "`n  $msg" -ForegroundColor Cyan       }

function Get-SvcStatus([string]$name) {
    try {
        $s = Get-Service -Name $name -ErrorAction Stop
        return $s.Status
    } catch {
        return "NotInstalled"
    }
}

function Wait-SvcState([string]$name, [string]$target, [int]$timeoutSec=30) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        if ((Get-SvcStatus $name) -eq $target) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# ══════════════════════════════════════════════════════════════════════════════
#  COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

switch ($Command) {

    # ── status ────────────────────────────────────────────────────────────────
    "status" {
        hdr "AttackLens Agent - Service Status"

        foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
            $st = Get-SvcStatus $svc
            $colour = switch ($st) {
                "Running"      { "Green"  }
                "Stopped"      { "Red"    }
                "NotInstalled" { "Yellow" }
                default        { "Gray"   }
            }
            Write-Host ("  {0,-22} {1}" -f "$svc`:", $st) -ForegroundColor $colour
        }

        hdr "Configuration"
        Write-Host "  Config file  : $ConfigFile"
        Write-Host "  Data dir     : $DataDir"
        Write-Host "  Log file     : $LogFile"
        Write-Host "  Security dir : $SecurityDir"
        Write-Host "  Version      : $(Get-AttackLensRegValue 'Version')"

        if (Test-Path $ConfigFile) {
            hdr "Manager URL (from config)"
            $url = Select-String -Path $ConfigFile -Pattern '^\s*url\s*=' | Select-Object -First 1
            if ($url) { Write-Host "  $($url.Line.Trim())" }
        } else {
            warn "agent.toml not found: $ConfigFile"
        }

        hdr "Agent Identity (client.key)"
        $clientKeyPath = Join-Path $SecurityDir "client.key"
        if (Test-Path $clientKeyPath) {
            $ckLines = Get-Content $clientKeyPath | Where-Object { $_ -match '^\s*(agent_name|agent_number|issued_at|token)\s*=' }
            foreach ($line in $ckLines) {
                $trimmed = $line.Trim()
                # Mask token to first 12 chars for security
                if ($trimmed -match '^token\s*=') {
                    $tok = ($trimmed -replace '.*=\s*"?([^"]+)"?.*','$1')
                    Write-Host ("  token        : " + $tok.Substring(0, [Math]::Min(12, $tok.Length)) + "...") -ForegroundColor DarkGray
                } else {
                    Write-Host "  $trimmed"
                }
            }
        } else {
            warn "client.key not found - agent has not enrolled yet (will auto-enroll on start)"
        }

        hdr "Recent log (last 10 lines)"
        if (Test-Path $LogFile) {
            Get-Content $LogFile -Tail 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
        } else {
            warn "Log file not found: $LogFile"
        }
        Write-Host ""
    }

    # ── start ─────────────────────────────────────────────────────────────────
    "start" {
        hdr "Starting AttackLens services"

        # Start Watchdog first so it's ready to monitor Agent from boot
        $wdSt = Get-SvcStatus $WATCHDOG_SVC
        if ($wdSt -eq "Running") {
            ok "$WATCHDOG_SVC already running"
        } elseif ($wdSt -eq "NotInstalled") {
            warn "$WATCHDOG_SVC not installed"
        } else {
            Write-Host "  Starting $WATCHDOG_SVC..." -NoNewline
            Start-Service -Name $WATCHDOG_SVC
            if (Wait-SvcState $WATCHDOG_SVC "Running") { ok "started" }
            else { err "timed out waiting for $WATCHDOG_SVC"; exit 1 }
        }

        $agSt = Get-SvcStatus $AGENT_SVC
        if ($agSt -eq "Running") {
            ok "$AGENT_SVC already running"
        } elseif ($agSt -eq "NotInstalled") {
            warn "$AGENT_SVC not installed - is the MSI installed?"
        } else {
            Write-Host "  Starting $AGENT_SVC..." -NoNewline
            Start-Service -Name $AGENT_SVC
            if (Wait-SvcState $AGENT_SVC "Running") { ok "started" }
            else { err "timed out waiting for $AGENT_SVC"; exit 1 }
        }
        Write-Host ""
    }

    # ── stop ──────────────────────────────────────────────────────────────────
    "stop" {
        hdr "Stopping AttackLens services"

        # Stop Agent first, then Watchdog (so Watchdog doesn't try to restart Agent)
        foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
            $st = Get-SvcStatus $svc
            if ($st -eq "Stopped") {
                ok "$svc already stopped"
            } elseif ($st -eq "NotInstalled") {
                warn "$svc not installed"
            } else {
                Write-Host "  Stopping $svc..." -NoNewline
                Stop-Service -Name $svc -Force
                if (Wait-SvcState $svc "Stopped") { ok "stopped" }
                else { err "timed out waiting for $svc to stop" }
            }
        }
        Write-Host ""
    }

    # ── restart ───────────────────────────────────────────────────────────────
    "restart" {
        hdr "Restarting AttackLens services"
        & $MyInvocation.MyCommand.Path stop  -Force:$Force
        Start-Sleep -Seconds 2
        & $MyInvocation.MyCommand.Path start -Force:$Force
    }

    # ── logs ──────────────────────────────────────────────────────────────────
    "logs" {
        if (-not (Test-Path $LogFile)) {
            warn "Log file not found: $LogFile"
            exit 0
        }
        hdr "Agent log - last $LogLines lines  ($LogFile)"
        Write-Host ""
        Get-Content $LogFile -Tail $LogLines | ForEach-Object { Write-Host $_ }
        Write-Host ""
        Write-Host "  Tip: run 'Get-Content ""$LogFile"" -Wait' to follow in real time" -ForegroundColor DarkGray
        Write-Host ""
    }

    # ── reenroll ──────────────────────────────────────────────────────────────
    { $_ -in @("enroll", "reenroll") } {
        hdr "Re-enrollment - deletes client.key so agent auto-re-enrolls on next start"
        if (-not $Force) {
            $confirm = Read-Host "  This deletes security\client.key and triggers automatic re-enrollment. Continue? [y/N]"
            if ($confirm -notmatch '^[yY]') { Write-Host "  Cancelled."; exit 0 }
        }

        # Stop agent so it isn't reading client.key while we delete it
        Write-Host "  Stopping $AGENT_SVC..." -NoNewline
        try { Stop-Service $AGENT_SVC -Force -ErrorAction SilentlyContinue } catch {}
        Wait-SvcState $AGENT_SVC "Stopped" | Out-Null
        ok "stopped"

        # Delete client.key - agent will auto-enroll and regenerate it on start
        $ClientKeyPath = Join-Path $SecurityDir "client.key"
        if (Test-Path $ClientKeyPath) {
            try {
                Remove-Item $ClientKeyPath -Force
                ok "deleted client.key"
            } catch {
                err "Could not delete client.key: $_"
                exit 1
            }
        } else {
            warn "client.key not found at $ClientKeyPath (may not have enrolled yet)"
        }

        # Also clear legacy DPAPI key files if present
        if (Test-Path $SecurityDir) {
            Get-ChildItem $SecurityDir -Filter "*.dpapi" | ForEach-Object {
                try { Remove-Item $_.FullName -Force; ok "deleted legacy key: $($_.Name)" }
                catch {}
            }
        }

        Write-Host ""
        ok "client.key removed - agent will auto-enroll on next start"
        Write-Host "  Starting $AGENT_SVC..." -NoNewline
        Start-Service $AGENT_SVC
        if (Wait-SvcState $AGENT_SVC "Running") {
            ok "started - auto-enrollment in progress"
            Write-Host ""
            Write-Host "  New client.key will appear at: $ClientKeyPath" -ForegroundColor DarkGray
            Write-Host "  View it with: Get-Content `"$ClientKeyPath`"" -ForegroundColor DarkGray
        } else {
            err "service failed to start - check $LogFile"
        }
        Write-Host ""
    }

    # ── config ────────────────────────────────────────────────────────────────
    "config" {
        if (-not (Test-Path $ConfigFile)) {
            warn "Config file not found: $ConfigFile"
            warn "Run: .\generate_config.ps1 -ManagerUrl <URL> -EnrollToken <TOKEN>"
            exit 1
        }
        Write-Host "  Opening: $ConfigFile"
        Start-Process notepad.exe -ArgumentList $ConfigFile
        Write-Host "  After editing, run: .\manage_services.ps1 restart"
        Write-Host ""
    }

    # ── harden ────────────────────────────────────────────────────────────────
    "harden" {
        hdr "Hardening: move agent from LocalSystem to NetworkService"
        Write-Host "  The watchdog remains LocalSystem so it can control the agent service."
        if (-not $Force) {
            $confirm = Read-Host "  Continue? [y/N]"
            if ($confirm -notmatch '^[yY]') { Write-Host "  Cancelled."; exit 0 }
        }

        # Add NetworkService to the built-in Event Log Readers group
        # This is required to read the Security channel without LocalSystem
        try {
            $group = [ADSI]"WinNT://./Event Log Readers,group"
            $members = @($group.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", "GetProperty", $null, $_, $null) }
            if ($members -notcontains "NETWORK SERVICE") {
                $group.Invoke("Add", ([ADSI]"WinNT://NT AUTHORITY/NETWORK SERVICE").Path)
                ok "Added NETWORK SERVICE to 'Event Log Readers' group"
            } else {
                ok "NETWORK SERVICE already in 'Event Log Readers' group"
            }
        } catch {
            err "Could not modify Event Log Readers group: $_"
            err "Services will remain as LocalSystem"
            exit 1
        }

        # Grant the new identity access before changing the account. Without
        # this ordering NetworkService cannot read agent.toml to repair ACLs.
        foreach ($dir in @(
            $DataDir,
            (Join-Path $DataDir "security"),
            (Join-Path $DataDir "spool"),
            (Join-Path $DataDir "data"),
            (Join-Path $DataDir "logs")
        )) {
            if (Test-Path -LiteralPath $dir) {
                & icacls.exe $dir /grant:r '*S-1-5-20:(OI)(CI)(M)' /T /C | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    err "Could not grant NetworkService access to $dir"
                    exit 1
                }
            }
        }
        if (Test-Path -LiteralPath $ConfigFile) {
            & icacls.exe $ConfigFile /grant:r '*S-1-5-20:(R)' /C | Out-Null
            if ($LASTEXITCODE -ne 0) {
                err "Could not grant NetworkService read access to agent.toml"
                exit 1
            }
        }

        if ((Get-SvcStatus $AGENT_SVC) -ne "NotInstalled") {
            Write-Host "  Configuring $AGENT_SVC as NetworkService..." -NoNewline
            & sc.exe config $AGENT_SVC obj= "NT AUTHORITY\NetworkService" password= "" | Out-Null
            if ($LASTEXITCODE -eq 0) { ok "done" }
            else { err "sc.exe failed for $AGENT_SVC (exit $LASTEXITCODE)"; exit 1 }
        }
        if ((Get-SvcStatus $WATCHDOG_SVC) -ne "NotInstalled") {
            Write-Host "  Keeping $WATCHDOG_SVC as LocalSystem..." -NoNewline
            & sc.exe config $WATCHDOG_SVC obj= "LocalSystem" password= "" | Out-Null
            if ($LASTEXITCODE -eq 0) { ok "done" }
            else { err "sc.exe failed for $WATCHDOG_SVC (exit $LASTEXITCODE)"; exit 1 }
        }

        Write-Host ""
        ok "Hardening complete. Restart services to apply:"
        Write-Host "    .\manage_services.ps1 restart"
        Write-Host ""
    }

    # ── version ───────────────────────────────────────────────────────────────
    "version" {
        $ver = Get-AttackLensRegValue "Version"
        if ($ver) {
            Write-Host ""
            Write-Host "  AttackLens Agent version: $ver" -ForegroundColor Cyan
            Write-Host "  Install dir:          $InstallDir"
            Write-Host "  Data dir:             $DataDir"
            Write-Host ""
        } else {
            warn "Version not found in registry - is AttackLens Agent installed?"
        }
    }

    # ── help ──────────────────────────────────────────────────────────────────
    "help" {
        Get-Help $MyInvocation.MyCommand.Path -Full
    }
}
