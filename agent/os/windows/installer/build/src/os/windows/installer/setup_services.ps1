<#
.SYNOPSIS
    Register or remove AttackLens Windows Services.

.DESCRIPTION
    Called automatically by MSI Custom Actions (CA_SetupServices_Deferred and
    CA_TeardownServices_Deferred). Can also be run manually to repair
    a broken install without running the full MSI.

    -Action Install:
      1. Finds python.exe (PATH → registry → common paths)
      2. Installs required Python packages via pip
      3. Registers AttackLensAgent + AttackLensWatchdog as Windows Services
      4. Configures service failure recovery actions
      5. Writes python.exe path to registry for CLI tools
      6. Adds outbound Windows Firewall rule for the agent

    -Action Uninstall:
      1. Stops both services
      2. Deletes both services via sc.exe
      3. Removes firewall rule

.PARAMETER Action
    "Install" or "Uninstall"

.PARAMETER InstallDir
    C:\Program Files\AttackLens\  (from MSI [INSTALLDIR])

.PARAMETER DataDir
    C:\ProgramData\AttackLens\  (from MSI [DATADIR])
#>

param(
    [ValidateSet("Install", "Uninstall")]
    [string] $Action     = "Install",
    [string] $InstallDir = "C:\Program Files\AttackLens",
    [string] $DataDir    = "C:\ProgramData\AttackLens"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AGENT_SVC    = "AttackLensAgent"
$WATCHDOG_SVC = "AttackLensWatchdog"
$REG_KEY      = "HKLM:\SOFTWARE\AttackLens\Agent"
$BinDir       = Join-Path $InstallDir "bin"

function ok  ([string]$m) { Write-Host "  [OK]  $m" -ForegroundColor Green  }
function warn([string]$m) { Write-Host "  [!!]  $m" -ForegroundColor Yellow }
function err ([string]$m) { Write-Host "  [ERR] $m" -ForegroundColor Red    }

# ══════════════════════════════════════════════════════════════════════════════
#  INSTALL
# ══════════════════════════════════════════════════════════════════════════════
if ($Action -eq "Install") {

    # ── Find Python ─────────────────────────────────────────────────────────
    $pythonExe = $null

    # Try PATH first
    $found = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($found) { $pythonExe = $found.Source }

    # Registry entries for CPython launcher
    if (-not $pythonExe) {
        $regPaths = @(
            "HKLM:\SOFTWARE\Python\PythonCore\3.13\InstallPath",
            "HKLM:\SOFTWARE\Python\PythonCore\3.12\InstallPath",
            "HKLM:\SOFTWARE\Python\PythonCore\3.11\InstallPath",
            "HKCU:\SOFTWARE\Python\PythonCore\3.13\InstallPath",
            "HKCU:\SOFTWARE\Python\PythonCore\3.12\InstallPath",
            "HKCU:\SOFTWARE\Python\PythonCore\3.11\InstallPath"
        )
        foreach ($rp in $regPaths) {
            try {
                $ep = (Get-ItemProperty $rp -Name "ExecutablePath" -ErrorAction Stop).ExecutablePath
                if ($ep -and (Test-Path $ep)) { $pythonExe = $ep; break }
            } catch {}
        }
    }

    # Common install locations fallback
    if (-not $pythonExe) {
        $candidates = @(
            "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
            "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
            "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
            "C:\Python313\python.exe",
            "C:\Python312\python.exe",
            "C:\Python311\python.exe",
            "C:\Program Files\Python313\python.exe",
            "C:\Program Files\Python312\python.exe",
            "C:\Program Files\Python311\python.exe"
        )
        foreach ($c in $candidates) {
            if (Test-Path $c) { $pythonExe = $c; break }
        }
    }

    if (-not $pythonExe) {
        err "Python 3.11+ not found. Install Python and retry."
        err "Download: https://www.python.org/downloads/"
        throw "Python not found"
    }

    $pyVer = & $pythonExe --version 2>&1
    ok "Python: $pyVer  ($pythonExe)"

    # ── Install Python dependencies ─────────────────────────────────────────
    Write-Host "  Installing Python packages..." -ForegroundColor Cyan
    $packages = "psutil", "cryptography", "requests", "keyring", "pywin32", "wmi", "tomli"
    & $pythonExe -m pip install --quiet --upgrade @packages 2>&1 | ForEach-Object {
        if ($_ -match "Successfully installed|already satisfied") {
            Write-Host "    $_" -ForegroundColor DarkGreen
        }
    }

    # pywin32 post-install (registers COM objects and fixes DLL paths)
    $pyScripts = Split-Path $pythonExe
    $postInstall = Join-Path $pyScripts "Scripts\pywin32_postinstall.py"
    if (Test-Path $postInstall) {
        & $pythonExe $postInstall -install 2>&1 | Out-Null
    }
    ok "Python packages installed"

    # ── Write python.exe path to registry ──────────────────────────────────
    try {
        if (-not (Test-Path $REG_KEY)) {
            New-Item -Path $REG_KEY -Force | Out-Null
        }
        Set-ItemProperty -Path $REG_KEY -Name "PythonExe" -Value $pythonExe
        ok "PythonExe written to registry"
    } catch {
        warn "Could not write PythonExe to registry: $_"
    }

    # ── Escape paths for sc.exe binpath ────────────────────────────────────
    # Service binary path format: "C:\Python\python.exe" "C:\Program Files\AttackLens\bin\run_agent.py"
    $agentScript    = Join-Path $BinDir "run_agent.py"
    $watchdogScript = Join-Path $BinDir "run_watchdog.py"

    $agentBinPath    = "`"$pythonExe`" `"$agentScript`""
    $watchdogBinPath = "`"$pythonExe`" `"$watchdogScript`""

    # ── Remove stale services if present ────────────────────────────────────
    foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
        $existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($existing) {
            if ($existing.Status -eq "Running") {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            & sc.exe delete $svc | Out-Null
            Start-Sleep -Milliseconds 500
            ok "Removed stale service: $svc"
        }
    }

    # ── Create AttackLensAgent service ─────────────────────────────────────
    & sc.exe create $AGENT_SVC `
        binpath= $agentBinPath `
        DisplayName= "AttackLens Agent" `
        start= delayed-auto `
        obj= "LocalSystem" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create $AGENT_SVC failed (exit $LASTEXITCODE)" }

    & sc.exe description $AGENT_SVC `
        "AttackLens endpoint telemetry agent — collects system metrics, security posture, and software inventory." | Out-Null

    # Recovery: restart after 10s (first two failures), then 60s
    & sc.exe failure $AGENT_SVC reset= 86400 actions= restart/10000/restart/10000/restart/60000 | Out-Null

    # Delayed-auto-start requires explicit flag
    & sc.exe config $AGENT_SVC start= delayed-auto | Out-Null

    # Set config path in service environment
    $configPath = Join-Path $DataDir "agent.toml"
    & sc.exe config $AGENT_SVC depend= "Tcpip/Dnscache" | Out-Null
    & reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$AGENT_SVC\Parameters" `
        /v "MACINTEL_CONFIG" /t REG_SZ /d $configPath /f | Out-Null

    ok "Service created: $AGENT_SVC"

    # ── Create AttackLensWatchdog service ───────────────────────────────────
    & sc.exe create $WATCHDOG_SVC `
        binpath= $watchdogBinPath `
        DisplayName= "AttackLens Watchdog" `
        start= delayed-auto `
        obj= "LocalSystem" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create $WATCHDOG_SVC failed (exit $LASTEXITCODE)" }

    & sc.exe description $WATCHDOG_SVC `
        "Monitors and restarts the AttackLens Agent service. Rate-limited to prevent restart storms." | Out-Null

    & sc.exe failure $WATCHDOG_SVC reset= 86400 actions= restart/30000/restart/30000/restart/60000 | Out-Null
    & sc.exe config  $WATCHDOG_SVC start= delayed-auto | Out-Null
    & sc.exe config  $WATCHDOG_SVC depend= Tcpip | Out-Null

    ok "Service created: $WATCHDOG_SVC"

    # ── Add Windows Firewall outbound allow rule ────────────────────────────
    try {
        Remove-NetFirewallRule -DisplayName "AttackLens Agent Outbound" -ErrorAction SilentlyContinue
        New-NetFirewallRule `
            -DisplayName "AttackLens Agent Outbound" `
            -Direction Outbound `
            -Action Allow `
            -Protocol TCP `
            -Program $pythonExe `
            -Profile Any `
            -Description "Allow AttackLens Agent to reach the manager." | Out-Null
        ok "Firewall outbound rule added"
    } catch {
        warn "Firewall rule not added (may need to be added manually): $_"
    }

    # ── Apply ACLs to security directory ───────────────────────────────────
    $secDir = Join-Path $DataDir "security"
    if (Test-Path $secDir) {
        & icacls $secDir /inheritance:r `
            /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
            /grant:r "BUILTIN\Administrators:(OI)(CI)F" | Out-Null
        ok "ACL applied: $secDir"
    }

    # ── Start services ──────────────────────────────────────────────────────
    Write-Host "  Starting services..." -ForegroundColor Cyan
    try {
        Start-Service -Name $WATCHDOG_SVC
        ok "$WATCHDOG_SVC started"
    } catch {
        warn "$WATCHDOG_SVC start failed (will auto-start on reboot): $_"
    }
    try {
        Start-Service -Name $AGENT_SVC
        ok "$AGENT_SVC started"
    } catch {
        warn "$AGENT_SVC start failed (will auto-start on reboot): $_"
    }

    Write-Host ""
    ok "AttackLens Agent services installed successfully."
}

# ══════════════════════════════════════════════════════════════════════════════
#  UNINSTALL
# ══════════════════════════════════════════════════════════════════════════════
if ($Action -eq "Uninstall") {

    # Stop and remove both services
    foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
        $existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $existing) { continue }

        try {
            if ($existing.Status -eq "Running") {
                Stop-Service -Name $svc -Force
                Start-Sleep -Seconds 3
            }
            & sc.exe delete $svc | Out-Null
            ok "Removed service: $svc"
        } catch {
            warn "Could not remove $svc`: $_"
        }
    }

    # Remove firewall rule
    try {
        Remove-NetFirewallRule -DisplayName "AttackLens Agent Outbound" -ErrorAction SilentlyContinue
        ok "Firewall rule removed"
    } catch {}

    ok "AttackLens services removed."
}
