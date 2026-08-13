#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AttackLens Windows Agent — installer (no MSI required).

.DESCRIPTION
    Fully validated install: pre-flight checks → copy binaries → write config →
    register services → add management CLI to PATH → verify enrollment.

    Pre-flight checks performed before touching the disk
    ────────────────────────────────────────────────────
    • PowerShell 5.1+
    • Windows 10 / Server 2016+ (build 10240+)
    • Free disk space (500 MB on InstallDir drive, 200 MB on DataDir drive)
    • Binary bundles present and non-empty (_internal\ directory exists)
    • TCP connectivity to ManagerIP:ManagerPort
    • HTTPS /health response from manager

    Rollback on any failure
    ───────────────────────
    If any step fails after files have been copied, the installer removes
    everything it wrote so the machine is left in a clean state.

.PARAMETER ManagerIP
    Manager hostname or IP (no scheme, no port).  Required.

.PARAMETER ManagerPort
    Manager port. Default: 8443

.PARAMETER TlsVerify
    $false = accept self-signed cert (dev).  $true = require CA cert (prod).
    Default: $false

.PARAMETER EnrollToken
    Enrollment token from the manager. Leave empty for open enrollment.

.PARAMETER AgentName
    Display name in the dashboard. Default: %COMPUTERNAME%

.PARAMETER BinSourceDir
    Folder containing attacklens-agent\ and attacklens-watchdog\ bundles.
    Auto-detected from pkg\dist\ relative to this script if omitted.

.PARAMETER InstallDir
    Root installation directory. Default: C:\Program Files\AttackLens

.PARAMETER DataDir
    Root data directory. Default: C:\ProgramData\AttackLens

.PARAMETER SkipNetworkCheck
    Skip TCP/HTTPS pre-flight check (useful when manager is not yet running).

.EXAMPLE
    .\install.ps1 -ManagerIP "34.224.174.38"

.EXAMPLE
    .\install.ps1 -ManagerIP "34.224.174.38" -ManagerPort 8443 `
                  -TlsVerify $false -EnrollToken "sk-enroll-abc123" `
                  -AgentName "DEV-WIN-01"
#>
param(
    [Parameter(Mandatory=$true)]
    [string] $ManagerIP,

    [int]    $ManagerPort        = 8443,
    [bool]   $TlsVerify          = $false,
    [string] $EnrollToken        = "",
    [string] $AgentName          = $env:COMPUTERNAME,
    [string] $BinSourceDir       = "",
    [string] $InstallDir         = "C:\Program Files\AttackLens",
    [string] $DataDir            = "C:\ProgramData\AttackLens",
    [switch] $SkipNetworkCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────
$AGENT_SVC        = "AttackLensAgent"
$WATCHDOG_SVC     = "AttackLensWatchdog"
$AGENT_DIR        = "attacklens-agent"
$WATCHDOG_DIR     = "attacklens-watchdog"
$AGENT_EXE        = "attacklens-agent.exe"
$WATCHDOG_EXE     = "attacklens-watchdog.exe"
$REG_SVC_PARAMS   = "HKLM:\SYSTEM\CurrentControlSet\Services\$AGENT_SVC\Parameters"
$REG_INSTALL      = "HKLM:\SOFTWARE\AttackLens\Agent"
$FW_RULE_NAME     = "AttackLens Agent Outbound"

# Derived paths
$BinDir      = Join-Path $InstallDir "bin"
$ScriptsDir  = Join-Path $InstallDir "scripts"
$ConfigDir   = Join-Path $DataDir    "config"
$LogDir      = Join-Path $DataDir    "logs"
$SecurityDir = Join-Path $DataDir    "security"
$SpoolDir    = Join-Path $DataDir    "spool"
$DataSubDir  = Join-Path $DataDir    "data"
$ConfigFile  = Join-Path $ConfigDir  "agent.toml"
$LogFile     = Join-Path $LogDir     "agent.log"

# Track what we've installed (for rollback)
$script:installed = [System.Collections.Generic.List[string]]::new()

# ── Output helpers ─────────────────────────────────────────────────────────────
function Write-Ok    ([string]$m) { Write-Host "  [OK]  $m" -ForegroundColor Green  }
function Write-Warn  ([string]$m) { Write-Host "  [!!]  $m" -ForegroundColor Yellow }
function Write-Fail  ([string]$m) { Write-Host "  [ERR] $m" -ForegroundColor Red    }
function Write-Step  ([string]$m) { Write-Host "`n  ── $m" -ForegroundColor Cyan    }
function Write-Dot   ([string]$m) { Write-Host "        $m" -ForegroundColor DarkGray }
function Write-Check ([string]$m) { Write-Host "  [ ]  $m" -NoNewline               }
function Write-Pass  ()           { Write-Host " PASS"  -ForegroundColor Green       }
function Write-Skip2 ([string]$m) { Write-Host "  [--]  $m" -ForegroundColor DarkGray }

# ── Shield logo ───────────────────────────────────────────────────────────────
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
    if ($Subtitle) {
        Write-Host ""
        Write-Host "        $Subtitle" -ForegroundColor White
    }
    Write-Host ""
}

Show-Logo -Subtitle "Installer  ·  v2.0"

Write-Host "  Manager  : https://${ManagerIP}:${ManagerPort}"
Write-Host "  TLS      : $(if ($TlsVerify) {'verify CA certificate'} else {'accept self-signed cert'})"
Write-Host "  Name     : $AgentName"
Write-Host "  Token    : $(if ($EnrollToken) { $EnrollToken.Substring(0,[Math]::Min(14,$EnrollToken.Length))+'...' } else { '(open enrollment)' })"
Write-Host "  Dirs     : $InstallDir  |  $DataDir"
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT CHECKS
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Pre-flight checks"

$preflightFailed = $false

# ── 1. PowerShell version ─────────────────────────────────────────────────────
Write-Check "PowerShell 5.1+"
$psVer = $PSVersionTable.PSVersion
if ($psVer.Major -lt 5 -or ($psVer.Major -eq 5 -and $psVer.Minor -lt 1)) {
    Write-Host " FAIL (found $psVer)" -ForegroundColor Red
    Write-Fail "PowerShell 5.1 or newer is required. Found: $psVer"
    Write-Fail "Update Windows Management Framework: https://aka.ms/wmf51"
    $preflightFailed = $true
} else {
    Write-Pass
    Write-Dot "Found: $psVer"
}

# ── 2. Windows version ────────────────────────────────────────────────────────
Write-Check "Windows 10 / Server 2016+"
$osVer = [System.Environment]::OSVersion.Version
$build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
          -ErrorAction SilentlyContinue).CurrentBuildNumber
if ($osVer.Major -lt 10) {
    Write-Host " FAIL" -ForegroundColor Red
    Write-Fail "Windows 10 (Build 10240) or newer required. Found: $($osVer.ToString())"
    $preflightFailed = $true
} else {
    Write-Pass
    Write-Dot "Build: $build  ($($osVer.ToString()))"
}

# ── 3. Disk space ─────────────────────────────────────────────────────────────
Write-Check "Disk space (500 MB on install drive, 200 MB on data drive)"
$installDrive = (Split-Path -Qualifier $InstallDir).TrimEnd(":")
$dataDrive    = (Split-Path -Qualifier $DataDir).TrimEnd(":")
$diskOk = $true
foreach ($pair in @(
    @{ drive=$installDrive; minMB=500 },
    @{ drive=$dataDrive;    minMB=200 }
)) {
    try {
        $di = Get-PSDrive -Name $pair.drive -ErrorAction Stop
        $freeMB = [math]::Round($di.Free / 1MB)
        if ($freeMB -lt $pair.minMB) {
            $diskOk = $false
            Write-Host " FAIL" -ForegroundColor Red
            Write-Fail "Drive $($pair.drive): only ${freeMB} MB free — need $($pair.minMB) MB"
            $preflightFailed = $true
            break
        }
    } catch { }
}
if ($diskOk) { Write-Pass }

# ── 4. Locate binaries ────────────────────────────────────────────────────────
Write-Check "Agent + Watchdog binaries"
if (-not $BinSourceDir) {
    $scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates  = @(
        [System.IO.Path]::GetFullPath((Join-Path $scriptDir "..\pkg\dist")),
        [System.IO.Path]::GetFullPath((Join-Path $scriptDir "pkg\dist")),
        [System.IO.Path]::GetFullPath((Join-Path (Get-Location) "pkg\dist")),
        $scriptDir
    )
    foreach ($c in $candidates) {
        if ((Test-Path (Join-Path $c "$AGENT_DIR\$AGENT_EXE")) -and
            (Test-Path (Join-Path $c "$WATCHDOG_DIR\$WATCHDOG_EXE"))) {
            $BinSourceDir = $c; break
        }
    }
}

$AgentSrcDir    = if ($BinSourceDir) { Join-Path $BinSourceDir $AGENT_DIR    } else { "" }
$WatchdogSrcDir = if ($BinSourceDir) { Join-Path $BinSourceDir $WATCHDOG_DIR } else { "" }

$binariesOk = $BinSourceDir -and
              (Test-Path (Join-Path $AgentSrcDir    $AGENT_EXE)) -and
              (Test-Path (Join-Path $WatchdogSrcDir $WATCHDOG_EXE)) -and
              (Test-Path (Join-Path $AgentSrcDir    "_internal")) -and
              (Test-Path (Join-Path $WatchdogSrcDir "_internal"))

if (-not $binariesOk) {
    Write-Host " FAIL" -ForegroundColor Red
    Write-Fail "Could not find both onedir bundles. Expected:"
    Write-Fail "  <dir>\attacklens-agent\attacklens-agent.exe + _internal\"
    Write-Fail "  <dir>\attacklens-watchdog\attacklens-watchdog.exe + _internal\"
    Write-Fail "Build them first:"
    Write-Fail "  cd agent\os\windows\pkg"
    Write-Fail "  pyinstaller attacklens-agent.spec"
    Write-Fail "  pyinstaller attacklens-watchdog.spec"
    $preflightFailed = $true
} else {
    # Verify exe file size is reasonable (> 100 KB)
    $agentSize = (Get-Item (Join-Path $AgentSrcDir $AGENT_EXE)).Length
    if ($agentSize -lt 100KB) {
        Write-Host " FAIL" -ForegroundColor Red
        Write-Fail "$AGENT_EXE is only $([math]::Round($agentSize/1KB)) KB — bundle may be corrupt"
        $preflightFailed = $true
    } else {
        Write-Pass
        Write-Dot "Agent:    $AgentSrcDir  ($([math]::Round($agentSize/1MB,1)) MB)"
        Write-Dot "Watchdog: $WatchdogSrcDir"
    }
}

# ── 5. Network: TCP connectivity ──────────────────────────────────────────────
if (-not $SkipNetworkCheck) {
    Write-Check "TCP connectivity → ${ManagerIP}:${ManagerPort}"
    try {
        $tcp = Test-NetConnection -ComputerName $ManagerIP -Port $ManagerPort `
               -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
        if ($tcp) {
            Write-Pass
        } else {
            Write-Host " FAIL" -ForegroundColor Red
            Write-Fail "Cannot reach ${ManagerIP}:${ManagerPort} over TCP."
            Write-Fail "Checks: manager running?  Firewall rule for port $ManagerPort?"
            Write-Fail "To skip: re-run with -SkipNetworkCheck"
            $preflightFailed = $true
        }
    } catch {
        Write-Host " FAIL" -ForegroundColor Red
        Write-Fail "TCP test failed: $_"
        Write-Fail "To skip: re-run with -SkipNetworkCheck"
        $preflightFailed = $true
    }

    # ── 6. HTTPS /health endpoint ─────────────────────────────────────────────
    if (-not $preflightFailed) {
        Write-Check "HTTPS /health endpoint"
        try {
            $resp = Invoke-WebRequest `
                -Uri "https://${ManagerIP}:${ManagerPort}/health" `
                -UseBasicParsing `
                -TimeoutSec 10 `
                -SkipCertificateCheck `
                -ErrorAction Stop
            if ($resp.StatusCode -lt 500) {
                Write-Pass
                Write-Dot "HTTP $($resp.StatusCode) — manager is up"
            } else {
                Write-Host " WARN ($($resp.StatusCode))" -ForegroundColor Yellow
                Write-Warn "Manager /health returned HTTP $($resp.StatusCode) — installation will continue"
            }
        } catch [System.Net.WebException] {
            $statusCode = [int]$_.Exception.Response.StatusCode
            if ($statusCode -gt 0 -and $statusCode -lt 500) {
                Write-Pass; Write-Dot "HTTP $statusCode (manager responded)"
            } else {
                Write-Host " WARN" -ForegroundColor Yellow
                Write-Warn "HTTPS check failed: $($_.Exception.Message)"
                Write-Warn "Installation will continue — verify manager is up after install."
            }
        } catch {
            Write-Host " WARN" -ForegroundColor Yellow
            Write-Warn "HTTPS check: $($_.Exception.Message)"
            Write-Warn "If using a self-signed cert this is expected — installation will continue."
        }
    }
} else {
    Write-Skip2 "Network checks skipped (-SkipNetworkCheck)"
}

# ── Abort if hard checks failed ───────────────────────────────────────────────
if ($preflightFailed) {
    Write-Host ""
    Write-Fail "Pre-flight checks FAILED. Fix the issues above and re-run."
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "  All pre-flight checks passed." -ForegroundColor Green

# ══════════════════════════════════════════════════════════════════════════════
#  ROLLBACK HELPER
# ══════════════════════════════════════════════════════════════════════════════
function Invoke-Rollback {
    param([string]$Reason)
    Write-Host ""
    Write-Fail "INSTALLATION FAILED: $Reason"
    Write-Host "  Rolling back..." -ForegroundColor Yellow

    # Stop + remove services
    foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            & sc.exe delete $svc 2>&1 | Out-Null
            Write-Warn "  Removed service: $svc"
        }
    }
    # Remove registry
    Remove-Item -Path $REG_SVC_PARAMS -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $REG_INSTALL    -Recurse -Force -ErrorAction SilentlyContinue
    # Remove install dir (binaries + scripts)
    if (Test-Path $InstallDir) {
        & icacls $InstallDir /reset /T /Q 2>&1 | Out-Null
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Warn "  Removed: $InstallDir"
    }
    # Remove config dir (but leave DataDir — may have had prior data)
    if (Test-Path $ConfigDir) {
        Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Warn "  Removed: $ConfigDir"
    }
    Write-Host ""
    Write-Fail "Rollback complete. Check the errors above and re-run install.ps1."
    Write-Host ""
    exit 1
}

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 1 — DIRECTORIES + ACLs
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 1/7  Creating directories and applying ACLs"

foreach ($dir in @($BinDir, $ScriptsDir, $ConfigDir, $LogDir,
                   $SecurityDir, $SpoolDir, $DataSubDir)) {
    try {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Dot "OK  $dir"
    } catch {
        Invoke-Rollback "Cannot create directory $dir : $_"
    }
}

# security\ — SYSTEM full control only
try {
    & icacls $SecurityDir /inheritance:r `
        /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" 2>&1 | Out-Null
} catch { Write-Warn "ACL on security\ failed (non-fatal): $_" }

# bin\ — SYSTEM + Admins full, Users read+execute
try {
    & icacls $BinDir /inheritance:r `
        /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" `
        /grant:r "BUILTIN\Administrators:(OI)(CI)(F)" `
        /grant:r "BUILTIN\Users:(OI)(CI)(RX)" 2>&1 | Out-Null
} catch { Write-Warn "ACL on bin\ failed (non-fatal): $_" }

Write-Ok "Directories created  ($InstallDir  |  $DataDir)"

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 2 — COPY BINARIES
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 2/7  Copying binaries"

$AgentDestDir    = Join-Path $BinDir $AGENT_DIR
$WatchdogDestDir = Join-Path $BinDir $WATCHDOG_DIR

foreach ($pair in @(
    @{ src=$AgentSrcDir;    dst=$AgentDestDir;    name="Agent"    },
    @{ src=$WatchdogSrcDir; dst=$WatchdogDestDir; name="Watchdog" }
)) {
    try {
        if (Test-Path $pair.dst) { Remove-Item $pair.dst -Recurse -Force }
        Copy-Item -Path $pair.src -Destination $pair.dst -Recurse -Force
        $exeSize = [math]::Round(
            (Get-Item (Join-Path $pair.dst (Split-Path $pair.src -Leaf) + ".exe") `
             -ErrorAction SilentlyContinue).Length / 1MB, 1)
        Write-Ok "$($pair.name): $($pair.dst)  (exe $exeSize MB)"
    } catch {
        Invoke-Rollback "Copy failed for $($pair.name): $_"
    }
}

$AgentExePath    = Join-Path $AgentDestDir    $AGENT_EXE
$WatchdogExePath = Join-Path $WatchdogDestDir $WATCHDOG_EXE

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 3 — COPY MANAGEMENT SCRIPTS
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 3/7  Installing management CLI"

$scriptSelf = Split-Path -Parent $MyInvocation.MyCommand.Path

foreach ($f in @("attacklens-service.ps1", "attacklens-service.cmd",
                 "uninstall.ps1", "generate_config.ps1")) {
    $src = Join-Path $scriptSelf $f
    if (Test-Path $src) {
        try {
            Copy-Item $src -Destination $ScriptsDir -Force
            Write-Dot "Copied: $f → $ScriptsDir"
        } catch {
            Write-Warn "Could not copy $f : $_ (non-fatal)"
        }
    }
}

# Add scripts\ to the system PATH if not already there
$sysPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($sysPath -notlike "*$ScriptsDir*") {
    try {
        [System.Environment]::SetEnvironmentVariable(
            "PATH", "$sysPath;$ScriptsDir", "Machine")
        Write-Ok "Added to system PATH: $ScriptsDir"
        Write-Dot "Open a new terminal to use:  attacklens-service status"
    } catch {
        Write-Warn "Could not update PATH: $_ — add $ScriptsDir manually"
    }
} else {
    Write-Ok "Already on PATH: $ScriptsDir"
}

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 4 — WRITE agent.toml
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 4/7  Writing agent.toml"

try {
    $MachineGuid    = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid
    $AgentId        = "win-$($MachineGuid.ToLower())"
} catch {
    $AgentId        = "win-$([System.Guid]::NewGuid().ToString().ToLower())"
    Write-Warn "Could not read MachineGuid — generated random ID: $AgentId"
}

$TlsStr      = if ($TlsVerify) { "true" } else { "false" }
$ManagerUrl  = "https://${ManagerIP}:${ManagerPort}"

function fwd([string]$p) { $p.Replace("\","/") }

$Toml = @"
# AttackLens Agent Configuration
# Generated: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')  by install.ps1
# Restart AttackLensAgent to apply changes.

[agent]
id   = "$AgentId"
name = "$AgentName"

[manager]
url         = "$ManagerUrl"
tls_verify  = $TlsStr
timeout_sec = 30
# spki_pin  = "sha256//base64=="   # uncomment to pin manager certificate

[enrollment]
token    = "$EnrollToken"
keystore = "dpapi"

[paths]
security_dir = "$(fwd $SecurityDir)"
log_dir      = "$(fwd $LogDir)"
spool_dir    = "$(fwd $SpoolDir)"

[logging]
level   = "INFO"
file    = "$(fwd $LogFile)"
max_mb  = 10
backups = 5

# ── Collection sections ────────────────────────────────────────────────────────
[collection.sections.metrics]
enabled = true; interval_sec = 10

[collection.sections.connections]
enabled = true; interval_sec = 10

[collection.sections.processes]
enabled = true; interval_sec = 10

[collection.sections.ports]
enabled = true; interval_sec = 30

[collection.sections.arp]
enabled = true; interval_sec = 60

[collection.sections.network]
enabled = true; interval_sec = 120

[collection.sections.mounts]
enabled = true; interval_sec = 120

[collection.sections.battery]
enabled = true; interval_sec = 120

[collection.sections.openfiles]
enabled = true; interval_sec = 120

[collection.sections.services]
enabled = true; interval_sec = 120

[collection.sections.users]
enabled = true; interval_sec = 120

[collection.sections.containers]
enabled = true; interval_sec = 120

[collection.sections.hardware]
enabled = true; interval_sec = 300

[collection.sections.eventlog]
enabled = true; interval_sec = 300

[collection.sections.developer_security]
enabled = true; interval_sec = 3600

[collection.sections.security_audit]
enabled = true; interval_sec = 21600

[collection.sections.storage]
enabled = true; interval_sec = 600

[collection.sections.tasks]
enabled = true; interval_sec = 600

[collection.sections.apps]
enabled = true; interval_sec = 900

[collection.sections.packages]
enabled = true; interval_sec = 900

[collection.sections.sbom]
enabled = true; interval_sec = 86400

[collection.sections.security]
enabled = true; interval_sec = 3600

[collection.sections.sysctl]
enabled = true; interval_sec = 3600

[collection.sections.configs]
enabled = true; interval_sec = 3600

[collection.sections.sca]
enabled = true; interval_sec = 3600

[collection.sections.binaries]
enabled = true; interval_sec = 86400
"@

try {
    [System.IO.File]::WriteAllText($ConfigFile, $Toml, [System.Text.Encoding]::UTF8)
    & icacls $ConfigFile /inheritance:r `
        /grant:r "NT AUTHORITY\SYSTEM:(R)" `
        /grant:r "BUILTIN\Administrators:(R)" 2>&1 | Out-Null
    Write-Ok "agent.toml written: $ConfigFile"
    Write-Dot "agent_id  = $AgentId"
    Write-Dot "manager   = $ManagerUrl  (tls_verify=$TlsStr)"
} catch {
    Invoke-Rollback "Failed to write agent.toml: $_"
}

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 5 — REGISTRY KEYS
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 5/7  Writing registry"

try {
    New-Item -Path $REG_INSTALL -Force | Out-Null
    Set-ItemProperty $REG_INSTALL -Name "InstallDir"  -Value $InstallDir
    Set-ItemProperty $REG_INSTALL -Name "DataDir"     -Value $DataDir
    Set-ItemProperty $REG_INSTALL -Name "BinDir"      -Value $BinDir
    Set-ItemProperty $REG_INSTALL -Name "ScriptsDir"  -Value $ScriptsDir
    Set-ItemProperty $REG_INSTALL -Name "ConfigPath"  -Value $ConfigFile
    Set-ItemProperty $REG_INSTALL -Name "Version"     -Value "2.0.0"
    Set-ItemProperty $REG_INSTALL -Name "ManagerUrl"  -Value $ManagerUrl
    Write-Ok "HKLM:\SOFTWARE\AttackLens\Agent"
} catch {
    Invoke-Rollback "Registry write failed (SOFTWARE key): $_"
}

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 6 — REGISTER SERVICES
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 6/7  Registering Windows Services"

# Remove stale services
foreach ($svc in @($AGENT_SVC, $WATCHDOG_SVC)) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        if ($s.Status -ne "Stopped") {
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddSeconds(10)
            while ((Get-Service $svc -EA SilentlyContinue).Status -ne "Stopped" -and
                   (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
        }
        & sc.exe delete $svc 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
        Write-Dot "Removed stale service: $svc"
    }
}

# Register AttackLensAgent
& sc.exe create $AGENT_SVC `
    binpath= "`"$AgentExePath`"" `
    DisplayName= "AttackLens Agent" `
    start= delayed-auto `
    obj= "LocalSystem" | Out-Null

if ($LASTEXITCODE -ne 0) { Invoke-Rollback "sc.exe create $AGENT_SVC failed (exit $LASTEXITCODE)" }

& sc.exe description $AGENT_SVC `
    "Endpoint telemetry agent. Collects system metrics, security posture, and software inventory and ships encrypted data to the AttackLens manager." | Out-Null

& sc.exe failure $AGENT_SVC `
    reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

# Write config path to service Parameters registry key
# service.py reads this at startup so it finds agent.toml without env vars
try {
    New-Item -Path $REG_SVC_PARAMS -Force | Out-Null
    Set-ItemProperty -Path $REG_SVC_PARAMS -Name "MACINTEL_CONFIG" -Value $ConfigFile
    Write-Ok "Service config path → registry"
} catch {
    Invoke-Rollback "Cannot write service Parameters registry key: $_"
}

Write-Ok "Registered: $AGENT_SVC"

# Register AttackLensWatchdog
& sc.exe create $WATCHDOG_SVC `
    binpath= "`"$WatchdogExePath`"" `
    DisplayName= "AttackLens Watchdog" `
    start= delayed-auto `
    obj= "LocalSystem" | Out-Null

if ($LASTEXITCODE -ne 0) { Invoke-Rollback "sc.exe create $WATCHDOG_SVC failed (exit $LASTEXITCODE)" }

& sc.exe description $WATCHDOG_SVC `
    "Monitors the AttackLens Agent service and restarts it on failure. Rate-limited to 5 restarts per 5-minute window." | Out-Null

& sc.exe failure $WATCHDOG_SVC `
    reset= 86400 actions= restart/30000/restart/60000/restart/120000 | Out-Null

Write-Ok "Registered: $WATCHDOG_SVC"

# Windows Firewall: allow agent outbound HTTPS
try {
    Remove-NetFirewallRule -DisplayName $FW_RULE_NAME -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName $FW_RULE_NAME `
        -Description "Allow AttackLens Agent to reach the manager for telemetry delivery." `
        -Direction Outbound -Action Allow -Protocol TCP `
        -RemoteAddress $ManagerIP -RemotePort $ManagerPort `
        -Program $AgentExePath -Profile Any | Out-Null
    Write-Ok "Firewall outbound rule: port $ManagerPort → $ManagerIP"
} catch {
    Write-Warn "Firewall rule not added: $_ — add manually if needed"
}

# ══════════════════════════════════════════════════════════════════════════════
#  STEP 7 — START SERVICES + POST-INSTALL HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════
Write-Step "Step 7/7  Starting services"

# Start the agent before its monitor to prevent concurrent StartService calls.
Write-Host "  Starting $AGENT_SVC..." -NoNewline
try {
    Start-Service -Name $AGENT_SVC -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Service $AGENT_SVC).Status -ne "Running" -and
           (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 400 }
    $agSt = (Get-Service $AGENT_SVC).Status
    Write-Host " $agSt" -ForegroundColor $(if ($agSt -eq "Running") {"Green"} else {"Yellow"})
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Warn "Agent start failed: $_ — check logs at $LogFile"
    $agSt = "Stopped"
}

# Start watchdog after the agent request has settled.
Write-Host "  Starting $WATCHDOG_SVC..." -NoNewline
try {
    Start-Service -Name $WATCHDOG_SVC -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Service $WATCHDOG_SVC).Status -ne "Running" -and
           (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 400 }
    $wdSt = (Get-Service $WATCHDOG_SVC).Status
    Write-Host " $wdSt" -ForegroundColor $(if ($wdSt -eq "Running") {"Green"} else {"Yellow"})
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Warn "Watchdog start failed: $_ — it will auto-start on next reboot"
    $wdSt = "Stopped"
}

# Wait for log to appear and check for successful startup message
if ($agSt -eq "Running") {
    Write-Host "  Waiting for agent startup log..." -NoNewline -ForegroundColor DarkGray
    $deadline = (Get-Date).AddSeconds(25)
    $enrolled = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        if (Test-Path $LogFile) {
            $recent = Get-Content $LogFile -Tail 30 -ErrorAction SilentlyContinue
            if ($recent -match "Enrollment OK|enrollment complete|Agent running") {
                $enrolled = $true; break
            }
            if ($recent -match "CRITICAL|enrollment failed|cannot start") {
                break
            }
        }
    }
    if ($enrolled) {
        Write-Host " enrolled!" -ForegroundColor Green
    } else {
        Write-Host " (check logs)" -ForegroundColor Yellow
        Write-Warn "Enrollment not confirmed yet — manager may be slow or enrollment token needed."
        Write-Warn "Run: attacklens-service logs    to watch enrollment in real time."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
$allGreen = ($agSt -eq "Running") -and ($wdSt -eq "Running")

Write-Host ""
Write-Host "  ══════════════════════════════════════════════" -ForegroundColor Cyan
if ($allGreen) {
    Write-Host "  Installation complete!" -ForegroundColor Green
} else {
    Write-Host "  Installation finished with warnings." -ForegroundColor Yellow
}
Write-Host "  ══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Agent ID   : $AgentId"
Write-Host "  Agent Name : $AgentName"
Write-Host "  Manager    : $ManagerUrl  (tls_verify=$TlsStr)"
Write-Host "  Config     : $ConfigFile"
Write-Host "  Logs       : $LogFile"
Write-Host "  Security   : $SecurityDir"
Write-Host ""
Write-Host ("  {0,-28} {1}" -f "$AGENT_SVC`:",
    $agSt) -ForegroundColor $(if ($agSt -eq "Running") {"Green"} else {"Yellow"})
Write-Host ("  {0,-28} {1}" -f "$WATCHDOG_SVC`:",
    $wdSt) -ForegroundColor $(if ($wdSt -eq "Running") {"Green"} else {"Yellow"})
Write-Host ""

if (-not $EnrollToken) {
    Write-Warn "No enrollment token — manager must have open enrollment enabled."
}

Write-Host "  Management CLI (open a new terminal after install):" -ForegroundColor Cyan
Write-Host "    attacklens-service status      check services + last log lines"  -ForegroundColor DarkGray
Write-Host "    attacklens-service logs        tail live log (Ctrl+C to stop)"   -ForegroundColor DarkGray
Write-Host "    attacklens-service diagnose    full health check"                 -ForegroundColor DarkGray
Write-Host "    attacklens-service repair      auto-fix common issues"            -ForegroundColor DarkGray
Write-Host ""
Write-Host "  To uninstall:" -ForegroundColor Cyan
Write-Host "    $ScriptsDir\uninstall.ps1"                                        -ForegroundColor DarkGray
Write-Host ""
