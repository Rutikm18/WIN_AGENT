<#
.SYNOPSIS
    Generate agent.toml for the AttackLens Windows Agent.

.DESCRIPTION
    Writes a complete, production-ready agent.toml to:
      $DataDir\config\agent.toml

    Called automatically by the MSI installer Custom Action.
    Also usable standalone (e.g. to regenerate config after changes).

    Directory layout written to config:
      Binaries : $InstallDir\bin\
      Config   : $DataDir\config\         (this file)
      Logs     : $DataDir\logs\
      Security : $DataDir\security\       (SYSTEM + Admins ACL)
      Spool    : $DataDir\spool\
      Data     : $DataDir\data\

.PARAMETER InstallDir
    Root for binaries. Default: C:\Program Files\AttackLens

.PARAMETER DataDir
    Root for data/config/logs. Default: C:\ProgramData\AttackLens

.PARAMETER ManagerUrl
    Manager HTTPS endpoint. Required (e.g. https://manager.corp.example:443).

.PARAMETER EnrollToken
    Enrollment token (sk-enroll-...) for first-run key exchange.
    Leave empty if using ManagerApiKey.

.PARAMETER ManagerApiKey
    Pre-shared 64-hex API key. Alternative to EnrollToken (skips enrollment).

.PARAMETER SpkiPin
    Optional SPKI certificate pin (sha256//base64==).
    Prevents MITM even if a rogue CA is installed in the Windows trust store.
    Generate with: python -c "from agent.os.windows.tls_transport import _compute_spki_hash; ..."
    Leave empty to disable pinning (cert chain validation still occurs).

.PARAMETER AgentId
    Unique agent identifier. Auto-generated from Windows MachineGuid if omitted.

.PARAMETER AgentName
    Human-readable label. Defaults to COMPUTERNAME.

.PARAMETER TlsVerify
    true  - verify manager TLS certificate against system CA bundle (production)
    false - skip TLS verification (dev / self-signed cert)
    path  - path to a CA bundle file (custom PKI)

.EXAMPLE
    # Production install (called by MSI)
    .\generate_config.ps1 `
        -ManagerUrl  "https://manager.corp.example:443" `
        -EnrollToken "sk-enroll-abc123" `
        -AgentName   "WORKSTATION-01" `
        -TlsVerify   "true"

.EXAMPLE
    # Dev install with self-signed cert and pre-shared key
    .\generate_config.ps1 `
        -ManagerUrl     "https://192.168.1.100:8443" `
        -ManagerApiKey  "deadbeef...64hexchars..." `
        -TlsVerify      "false"

.EXAMPLE
    # Regenerate config after a manager migration
    .\generate_config.ps1 -ManagerUrl "https://new-manager.corp.example"
#>

param(
    [string] $InstallDir    = "C:\Program Files\AttackLens",
    [string] $DataDir       = "",
    [string] $ManagerUrl    = "",
    [string] $EnrollToken   = "",
    [string] $ManagerApiKey = "",
    [string] $SpkiPin       = "",
    [string] $AgentId       = "",
    [string] $AgentName     = "",
    [string] $TlsVerify     = "true",
    [string] $AllowInsecureTransport = "false"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve data directory ─────────────────────────────────────────────────────
if (-not $DataDir) {
    $DataDir = Join-Path $env:PROGRAMDATA "AttackLens"
}

# ── Derived paths ──────────────────────────────────────────────────────────────
$BinDir      = Join-Path $InstallDir "bin"
$ConfigDir   = Join-Path $DataDir "config"
$LogDir      = Join-Path $DataDir "logs"
$SecurityDir = Join-Path $DataDir "security"
$SpoolDir    = Join-Path $DataDir "spool"
$SubDataDir  = Join-Path $DataDir "data"
$ConfigPath  = Join-Path $ConfigDir "agent.toml"
$AgentExe    = Join-Path $BinDir "attacklens-agent.exe"
$WatchdogExe = Join-Path $BinDir "attacklens-watchdog.exe"
$LogFile     = Join-Path $LogDir "agent.log"

# ── Resolve agent identity ─────────────────────────────────────────────────────
# Derived from Windows MachineGuid - stable across reinstalls on the same machine.
if (-not $AgentId) {
    try {
        $mguid  = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
        $AgentId = "win-$($mguid.ToLower())"
    } catch {
        $AgentId = "win-$([System.Guid]::NewGuid().ToString().ToLower())"
    }
}

if (-not $AgentName) {
    $AgentName = $env:COMPUTERNAME
}

# ── Validate required inputs ───────────────────────────────────────────────────
if (-not $ManagerUrl) {
    Write-Error "ManagerUrl is required."
}
if ($AllowInsecureTransport -notmatch '^(?i:true|false|0|1)$') {
    Write-Error "AllowInsecureTransport must be 0, 1, true, or false."
}
$allowHttp = $AllowInsecureTransport -match '^(?i:true|1)$'
if ($ManagerUrl -notmatch '^(?i:https?)://') {
    Write-Error "ManagerUrl must use https:// (or http:// with AllowInsecureTransport=true)."
}
if ($ManagerUrl -match '^(?i:http)://' -and -not $allowHttp) {
    Write-Error "HTTP ManagerUrl requires -AllowInsecureTransport true."
}
if ($EnrollToken -and $ManagerApiKey) {
    Write-Warning "Both EnrollToken and ManagerApiKey provided - EnrollToken takes precedence."
    $ManagerApiKey = ""
}

# ── Ensure directories exist ───────────────────────────────────────────────────
foreach ($dir in @($BinDir, $ConfigDir, $LogDir, $SecurityDir, $SpoolDir, $SubDataDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Verbose "Created: $dir"
    }
}

# Restrict security dir ACL: SYSTEM + Administrators only
try {
    # Keep these SIDs aligned with os/windows/acl.py secure_dir policy.
    & icacls $SecurityDir /inheritance:r `
        /remove:g "*S-1-1-0" /remove:g "*S-1-5-11" /remove:g "*S-1-5-32-545" `
        /grant:r "*S-1-5-18:(OI)(CI)(F)" `
        /grant:r "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed while protecting $SecurityDir (exit $LASTEXITCODE)" }
    Write-Verbose "Security dir ACL restricted: $SecurityDir"
} catch {
    Write-Warning "Could not restrict security dir ACL: $_"
}

# ── Path helper: forward-slashes inside TOML strings ──────────────────────────
function fwd([string]$p) { return $p.Replace('\', '/') }

# ── Build agent.toml ──────────────────────────────────────────────────────────
$ts    = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$tlsLc = $TlsVerify.Trim().ToLower()

# Resolve tls_verify value for TOML
# true/false → TOML bool; anything else → quoted string (path to CA bundle)
$tlsToml = switch ($tlsLc) {
    "true"  { "true" }
    "false" { "false" }
    default { "`"$TlsVerify`"" }
}

$lines = [System.Collections.Generic.List[string]]::new()

$lines.AddRange([string[]]@(
    "# AttackLens Windows Agent - Configuration",
    "# Generated: $ts by generate_config.ps1",
    "# Restart the AttackLensAgent Windows Service to apply changes.",
    "# Full schema: https://github.com/your-org/attacklens/blob/main/docs/agent-config.md",
    ""
))

# ── [agent] ───────────────────────────────────────────────────────────────────
$lines.AddRange([string[]]@(
    "[agent]",
    "id   = `"$AgentId`"",
    "name = `"$AgentName`"",
    ""
))

# ── [manager] ─────────────────────────────────────────────────────────────────
$lines.AddRange([string[]]@(
    "[manager]",
    "url        = `"$ManagerUrl`"",
    "tls_verify = $tlsToml",
    "allow_insecure_transport = $($allowHttp.ToString().ToLowerInvariant())",
    "timeout_sec = 30"
))

if ($ManagerApiKey -match '^[0-9a-fA-F]{64}$') {
    $lines.Add("api_key = `"$($ManagerApiKey.ToLower())`"")
}

if ($SpkiPin) {
    # Normalise: ensure "sha256//" prefix
    $pin = if ($SpkiPin.StartsWith("sha256//")) { $SpkiPin } else { "sha256//$SpkiPin" }
    $lines.Add("spki_pin = `"$pin`"")
} else {
    $lines.Add("# spki_pin = `"sha256//base64=`"   # optional SPKI cert pin - blocks MITM via rogue CA")
}
$lines.Add("")

# ── [enrollment] ──────────────────────────────────────────────────────────────
# token may be empty when the manager allows open enrollment. On first start
# the manager returns an API key and the agent writes the protected client key.
# To re-enroll: delete security\client.key and restart AttackLensAgent.
$lines.AddRange([string[]]@(
    "[enrollment]",
    "# optional when the manager allows open enrollment",
    "token    = `"$EnrollToken`"",
    "keystore = `"dpapi`"",
    ""
))

# ── [paths] ───────────────────────────────────────────────────────────────────
$autoReenroll = if ($EnrollToken) { "true" } else { "false" }
$lines.AddRange([string[]]@(
    "[transport]",
    "initial_backoff_sec = 5",
    "max_backoff_sec = 300",
    "auth_failure_threshold = 3",
    "auto_reenroll = $autoReenroll",
    "min_free_mb = 128",
    "outbox_busy_timeout_ms = 5000",
    ""
))

$lines.AddRange([string[]]@(
    "[paths]",
    "install_dir  = `"$(fwd $BinDir)`"",
    "config_dir   = `"$(fwd $ConfigDir)`"",
    "log_dir      = `"$(fwd $LogDir)`"",
    "data_dir     = `"$(fwd $SubDataDir)`"",
    "security_dir = `"$(fwd $SecurityDir)`"",
    "spool_dir    = `"$(fwd $SpoolDir)`"",
    ""
))

# ── [logging] ─────────────────────────────────────────────────────────────────
$lines.AddRange([string[]]@(
    "[logging]",
    "level   = `"INFO`"",
    "file    = `"$(fwd $LogFile)`"",
    "max_mb  = 10",
    "backups = 3",
    ""
))

# ── [collection] ──────────────────────────────────────────────────────────────
# Per-section intervals (seconds) and enable flags.
# Disable sections by setting enabled = false, or increase interval to reduce load.
$sections = [ordered]@{
    # section            enabled  interval_sec  note
    metrics     = @{ e=$true;  i=10   }
    connections = @{ e=$true;  i=10   }
    processes   = @{ e=$true;  i=10   }
    ports       = @{ e=$true;  i=30   }
    network     = @{ e=$true;  i=120  }
    arp         = @{ e=$true;  i=60   }
    mounts      = @{ e=$true;  i=120  }
    battery     = @{ e=$true;  i=120  }
    openfiles   = @{ e=$true;  i=120  }
    services    = @{ e=$true;  i=120  }
    users       = @{ e=$true;  i=120  }
    hardware    = @{ e=$true;  i=300  }
    containers  = @{ e=$true;  i=120  }
    storage     = @{ e=$true;  i=600  }
    tasks       = @{ e=$true;  i=600  }
    apps        = @{ e=$true;  i=900  }
    packages    = @{ e=$true;  i=900  }
    binaries    = @{ e=$true;  i=86400 }
    sbom        = @{ e=$true;  i=86400 }
    security    = @{ e=$true;  i=3600 }
    sysctl      = @{ e=$true;  i=3600 }
    configs     = @{ e=$true;  i=3600 }
    # Continuous CIS-aligned Security Configuration Assessment (hourly)
    sca         = @{ e=$true;  i=3600 }
    # Windows-only section - reads Security + System Event Log channels
    # Covers: logon events, process creation, service install, task manipulation
    eventlog    = @{ e=$true;  i=300  }
    # Native persistence inventory and first-seen baseline change detection
    persistence = @{ e=$true; i=1800 }
    # DeepMesh privacy-safe developer/AI attack-surface snapshot
    developer_security = @{ e=$true; i=3600 }
    # Read-only developer, AI/MCP, persistence and credential-surface audit
    security_audit = @{ e=$true; i=21600 }
}

foreach ($name in $sections.Keys) {
    $s = $sections[$name]
    $enabled_str = if ($s.e) { "true" } else { "false" }
    $lines.AddRange([string[]]@(
        "[collection.sections.$name]",
        "enabled      = $enabled_str",
        "interval_sec = $($s.i)",
        ""
    ))
}

# ── Write file ─────────────────────────────────────────────────────────────────
$content = $lines -join "`r`n"
$tmpConfigPath = "$ConfigPath.tmp.$([guid]::NewGuid().ToString('N'))"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($tmpConfigPath, $content, $utf8NoBom)
if (Test-Path -LiteralPath $ConfigPath) {
    Move-Item -LiteralPath $tmpConfigPath -Destination $ConfigPath -Force
} else {
    Move-Item -LiteralPath $tmpConfigPath -Destination $ConfigPath
}

# ── Summary ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  agent.toml written" -ForegroundColor Green
Write-Host "    Path:       $ConfigPath"
Write-Host "    Agent ID:   $AgentId"
Write-Host "    Agent Name: $AgentName"
Write-Host "    Manager:    $ManagerUrl"
Write-Host "    TLS verify: $tlsToml"
if ($SpkiPin) {
    Write-Host "    SPKI pin:   set"
}
if ($EnrollToken) {
    Write-Host "    Enrollment: token set (first-run enrollment will occur on service start)"
} elseif ($ManagerApiKey -match '^[0-9a-fA-F]{64}$') {
    Write-Host "    Enrollment: api_key set directly (enrollment skipped)"
} else {
    Write-Host "    Enrollment: no token set (manager must allow open enrollment)"
}
Write-Host ""
