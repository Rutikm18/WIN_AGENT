<#
.SYNOPSIS
    Generate agent.toml for the Jarvis Windows Agent.

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
    Root for binaries. Default: C:\Program Files\Jarvis

.PARAMETER DataDir
    Root for data/config/logs. Default: C:\ProgramData\Jarvis

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
    [string] $InstallDir    = "C:\Program Files\Jarvis",
    [string] $DataDir       = "",
    [string] $ManagerUrl    = "https://localhost:8443",
    [string] $EnrollToken   = "",
    [string] $ManagerApiKey = "",
    [string] $SpkiPin       = "",
    [string] $AgentId       = "",
    [string] $AgentName     = "",
    [string] $TlsVerify     = "true"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve data directory ─────────────────────────────────────────────────────
if (-not $DataDir) {
    $DataDir = Join-Path $env:PROGRAMDATA "Jarvis"
}

# ── Derived paths ──────────────────────────────────────────────────────────────
$BinDir      = Join-Path $InstallDir "bin"
$ConfigDir   = Join-Path $DataDir "config"
$LogDir      = Join-Path $DataDir "logs"
$SecurityDir = Join-Path $DataDir "security"
$SpoolDir    = Join-Path $DataDir "spool"
$SubDataDir  = Join-Path $DataDir "data"
$ConfigPath  = Join-Path $ConfigDir "agent.toml"
$AgentExe    = Join-Path $BinDir "jarvis-agent.exe"
$WatchdogExe = Join-Path $BinDir "jarvis-watchdog.exe"
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
    & icacls $SecurityDir /inheritance:r `
        /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
        /grant:r "BUILTIN\Administrators:(OI)(CI)F" | Out-Null
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
    "# Jarvis Windows Agent - Configuration",
    "# Generated: $ts by generate_config.ps1",
    "# Restart the JarvisAgent Windows Service to apply changes.",
    "# Full schema: https://github.com/your-org/jarvis/blob/main/docs/agent-config.md",
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
# token is intentionally empty: the agent auto-enrolls on first start and
# writes security\client.key containing agent_name, agent_number, and token.
# To re-enroll: delete security\client.key and restart JarvisAgent.
$lines.AddRange([string[]]@(
    "[enrollment]",
    "# token is auto-generated - see security\client.key after first run",
    "token    = `"$EnrollToken`"",
    "keystore = `"dpapi`"",
    ""
))

# ── [paths] ───────────────────────────────────────────────────────────────────
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
    # Windows-only section - reads Security + System Event Log channels
    # Covers: logon events, process creation, service install, task manipulation
    eventlog    = @{ e=$true;  i=300  }
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
[System.IO.File]::WriteAllText($ConfigPath, $content, [System.Text.Encoding]::UTF8)

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
    Write-Warning "  Neither EnrollToken nor ManagerApiKey provided."
    Write-Warning "  Set JARVIS_ENROLL_TOKEN environment variable before starting the service,"
    Write-Warning "  or add token to [enrollment] in $ConfigPath"
}
Write-Host ""
