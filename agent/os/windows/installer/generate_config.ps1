<#
.SYNOPSIS
    Generate agent.toml for the AttackLens Windows Agent.

.DESCRIPTION
    Writes a complete, production-ready agent.toml to:
      $DataDir\agent.toml

    Called automatically by the MSI Custom Action CA_GenerateConfig_Deferred.
    Can also be run standalone to regenerate config after changes.

.PARAMETER InstallDir
    Root for binaries and source. Default: C:\Program Files\AttackLens

.PARAMETER DataDir
    Root for data, config, logs. Default: C:\ProgramData\AttackLens

.PARAMETER ManagerUrl
    Manager HTTP(S) endpoint. e.g. http://34.224.174.38:8080

.PARAMETER TlsVerify
    true  — verify manager TLS against system trust store (production)
    false — skip verification (dev / self-signed cert)
    path  — path to a CA bundle file

.PARAMETER EnrollToken
    One-time enrollment token (sk-enroll-...).

.PARAMETER ManagerApiKey
    Pre-shared 64-hex API key (skips enrollment flow).

.PARAMETER SpkiPin
    SPKI certificate pin (sha256//base64==) to prevent MITM via rogue CA.

.PARAMETER AgentId
    Unique agent identifier. Derived from Windows MachineGuid if omitted.

.PARAMETER AgentName
    Human-readable label. Defaults to $env:COMPUTERNAME.

.EXAMPLE
    # MSI automatic invocation (via Custom Action)
    .\generate_config.ps1 `
        -ManagerUrl  "http://34.224.174.38:8080" `
        -EnrollToken "sk-enroll-abc123" `
        -AgentName   "WORKSTATION-01" `
        -TlsVerify   "false"

.EXAMPLE
    # Standalone regenerate (preserve id/name from existing toml)
    .\generate_config.ps1 -ManagerUrl "http://newmanager:8080"
#>

param(
    [string] $InstallDir    = "C:\Program Files\AttackLens",
    [string] $DataDir       = "",
    [string] $ManagerUrl    = "",
    [string] $TlsVerify     = "true",
    [string] $EnrollToken   = "",
    [string] $ManagerApiKey = "",
    [string] $SpkiPin       = "",
    [string] $AgentId       = "",
    [string] $AgentName     = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve data directory ──────────────────────────────────────────────────
if (-not $DataDir) {
    $DataDir = Join-Path $env:PROGRAMDATA "AttackLens"
}

# ── Derived paths ───────────────────────────────────────────────────────────
$BinDir      = Join-Path $InstallDir "bin"
$LogDir      = Join-Path $DataDir "logs"
$SecurityDir = Join-Path $DataDir "security"
$SpoolDir    = Join-Path $DataDir "spool"
$SubDataDir  = Join-Path $DataDir "data"
$ConfigPath  = Join-Path $DataDir "agent.toml"
$LogFile     = Join-Path $LogDir "agent.log"

# ── Agent identity ──────────────────────────────────────────────────────────
if (-not $AgentId) {
    # Try to preserve existing agent ID from current config
    if (Test-Path $ConfigPath) {
        $existing = Select-String -Path $ConfigPath -Pattern '^\s*id\s*=\s*"([^"]+)"'
        if ($existing) {
            $AgentId = $existing.Matches[0].Groups[1].Value
        }
    }
    # Derive from Windows MachineGuid
    if (-not $AgentId) {
        try {
            $mguid  = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
            $AgentId = "win-$($mguid.ToLower())"
        } catch {
            $AgentId = "win-$([System.Guid]::NewGuid().ToString().ToLower())"
        }
    }
}

if (-not $AgentName) {
    if (Test-Path $ConfigPath) {
        $existing = Select-String -Path $ConfigPath -Pattern '^\s*name\s*=\s*"([^"]+)"'
        if ($existing) { $AgentName = $existing.Matches[0].Groups[1].Value }
    }
    if (-not $AgentName) { $AgentName = $env:COMPUTERNAME }
}

# ── Validate ────────────────────────────────────────────────────────────────
if (-not $ManagerUrl) {
    throw "ManagerUrl is required."
}
if ($ManagerUrl -notmatch '^(?i:https)://') {
    throw "ManagerUrl must use https://. Plain HTTP is not accepted by this legacy generator."
}
if ($EnrollToken -and $ManagerApiKey) {
    Write-Warning "Both EnrollToken and ManagerApiKey provided — EnrollToken takes precedence."
    $ManagerApiKey = ""
}

# ── Ensure directories exist ────────────────────────────────────────────────
foreach ($dir in @($BinDir, $LogDir, $SecurityDir, $SpoolDir, $SubDataDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Restrict security dir: SYSTEM + Admins only
try {
    & icacls $SecurityDir /inheritance:r `
        /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" `
        /grant:r "BUILTIN\Administrators:(OI)(CI)F" | Out-Null
} catch {
    Write-Warning "Could not restrict SecurityDir ACL: $_"
}

# ── TOML helpers ────────────────────────────────────────────────────────────
function fwd([string]$p) { return $p.Replace('\', '/') }

$ts    = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$tlsLc = $TlsVerify.Trim().ToLower()
$tlsToml = switch ($tlsLc) {
    "true"  { "true" }
    "false" { "false" }
    default { "`"$TlsVerify`"" }
}

# ── Build TOML content ──────────────────────────────────────────────────────
$L = [System.Collections.Generic.List[string]]::new()

$L.AddRange([string[]]@(
    "# AttackLens Windows Agent — Configuration",
    "# Generated: $ts",
    "# Restart AttackLensAgent service to apply changes.",
    "",
    "[agent]",
    "id   = `"$AgentId`"",
    "name = `"$AgentName`"",
    ""
))

# [manager]
$L.AddRange([string[]]@(
    "[manager]",
    "url        = `"$ManagerUrl`"",
    "tls_verify = $tlsToml",
    "timeout_sec = 30"
))
if ($ManagerApiKey -match '^[0-9a-fA-F]{64}$') {
    $L.Add("api_key    = `"$($ManagerApiKey.ToLower())`"")
}
if ($SpkiPin) {
    $pin = if ($SpkiPin.StartsWith("sha256//")) { $SpkiPin } else { "sha256//$SpkiPin" }
    $L.Add("spki_pin   = `"$pin`"")
} else {
    $L.Add("# spki_pin = `"sha256//base64=`"")
}
$L.Add("")

# [enrollment]
$L.AddRange([string[]]@(
    "[enrollment]",
    "token    = `"$EnrollToken`"",
    "keystore = `"dpapi`"",
    ""
))

# [paths]
$L.AddRange([string[]]@(
    "[paths]",
    "install_dir  = `"$(fwd $InstallDir)`"",
    "config_dir   = `"$(fwd $DataDir)`"",
    "log_dir      = `"$(fwd $LogDir)`"",
    "data_dir     = `"$(fwd $SubDataDir)`"",
    "security_dir = `"$(fwd $SecurityDir)`"",
    "spool_dir    = `"$(fwd $SpoolDir)`"",
    "pid_file     = `"$(fwd (Join-Path $DataDir 'attacklens-agent.pid'))`"",
    ""
))

# [binaries]
$L.AddRange([string[]]@(
    "[binaries]",
    "agent    = `"$(fwd (Join-Path $BinDir 'run_agent.py'))`"",
    "watchdog = `"$(fwd (Join-Path $BinDir 'run_watchdog.py'))`"",
    ""
))

# [logging]
$L.AddRange([string[]]@(
    "[logging]",
    "level   = `"INFO`"",
    "file    = `"$(fwd $LogFile)`"",
    "max_mb  = 10",
    "backups = 5",
    ""
))

# [collection] — standard, Windows event, SCA, and developer-security sections
$sections = [ordered]@{
    metrics     = @{ e=$true;  i=10    }
    connections = @{ e=$true;  i=10    }
    processes   = @{ e=$true;  i=10    }
    ports       = @{ e=$true;  i=30    }
    network     = @{ e=$true;  i=120   }
    arp         = @{ e=$true;  i=60    }
    mounts      = @{ e=$true;  i=120   }
    battery     = @{ e=$true;  i=120   }
    openfiles   = @{ e=$true;  i=120   }
    services    = @{ e=$true;  i=120   }
    users       = @{ e=$true;  i=120   }
    hardware    = @{ e=$true;  i=300   }
    containers  = @{ e=$true;  i=120   }
    storage     = @{ e=$true;  i=600   }
    tasks       = @{ e=$true;  i=600   }
    apps        = @{ e=$true;  i=3600  }
    packages    = @{ e=$true;  i=3600  }
    binaries    = @{ e=$true;  i=86400 }
    sbom        = @{ e=$true;  i=86400 }
    security    = @{ e=$true;  i=3600  }
    sysctl      = @{ e=$true;  i=3600  }
    configs     = @{ e=$true;  i=3600  }
    # Continuous CIS-aligned Security Configuration Assessment (hourly)
    sca         = @{ e=$true;  i=3600 }
    # Windows-only: reads Security + System Event Log channels
    eventlog    = @{ e=$true;  i=300   }
    security_audit = @{ e=$true; i=21600 }
}

foreach ($name in $sections.Keys) {
    $s = $sections[$name]
    $en = if ($s.e) { "true" } else { "false" }
    $L.AddRange([string[]]@(
        "[collection.sections.$name]",
        "enabled      = $en",
        "interval_sec = $($s.i)",
        ""
    ))
}

# ── Write file ──────────────────────────────────────────────────────────────
$content = $L -join "`r`n"
[System.IO.File]::WriteAllText($ConfigPath, $content, [System.Text.Encoding]::UTF8)

# Restrict config ACL: Admins + SYSTEM read, Users read (for CLI status)
try {
    & icacls $ConfigPath /inheritance:r `
        /grant:r "NT AUTHORITY\SYSTEM:(R)" `
        /grant:r "BUILTIN\Administrators:(R)" `
        /grant:r "BUILTIN\Users:(R)" | Out-Null
} catch {
    Write-Warning "Could not restrict config ACL: $_"
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  agent.toml written" -ForegroundColor Green
Write-Host "    Path       : $ConfigPath"
Write-Host "    Agent ID   : $AgentId"
Write-Host "    Agent Name : $AgentName"
Write-Host "    Manager    : $ManagerUrl"
Write-Host "    TLS verify : $tlsToml"
if ($SpkiPin)       { Write-Host "    SPKI pin   : set" }
if ($EnrollToken)   { Write-Host "    Enrollment : token set (agent will enroll on first start)" }
elseif ($ManagerApiKey -match '^[0-9a-fA-F]{64}$') {
                      Write-Host "    API key    : set (enrollment skipped)" }
else {
    Write-Warning "  Neither EnrollToken nor ManagerApiKey provided."
    Write-Warning "  Edit $ConfigPath and set [enrollment] token, then restart AttackLensAgent."
}
Write-Host ""
