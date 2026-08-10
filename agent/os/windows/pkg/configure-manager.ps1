[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManagerUrl,
    [switch]$AllowInsecureTransport,
    [ValidateSet('true', 'false')]
    [string]$TlsVerify = 'true',
    [string]$CaBundle = '',
    [string]$SpkiPin = '',
    [string]$EnrollmentToken = '',
    [string]$AgentName = '',
    [string]$ConfigPath = 'C:\ProgramData\AttackLens\config\agent.toml',
    [string]$AgentExecutable = 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe',
    [switch]$NoServiceRestart
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Quote-Toml([string]$Value) {
    if ($null -eq $Value) { return '""' }
    if ($Value -match '[\r\n]') {
        throw 'Configuration values must not contain line breaks.'
    }
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function Set-TomlSectionValues(
    [string]$Text,
    [string]$SectionName,
    [System.Collections.IDictionary]$Values
) {
    $sectionPattern = '(?ms)^\[' + [regex]::Escape($SectionName) +
        '\][ \t]*\r?\n.*?(?=^\[|\z)'
    $match = [regex]::Match($Text, $sectionPattern)
    if (-not $match.Success) {
        throw "Required TOML section [$SectionName] is missing. Use the validated full editor or repair the MSI."
    }
    $updated = $match.Value
    foreach ($key in $Values.Keys) {
        $rendered = [string]$Values[$key]
        $keyPattern = '(?m)^[ \t]*' + [regex]::Escape([string]$key) + '[ \t]*=.*$'
        if ([regex]::IsMatch($updated, $keyPattern)) {
            $replacement = "${key} = $rendered"
            $updated = [regex]::Replace(
                $updated,
                $keyPattern,
                [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $replacement },
                1
            )
        } else {
            if (-not $updated.EndsWith("`n")) { $updated += "`r`n" }
            $updated += "${key} = $rendered`r`n"
        }
    }
    return $Text.Remove($match.Index, $match.Length).Insert($match.Index, $updated)
}

function Invoke-ConfigValidation([string]$Path) {
    $previousConfig = $env:ATTACKLENS_CONFIG
    $previousErrorAction = $ErrorActionPreference
    try {
        $env:ATTACKLENS_CONFIG = $Path
        # Native stderr must be captured as diagnostic text. Under Windows
        # PowerShell, the script-wide Stop preference would otherwise abort
        # before the validator exit code and complete message are available.
        $ErrorActionPreference = 'Continue'
        $output = & $AgentExecutable validate-config 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "Configuration validation failed (exit $exitCode): $($output -join ' | ')"
        }
    } finally {
        $env:ATTACKLENS_CONFIG = $previousConfig
        $ErrorActionPreference = $previousErrorAction
    }
}

function Write-ExistingFilePreservingSecurity(
    [string]$Path,
    [byte[]]$Bytes
) {
    # Keep the existing Windows file object, owner and DACL. File.Replace is
    # intentionally not used: it requests WRITE_DAC while merging ACLs, but
    # the supported Administrator ACL grants Modify rather than Full Control.
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.SetLength(0)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Stop-AttackLensServices {
    foreach ($name in @('AttackLensWatchdog', 'AttackLensAgent')) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $name -Force -ErrorAction Stop
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90))
        }
    }
}

function Start-AttackLensServices {
    foreach ($name in @('AttackLensAgent', 'AttackLensWatchdog')) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            Start-Service -Name $name -ErrorAction Stop
            $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(120))
        }
    }
}

if (-not $NoServiceRestart -and -not (Test-Administrator)) {
    throw 'Run PowerShell as Administrator to change the AttackLens manager.'
}

$ManagerUrl = $ManagerUrl.Trim().TrimEnd('/')
if (-not $ManagerUrl -or $ManagerUrl -match '[\r\n"]') {
    throw 'ManagerUrl must not be empty or contain quotes or line breaks.'
}
if ($ManagerUrl -notmatch '^(?i:https?)://') {
    if ($ManagerUrl -match '[/\\?#@]') {
        throw 'ManagerUrl must be an IP, DNS name, or absolute HTTP(S) URL.'
    }
    $managerHost = $ManagerUrl
    if ($managerHost.Contains(':') -and
            -not ($managerHost.StartsWith('[') -and $managerHost.EndsWith(']'))) {
        $managerHost = "[$managerHost]"
    }
    $ManagerUrl = "http://${managerHost}:8080"
    $AllowInsecureTransport = $true
    $TlsVerify = 'false'
}

$parsed = $null
if (-not [Uri]::TryCreate($ManagerUrl, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -notin @('http', 'https') -or -not $parsed.Host -or
        -not [string]::IsNullOrEmpty($parsed.UserInfo)) {
    throw 'ManagerUrl must be an absolute HTTP(S) URL without embedded credentials.'
}
if ($parsed.Scheme -eq 'http' -and -not $AllowInsecureTransport) {
    throw 'Plain HTTP requires -AllowInsecureTransport. Use HTTPS in production.'
}
if ($parsed.Scheme -eq 'http') {
    $TlsVerify = 'false'
}
if ($CaBundle -and -not [IO.Path]::IsPathRooted($CaBundle)) {
    throw 'CaBundle must be an absolute path.'
}
if ($SpkiPin -and $SpkiPin -notmatch '^sha256//.+$') {
    throw 'SpkiPin must use sha256//<base64> format.'
}
foreach ($value in @($CaBundle, $SpkiPin, $EnrollmentToken, $AgentName)) {
    if ($value -match '[\r\n]') {
        throw 'Configuration values must not contain line breaks.'
    }
}

$resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath).Path
$resolvedAgent = (Resolve-Path -LiteralPath $AgentExecutable).Path
$AgentExecutable = $resolvedAgent
$configDir = Split-Path -Parent $resolvedConfig
$stagePath = Join-Path $configDir ("agent.toml.manager-stage-{0}" -f $PID)
$backupPath = Join-Path $configDir 'agent.toml.manager-backup'
$encoding = [Text.UTF8Encoding]::new($false)
$configChanged = $false

try {
    $existingToml = [IO.File]::ReadAllText($resolvedConfig)
    $managerValues = [ordered]@{
        url = (Quote-Toml $ManagerUrl)
        tls_verify = $TlsVerify.ToLowerInvariant()
        allow_insecure_transport = $AllowInsecureTransport.IsPresent.ToString().ToLowerInvariant()
    }
    if ($CaBundle) {
        $managerValues.ca_bundle = Quote-Toml $CaBundle
    }
    if ($SpkiPin) {
        $managerValues.spki_pin = Quote-Toml $SpkiPin
    }
    $updatedToml = Set-TomlSectionValues $existingToml 'manager' $managerValues
    if ($EnrollmentToken) {
        $updatedToml = Set-TomlSectionValues $updatedToml 'enrollment' (
            [ordered]@{ token = (Quote-Toml $EnrollmentToken) }
        )
        $updatedToml = Set-TomlSectionValues $updatedToml 'transport' (
            [ordered]@{ auto_reenroll = 'true' }
        )
    }
    if ($AgentName) {
        $updatedToml = Set-TomlSectionValues $updatedToml 'agent' (
            [ordered]@{ name = (Quote-Toml $AgentName) }
        )
    }

    [IO.File]::WriteAllText($stagePath, $updatedToml, $encoding)
    Invoke-ConfigValidation $stagePath

    if (-not $NoServiceRestart) {
        Stop-AttackLensServices
    }

    Copy-Item -LiteralPath $resolvedConfig -Destination $backupPath -Force
    $updatedBytes = $encoding.GetBytes($updatedToml)
    $configChanged = $true
    Write-ExistingFilePreservingSecurity $resolvedConfig $updatedBytes
    Invoke-ConfigValidation $resolvedConfig

    if (-not $NoServiceRestart) {
        Start-AttackLensServices
    }

    [ordered]@{
        ok = $true
        manager_endpoint = "$($parsed.Scheme)://$($parsed.Authority)$($parsed.AbsolutePath.TrimEnd('/'))"
        configuration = $resolvedConfig
        backup = $backupPath
        acl_strategy = 'existing file object preserved; no DACL rewrite requested'
        services_restarted = -not $NoServiceRestart
    } | ConvertTo-Json -Depth 4
} catch {
    $failure = $_
    if ($configChanged -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        try {
            $rollbackBytes = [IO.File]::ReadAllBytes($backupPath)
            Write-ExistingFilePreservingSecurity $resolvedConfig $rollbackBytes
        } catch {
            Write-Warning "Configuration rollback failed: $_"
        }
    }
    if (-not $NoServiceRestart) {
        try { Start-AttackLensServices } catch {
            Write-Warning "Could not restore service state after failure: $_"
        }
    }
    throw $failure
} finally {
    if (Test-Path -LiteralPath $stagePath) {
        Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue
    }
}
