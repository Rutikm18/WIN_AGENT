# ===========================================================================
# gen_config.ps1 — AttackLens Agent configuration generator
#
# Installed by the MSI under Program Files and run as NT AUTHORITY\SYSTEM
# during the deferred CA_WriteConfig custom action, BEFORE services start.
#
# Runtime values come from an explicit Base64 CustomActionData argument. The
# MSI prepares it while the full installer session is available. The legacy
# environment-variable form remains accepted by the installed reconfiguration
# tool and older automation.
#
# MSI uses compact aliases to remain within the Windows Installer CustomAction
# table limit. Long property names remain accepted for direct/legacy use.
#
# On enrollment: the agent reads token from [enrollment].token in agent.toml
# on first start, calls POST /api/v1/enroll on the manager, receives an
# api_key, and stores it in Windows DPAPI Credential Manager as client.key.
# Subsequent starts skip enrollment (key already in keystore).
# ===========================================================================
param(
    [string]$EncodedCustomActionData = ''
)

try {

    $installerLog = 'C:\ProgramData\AttackLens\logs\installer-config.log'

    function Write-InstallerDiagnostic([string]$message) {
        try {
            $logParent = Split-Path -Parent $installerLog
            New-Item -Force -ItemType Directory -Path $logParent | Out-Null
            $timestamp = [DateTimeOffset]::UtcNow.ToString('o')
            Add-Content -LiteralPath $installerLog -Encoding UTF8 `
                -Value "$timestamp $message"
        } catch {
            # Diagnostics must never mask the original installer result.
        }
    }

    # ── Parse MSI CustomActionData ─────────────────────────────────────────────
    $ca = @{}
    $raw = $env:MsiCustomActionData
    if ($EncodedCustomActionData) {
        if ($EncodedCustomActionData -notmatch '^[A-Za-z0-9+/]+={0,2}$' -or
                $EncodedCustomActionData.Length -gt 131072) {
            throw 'Encoded CustomActionData is malformed or too large'
        }
        try {
            $json = [Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($EncodedCustomActionData)
            )
            $decoded = $json | ConvertFrom-Json -ErrorAction Stop
            foreach ($property in $decoded.PSObject.Properties) {
                $ca[[string]$property.Name] = [string]$property.Value
            }
        } catch {
            throw "Unable to decode MSI CustomActionData: $($_.Exception.Message)"
        }
    } elseif ($raw) {
        # Split only when the next token is a known property. This preserves
        # semicolons and additional '=' characters inside enrollment tokens.
        $known = 'MANAGER_URL|MANAGER_IP|MANAGER_PORT|TLS_VERIFY|ALLOW_INSECURE_TRANSPORT|CA_BUNDLE|SPKI_PIN|ENROLL_TOKEN|AGENT_NAME|COLLECTION_PROFILE|PRESERVE_STATE|PURGE_ON_UNINSTALL|U|I|P|V|H|C|S|T|N|R|K|X'
        foreach ($pair in ($raw -split ";(?=(?:$known)=)")) {
            if ($pair -match '^([^=]+)=(.*)$') {
                $ca[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
    }

    $aliases = @{
        U = 'MANAGER_URL'
        I = 'MANAGER_IP'
        P = 'MANAGER_PORT'
        V = 'TLS_VERIFY'
        H = 'ALLOW_INSECURE_TRANSPORT'
        C = 'CA_BUNDLE'
        S = 'SPKI_PIN'
        T = 'ENROLL_TOKEN'
        N = 'AGENT_NAME'
        R = 'COLLECTION_PROFILE'
        K = 'PRESERVE_STATE'
        X = 'PURGE_ON_UNINSTALL'
    }
    foreach ($alias in $aliases.Keys) {
        $name = $aliases[$alias]
        if ($ca.ContainsKey($alias) -and -not $ca.ContainsKey($name)) {
            $ca[$name] = $ca[$alias]
        }
    }

    function Read-MsiValue([string]$value) {
        if ($null -eq $value) { return '' }
        $value = $value.Trim()
        if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
            $value = $value.Substring(1, $value.Length - 2).Replace('""', '"')
        }
        return $value
    }
    foreach ($key in @('MANAGER_URL','MANAGER_IP','MANAGER_PORT','TLS_VERIFY',
                       'ALLOW_INSECURE_TRANSPORT',
                       'CA_BUNDLE','SPKI_PIN','ENROLL_TOKEN','AGENT_NAME',
                       'COLLECTION_PROFILE','PRESERVE_STATE','PURGE_ON_UNINSTALL')) {
        if ($ca.ContainsKey($key)) { $ca[$key] = Read-MsiValue $ca[$key] }
    }
    $managerOverrideRequested = [bool]($ca['MANAGER_URL'] -or $ca['MANAGER_IP'])
    $agentNameRequested = [bool]$ca['AGENT_NAME']

    # ── Resolve parameters with sensible defaults ─────────────────────────────
    $managerIp   = if ($ca['MANAGER_IP'])   { $ca['MANAGER_IP']   } else { ''    }
    $managerPort = if ($ca['MANAGER_PORT']) { $ca['MANAGER_PORT'] } else { '8080' }
    $tlsVerify   = if ($ca['TLS_VERIFY']) { $ca['TLS_VERIFY'] } else { 'false' }
    $allowHttpRaw = if ($ca['ALLOW_INSECURE_TRANSPORT']) {
        $ca['ALLOW_INSECURE_TRANSPORT']
    } else {
        'true'
    }
    $caBundle    = if ($ca['CA_BUNDLE']) { $ca['CA_BUNDLE'] } else { '' }
    $spkiPin     = if ($ca['SPKI_PIN'])  { $ca['SPKI_PIN']  } else { '' }
    $enrollToken = if ($ca['ENROLL_TOKEN']) { $ca['ENROLL_TOKEN'] } else { ''          }
    $agentName   = if ($ca['AGENT_NAME'])   { $ca['AGENT_NAME']   } else { ''          }
    $profile     = if ($ca['COLLECTION_PROFILE']) { $ca['COLLECTION_PROFILE'].ToLowerInvariant() } else { 'standard' }
    $preserveRaw = if ($ca['PRESERVE_STATE']) { $ca['PRESERVE_STATE'] } else { '1' }

    if (-not $agentName) {
        $agentName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'unknown' }
    }

    if ($preserveRaw -notmatch '^(?i:true|false|0|1)$') {
        throw "PRESERVE_STATE must be 0, 1, true, or false"
    }
    $preserveState = $preserveRaw -match '^(?i:true|1)$'
    if ($allowHttpRaw -notmatch '^(?i:true|false|0|1)$') {
        throw "ALLOW_INSECURE_TRANSPORT must be 0, 1, true, or false"
    }
    $allowHttp = $allowHttpRaw -match '^(?i:true|1)$'

    # MANAGER_URL is authoritative. Compatibility host/port properties are
    # used only when the full URL is absent and default to http://host:8080.
    # The explicit allow flag remains in agent.toml so policy is unambiguous.
    if ($managerPort -notmatch '^[0-9]+$' -or [int]$managerPort -lt 1 -or [int]$managerPort -gt 65535) {
        throw "MANAGER_PORT must be an integer between 1 and 65535"
    }
    $managerUrl = ''
    if ($ca['MANAGER_URL']) {
        $managerUrl = $ca['MANAGER_URL']
    } elseif ($managerIp) {
        $fallbackHost = $managerIp
        if ($fallbackHost.Contains(':') -and -not ($fallbackHost.StartsWith('[') -and $fallbackHost.EndsWith(']'))) {
            $fallbackHost = "[$fallbackHost]"
        }
        $managerUrl = "http://${fallbackHost}:${managerPort}"
    }
    if ($managerUrl -and $managerUrl -notmatch '^(?i:https?)://') {
        # The GUI accepts a bare IP/FQDN. Normalize it to the requested HTTP
        # default instead of rejecting the installation after the user exits.
        $fallbackHost = $managerUrl.Trim().TrimEnd('/')
        if ($fallbackHost -match '[/\\?#@]') {
            throw "MANAGER_URL must be an IP, DNS name, or absolute HTTP(S) URL"
        }
        if ($fallbackHost.Contains(':') -and
                -not ($fallbackHost.StartsWith('[') -and $fallbackHost.EndsWith(']'))) {
            $fallbackHost = "[$fallbackHost]"
        }
        $managerUrl = "http://${fallbackHost}:${managerPort}"
    }
    if ($managerUrl -match '^(?i:http)://' -and -not $allowHttp) {
        throw "HTTP MANAGER_URL requires ALLOW_INSECURE_TRANSPORT=true"
    }
    if ($tlsVerify -notmatch '^(?i:true|false)$') {
        if (-not $caBundle) { $caBundle = $tlsVerify }
        $tlsVerify = 'true'
    }
    $tlsVerify = $tlsVerify.ToLowerInvariant()
    if ($caBundle -and -not [System.IO.Path]::IsPathRooted($caBundle)) {
        throw "CA_BUNDLE must be an absolute path"
    }
    if ($spkiPin -and ($spkiPin -notmatch '^sha256//.+$')) {
        throw "SPKI_PIN must use the sha256//<base64> format"
    }
    if ($profile -notin @('baseline', 'standard', 'intensive', 'incident')) {
        throw "COLLECTION_PROFILE must be baseline, standard, intensive, or incident"
    }

    function Quote-Toml([string]$value) {
        if ($null -eq $value) { return '""' }
        if ($value.Contains("`r") -or $value.Contains("`n")) { throw "Configuration value contains a newline" }
        return '"' + $value.Replace('\', '\\').Replace('"', '\"') + '"'
    }

    function Set-TomlSectionValues(
        [string]$text,
        [string]$sectionName,
        [System.Collections.IDictionary]$values
    ) {
        # Restrict replacements to one TOML table so similarly named keys in
        # other tables remain untouched. Missing keys are appended, allowing
        # safe migration from older schemas.
        $sectionPattern = '(?ms)^\[' + [regex]::Escape($sectionName) +
            '\][ \t]*\r?\n.*?(?=^\[|\z)'
        $match = [regex]::Match($text, $sectionPattern)
        if (-not $match.Success) {
            $suffix = if ($text.EndsWith("`n")) { '' } else { "`r`n" }
            $suffix += "`r`n[$sectionName]`r`n"
            foreach ($key in $values.Keys) {
                $suffix += "${key} = $($values[$key])`r`n"
            }
            return $text + $suffix
        }
        $updated = $match.Value
        foreach ($key in $values.Keys) {
            $rendered = [string]$values[$key]
            $keyPattern = '(?m)^[ \t]*' + [regex]::Escape([string]$key) + '[ \t]*=.*$'
            if ([regex]::IsMatch($updated, $keyPattern)) {
                $replacement = "${key} = $rendered"
                $updated = [regex]::Replace($updated, $keyPattern,
                    [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $replacement }, 1)
            } else {
                if (-not $updated.EndsWith("`n")) { $updated += "`r`n" }
                $updated += "${key} = $rendered`r`n"
            }
        }
        return $text.Remove($match.Index, $match.Length).Insert($match.Index, $updated)
    }

    # ── Generate stable agent_id from Windows MachineGuid ────────────────────
    # MachineGuid is hardware-bound and survives agent reinstalls on the same
    # machine, so the manager keeps the same agent record across upgrades.
    try {
        $mguid   = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
                       -Name MachineGuid -ErrorAction Stop).MachineGuid.ToLower()
        $agentId = "win-$mguid"
    } catch {
        $agentId = "win-$([guid]::NewGuid().ToString().ToLower())"
    }

    # ── Create ProgramData directory tree ─────────────────────────────────────
    $managerInputSource = if ($ca['MANAGER_URL']) {
        'MANAGER_URL'
    } elseif ($managerIp) {
        'MANAGER_IP'
    } else {
        'none'
    }
    $managerTransport = if ($managerUrl -match '^https://') {
        'https'
    } elseif ($managerUrl) {
        'http'
    } else {
        'none'
    }
    Write-InstallerDiagnostic (
        'Captured installer configuration: manager_source={0}; manager_configured={1}; transport={2}; port={3}.' -f
        $managerInputSource, [bool]$managerUrl, $managerTransport, $managerPort
    )

    $base = 'C:\ProgramData\AttackLens'
    foreach ($sub in @('config', 'logs', 'security', 'spool', 'data', 'status', 'support')) {
        New-Item -Force -ItemType Directory -Path "$base\$sub" | Out-Null
    }

    function Apply-AttackLensAcl([string]$target, [ValidateSet('secure_dir','service_data_dir','status_dir','config_file')] [string]$mode) {
        # Keep these SIDs and rights aligned with os/windows/acl.py.
        $aclArgs = @(
            $target, '/inheritance:r',
            '/remove:g', '*S-1-1-0', '/remove:g', '*S-1-5-11',
            '/remove:g', '*S-1-5-32-545'
        )
        if ($mode -eq 'config_file') {
            $aclArgs += @('/grant:r', '*S-1-5-18:(F)',
                          '/grant:r', '*S-1-5-32-544:(M)')
        } elseif ($mode -eq 'secure_dir') {
            $aclArgs += @('/grant:r', '*S-1-5-18:(OI)(CI)(F)',
                          '/grant:r', '*S-1-5-32-544:(OI)(CI)(F)')
        } elseif ($mode -eq 'status_dir') {
            $aclArgs += @('/grant:r', '*S-1-5-18:(OI)(CI)(F)',
                          '/grant:r', '*S-1-5-32-544:(OI)(CI)(M)',
                          '/grant:r', '*S-1-5-32-545:(OI)(CI)(RX)')
        } else {
            $aclArgs += @('/grant:r', '*S-1-5-18:(OI)(CI)(F)',
                          '/grant:r', '*S-1-5-32-544:(OI)(CI)(M)')
        }
        $aclOutput = & icacls @aclArgs 2>&1
        $aclExitCode = $LASTEXITCODE
        if ($aclExitCode -ne 0 -and $mode -eq 'config_file') {
            # A legacy package could leave SYSTEM read-only and Administrators
            # as owner. Setting SYSTEM as owner first fails in that state.
            # Take ownership without changing file contents, bootstrap SYSTEM
            # full control, then apply the final least-privilege descriptor.
            $takeownOutput = & takeown.exe /F $target /A 2>&1
            $takeownExitCode = $LASTEXITCODE
            if ($takeownExitCode -ne 0) {
                $detail = ($takeownOutput | ForEach-Object { [string]$_ }) -join ' | '
                throw "takeown failed for existing config at $target (exit $takeownExitCode): $detail"
            }
            $bootstrapOutput = & icacls.exe $target /grant:r `
                '*S-1-5-18:(F)' '*S-1-5-32-544:(M)' 2>&1
            $bootstrapExitCode = $LASTEXITCODE
            if ($bootstrapExitCode -ne 0) {
                $detail = ($bootstrapOutput | ForEach-Object { [string]$_ }) -join ' | '
                throw "Cannot bootstrap SYSTEM access to $target (icacls exit $bootstrapExitCode): $detail"
            }
            $aclOutput = & icacls @aclArgs 2>&1
            $aclExitCode = $LASTEXITCODE
        }
        if ($aclExitCode -ne 0) {
            $aclDetail = ($aclOutput | ForEach-Object { [string]$_ }) -join ' | '
            throw "icacls failed for $mode at $target (exit $aclExitCode): $aclDetail"
        }
        if ($mode -eq 'config_file') {
            # Normalize ownership only after SYSTEM has WRITE_OWNER/FULL rights.
            $ownerOutput = & icacls.exe $target /setowner '*S-1-5-18' 2>&1
            $ownerExitCode = $LASTEXITCODE
            if ($ownerExitCode -ne 0) {
                $ownerDetail = ($ownerOutput | ForEach-Object { [string]$_ }) -join ' | '
                throw "Cannot normalize SYSTEM owner on $target (icacls exit $ownerExitCode): $ownerDetail"
            }
        }
    }

    Apply-AttackLensAcl "$base\config"   'service_data_dir'
    Apply-AttackLensAcl "$base\logs"     'service_data_dir'
    Apply-AttackLensAcl "$base\security" 'secure_dir'
    Apply-AttackLensAcl "$base\spool"    'service_data_dir'
    Apply-AttackLensAcl "$base\data"     'service_data_dir'
    Apply-AttackLensAcl "$base\support"  'service_data_dir'
    Apply-AttackLensAcl "$base\status"   'status_dir'

    # ── Write agent.toml ──────────────────────────────────────────────────────
    $cfg = "$base\config\agent.toml"
    $n   = "`r`n"

    if ((Test-Path -LiteralPath $cfg) -and $preserveState) {
        # Upgrade, repair, and reinstall preserve the operator's complete
        # configuration and identity by default. Set PRESERVE_STATE=0 for an
        # intentional regeneration from MSI properties.
        if ($managerOverrideRequested) {
            $existingToml = [System.IO.File]::ReadAllText($cfg)
            $allowHttpToml = if ($allowHttp) { 'true' } else { 'false' }
            $managerValues = [ordered]@{
                url = (Quote-Toml $managerUrl)
                tls_verify = $tlsVerify
                allow_insecure_transport = $allowHttpToml
            }
            if ($caBundle) {
                $managerValues.ca_bundle = Quote-Toml $caBundle
            }
            if ($spkiPin) {
                $managerValues.spki_pin = Quote-Toml $spkiPin
            }
            $updatedToml = Set-TomlSectionValues $existingToml 'manager' $managerValues
            if ($enrollToken) {
                $updatedToml = Set-TomlSectionValues $updatedToml 'enrollment' `
                    ([ordered]@{ token = (Quote-Toml $enrollToken) })
                $updatedToml = Set-TomlSectionValues $updatedToml 'transport' `
                    ([ordered]@{ auto_reenroll = 'true' })
            }
            if ($agentNameRequested) {
                $updatedToml = Set-TomlSectionValues $updatedToml 'agent' `
                    ([ordered]@{ name = (Quote-Toml $agentName) })
            }
            $tmpCfg = "$cfg.tmp.$([guid]::NewGuid().ToString('N'))"
            $backupCfg = "$cfg.previous"
            [System.IO.File]::WriteAllText($tmpCfg, $updatedToml,
                [System.Text.UTF8Encoding]::new($false))
            [System.IO.File]::Replace($tmpCfg, $cfg, $backupCfg)
            Apply-AttackLensAcl $backupCfg 'config_file'
            Write-InstallerDiagnostic 'Updated explicit manager settings while preserving identity, collection policy, and queued telemetry.'
        } else {
            Write-InstallerDiagnostic 'Preserved existing configuration and repaired its ACL successfully. No manager override was supplied.'
        }
        Apply-AttackLensAcl $cfg 'config_file'
        return
    }

    $toml  = "# AttackLens Windows Agent configuration schema v1${n}"
    $toml += "config_schema = 1${n}${n}"
    $toml += "[agent]${n}"
    $toml += "id   = $(Quote-Toml $agentId)${n}"
    $toml += "name = $(Quote-Toml $agentName)${n}"
    $toml += "${n}"
    $toml += "[manager]${n}"
    $toml += "url         = $(Quote-Toml $managerUrl)${n}"
    $toml += "tls_verify  = $tlsVerify${n}"
    $allowHttpToml = if ($allowHttp) { 'true' } else { 'false' }
    $toml += "allow_insecure_transport = $allowHttpToml${n}"
    if ($caBundle) { $toml += "ca_bundle   = $(Quote-Toml $caBundle)${n}" }
    if ($spkiPin) {
        $pin = if ($spkiPin.StartsWith('sha256//')) { $spkiPin } else { "sha256//$spkiPin" }
        $toml += "spki_pin    = $(Quote-Toml $pin)${n}"
    }
    $toml += "timeout_sec = 30${n}"
    $toml += "proxy_auto_detect = true${n}"
    $toml += "${n}"
    # enrollment.token is consumed on FIRST START only.
    # After enrollment the agent stores the api_key in DPAPI Credential Manager
    # (security\<agent_id>.key.dpapi) and no longer reads the token.
    # To re-enroll: delete security\client.key and restart the service.
    $toml += "[enrollment]${n}"
    $toml += "token    = $(Quote-Toml $enrollToken)${n}"
    $toml += "keystore = `"dpapi`"${n}"
    $toml += "${n}"
    $autoReenrollToml = if ($enrollToken) { 'true' } else { 'false' }
    $toml += "[transport]${n}"
    $toml += "initial_backoff_sec = 5${n}"
    $toml += "max_backoff_sec = 300${n}"
    $toml += "auth_failure_threshold = 3${n}"
    $toml += "auto_reenroll = $autoReenrollToml${n}"
    $toml += "min_free_mb = 128${n}"
    $toml += "outbox_busy_timeout_ms = 5000${n}"
    $toml += "delivery_stall_sec = 300${n}"
    $toml += "${n}"
    $toml += "[paths]${n}"
    $toml += "security_dir = `"C:/ProgramData/AttackLens/security`"${n}"
    $toml += "log_dir      = `"C:/ProgramData/AttackLens/logs`"${n}"
    $toml += "spool_dir    = `"C:/ProgramData/AttackLens/spool`"${n}"
    $toml += "data_dir     = `"C:/ProgramData/AttackLens/data`"${n}"
    $toml += "status_dir   = `"C:/ProgramData/AttackLens/status`"${n}"
    $toml += "${n}"
    $toml += "[logging]${n}"
    $toml += "level   = `"INFO`"${n}"
    $toml += "file    = `"C:/ProgramData/AttackLens/logs/agent.log`"${n}"
    $toml += "max_mb  = 10${n}"
    $toml += "backups = 5${n}"
    $toml += "${n}"

    # Per-section collection intervals (seconds) and enable flags.
    # Disable a section: set enabled = false.  Reduce load: increase interval_sec.
    $sections = [ordered]@{
        metrics     = @{ enabled = 'true';  interval = 10    }
        connections = @{ enabled = 'true';  interval = 10    }
        processes   = @{ enabled = 'true';  interval = 10    }
        ports       = @{ enabled = 'true';  interval = 30    }
        network     = @{ enabled = 'true';  interval = 120   }
        arp         = @{ enabled = 'true';  interval = 60    }
        mounts      = @{ enabled = 'true';  interval = 120   }
        battery     = @{ enabled = 'true';  interval = 120   }
        openfiles   = @{ enabled = 'true';  interval = 120   }
        services    = @{ enabled = 'true';  interval = 120   }
        users       = @{ enabled = 'true';  interval = 120   }
        hardware    = @{ enabled = 'true';  interval = 300   }
        containers  = @{ enabled = 'true';  interval = 120   }
        storage     = @{ enabled = 'true';  interval = 600   }
        tasks       = @{ enabled = 'true';  interval = 600   }
        apps        = @{ enabled = 'true';  interval = 900   }
        packages    = @{ enabled = 'true';  interval = 900   }
        binaries    = @{ enabled = 'true';  interval = 86400 }
        sbom        = @{ enabled = 'true';  interval = 900   }
        security    = @{ enabled = 'true';  interval = 3600  }
        sysctl      = @{ enabled = 'true';  interval = 3600  }
        configs     = @{ enabled = 'true';  interval = 3600  }
        # Continuous CIS-aligned Security Configuration Assessment (hourly)
        sca         = @{ enabled = 'true';  interval = 3600 }
        # Windows-only: Security + System event log (logon, process, service, task events)
        eventlog    = @{ enabled = 'true';  interval = 300   }
        # Native persistence inventory; baseline changes are transactional.
        persistence = @{ enabled = 'true';  interval = 1800  }
        # DeepMesh privacy-safe developer/AI attack-surface snapshot.
        developer_security = @{ enabled = 'true'; interval = 3600 }
        security_audit = @{ enabled = 'true'; interval = 21600 }
    }

    $enabledProfile = @{
        baseline  = @('metrics','services','users','security','eventlog','persistence')
        standard  = @('metrics','connections','processes','ports','network','arp','mounts','battery','openfiles','services','users','hardware','containers','storage','tasks','apps','packages','binaries','sbom','security','sysctl','configs','sca','eventlog','persistence','developer_security','security_audit')
        intensive = @($sections.Keys)
        incident  = @('metrics','connections','processes','network','services','users','security','eventlog','persistence','sca','developer_security','security_audit')
    }[$profile]
    foreach ($name in $sections.Keys) {
        $s     = $sections[$name]
        $profileEnabled = $enabledProfile -contains $name
        if ($profile -eq 'intensive' -and $name -eq 'binaries') { $profileEnabled = $true }
        $toml += "[collection.sections.$name]${n}"
        $enabledToml = if ($profileEnabled) { 'true' } else { 'false' }
        $toml += "enabled      = $enabledToml${n}"
        $toml += "interval_sec = $($s.interval)${n}"
        $toml += "${n}"
    }

    # Atomic replacement prevents the service from observing a partial TOML
    # file if the machine loses power during installation or repair.
    $tmpCfg = "$cfg.tmp.$([guid]::NewGuid().ToString('N'))"
    [System.IO.File]::WriteAllText($tmpCfg, $toml, [System.Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $cfg) {
        [System.IO.File]::Replace($tmpCfg, $cfg, $null)
    } else {
        Move-Item -LiteralPath $tmpCfg -Destination $cfg -Force
    }
    Apply-AttackLensAcl $cfg 'config_file'
    Write-InstallerDiagnostic 'Generated configuration and applied its ACL successfully.'

} catch {
    # Surface the error so the MSI install fails visibly (Return="check" on the CA).
    $msg = "AttackLens gen_config failed: $_"
    Write-InstallerDiagnostic $msg
    try {
        [System.Diagnostics.EventLog]::WriteEntry('Application', $msg,
            [System.Diagnostics.EventLogEntryType]::Error, 1001)
    } catch {}
    throw $msg
}
