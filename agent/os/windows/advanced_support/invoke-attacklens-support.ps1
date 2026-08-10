[CmdletBinding()]
param(
    [ValidateSet('Diagnose', 'Repair', 'Bundle', 'All')]
    [string]$Mode = 'Diagnose',
    [string]$ConfigPath = "$env:ProgramData\AttackLens\config\agent.toml",
    [string]$OutputDirectory = "$env:ProgramData\AttackLens\support"
)

$ErrorActionPreference = 'Stop'
$agentService = 'AttackLensAgent'
$watchdogService = 'AttackLensWatchdog'
$programRoot = Join-Path $env:ProgramData 'AttackLens'
$defaultInstall = Join-Path $env:ProgramFiles 'AttackLens\bin'
$agentExe = Join-Path $defaultInstall 'attacklens-agent\attacklens-agent.exe'
$watchdogExe = Join-Path $defaultInstall 'attacklens-watchdog\attacklens-watchdog.exe'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Sc([string[]]$Arguments) {
    $output = @(& sc.exe @Arguments 2>&1)
    [pscustomobject]@{
        Arguments = $Arguments -join ' '
        ExitCode = $LASTEXITCODE
        Output = @($output | ForEach-Object { [string]$_ })
    }
}

function Get-ServiceEvidence([string]$Name) {
    $service = $null
    $serviceError = $null
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    } catch {
        $serviceError = $_.Exception.Message
    }
    $fallback = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $query = Invoke-Sc @('queryex', $Name)
    $qc = Invoke-Sc @('qc', $Name)
    $failure = Invoke-Sc @('qfailure', $Name)
    [ordered]@{
        name = $Name
        exists = ($null -ne $service) -or ($null -ne $fallback)
        state = if ($service) { $service.State } elseif ($fallback) { [string]$fallback.Status } else { 'missing' }
        start_mode = if ($service) { $service.StartMode } else { $null }
        account = if ($service) { $service.StartName } else { $null }
        path = if ($service) { $service.PathName } else { $null }
        process_id = if ($service) { $service.ProcessId } else { $null }
        cim_error = $serviceError
        query = $query
        configuration = $qc
        failure_policy = $failure
    }
}

function Invoke-AgentDiagnosis {
    if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
        return [ordered]@{ ok = $false; error = "agent executable not found: $agentExe" }
    }
    $previousConfig = [Environment]::GetEnvironmentVariable('ATTACKLENS_CONFIG', 'Process')
    [Environment]::SetEnvironmentVariable('ATTACKLENS_CONFIG', $ConfigPath, 'Process')
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $agentExe diagnose 2>&1)
        $exitCode = $LASTEXITCODE
    } catch {
        return [ordered]@{ ok = $false; error = $_.Exception.Message; exit_code = -1 }
    } finally {
        $ErrorActionPreference = $previousPreference
        [Environment]::SetEnvironmentVariable(
            'ATTACKLENS_CONFIG', $previousConfig, 'Process'
        )
    }
    $outputText = ($output | ForEach-Object { [string]$_ }) -join "`n"
    try {
        $parsed = $outputText | ConvertFrom-Json -AsHashtable
        $parsed['exit_code'] = $exitCode
        return $parsed
    } catch {
        return [ordered]@{
            ok = $false
            exit_code = $exitCode
            output = $outputText
        }
    }
}

function Convert-EventEvidence($Event) {
    $message = try { [string]$Event.Message } catch { '' }
    $rawData = @($Event.Properties | ForEach-Object { [string]$_.Value })
    [ordered]@{
        time_created = $Event.TimeCreated
        id = $Event.Id
        level = $Event.LevelDisplayName
        provider = $Event.ProviderName
        message = $message
        event_data = $rawData
    }
}

function Get-Diagnosis {
    $eventErrors = @()
    try {
        $eventErrors = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 1000 -ErrorAction Stop | Where-Object {
            $message = try { [string]$_.Message } catch { '' }
            $rawData = @($_.Properties | ForEach-Object { [string]$_.Value }) -join ' '
            ($message -match 'AttackLensAgent|AttackLensWatchdog|AttackLens Agent|CA_WriteConfig') -or
            ($rawData -match 'AttackLens|gen_config')
        } | Select-Object -First 100 | ForEach-Object { Convert-EventEvidence $_ })
    } catch {
        $eventErrors = @([pscustomobject]@{ error = $_.Exception.Message })
    }

    $scmEvents = @()
    try {
        $scmEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Service Control Manager'
            Id = 7000, 7001, 7009, 7011, 7023, 7024, 7031, 7034
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 200 -ErrorAction Stop | Where-Object {
            $_.Message -match 'AttackLensAgent|AttackLensWatchdog|AttackLens Agent|AttackLens Watchdog'
        } | Select-Object -First 100 TimeCreated, Id, LevelDisplayName, ProviderName, Message
    } catch {
        $scmEvents = @([pscustomobject]@{ error = $_.Exception.Message })
    }

    $paths = @(
        $ConfigPath,
        (Join-Path $programRoot 'logs'),
        (Join-Path $programRoot 'data'),
        (Join-Path $programRoot 'spool'),
        (Join-Path $programRoot 'security'),
        (Join-Path $programRoot 'logs\installer-config.log'),
        $agentExe,
        $watchdogExe
    )
    $pathEvidence = foreach ($path in $paths) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        $acl = @()
        if ($item) {
            # Native stderr is diagnostic evidence. With the script-wide Stop
            # preference it must not abort all remaining checks.
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $acl = @(
                    (& icacls.exe $path 2>&1) |
                        ForEach-Object { [string]$_ }
                )
                if ($LASTEXITCODE -ne 0) {
                    $acl += "icacls_exit_code=$LASTEXITCODE"
                }
            } catch {
                $acl = @("icacls_error=$($_.Exception.Message)")
            } finally {
                $ErrorActionPreference = $previousPreference
            }
        }
        [ordered]@{
            path = $path
            exists = $null -ne $item
            type = if ($item) { if ($item.PSIsContainer) { 'directory' } else { 'file' } } else { $null }
            length = if ($item -and -not $item.PSIsContainer) { $item.Length } else { $null }
            acl = @($acl)
        }
    }

    $drive = Get-PSDrive -Name ([IO.Path]::GetPathRoot($programRoot).TrimEnd('\').TrimEnd(':')) -ErrorAction SilentlyContinue
    $osEvidence = try {
        Get-CimInstance Win32_OperatingSystem -ErrorAction Stop |
            Select-Object Caption, Version, BuildNumber, LastBootUpTime
    } catch {
        [ordered]@{
            caption = [Environment]::OSVersion.VersionString
            version = [Environment]::OSVersion.Version.ToString()
            error = $_.Exception.Message
        }
    }

    [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        computer = $env:COMPUTERNAME
        elevated = Test-Administrator
        os = $osEvidence
        disk = if ($drive) { [ordered]@{ root = $drive.Root; free_mb = [math]::Floor($drive.Free / 1MB); used_mb = [math]::Floor($drive.Used / 1MB) } } else { $null }
        services = [ordered]@{
            agent = Get-ServiceEvidence $agentService
            watchdog = Get-ServiceEvidence $watchdogService
        }
        paths = @($pathEvidence)
        agent_diagnosis = Invoke-AgentDiagnosis
        installer_diagnostics = if (Test-Path -LiteralPath (Join-Path $programRoot 'logs\installer-config.log')) {
            @(Get-Content -LiteralPath (Join-Path $programRoot 'logs\installer-config.log') -Tail 100)
        } else { @() }
        application_events = @($eventErrors)
        scm_events = @($scmEvents)
        reboot_pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    }
}

function Ensure-Service([string]$Name, [string]$DisplayName, [string]$Binary, [int]$RestartDelay) {
    if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
        throw "Cannot repair $Name because its binary is missing: $Binary"
    }
    if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
        $result = Invoke-Sc @('create', $Name, "binPath=", "`"$Binary`"", 'DisplayName=', $DisplayName, 'start=', 'delayed-auto', 'obj=', 'LocalSystem')
        if ($result.ExitCode -ne 0) { throw "sc.exe create $Name failed: $($result.Output -join ' ')" }
    }
    Invoke-Sc @('config', $Name, "binPath=", "`"$Binary`"", 'start=', 'delayed-auto', 'depend=', '/', 'obj=', 'LocalSystem') | Out-Null
    Invoke-Sc @('failure', $Name, 'reset=', '86400', 'actions=', "restart/$($RestartDelay * 1000)/restart/$($RestartDelay * 1000)/restart/60000") | Out-Null
    Invoke-Sc @('failureflag', $Name, '1') | Out-Null
}

function Invoke-Repair {
    if (-not (Test-Administrator)) { throw 'Repair mode must run from an elevated PowerShell session.' }

    foreach ($directory in @('config', 'logs', 'data', 'spool', 'security', 'support')) {
        New-Item -ItemType Directory -Path (Join-Path $programRoot $directory) -Force | Out-Null
    }
    foreach ($directory in @('config', 'logs', 'data', 'spool', 'security')) {
        $target = Join-Path $programRoot $directory
        & icacls.exe $target /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-20:(OI)(CI)(M)' '*S-1-5-32-544:(OI)(CI)(F)' 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "ACL repair failed for $target" }
    }
    if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
        $aclOutput = @(& icacls.exe $ConfigPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-20:(R)' '*S-1-5-32-544:(M)' 2>&1)
        $aclExitCode = $LASTEXITCODE
        if ($aclExitCode -ne 0) {
            $takeownOutput = @(& takeown.exe /F $ConfigPath /A 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Config ownership recovery failed: $($takeownOutput -join ' | ')"
            }
            & icacls.exe $ConfigPath /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(M)' 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "SYSTEM bootstrap ACL failed for $ConfigPath" }
            $aclOutput = @(& icacls.exe $ConfigPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-20:(R)' '*S-1-5-32-544:(M)' 2>&1)
            $aclExitCode = $LASTEXITCODE
        }
        if ($aclExitCode -ne 0) { throw "Config ACL repair failed: $($aclOutput -join ' | ')" }
        & icacls.exe $ConfigPath /setowner '*S-1-5-18' 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Config owner normalization failed for $ConfigPath" }
    }

    $missingBinaries = @(@($agentExe, $watchdogExe) | Where-Object {
        -not (Test-Path -LiteralPath $_ -PathType Leaf)
    })
    if ($missingBinaries.Count -gt 0) {
        Write-Warning 'ProgramData ACLs were repaired, but installation files are absent after MSI rollback. Re-run the corrected MSI.'
        return
    }

    Ensure-Service $agentService 'AttackLens Agent' $agentExe 10
    Ensure-Service $watchdogService 'AttackLens Watchdog' $watchdogExe 30
    & reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$agentService\Parameters" /v ATTACKLENS_CONFIG /t REG_SZ /d $ConfigPath /f 2>&1 | Out-Null
    $env:ATTACKLENS_CONFIG = $ConfigPath
    & $agentExe repair | Out-Host
    Remove-Item Env:\ATTACKLENS_CONFIG -ErrorAction SilentlyContinue

    Start-Service $agentService
    (Get-Service $agentService).WaitForStatus('Running', [TimeSpan]::FromSeconds(120))
    Start-Service $watchdogService
    (Get-Service $watchdogService).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
}

function New-SupportBundle([System.Collections.IDictionary]$Diagnosis) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $stage = Join-Path ([IO.Path]::GetTempPath()) "attacklens-support-$timestamp"
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        $Diagnosis | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $stage 'diagnosis.json') -Encoding utf8
        $logDir = Join-Path $programRoot 'logs'
        if (Test-Path -LiteralPath $logDir) {
            Copy-Item -LiteralPath $logDir -Destination (Join-Path $stage 'logs') -Recurse -Force
        }
        $target = Join-Path $OutputDirectory "attacklens-support-$timestamp.zip"
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $target -Force
        return $target
    } finally {
        if ($stage.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($Mode -in @('Repair', 'All')) { Invoke-Repair }
$diagnosis = Get-Diagnosis
$diagnosis | ConvertTo-Json -Depth 12
if ($Mode -in @('Bundle', 'All')) {
    $bundle = New-SupportBundle $diagnosis
    Write-Host "Support bundle: $bundle" -ForegroundColor Green
}
