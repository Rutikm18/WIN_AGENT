[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\AttackLens\config\agent.toml',
    [string]$Editor = "$env:SystemRoot\System32\notepad.exe"
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

function Start-AttackLensServices {
    Start-Service -Name AttackLensAgent -ErrorAction Stop
    (Get-Service -Name AttackLensAgent).WaitForStatus(
        'Running', [TimeSpan]::FromSeconds(120)
    )
    Start-Service -Name AttackLensWatchdog -ErrorAction Stop
    (Get-Service -Name AttackLensWatchdog).WaitForStatus(
        'Running', [TimeSpan]::FromSeconds(120)
    )
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

function Write-ExistingFilePreservingSecurity([string]$Path, [byte[]]$Bytes) {
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

function Invoke-ConfigValidation([string]$Path) {
    $previousConfigEnv = $env:ATTACKLENS_CONFIG
    $previousErrorAction = $ErrorActionPreference
    try {
        $env:ATTACKLENS_CONFIG = $Path
        $ErrorActionPreference = 'Continue'
        $output = & $agentExe validate-config 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Configuration validation failed with exit code ${LASTEXITCODE}: $($output -join ' | ')"
        }
    } finally {
        $env:ATTACKLENS_CONFIG = $previousConfigEnv
        $ErrorActionPreference = $previousErrorAction
    }
}

if (-not (Test-Administrator)) {
    throw 'Run PowerShell as Administrator. Standard users cannot redirect or disable the security agent.'
}

$resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath).Path
$resolvedEditor = (Resolve-Path -LiteralPath $Editor).Path
$configDir = Split-Path -Parent $resolvedConfig
$editPath = Join-Path $configDir ("agent.toml.edit-{0}" -f $PID)
$backupPath = Join-Path $configDir 'agent.toml.manual-backup'
$agentExe = 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe'
if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
    throw "Installed agent validator not found: $agentExe"
}

Copy-Item -LiteralPath $resolvedConfig -Destination $editPath -Force
try {
    Write-Host "Editing staged configuration: $editPath" -ForegroundColor Cyan
    Write-Host 'Save the file and close the editor to continue validation.'
    $editorProcess = Start-Process -FilePath $resolvedEditor `
        -ArgumentList ('"{0}"' -f $editPath) -Wait -PassThru
    if ($editorProcess.ExitCode -ne 0) {
        throw "Editor returned exit code $($editorProcess.ExitCode)."
    }

    Invoke-ConfigValidation $editPath

    Stop-AttackLensServices
    Copy-Item -LiteralPath $resolvedConfig -Destination $backupPath -Force
    try {
        Write-ExistingFilePreservingSecurity `
            $resolvedConfig ([IO.File]::ReadAllBytes($editPath))
        Invoke-ConfigValidation $resolvedConfig
        Start-AttackLensServices
    } catch {
        $activationFailure = $_
        try {
            Write-ExistingFilePreservingSecurity `
                $resolvedConfig ([IO.File]::ReadAllBytes($backupPath))
        } catch {
            Write-Warning "Configuration rollback failed: $_"
        }
        try {
            Start-AttackLensServices
        } catch {
            Write-Warning "Could not restore service state after failure: $_"
        }
        throw $activationFailure
    }

    [ordered]@{
        ok = $true
        configuration = $resolvedConfig
        backup = $backupPath
        services = @('AttackLensAgent', 'AttackLensWatchdog')
        note = 'Configuration validated, durably written through the existing file object, and activated without rewriting its ACL.'
    } | ConvertTo-Json -Depth 4
} finally {
    if (Test-Path -LiteralPath $editPath) {
        Remove-Item -LiteralPath $editPath -Force -ErrorAction SilentlyContinue
    }
}
