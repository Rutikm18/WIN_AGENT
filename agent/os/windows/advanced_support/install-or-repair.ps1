[CmdletBinding()]
param(
    [string]$MsiPath = (Join-Path $PSScriptRoot '..\pkg\dist\attacklens-agent-2.0.10-x64.msi'),
    [string]$ManagerUrl = '',
    [switch]$AllowInsecureTransport,
    [string]$LogPath = (Join-Path $env:TEMP 'attacklens-install-2.0.10.log')
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

if (-not (Test-Administrator)) {
    throw 'Open PowerShell with Run as administrator, then run this command again.'
}

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath -ErrorAction Stop).Path
if ([IO.Path]::GetExtension($resolvedMsi) -ne '.msi') {
    throw "MsiPath must reference an MSI file: $resolvedMsi"
}
if ($ManagerUrl) {
    if ($ManagerUrl -match '["\r\n]' -or $ManagerUrl -notmatch '^https?://[^\s]+$') {
        throw 'ManagerUrl must be one HTTP(S) URL without quotes or whitespace.'
    }
    if ($ManagerUrl.StartsWith('http://', [StringComparison]::OrdinalIgnoreCase) -and
            -not $AllowInsecureTransport) {
        throw 'HTTP requires -AllowInsecureTransport. HTTPS is recommended.'
    }
}

$resolvedLog = [IO.Path]::GetFullPath($LogPath)
$logParent = Split-Path -Parent $resolvedLog
New-Item -ItemType Directory -Path $logParent -Force | Out-Null

$supportScript = Join-Path $PSScriptRoot 'invoke-attacklens-support.ps1'
Write-Host 'Repairing preserved AttackLens ACL/state...' -ForegroundColor Cyan
& $supportScript -Mode Repair | Out-Host

$arguments = @(
    '/i', "`"$resolvedMsi`"", '/qn',
    'ACCEPT_EULA=1', 'PRESERVE_STATE=1',
    '/l*v', "`"$resolvedLog`""
)
if ($ManagerUrl) {
    $arguments += "MANAGER_URL=`"$ManagerUrl`""
    if ($AllowInsecureTransport) {
        $arguments += 'ALLOW_INSECURE_TRANSPORT=true'
    }
}

Write-Host 'Installing AttackLens Agent...' -ForegroundColor Cyan
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments `
    -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) {
    Write-Host "Windows Installer failed with exit code $($process.ExitCode)." `
        -ForegroundColor Red
    if (Test-Path -LiteralPath $resolvedLog) {
        Select-String -LiteralPath $resolvedLog -Pattern @(
            'Return value 3', 'Error 1722', 'Error 1920', 'Error 1925',
            'Error 1730', 'must be an Administrator', 'CA_WriteConfig'
        ) | Select-Object -Last 30 | ForEach-Object {
            Write-Host "[$($_.LineNumber)] $($_.Line)" -ForegroundColor Red
        }
    }
    throw "Installation failed. Full log: $resolvedLog"
}

$serviceResults = foreach ($name in @('AttackLensAgent', 'AttackLensWatchdog')) {
    $service = Get-Service -Name $name -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        Start-Service -Name $name -ErrorAction Stop
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(120))
        $service.Refresh()
    }
    [ordered]@{ name = $name; status = [string]$service.Status }
}

[ordered]@{
    ok = $true
    msi = $resolvedMsi
    log = $resolvedLog
    services = @($serviceResults)
    preserved_state = $true
} | ConvertTo-Json -Depth 5
