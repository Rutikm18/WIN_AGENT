[CmdletBinding()]
param([switch]$WaitForUpdate)

$ErrorActionPreference = 'Stop'
$statusPath = 'C:\ProgramData\AttackLens\status\agent-status.json'
$deadline = [DateTime]::UtcNow.AddSeconds(30)
do {
    if (Test-Path -LiteralPath $statusPath -PathType Leaf) { break }
    if (-not $WaitForUpdate -or [DateTime]::UtcNow -ge $deadline) { break }
    Start-Sleep -Milliseconds 500
} while ($true)

$services = foreach ($name in @('AttackLensAgent', 'AttackLensWatchdog')) {
    try {
        $service = Get-Service -Name $name -ErrorAction Stop
        [ordered]@{ name = $name; installed = $true; state = [string]$service.Status }
    } catch {
        [ordered]@{ name = $name; installed = $false; state = 'missing' }
    }
}

$agentStatus = $null
$statusError = $null
try {
    if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
        throw "Status file is not present yet: $statusPath"
    }
    $agentStatus = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
} catch {
    $statusError = [string]$_
}

[ordered]@{
    services = @($services)
    runtime_root = 'C:\ProgramData\AttackLens'
    status_file = $statusPath
    agent = $agentStatus
    status_error = $statusError
    admin_diagnostics = 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe diagnose'
} | ConvertTo-Json -Depth 10
