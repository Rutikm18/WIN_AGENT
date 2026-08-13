<#
.SYNOPSIS
    Verify compiled AttackLens MSI contracts after WiX linking.

.DESCRIPTION
    Reads the MSI database without installing it and verifies product metadata,
    EULA enforcement/content, secure public properties, service ordering, file
    coverage, architecture, and (for release mode) Authenticode identity and
    timestamp state.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $MsiPath,
    [Parameter(Mandatory = $true)][string] $ManifestPath,
    [Parameter(Mandatory = $true)][string] $ExpectedVersion,
    [switch] $RequireSignature,
    [string] $ExpectedThumbprint = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.GetType().InvokeMember(
    "OpenDatabase", "InvokeMethod", $null, $installer, @($resolvedMsi, 0)
)

function Invoke-MsiQuery {
    param(
        [Parameter(Mandatory = $true)][string] $Sql,
        [Parameter(Mandatory = $true)][int] $ColumnCount
    )

    $view = $database.GetType().InvokeMember(
        "OpenView", "InvokeMethod", $null, $database, @($Sql)
    )
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $view.GetType().InvokeMember(
            "Execute", "InvokeMethod", $null, $view, $null
        ) | Out-Null
        while ($true) {
            $record = $view.GetType().InvokeMember(
                "Fetch", "InvokeMethod", $null, $view, $null
            )
            if ($null -eq $record) { break }
            $row = [ordered]@{}
            for ($index = 1; $index -le $ColumnCount; $index++) {
                $row["C$index"] = $record.GetType().InvokeMember(
                    "StringData", "GetProperty", $null, $record, $index
                )
            }
            $rows.Add([pscustomobject] $row)
        }
    } finally {
        $view.GetType().InvokeMember(
            "Close", "InvokeMethod", $null, $view, $null
        ) | Out-Null
    }
    return $rows.ToArray()
}

function Get-MsiProperty {
    param([Parameter(Mandatory = $true)][string] $Name)
    $escaped = $Name.Replace("'", "''")
    $rows = @(Invoke-MsiQuery `
        -Sql "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$escaped'" `
        -ColumnCount 1)
    if ($rows.Count -eq 0) { return $null }
    if ($rows.Count -ne 1) { throw "Duplicate MSI property: $Name" }
    return [string] $rows[0].C1
}

$expectedProperties = [ordered]@{
    ProductName = "AttackLens Agent"
    ProductVersion = $ExpectedVersion
    Manufacturer = "AttackLens"
    ALLUSERS = "1"
    MANAGER_PORT = "8080"
    TLS_VERIFY = "false"
    ALLOW_INSECURE_TRANSPORT = "true"
}
foreach ($entry in $expectedProperties.GetEnumerator()) {
    $actual = Get-MsiProperty -Name $entry.Key
    if ($actual -ne $entry.Value) {
        throw "MSI property $($entry.Key) expected '$($entry.Value)', found '$actual'."
    }
}
if ($null -ne (Get-MsiProperty -Name "MANAGER_IP")) {
    throw "MANAGER_IP must not have a compiled localhost/default value."
}

$secureProperties = ";$(Get-MsiProperty -Name 'SecureCustomProperties');"
foreach ($name in @(
    "ACCEPT_EULA", "ATTACKLENS_CONFIG_DATA", "ENROLL_TOKEN", "MANAGER_IP", "MANAGER_PORT",
    "MANAGER_URL", "TLS_VERIFY"
)) {
    if ($secureProperties -notlike "*;$name;*") {
        throw "SecureCustomProperties is missing $name."
    }
}
$hiddenProperties = ";$(Get-MsiProperty -Name 'MsiHiddenProperties');"
foreach ($name in @('ATTACKLENS_CONFIG_DATA', 'ENROLL_TOKEN')) {
    if ($hiddenProperties -notlike "*;$name;*") {
        throw "MsiHiddenProperties is missing $name."
    }
}

$launchRows = @(Invoke-MsiQuery `
    -Sql "SELECT ``Condition``,``Description`` FROM ``LaunchCondition``" `
    -ColumnCount 2)
$eulaLaunch = @($launchRows | Where-Object {
    $_.C1 -like "*UILevel = 5*" -and $_.C1 -like "*ACCEPT_EULA = *1*"
})
if ($eulaLaunch.Count -ne 1) {
    throw "Compiled MSI does not enforce ACCEPT_EULA for unattended installs."
}

$dialogRows = @(Invoke-MsiQuery -Sql "SELECT ``Dialog`` FROM ``Dialog``" -ColumnCount 1)
if (@($dialogRows | Where-Object { $_.C1 -eq "LicenseAgreementDlg" }).Count -ne 1) {
    throw "LicenseAgreementDlg is missing from the compiled MSI."
}
$licenseRows = @(Invoke-MsiQuery -Sql (
    "SELECT ``Control``,``Type``,``Text`` FROM ``Control`` " +
    "WHERE ``Dialog_``='LicenseAgreementDlg'"
) -ColumnCount 3)
$licenseControl = @($licenseRows | Where-Object {
    $_.C1 -eq "LicenseText" -and $_.C2 -eq "ScrollableText"
})
if ($licenseControl.Count -ne 1 -or
        $licenseControl[0].C3 -notlike "*AttackLens Software License Agreement*") {
    throw "AttackLens RTF license text is not embedded in LicenseAgreementDlg."
}

$serviceRows = @(Invoke-MsiQuery -Sql (
    "SELECT ``Name``,``Dependencies``,``StartType``,``ErrorControl`` " +
    "FROM ``ServiceInstall``"
) -ColumnCount 4)
$agentService = @($serviceRows | Where-Object { $_.C1 -eq "AttackLensAgent" })
$watchdogService = @($serviceRows | Where-Object { $_.C1 -eq "AttackLensWatchdog" })
if ($agentService.Count -ne 1 -or $watchdogService.Count -ne 1) {
    throw "Both AttackLens Windows services must be present exactly once."
}
foreach ($service in @($agentService[0], $watchdogService[0])) {
    if (-not [string]::IsNullOrWhiteSpace([string] $service.C2)) {
        throw "Service $($service.C1) must not have SCM dependencies; found '$($service.C2)'."
    }
    if ([int] $service.C3 -ne 2) {
        throw "Service $($service.C1) must compile as automatic start; found StartType=$($service.C3)."
    }
}

$serviceRegistryRows = @(Invoke-MsiQuery -Sql (
    "SELECT ``Root``,``Key``,``Name``,``Value`` FROM ``Registry`` " +
    "WHERE ``Name``='DelayedAutostart' OR ``Name``='PreshutdownTimeout'"
) -ColumnCount 4)
foreach ($serviceName in @('AttackLensAgent', 'AttackLensWatchdog')) {
    $serviceKey = "SYSTEM\CurrentControlSet\Services\$serviceName"
    $delayedRows = @($serviceRegistryRows | Where-Object {
        [int] $_.C1 -eq 2 -and $_.C2 -eq $serviceKey -and
        $_.C3 -eq 'DelayedAutostart' -and $_.C4 -eq '#1'
    })
    if ($delayedRows.Count -ne 1) {
        throw "Compiled MSI must enable delayed auto-start once for $serviceName."
    }
}
$preshutdownRows = @($serviceRegistryRows | Where-Object {
    [int] $_.C1 -eq 2 -and
    $_.C2 -eq 'SYSTEM\CurrentControlSet\Services\AttackLensAgent' -and
    $_.C3 -eq 'PreshutdownTimeout' -and $_.C4 -eq '#180000'
})
if ($preshutdownRows.Count -ne 1) {
    throw 'Compiled MSI must grant AttackLensAgent a 180-second preshutdown timeout.'
}

$customActionRows = @(Invoke-MsiQuery -Sql (
    "SELECT ``Action``,``Source``,``Target``,``Type`` FROM ``CustomAction``"
) -ColumnCount 4)
$prepareConfig = @($customActionRows | Where-Object {
    $_.C1 -eq 'CA_PrepareWriteConfig'
})
if ($prepareConfig.Count -ne 1) {
    throw 'Compiled MSI must prepare GUI properties for CA_WriteConfig exactly once.'
}
 $stageConfig = @($customActionRows | Where-Object {
    $_.C1 -eq 'CA_StageWriteConfigUI'
})
if ($stageConfig.Count -ne 1 -or
        $stageConfig[0].C2 -ne 'PrepareConfigDataScript' -or
        $stageConfig[0].C3 -ne 'StageConfigDataFromUI') {
    throw 'Compiled MSI must securely stage full-UI properties exactly once.'
}
$stagedDefault = Get-MsiProperty -Name 'ATTACKLENS_CONFIG_DATA'
if (-not [string]::IsNullOrEmpty($stagedDefault)) {
    throw 'ATTACKLENS_CONFIG_DATA must not have a compiled value.'
}
$uiSequenceRows = @(Invoke-MsiQuery -Sql (
    "SELECT ``Action``,``Condition``,``Sequence`` FROM ``InstallUISequence``"
) -ColumnCount 3)
$uiStage = @($uiSequenceRows | Where-Object { $_.C1 -eq 'CA_StageWriteConfigUI' })
if ($uiStage.Count -ne 1) {
    throw 'CA_StageWriteConfigUI must run in the full UI sequence.'
}
$progressDialog = @($uiSequenceRows | Where-Object { $_.C1 -eq 'ProgressDlg' })
$executeAction = @($uiSequenceRows | Where-Object { $_.C1 -eq 'ExecuteAction' })
if ($progressDialog.Count -ne 1 -or $executeAction.Count -ne 1 -or
        [int]$uiStage[0].C3 -le [int]$progressDialog[0].C3 -or
        [int]$uiStage[0].C3 -ge [int]$executeAction[0].C3) {
    throw 'GUI configuration must be captured after ProgressDlg and before ExecuteAction.'
}
if ($prepareConfig[0].C2 -ne 'PrepareConfigDataScript' -or
        $prepareConfig[0].C3 -ne 'PrepareConfigData') {
    throw 'GUI property bridge must use the Binary-table JScript function target.'
}
foreach ($actionName in @('CA_WriteConfig', 'CA_PurgeState')) {
    $action = @($customActionRows | Where-Object { $_.C1 -eq $actionName })
    if ($action.Count -ne 1) {
        throw "Compiled MSI must contain custom action $actionName exactly once."
    }
    if (-not ([string] $action[0].C3).Contains(
            '[System64Folder]WindowsPowerShell\v1.0\powershell.exe')) {
        throw "$actionName must use 64-bit PowerShell from System64Folder."
    }
}
$writeConfig = @($customActionRows | Where-Object { $_.C1 -eq 'CA_WriteConfig' })[0]
if (-not ([string]$writeConfig.C3).Contains(
        '-EncodedCustomActionData "[CustomActionData]"')) {
    throw 'CA_WriteConfig does not explicitly consume deferred CustomActionData.'
}
if ((([int]$writeConfig.C4) -band 0x2000) -eq 0) {
    throw 'CA_WriteConfig must hide its target because it can contain an enrollment token.'
}
$agentRecovery = @($customActionRows | Where-Object {
    $_.C1 -eq 'CA_SetAgentRecoveryActions'
})
if ($agentRecovery.Count -ne 1) {
    throw 'Compiled MSI must configure graduated agent recovery actions exactly once.'
}
$agentRecoveryTarget = [string] $agentRecovery[0].C3
foreach ($requiredFragment in @(
    'failure AttackLensAgent',
    'reset= 86400',
    'actions= restart/5000/restart/10000/restart/30000'
)) {
    if (-not $agentRecoveryTarget.Contains($requiredFragment)) {
        throw "Compiled agent recovery action is missing: $requiredFragment"
    }
}
$agentFailureFlag = @($customActionRows | Where-Object {
    $_.C1 -eq 'CA_SetAgentFailureFlag'
})
if ($agentFailureFlag.Count -ne 1 -or
        -not ([string] $agentFailureFlag[0].C3).Contains(
            'failureflag AttackLensAgent 1')) {
    throw 'Compiled MSI must apply agent recovery actions to non-crash failures.'
}
foreach ($serviceName in @('Agent', 'Watchdog')) {
    $actionName = "CA_Set${serviceName}DelayedAutoStart"
    $serviceScmName = if ($serviceName -eq 'Agent') {
        'AttackLensAgent'
    } else {
        'AttackLensWatchdog'
    }
    $delayedAction = @($customActionRows | Where-Object {
        $_.C1 -eq $actionName
    })
    if ($delayedAction.Count -ne 1 -or
            -not ([string] $delayedAction[0].C3).Contains(
                "config $serviceScmName start= delayed-auto")) {
        throw "Compiled MSI must explicitly enable delayed auto-start for $serviceScmName."
    }
}
$executeSequenceRows = @(Invoke-MsiQuery -Sql (
    "SELECT ``Action``,``Condition``,``Sequence`` FROM ``InstallExecuteSequence``"
) -ColumnCount 3)
$configureServices = @($executeSequenceRows | Where-Object {
    $_.C1 -eq 'MsiConfigureServices'
})
$agentDelayedSequence = @($executeSequenceRows | Where-Object {
    $_.C1 -eq 'CA_SetAgentDelayedAutoStart'
})
$watchdogDelayedSequence = @($executeSequenceRows | Where-Object {
    $_.C1 -eq 'CA_SetWatchdogDelayedAutoStart'
})
$recoverySequence = @($executeSequenceRows | Where-Object {
    $_.C1 -eq 'CA_SetAgentRecoveryActions'
})
$failureFlagSequence = @($executeSequenceRows | Where-Object {
    $_.C1 -eq 'CA_SetAgentFailureFlag'
})
$startServices = @($executeSequenceRows | Where-Object {
    $_.C1 -eq 'StartServices'
})
if ($configureServices.Count -ne 1 -or $agentDelayedSequence.Count -ne 1 -or
        $watchdogDelayedSequence.Count -ne 1 -or $recoverySequence.Count -ne 1 -or
        $failureFlagSequence.Count -ne 1 -or $startServices.Count -ne 1 -or
        [int] $agentDelayedSequence[0].C3 -le [int] $configureServices[0].C3 -or
        [int] $watchdogDelayedSequence[0].C3 -le [int] $agentDelayedSequence[0].C3 -or
        [int] $recoverySequence[0].C3 -le [int] $watchdogDelayedSequence[0].C3 -or
        [int] $failureFlagSequence[0].C3 -le [int] $recoverySequence[0].C3 -or
        [int] $failureFlagSequence[0].C3 -ge [int] $startServices[0].C3) {
    throw ('Delayed-auto-start and recovery policies must run after ' +
        'MsiConfigureServices and before StartServices in dependency order.')
}
foreach ($service in @($agentService[0], $watchdogService[0])) {
    if ($service.C3 -ne "2") { throw "Service $($service.C1) is not automatic." }
    if (([int] $service.C4 -band 0x8000) -eq 0) {
        throw "Service $($service.C1) is not authored as vital."
    }
}

$manifest = Get-Content -LiteralPath $resolvedManifest -Raw | ConvertFrom-Json
$manifestEntries = @($manifest.files.PSObject.Properties)
if ($manifestEntries.Count -lt 3) {
    throw "Install manifest does not cover the frozen payload."
}
$fileRows = @(Invoke-MsiQuery -Sql "SELECT ``File``,``FileName`` FROM ``File``" -ColumnCount 2)
$expectedMsiFiles = $manifestEntries.Count + 7  # manifest + five tools/readme assets
if ($fileRows.Count -ne $expectedMsiFiles) {
    throw "MSI File table has $($fileRows.Count) rows; expected $expectedMsiFiles."
}
$longFileNames = @($fileRows | ForEach-Object {
    ([string] $_.C2).Split('|')[-1]
})
foreach ($requiredFile in @(
    'gen_config.ps1', 'purge_state.ps1', 'configure-manager.ps1',
    'attacklens-status.ps1', 'edit-agent-config.ps1',
    'RUNTIME_LOCATION.txt', 'install-manifest.json'
)) {
    if ($requiredFile -notin $longFileNames) {
        throw "Compiled MSI is missing required operator/runtime asset: $requiredFile"
    }
}

# Verify the CAB payload byte-for-byte, not only File-table names. This catches
# stale build directories or a WiX source path that packages an older operator
# tool even when the working-tree script and static tests are correct.
$wixCommand = Get-Command wix -ErrorAction Stop
$verificationRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'attacklens-msi-payload-' + [guid]::NewGuid().ToString('N')
)
$extractionRoot = Join-Path $verificationRoot 'extract'
$decompiledWxs = Join-Path $verificationRoot 'payload.wxs'
New-Item -ItemType Directory -Path $verificationRoot | Out-Null
try {
    $decompileOutput = & $wixCommand.Source msi decompile $resolvedMsi `
        -x $extractionRoot -o $decompiledWxs -sct 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to extract compiled MSI payload: $($decompileOutput -join ' | ')"
    }

    $payloadContracts = [ordered]@{
        'File\ConfigGeneratorScript' = (Join-Path $PSScriptRoot 'pkg\gen_config.ps1')
        'File\ConfigureManagerScript' = (Join-Path $PSScriptRoot 'pkg\configure-manager.ps1')
        'File\EditAgentConfigScript' = (Join-Path $PSScriptRoot 'pkg\edit-agent-config.ps1')
        'File\AgentStatusScript' = (Join-Path $PSScriptRoot 'pkg\attacklens-status.ps1')
        'File\PurgeStateScript' = (Join-Path $PSScriptRoot 'pkg\purge_state.ps1')
        'File\RuntimeLocationReadme' = (Join-Path $PSScriptRoot 'pkg\RUNTIME_LOCATION.txt')
        'Binary\PrepareConfigDataScript' = (Join-Path $PSScriptRoot 'pkg\prepare_config_data.js')
    }
    foreach ($contract in $payloadContracts.GetEnumerator()) {
        $extractedPath = Join-Path $extractionRoot $contract.Key
        $sourcePath = $contract.Value
        if (-not (Test-Path -LiteralPath $extractedPath -PathType Leaf)) {
            throw "Compiled MSI extraction is missing payload $($contract.Key)."
        }
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Expected payload source is missing: $sourcePath"
        }
        $actualHash = (Get-FileHash -LiteralPath $extractedPath -Algorithm SHA256).Hash
        $expectedHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
        if ($actualHash -ne $expectedHash) {
            throw "Compiled payload $($contract.Key) is stale: expected $expectedHash, found $actualHash."
        }
    }
} finally {
    $expectedTempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedVerificationRoot = [IO.Path]::GetFullPath($verificationRoot)
    if ($resolvedVerificationRoot.StartsWith(
            $expectedTempPrefix,
            [StringComparison]::OrdinalIgnoreCase
        ) -and (Split-Path -Leaf $resolvedVerificationRoot) -like 'attacklens-msi-payload-*') {
        Remove-Item -LiteralPath $resolvedVerificationRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}

$summary = $installer.GetType().InvokeMember(
    "SummaryInformation", "GetProperty", $null, $installer, @($resolvedMsi, 0)
)
$template = [string] $summary.GetType().InvokeMember(
    "Property", "GetProperty", $null, $summary, 7
)
if ($template -notlike "x64;*") {
    throw "MSI template is not x64: $template"
}

$signature = Get-AuthenticodeSignature -LiteralPath $resolvedMsi
if ($RequireSignature) {
    $thumbprint = ($ExpectedThumbprint -replace '\s', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "ExpectedThumbprint is required for signed release verification."
    }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "MSI Authenticode signature is not valid: $($signature.Status)"
    }
    if (-not $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $thumbprint) {
        throw "MSI signer thumbprint does not match the release certificate."
    }
    if (-not $signature.TimeStamperCertificate) {
        throw "MSI signature is not timestamped."
    }
}

[pscustomobject]@{
    msi = $resolvedMsi
    version = $ExpectedVersion
    architecture = "x64"
    file_rows = $fileRows.Count
    manifest_entries = $manifestEntries.Count
    license_embedded = $true
    unattended_eula_required = $true
    services_dependency_free = $true
    configuration_uses_64bit_powershell = $true
    signature = [string] $signature.Status
}
