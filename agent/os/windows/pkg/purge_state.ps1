<#
.SYNOPSIS
    Safely removes only the AttackLens Windows agent state directory.

.DESCRIPTION
    This script is installed by the MSI and runs elevated only when the
    administrator explicitly sets PURGE_ON_UNINSTALL=1. It refuses empty,
    rooted, or non-standard paths so a malformed MSI property cannot turn the
    purge action into a broad recursive delete.
#>
$ErrorActionPreference = "Stop"

function Read-MsiValue([string] $Name) {
    $data = [string]$env:MsiCustomActionData
    if ([string]::IsNullOrWhiteSpace($data)) {
        throw "MsiCustomActionData is empty"
    }
    $match = [regex]::Match($data, "(?:^|;)" + [regex]::Escape($Name) + "=([^;]*)")
    if (-not $match.Success) {
        throw "Missing purge property: $Name"
    }
    return $match.Groups[1].Value.Trim().Trim('"')
}

$requested = try {
    Read-MsiValue "D"
} catch {
    # Compatibility with packages that used the original long property name.
    Read-MsiValue "DATA_ROOT"
}
if ([string]::IsNullOrWhiteSpace($requested)) {
    throw "DATA_ROOT is empty; refusing purge"
}

$expectedRoot = Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) "AttackLens"
$expectedFull = [IO.Path]::GetFullPath($expectedRoot).TrimEnd('\')
$requestedFull = [IO.Path]::GetFullPath($requested).TrimEnd('\')

if (-not [string]::Equals($requestedFull, $expectedFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing purge outside the standard AttackLens data root"
}
if ($requestedFull -match '^[A-Za-z]:\\?$' -or $requestedFull -eq '\\') {
    throw "Refusing purge of a filesystem root"
}

if (Test-Path -LiteralPath $requestedFull) {
    Remove-Item -LiteralPath $requestedFull -Recurse -Force -ErrorAction Stop
}

Write-Output "AttackLens state purged: $requestedFull"
