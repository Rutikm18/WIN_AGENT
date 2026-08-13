<#
.SYNOPSIS
    Build and validate the complete AttackLens Windows Agent MSI.

.DESCRIPTION
    This is the single operator entry point for Windows MSI production. It:
      1. validates the PowerShell build scripts and required tools;
      2. runs the Windows agent unit tests;
      3. regenerates the installer icon and WiX UI artwork;
      4. builds the agent and watchdog executables;
      5. builds and validates the MSI; and
      6. prints the final path, size, signature state, and SHA-256 hash.

    Supply -Release and -SignThumbprint for a release build. Both service
    executables are signed before they are packaged, then the final MSI is
    signed. Release mode is fail-closed: tests and executable builds cannot be
    skipped, the certificate must chain successfully, and every signature must
    include an RFC 3161 timestamp.

.PARAMETER Version
    Three-part MSI product version. Default: 2.0.25.

.PARAMETER SignThumbprint
    SHA-1 thumbprint of an Authenticode code-signing certificate in the
    CurrentUser or LocalMachine Personal certificate store.

.PARAMETER Release
    Require a production release build. This requires SignThumbprint and
    rejects SkipTests and SkipExecutableBuild.

.PARAMETER TimestampUrl
    RFC 3161 timestamp service used by SignTool.

.PARAMETER SkipTests
    Skip the Python unit-test suite.

.PARAMETER SkipExecutableBuild
    Reuse the existing PyInstaller output and rebuild only the MSI. Intended
    for packaging diagnostics, not normal release builds.

.PARAMETER SkipDefenderScan
    Skip the Microsoft Defender custom scan for development diagnostics.
    Release builds cannot skip this scan.

.EXAMPLE
    .\build_windows_msi.ps1

.EXAMPLE
    .\build_windows_msi.ps1 -Version 2.0.25

.EXAMPLE
    .\build_windows_msi.ps1 -Version 2.1.0 -Release `
        -SignThumbprint "0123456789ABCDEF0123456789ABCDEF01234567"
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')]
    [string] $Version = "2.0.25",

    [string] $SignThumbprint = "",

    [switch] $Release,

    [ValidatePattern('^https?://[^\s]+$')]
    [string] $TimestampUrl = "http://timestamp.digicert.com",

    [switch] $SkipTests,

    [switch] $SkipExecutableBuild,

    [switch] $SkipDefenderScan
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$windowsDir = $PSScriptRoot
$rootDir = (Resolve-Path -LiteralPath (Join-Path $windowsDir "..\..\..")).Path
$pkgDir = Join-Path $windowsDir "pkg"
$distDir = Join-Path $pkgDir "dist"
$assetsDir = Join-Path $pkgDir "assets"
$msiBuildScript = Join-Path $pkgDir "build_msi.ps1"
$exeBuildScript = Join-Path $pkgDir "build_exe.ps1"
$brandBuildScript = Join-Path $pkgDir "generate_brand_assets.ps1"
$verifyMsiScript = Join-Path $windowsDir "verify_built_msi.ps1"
$msiPath = Join-Path $distDir "attacklens-agent-$Version-x64.msi"
$agentExe = Join-Path $distDir "attacklens-agent\attacklens-agent.exe"
$watchdogExe = Join-Path $distDir "attacklens-watchdog\attacklens-watchdog.exe"
$timestampUrl = $TimestampUrl

$versionParts = @($Version.Split('.') | ForEach-Object { [int] $_ })
if ($versionParts.Count -ne 3 -or
        $versionParts[0] -gt 255 -or
        $versionParts[1] -gt 255 -or
        $versionParts[2] -gt 65535) {
    throw "Version must be major.minor.build with major/minor <= 255 and build <= 65535."
}
$cleanThumbprint = ($SignThumbprint -replace '\s', '').ToUpperInvariant()
$isRelease = $Release -or [bool] $cleanThumbprint
if ($Release -and -not $cleanThumbprint) {
    throw "Release builds require -SignThumbprint. Unsigned output is development-only."
}
if ($isRelease -and $SkipTests) {
    throw "Release builds cannot use -SkipTests."
}
if ($isRelease -and $SkipExecutableBuild) {
    throw "Release builds cannot use -SkipExecutableBuild; binaries must be rebuilt and signed in this run."
}
if ($isRelease -and $SkipDefenderScan) {
    throw "Release builds cannot use -SkipDefenderScan."
}
if ($cleanThumbprint -and $cleanThumbprint -notmatch '^[0-9A-F]{40}$') {
    throw "SignThumbprint must be a 40-character SHA-1 certificate thumbprint."
}

function Write-Step {
    param([Parameter(Mandatory = $true)][string] $Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Write-Ok {
    param([Parameter(Mandatory = $true)][string] $Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [Parameter(Mandatory = $true)][object[]] $ArgumentList,
        [Parameter(Mandatory = $true)][string] $FailureMessage
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)"
    }
}

function Resolve-Python313 {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($env:ATTACKLENS_PYTHON) {
        $candidates.Add($env:ATTACKLENS_PYTHON)
    }
    if ($env:LOCALAPPDATA) {
        $candidates.Add(
            (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe")
        )
    }
    if ($env:ProgramFiles) {
        $candidates.Add((Join-Path $env:ProgramFiles "Python313\python.exe"))
    }

    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($pythonCommand -and $pythonCommand.Source) {
        $candidates.Add($pythonCommand.Source)
    }

    foreach ($candidate in $candidates) {
        if (-not $candidate -or $candidate -match '\\WindowsApps\\') {
            continue
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf `
                -ErrorAction SilentlyContinue)) {
            continue
        }

        $resolved = (Resolve-Path -LiteralPath $candidate).Path
        $detectedVersion = & $resolved -c `
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
        if ($LASTEXITCODE -eq 0 -and $detectedVersion -eq "3.13") {
            return $resolved
        }
    }

    throw "Python 3.13 was not found. Set ATTACKLENS_PYTHON to python.exe."
}

function Resolve-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command -and $command.Source) {
        return $command.Source
    }

    $kitsRoot = ${env:ProgramFiles(x86)}
    if ($kitsRoot) {
        $sdkBin = Join-Path $kitsRoot "Windows Kits\10\bin"
        if (Test-Path -LiteralPath $sdkBin -PathType Container) {
            $versionDirs = Get-ChildItem -LiteralPath $sdkBin -Directory |
                Sort-Object Name -Descending
            foreach ($versionDir in $versionDirs) {
                $candidate = Join-Path $versionDir.FullName "x64\signtool.exe"
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return $candidate
                }
            }
        }
    }

    throw "signtool.exe was not found. Install the Windows SDK signing tools."
}

function Resolve-DefenderScanner {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($env:ProgramData) {
        $platformRoot = Join-Path $env:ProgramData "Microsoft\Windows Defender\Platform"
        if (Test-Path -LiteralPath $platformRoot -PathType Container) {
            foreach ($platformDir in Get-ChildItem -LiteralPath $platformRoot -Directory |
                    Sort-Object Name -Descending) {
                $candidates.Add((Join-Path $platformDir.FullName "MpCmdRun.exe"))
            }
        }
    }
    if ($env:ProgramFiles) {
        $candidates.Add((Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"))
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Invoke-DefenderArtifactScan {
    param(
        [Parameter(Mandatory = $true)][string] $Scanner,
        [Parameter(Mandatory = $true)][string[]] $Paths
    )

    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Defender scan target not found: $path"
        }
        Write-Host "  Scanning $([IO.Path]::GetFileName($path))..."
        Invoke-Checked -FilePath $Scanner -ArgumentList @(
            "-Scan", "-ScanType", "3", "-File", $path,
            "-DisableRemediation"
        ) -FailureMessage "Microsoft Defender rejected or could not scan $path"
        Write-Ok "Microsoft Defender found no threat: $([IO.Path]::GetFileName($path))"
    }
}

function Resolve-SigningCertificate {
    param([Parameter(Mandatory = $true)][string] $Thumbprint)

    $certificateMatches = New-Object System.Collections.Generic.List[object]
    foreach ($location in @("CurrentUser", "LocalMachine")) {
        $storePath = "Cert:\$location\My"
        if (-not (Test-Path -LiteralPath $storePath)) {
            continue
        }
        foreach ($certificate in Get-ChildItem -LiteralPath $storePath) {
            $candidateThumbprint = ($certificate.Thumbprint -replace '\s', '').ToUpperInvariant()
            if ($candidateThumbprint -eq $Thumbprint) {
                $certificateMatches.Add([pscustomobject]@{
                    Certificate = $certificate
                    StoreLocation = $location
                })
            }
        }
    }

    if ($certificateMatches.Count -ne 1) {
        throw "SignThumbprint must match exactly one certificate in CurrentUser or LocalMachine Personal stores; found $($certificateMatches.Count)."
    }

    $match = $certificateMatches[0]
    $certificate = $match.Certificate
    $now = Get-Date
    if (-not $certificate.HasPrivateKey) {
        throw "The code-signing certificate does not have an accessible private key."
    }
    if ($now -lt $certificate.NotBefore -or $now -gt $certificate.NotAfter) {
        throw "The code-signing certificate is not currently valid."
    }
    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $ekuOids = @($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    if ($codeSigningOid -notin $ekuOids) {
        throw "The selected certificate is not valid for Code Signing."
    }

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag =
            [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags =
            [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.ApplicationPolicy.Add(
            [Security.Cryptography.Oid]::new($codeSigningOid)
        )
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        if (-not $chain.Build($certificate)) {
            $details = @($chain.ChainStatus | ForEach-Object {
                "$($_.Status): $($_.StatusInformation.Trim())"
            }) -join "; "
            throw "The code-signing certificate chain is not trusted: $details"
        }
    } finally {
        $chain.Dispose()
    }

    return $match
}

function Invoke-AuthenticodeSign {
    param(
        [Parameter(Mandatory = $true)][string] $SignTool,
        [Parameter(Mandatory = $true)][string] $Thumbprint,
        [Parameter(Mandatory = $true)]
        [ValidateSet("CurrentUser", "LocalMachine")]
        [string] $StoreLocation,
        [Parameter(Mandatory = $true)][string[]] $Paths
    )

    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Signing target not found: $path"
        }

        Write-Host "  Signing $([IO.Path]::GetFileName($path))..."
        $signArguments = @(
            "sign",
            "/s", "My",
            "/sha1", $Thumbprint,
            "/fd", "SHA256",
            "/tr", $timestampUrl,
            "/td", "SHA256",
            "/v",
            $path
        )
        if ($StoreLocation -eq "LocalMachine") {
            $signArguments = @("sign", "/sm") + $signArguments[1..($signArguments.Count - 1)]
        }
        Invoke-Checked -FilePath $SignTool -ArgumentList $signArguments `
            -FailureMessage "Authenticode signing failed for $path"

        Invoke-Checked -FilePath $SignTool -ArgumentList @(
            "verify", "/pa", "/all", "/tw", "/v", $path
        ) -FailureMessage "Independent Authenticode verification failed for $path"

        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "Signature verification failed for ${path}: $($signature.Status)"
        }
        if (-not $signature.SignerCertificate -or
                $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $Thumbprint) {
            throw "Signature signer mismatch for $path"
        }
        if (-not $signature.TimeStamperCertificate) {
            throw "The signature is missing an RFC 3161 timestamp: $path"
        }
        Write-Ok "Valid signature: $([IO.Path]::GetFileName($path))"
    }
}

if ($env:OS -ne "Windows_NT") {
    throw "This build entry point must run on Windows."
}

Write-Host ""
Write-Host "  AttackLens Windows MSI Builder" -ForegroundColor Cyan
Write-Host "  Version : $Version" -ForegroundColor DarkGray
Write-Host "  Root    : $rootDir" -ForegroundColor DarkGray
Write-Host ""

Write-Step "Preflight"
foreach ($requiredScript in @(
    $msiBuildScript,
    $exeBuildScript,
    $brandBuildScript,
    $verifyMsiScript
)) {
    if (-not (Test-Path -LiteralPath $requiredScript -PathType Leaf)) {
        throw "Required build script not found: $requiredScript"
    }
}

$wixCommand = Get-Command wix.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $wixCommand) {
    $wixCommand = Get-Command wix -ErrorAction SilentlyContinue |
        Select-Object -First 1
}
if (-not $wixCommand -or -not $wixCommand.Source) {
    throw "WiX Toolset was not found on PATH."
}
$wixExe = $wixCommand.Source
Write-Ok "WiX Toolset: $wixExe"

$pythonExe = Resolve-Python313
Write-Ok "Python 3.13: $pythonExe"

$signTool = $null
$signingCertificate = $null
if ($cleanThumbprint) {
    $signTool = Resolve-SignTool
    Write-Ok "Windows signing tool: $signTool"
    $signingCertificate = Resolve-SigningCertificate -Thumbprint $cleanThumbprint
    Write-Ok (
        "Trusted code-signing certificate: {0} ({1}\\My)" -f
        $signingCertificate.Certificate.Subject,
        $signingCertificate.StoreLocation
    )
} else {
    Write-Host "  Signing: disabled (development MSI)" -ForegroundColor Yellow
}
$defenderScanner = Resolve-DefenderScanner
if (-not $SkipDefenderScan -and -not $defenderScanner) {
    if ($isRelease) {
        throw "Microsoft Defender MpCmdRun.exe is required for release artifact scanning."
    }
    Write-Host "  Defender scan: unavailable (development build)" -ForegroundColor Yellow
} elseif ($defenderScanner) {
    Write-Ok "Microsoft Defender scanner: $defenderScanner"
}

Write-Step "PowerShell syntax validation"
$scriptFiles = @(
    Get-ChildItem -LiteralPath $windowsDir -File -Filter "*.ps1"
    Get-ChildItem -LiteralPath (Join-Path $windowsDir "installer") `
        -File -Filter "*.ps1"
    Get-ChildItem -LiteralPath $pkgDir -File -Filter "*.ps1"
)
$syntaxFailures = New-Object System.Collections.Generic.List[string]
foreach ($scriptFile in $scriptFiles) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $scriptFile.FullName,
        [ref] $tokens,
        [ref] $errors
    )
    foreach ($parseError in $errors) {
        $syntaxFailures.Add(
            "$($scriptFile.FullName):$($parseError.Extent.StartLineNumber) " +
            $parseError.Message
        )
    }
}
if ($syntaxFailures.Count -gt 0) {
    throw "PowerShell syntax validation failed:`n$($syntaxFailures -join "`n")"
}
Write-Ok "$($scriptFiles.Count) PowerShell scripts parsed successfully"

if ($SkipTests) {
    Write-Step "Python unit tests"
    Write-Host "  Skipped (-SkipTests)" -ForegroundColor Yellow
} else {
    Write-Step "Python unit tests"
    Push-Location $rootDir
    try {
        $windowsUnitTests = @(
            Get-ChildItem -LiteralPath (Join-Path $rootDir "agent\tests\unit") `
                -File -Filter "test_windows_*.py" |
                Sort-Object Name |
                Select-Object -ExpandProperty FullName
        )
        if ($windowsUnitTests.Count -eq 0) {
            throw "No agent/tests/unit/test_windows_*.py tests were found."
        }
        $pytestArguments = @("-m", "pytest") +
            [object[]] $windowsUnitTests + @(
            (Join-Path $rootDir "agent\os\windows\tests"),
            "-q"
        )
        Invoke-Checked -FilePath $pythonExe -ArgumentList $pytestArguments `
            -FailureMessage "Windows agent unit tests failed"
    } finally {
        Pop-Location
    }
    Write-Ok "Windows agent unit tests passed"
}

Write-Step "Installer branding"
$sourceLogo = Join-Path $assetsDir "attacklens-logo-256.png"
if (-not (Test-Path -LiteralPath $sourceLogo -PathType Leaf)) {
    throw "Installer source logo not found: $sourceLogo"
}
& $brandBuildScript -SourcePng $sourceLogo
if ($LASTEXITCODE -ne 0) {
    throw "Installer branding generation failed (exit code $LASTEXITCODE)"
}
foreach ($assetName in @(
    "attacklens.ico",
    "installer-banner.bmp",
    "installer-dialog.bmp",
    "license.rtf"
)) {
    $assetPath = Join-Path $assetsDir $assetName
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        throw "Required installer asset not found: $assetPath"
    }
    if ((Get-Item -LiteralPath $assetPath).Length -le 0) {
        throw "Required installer asset is empty: $assetPath"
    }
}
$licensePath = Join-Path $assetsDir "license.rtf"
$licenseText = [IO.File]::ReadAllText($licensePath)
foreach ($requiredLicenseText in @(
    "{\rtf1",
    "AttackLens Software License Agreement",
    "Endpoint data and security",
    "Warranty disclaimer",
    "Limitation of liability"
)) {
    if (-not $licenseText.Contains($requiredLicenseText)) {
        throw "Installer license is missing required text: $requiredLicenseText"
    }
}
Write-Ok "Icon, installer artwork, and license are ready"

if ($cleanThumbprint) {
    Write-Step "Build and sign service executables"
    if ($SkipExecutableBuild) {
        Write-Host "  Executable build skipped; using existing output" `
            -ForegroundColor Yellow
    } else {
        & $exeBuildScript
        if ($LASTEXITCODE -ne 0) {
            throw "Executable build failed (exit code $LASTEXITCODE)"
        }
    }
    Invoke-AuthenticodeSign -SignTool $signTool `
        -Thumbprint $cleanThumbprint `
        -StoreLocation $signingCertificate.StoreLocation `
        -Paths @($agentExe, $watchdogExe)

    Write-Step "Build MSI"
    & $msiBuildScript -Version $Version -SkipBuild
    if ($LASTEXITCODE -ne 0) {
        throw "MSI build failed (exit code $LASTEXITCODE)"
    }
    Invoke-AuthenticodeSign -SignTool $signTool `
        -Thumbprint $cleanThumbprint `
        -StoreLocation $signingCertificate.StoreLocation `
        -Paths @($msiPath)
} else {
    Write-Step "Build MSI"
    if ($SkipExecutableBuild) {
        & $msiBuildScript -Version $Version -SkipBuild
    } else {
        & $msiBuildScript -Version $Version
    }
    if ($LASTEXITCODE -ne 0) {
        throw "MSI build failed (exit code $LASTEXITCODE)"
    }
}

if (-not $SkipDefenderScan -and $defenderScanner) {
    Write-Step "Microsoft Defender artifact scan"
    Invoke-DefenderArtifactScan -Scanner $defenderScanner `
        -Paths @($agentExe, $watchdogExe, $msiPath)
}

Write-Step "WiX MSI validation"
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw "Expected MSI was not generated: $msiPath"
}
Invoke-Checked -FilePath $wixExe -ArgumentList @(
    "msi", "validate", $msiPath
) -FailureMessage "WiX MSI validation failed"
Write-Ok "MSI validation passed"

Write-Step "Compiled MSI contract verification"
$manifestPath = Join-Path $pkgDir "build\install-manifest.json"
if ($isRelease) {
    & $verifyMsiScript -MsiPath $msiPath `
        -ManifestPath $manifestPath `
        -ExpectedVersion $Version `
        -RequireSignature `
        -ExpectedThumbprint $cleanThumbprint
} else {
    & $verifyMsiScript -MsiPath $msiPath `
        -ManifestPath $manifestPath `
        -ExpectedVersion $Version
}
Write-Ok "Compiled MSI contracts passed"

$msiItem = Get-Item -LiteralPath $msiPath
$msiHash = Get-FileHash -LiteralPath $msiPath -Algorithm SHA256
$msiSignature = Get-AuthenticodeSignature -LiteralPath $msiPath
$sizeMb = [math]::Round($msiItem.Length / 1MB, 2)
$releaseReportPath = $null
if ($isRelease) {
    if ($msiSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
            -not $msiSignature.TimeStamperCertificate) {
        throw "Release MSI signature or timestamp verification failed after ICE validation."
    }
    $artifactRecords = foreach ($artifactPath in @($agentExe, $watchdogExe, $msiPath)) {
        $artifactItem = Get-Item -LiteralPath $artifactPath
        $artifactHash = Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
        $artifactSignature = Get-AuthenticodeSignature -LiteralPath $artifactPath
        [ordered]@{
            name = $artifactItem.Name
            path = $artifactItem.FullName
            bytes = [int64] $artifactItem.Length
            sha256 = $artifactHash.Hash.ToLowerInvariant()
            signature_status = [string] $artifactSignature.Status
            signer_subject = $artifactSignature.SignerCertificate.Subject
            signer_thumbprint = $artifactSignature.SignerCertificate.Thumbprint
            timestamp_subject = $artifactSignature.TimeStamperCertificate.Subject
        }
    }
    $releaseReport = [ordered]@{
        schema = 1
        product = "AttackLens Agent"
        version = $Version
        architecture = "x64"
        generated_at_utc = [DateTime]::UtcNow.ToString("o")
        tests = "complete_windows_matrix"
        defender_scan = "passed"
        wix_ice_validation = "passed"
        artifacts = @($artifactRecords)
    }
    $releaseReportPath = Join-Path $distDir "attacklens-agent-$Version-x64.release.json"
    [IO.File]::WriteAllText(
        $releaseReportPath,
        ($releaseReport | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false)
    )
    Write-Ok "Release verification report: $releaseReportPath"
}

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Green
Write-Host "  BUILD SUCCEEDED" -ForegroundColor Green
Write-Host "============================================================" `
    -ForegroundColor Green
Write-Host "  MSI       : $($msiItem.FullName)"
Write-Host "  Size      : $sizeMb MB ($($msiItem.Length) bytes)"
Write-Host "  SHA-256   : $($msiHash.Hash)"
Write-Host "  Signature : $($msiSignature.Status)"
if (-not $cleanThumbprint) {
    Write-Host "  Build type: unsigned development MSI" -ForegroundColor Yellow
} else {
    Write-Host "  Build type: signed release MSI" -ForegroundColor Green
    Write-Host "  Report    : $releaseReportPath"
}
Write-Host ""
