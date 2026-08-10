"""Release-hardening contracts for the Windows MSI pipeline."""
from __future__ import annotations

from pathlib import Path


WINDOWS_DIR = Path(__file__).parents[2] / "os" / "windows"
RELEASE_BUILD = WINDOWS_DIR / "build_windows_msi.ps1"
RELEASE_VERIFY = WINDOWS_DIR / "verify_built_msi.ps1"
LOW_LEVEL_BUILD = WINDOWS_DIR / "pkg" / "build_msi.ps1"
ALTERNATE_BUILD = WINDOWS_DIR / "pkg" / "build_attacklens_msi.ps1"
WIX = WINDOWS_DIR / "pkg" / "attacklens.wxs"
CONFIG_GENERATOR = WINDOWS_DIR / "pkg" / "gen_config.ps1"
LICENSE = WINDOWS_DIR / "pkg" / "assets" / "license.rtf"


def test_release_mode_is_fail_closed():
    text = RELEASE_BUILD.read_text(encoding="utf-8")
    assert 'Release builds require -SignThumbprint' in text
    assert 'Release builds cannot use -SkipTests' in text
    assert 'Release builds cannot use -SkipExecutableBuild' in text
    assert 'Release builds cannot use -SkipDefenderScan' in text
    assert "Resolve-SigningCertificate" in text
    assert "HasPrivateKey" in text
    assert '1.3.6.1.5.5.7.3.3' in text
    assert "X509RevocationMode]::Online" in text


def test_release_builder_runs_the_complete_windows_test_matrix():
    text = RELEASE_BUILD.read_text(encoding="utf-8")
    assert 'test_windows_*.py' in text
    assert 'agent\\os\\windows\\tests' in text
    assert '"-m", "pytest"' in text
    assert 'unittest' not in text


def test_signatures_are_timestamped_and_independently_verified():
    text = RELEASE_BUILD.read_text(encoding="utf-8")
    for marker in (
        '"/fd", "SHA256"',
        '"/tr", $timestampUrl',
        '"/td", "SHA256"',
        '"verify", "/pa", "/all", "/tw", "/v"',
        "TimeStamperCertificate",
        "Signature signer mismatch",
    ):
        assert marker in text
    assert '-Paths @($agentExe, $watchdogExe)' in text
    assert '-Paths @($msiPath)' in text


def test_low_level_builder_cannot_create_a_partially_signed_release():
    text = ALTERNATE_BUILD.read_text(encoding="utf-8")
    assert '-SignIdentity is not supported here' in text
    assert 'Signing failed - unsigned MSI retained' not in text


def test_manifest_covers_every_frozen_payload_file():
    for path in (LOW_LEVEL_BUILD, ALTERNATE_BUILD):
        text = path.read_text(encoding="utf-8")
        assert 'Get-ChildItem -LiteralPath $sourceRoot -Recurse -File' in text
        assert 'InstallPrefix = "bin/attacklens-agent"' in text
        assert 'InstallPrefix = "bin/attacklens-watchdog"' in text
        assert 'Install manifest generated ($($manifestFiles.Count) files)' in text


def test_defender_scan_does_not_create_exclusions_or_remediate_files():
    text = RELEASE_BUILD.read_text(encoding="utf-8")
    assert "Resolve-DefenderScanner" in text
    assert '"-Scan", "-ScanType", "3", "-File", $path' in text
    assert '"-DisableRemediation"' in text
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (RELEASE_BUILD, WIX, CONFIG_GENERATOR)
    ).lower()
    assert "add-mppreference" not in combined
    assert "exclusionpath" not in combined
    assert "netsh advfirewall set" not in combined
    assert "firewallexception" not in combined


def test_gui_and_silent_installs_are_license_gated():
    wix = WIX.read_text(encoding="utf-8")
    license_text = LICENSE.read_text(encoding="utf-8")
    assert 'WixUILicenseRtf' in wix
    assert 'Property Id="ACCEPT_EULA" Secure="yes"' in wix
    assert 'UILevel = 5' in wix
    assert 'ACCEPT_EULA = &quot;1&quot;' in wix
    assert "AttackLens Software License Agreement" in license_text
    assert "Endpoint data and security" in license_text


def test_secure_manager_defaults_and_service_start_order():
    wix = WIX.read_text(encoding="utf-8")
    generator = CONFIG_GENERATOR.read_text(encoding="utf-8")
    assert '<Property Id="MANAGER_IP" Secure="yes" />' in wix
    assert '<Property Id="MANAGER_PORT" Value="443" Secure="yes" />' in wix
    assert 'Value="localhost"' not in wix
    assert 'MANAGER_URL or MANAGER_IP is required' in generator
    assert '<ServiceDependency Id="AttackLensAgent" />' in wix


def test_msi_version_bounds_match_windows_installer_contract():
    text = RELEASE_BUILD.read_text(encoding="utf-8")
    assert '$versionParts[0] -gt 255' in text
    assert '$versionParts[1] -gt 255' in text
    assert '$versionParts[2] -gt 65535' in text


def test_compiled_msi_is_verified_after_ice_validation():
    build = RELEASE_BUILD.read_text(encoding="utf-8")
    verifier = RELEASE_VERIFY.read_text(encoding="utf-8")
    assert 'Compiled MSI contract verification' in build
    assert '& $verifyMsiScript -MsiPath $msiPath' in build
    for marker in (
        "LicenseAgreementDlg",
        "AttackLens Software License Agreement",
        "SecureCustomProperties",
        "MsiHiddenProperties",
        "AttackLensWatchdog must depend on AttackLensAgent",
        "MSI File table",
        "TimeStamperCertificate",
    ):
        assert marker in verifier
