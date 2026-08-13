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


def test_secure_optional_manager_defaults_and_service_start_order():
    wix = WIX.read_text(encoding="utf-8")
    generator = CONFIG_GENERATOR.read_text(encoding="utf-8")
    assert '<Property Id="MANAGER_IP" Secure="yes" />' in wix
    assert '<Property Id="MANAGER_PORT" Value="8080" Secure="yes" />' in wix
    assert '<Property Id="TLS_VERIFY"    Value="false" Secure="yes" />' in wix
    assert '<Property Id="ALLOW_INSECURE_TRANSPORT" Value="true" Secure="yes" />' in wix
    assert 'Value="localhost"' not in wix
    assert 'MANAGER_URL or MANAGER_IP is required' not in generator
    assert "$managerUrl = ''" in generator
    assert "if ($managerUrl -and $managerUrl -notmatch" in generator
    assert "Captured installer configuration: manager_source=" in generator
    assert '<ServiceDependency Id="AttackLensAgent" />' not in wix


def test_config_acl_migration_recovers_legacy_owner_before_failing_install():
    wix = WIX.read_text(encoding="utf-8")
    generator = CONFIG_GENERATOR.read_text(encoding="utf-8")
    assert "takeown.exe /F $target /A" in generator
    assert "Cannot bootstrap SYSTEM access" in generator
    assert "installer-config.log" in generator
    assert "Preserved existing configuration and repaired its ACL successfully." in generator
    assert generator.index("$aclOutput = & icacls @aclArgs") < generator.index(
        "$ownerOutput = & icacls.exe $target /setowner"
    )
    assert "[System64Folder]WindowsPowerShell\\v1.0\\powershell.exe" in wix
    assert "[SystemFolder]WindowsPowerShell\\v1.0\\powershell.exe" not in wix


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
        "must not have SCM dependencies",
        "must use 64-bit PowerShell from System64Folder",
        "MSI File table",
        "TimeStamperCertificate",
        "attacklens-msi-payload-",
        "Compiled payload",
        "ConfigureManagerScript",
        "PrepareConfigDataScript",
    ):
        assert marker in verifier


def test_compiled_msi_verifier_checks_graduated_scm_recovery_policy():
    verifier = RELEASE_VERIFY.read_text(encoding="utf-8")
    assert "CA_SetAgentRecoveryActions" in verifier
    assert "restart/5000/restart/10000/restart/30000" in verifier
    assert "CA_SetAgentFailureFlag" in verifier
    assert "failureflag AttackLensAgent 1" in verifier
    assert "MsiConfigureServices" in verifier
    assert "before StartServices" in verifier


def test_compiled_msi_verifier_checks_delayed_start_and_preshutdown_timeout():
    verifier = RELEASE_VERIFY.read_text(encoding="utf-8")
    assert "must compile as automatic start" in verifier
    assert "DelayedAutostart" in verifier
    assert "AttackLensWatchdog" in verifier
    assert "PreshutdownTimeout" in verifier
    assert "#180000" in verifier
