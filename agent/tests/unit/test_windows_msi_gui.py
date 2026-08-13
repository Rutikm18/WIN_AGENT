"""Static contract tests for the interactive Windows MSI pages."""
from __future__ import annotations

from pathlib import Path


WINDOWS_DIR = Path(__file__).parents[2] / "os" / "windows"
WIX = WINDOWS_DIR / "pkg" / "attacklens.wxs"
GUI = WINDOWS_DIR / "pkg" / "attacklens-ui.wxs"
BUILD = WINDOWS_DIR / "pkg" / "build_attacklens_msi.ps1"


def test_gui_pages_cover_the_install_decisions():
    text = GUI.read_text(encoding="utf-8")
    for dialog_id in (
        "AttackLensManagerDlg",
        "AttackLensEnrollmentDlg",
        "AttackLensProfileDlg",
        "AttackLensSecurityDlg",
    ):
        assert f'Dialog Id="{dialog_id}"' in text


def test_gui_uses_the_same_validated_msi_properties():
    gui_text = GUI.read_text(encoding="utf-8")
    wix_text = WIX.read_text(encoding="utf-8")
    for name in (
        "MANAGER_URL", "MANAGER_PORT", "TLS_VERIFY",
        "CA_BUNDLE", "SPKI_PIN", "ENROLL_TOKEN", "AGENT_NAME",
        "COLLECTION_PROFILE", "PRESERVE_STATE", "PURGE_ON_UNINSTALL",
    ):
        assert f'Property="{name}"' in gui_text or f"[{name}]" in gui_text
        assert f'Property Id="{name}"' in wix_text

    # MANAGER_IP remains a secure silent-install compatibility alias but is
    # intentionally absent from the GUI to avoid two competing address boxes.
    assert 'Property="MANAGER_IP"' not in gui_text
    assert '<Property Id="MANAGER_IP" Secure="yes" />' in wix_text

    assert 'Property="ENROLL_TOKEN"' in gui_text
    assert 'Password="yes"' in gui_text
    assert '<RadioButtonGroup Property="TLS_VERIFY">' in gui_text
    assert '<RadioButton Value="true"' in gui_text
    assert '<RadioButton Value="false"' in gui_text


def test_gui_requires_one_unambiguous_manager_address():
    text = GUI.read_text(encoding="utf-8")
    assert "Enter one manager address" in text
    assert 'Text="Manager address:"' in text
    assert 'Property="MANAGER_IP"' not in text
    assert 'DisableCondition="NOT MANAGER_URL"' in text
    assert 'Value="AttackLensEnrollmentDlg"' in text
    assert 'Condition="MANAGER_URL"' in text


def test_msi_build_includes_gui_fragment_and_extension():
    text = BUILD.read_text(encoding="utf-8")
    assert 'Join-Path $pkg "attacklens-ui.wxs"' in text
    assert '"-ext", "WixToolset.UI.wixext"' in text
    wix_text = WIX.read_text(encoding="utf-8")
    gui_text = GUI.read_text(encoding="utf-8")
    assert '<UIRef Id="AttackLensUI" />' in wix_text
    assert '<UI Id="AttackLensUI">' in gui_text
    assert 'xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui"' in gui_text


def test_license_is_visible_in_gui_and_explicit_for_silent_installs():
    wix_text = WIX.read_text(encoding="utf-8")
    assert 'WixUILicenseRtf' in wix_text
    assert 'assets\\license.rtf' in wix_text
    assert 'Property Id="ACCEPT_EULA" Secure="yes"' in wix_text
    assert 'UILevel = 5' in wix_text
    assert 'ACCEPT_EULA = &quot;1&quot;' in wix_text
