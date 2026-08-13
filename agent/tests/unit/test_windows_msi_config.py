"""Static contract tests for the primary Windows MSI config path."""
from __future__ import annotations

from pathlib import Path


WINDOWS_DIR = Path(__file__).parents[2] / "os" / "windows"
WIX = WINDOWS_DIR / "pkg" / "attacklens.wxs"
GENERATOR = WINDOWS_DIR / "pkg" / "gen_config.ps1"
BRIDGE = WINDOWS_DIR / "pkg" / "prepare_config_data.js"
EDITOR = WINDOWS_DIR / "pkg" / "edit-agent-config.ps1"
MANAGER_TOOL = WINDOWS_DIR / "pkg" / "configure-manager.ps1"
PURGE = WINDOWS_DIR / "pkg" / "purge_state.ps1"
BUILD = WINDOWS_DIR / "pkg" / "build_attacklens_msi.ps1"
LEGACY_BUILD = WINDOWS_DIR / "pkg" / "build_msi.ps1"


def test_primary_msi_exposes_final_property_model():
    text = WIX.read_text(encoding="utf-8")
    bridge = BRIDGE.read_text(encoding="utf-8")
    for name in (
        "MANAGER_URL", "MANAGER_IP", "MANAGER_PORT", "TLS_VERIFY",
        "CA_BUNDLE", "SPKI_PIN", "ENROLL_TOKEN", "AGENT_NAME",
        "COLLECTION_PROFILE", "PRESERVE_STATE", "PURGE_ON_UNINSTALL",
    ):
        assert f'Property Id="{name}"' in text
        assert f"'{name}'" in bridge
    assert "Session.Property('CA_WriteConfig')" in bridge
    assert "Session.Property('ATTACKLENS_CONFIG_DATA')" in bridge
    assert "function StageConfigDataFromUI()" in bridge
    assert 'BinaryRef="PrepareConfigDataScript"' in text
    assert 'JScriptCall="PrepareConfigData"' in text
    assert 'JScriptCall="StageConfigDataFromUI"' in text
    assert '<Property Id="ATTACKLENS_CONFIG_DATA" Secure="yes" Hidden="yes" />' in text
    assert '<InstallUISequence>' in text
    assert 'After="ProgressDlg"' in text
    assert '-EncodedCustomActionData &quot;[CustomActionData]&quot;' in text
    assert 'HideTarget="yes"' in text


def test_enrollment_token_is_hidden_and_elevated():
    text = WIX.read_text(encoding="utf-8")
    assert '<Property Id="ENROLL_TOKEN"  Secure="yes" Hidden="yes" />' in text
    assert 'Execute="deferred"' in text and 'Impersonate="no"' in text
    assert '<Property Id="ATTACKLENS_CONFIG_DATA" Secure="yes" Hidden="yes" />' in text


def test_deferred_generator_properties_cross_the_elevation_boundary():
    text = WIX.read_text(encoding="utf-8")
    for name in (
        "MANAGER_URL", "MANAGER_IP", "MANAGER_PORT", "TLS_VERIFY",
        "CA_BUNDLE", "SPKI_PIN", "ENROLL_TOKEN", "AGENT_NAME",
        "COLLECTION_PROFILE", "PRESERVE_STATE", "PURGE_ON_UNINSTALL",
    ):
        assert f'Property Id="{name}"' in text
        property_line = next(line for line in text.splitlines() if f'Property Id="{name}"' in line)
        assert 'Secure="yes"' in property_line


def test_generator_preserves_state_and_writes_atomically():
    text = GENERATOR.read_text(encoding="utf-8")
    assert "PRESERVE_STATE" in text
    assert "Apply-AttackLensAcl $cfg 'config_file'" in text
    assert "[System.IO.File]::Replace($tmpCfg, $cfg, $null)" in text
    assert "MANAGER_URL" in text and "https://" in text
    assert "/setowner '*S-1-5-18'" in text
    assert "'*S-1-5-18:(F)'" in text
    assert "$managerOverrideRequested" in text
    assert "Set-TomlSectionValues $existingToml 'manager'" in text
    assert '"$cfg.previous"' in text
    assert "while preserving identity, collection policy, and queued telemetry" in text


def test_msi_installs_runtime_discovery_and_manager_repair_tools():
    text = WIX.read_text(encoding="utf-8")
    for marker in (
        'Directory Id="STATUSDIR" Name="status"',
        'Directory Id="SUPPORTDIR" Name="support"',
        'Name="configure-manager.ps1"',
        'Name="attacklens-status.ps1"',
        'Name="edit-agent-config.ps1"',
        'Name="RUNTIME_LOCATION.txt"',
        'ComponentRef Id="CmpStatusDir"',
        'ComponentRef Id="CmpSupportDir"',
    ):
        assert marker in text


def test_config_editor_is_elevated_validated_atomic_and_recoverable():
    text = EDITOR.read_text(encoding="utf-8")
    for marker in (
        "Test-Administrator",
        "validate-config",
        "agent.toml.manual-backup",
        "Write-ExistingFilePreservingSecurity",
        "$stream.Flush($true)",
        "Stop-AttackLensServices",
        "Start-Service -Name AttackLensAgent",
        "[IO.File]::ReadAllBytes($backupPath)",
    ):
        assert marker in text


def test_manager_compatibility_defaults_are_http_8080_and_explicit():
    generator = GENERATOR.read_text(encoding="utf-8")
    wix = WIX.read_text(encoding="utf-8")
    assert "else { '8080' }" in generator
    assert "else { 'false' }" in generator
    assert '"http://${fallbackHost}:${managerPort}"' in generator
    assert "MANAGER_URL must be an IP, DNS name" in generator
    assert '<Property Id="MANAGER_PORT" Value="8080" Secure="yes" />' in wix
    assert '<Property Id="TLS_VERIFY"    Value="false" Secure="yes" />' in wix
    assert '<Property Id="ALLOW_INSECURE_TRANSPORT" Value="true" Secure="yes" />' in wix


def test_runtime_manager_reconfiguration_does_not_require_write_dac():
    manager_tool = MANAGER_TOOL.read_text(encoding="utf-8")
    editor = EDITOR.read_text(encoding="utf-8")
    assert "Write-ExistingFilePreservingSecurity" in manager_tool
    assert "$stream.Flush($true)" in manager_tool
    assert "Invoke-ConfigValidation $stagePath" in manager_tool
    assert "Invoke-ConfigValidation $resolvedConfig" in manager_tool
    assert "[IO.File]::ReadAllBytes($backupPath)" in manager_tool
    assert "& $generator" not in manager_tool
    assert "File]::Replace" not in manager_tool
    assert "icacls" not in manager_tool.lower()
    assert "File]::Replace" not in editor
    assert "icacls" not in editor.lower()


def test_generator_allows_offline_install_without_manager():
    text = GENERATOR.read_text(encoding="utf-8")
    assert 'throw "MANAGER_URL or MANAGER_IP is required"' not in text
    assert "$managerUrl = ''" in text
    assert "if ($managerUrl -and $managerUrl -notmatch" in text
    assert "Captured installer configuration: manager_source=" in text


def test_purge_is_explicitly_opt_in_and_path_bound():
    wix_text = WIX.read_text(encoding="utf-8")
    purge_text = PURGE.read_text(encoding="utf-8")
    for marker in (
        'Id="CA_PurgeState"',
        'File Id="PurgeStateScript"',
        'Source="$(var.ScriptDir)\\purge_state.ps1"',
        'PURGE_ON_UNINSTALL=&quot;1&quot;',
        'Before="RemoveFiles"',
        'Name="PurgeOnUninstall"',
        'RegistrySearch Id="PurgeOnUninstallSearch"',
    ):
        assert marker in wix_text
    assert 'GetFolderPath("CommonApplicationData")' in purge_text
    assert "Refusing purge outside the standard AttackLens data root" in purge_text
    assert 'Remove-Item -LiteralPath $requestedFull -Recurse -Force' in purge_text


def test_both_msi_builders_include_gui_and_purge_payloads():
    for path in (BUILD, LEGACY_BUILD):
        text = path.read_text(encoding="utf-8")
        assert '$purgePs1Path = Join-Path $pkg "purge_state.ps1"' in text
        assert 'purge_state.ps1 not found' in text
        assert 'attacklens-ui.wxs' in text
        assert 'WixToolset.UI.wixext' in text
