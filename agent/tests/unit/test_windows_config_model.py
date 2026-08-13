"""Cross-platform tests for Windows agent TOML validation."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))

from agent.os.windows.config_model import (  # noqa: E402
    ConfigValidationError,
    default_paths,
    load_config_dict,
    load_config,
)


def minimal_config() -> dict:
    return {
        "config_schema": 1,
        "agent": {"id": "win-test-01", "name": "TEST-PC"},
        "manager": {"url": "https://manager.example.test:443"},
    }


def test_valid_minimal_config_gets_windows_path_defaults():
    model = load_config_dict(minimal_config())
    assert model.agent.id == "win-test-01"
    assert model.manager.tls_verify is False
    assert model.manager.allow_insecure_transport is True
    assert model.paths["spool_dir"].endswith("AttackLens" + "\\spool") or model.paths["spool_dir"].endswith("AttackLens/spool")


def test_manager_is_optional_for_offline_spool_mode():
    cfg = {
        "config_schema": 1,
        "agent": {"id": "win-offline-01", "name": "OFFLINE-PC"},
    }
    model = load_config_dict(cfg)
    assert model.manager.url == ""
    assert model.to_dict()["manager"]["url"] == ""


def test_full_production_config_is_typed():
    cfg = minimal_config()
    cfg.update({
        "manager": {
            "url": "https://manager.example.test",
            "tls_verify": True,
            "ca_bundle": "C:/ProgramData/AttackLens/security/manager-ca.pem",
            "spki_pin": "sha256//abc123=",
            "timeout_sec": 45,
            "proxy_pac_url": "https://proxy.example.test/manager.pac",
            "proxy_auto_detect": False,
        },
        "enrollment": {"token": "token=value;safe"},
        "paths": {"data_dir": "C:/ProgramData/AttackLens/data"},
        "collection": {"sections": {"eventlog": {"enabled": True, "interval_sec": 60}}},
    })
    model = load_config_dict(cfg)
    assert model.manager.ca_bundle.endswith("manager-ca.pem")
    assert model.manager.timeout_sec == 45
    assert model.manager.proxy_pac_url.endswith("manager.pac")
    assert model.manager.proxy_auto_detect is False
    assert model.collection.sections["eventlog"]["interval_sec"] == 60


@pytest.mark.parametrize("url", ["ftp://manager.example.test", "not-a-url"])
def test_invalid_manager_url_fails_closed(url):
    cfg = minimal_config()
    cfg["manager"]["url"] = url
    with pytest.raises(ConfigValidationError, match="manager.*url"):
        load_config_dict(cfg)


def test_http_is_allowed_by_default_and_can_be_explicitly_disabled():
    cfg = minimal_config()
    cfg["manager"] = {"url": "http://127.0.0.1:8080"}
    assert load_config_dict(cfg).manager.allow_insecure_transport is True
    cfg["manager"]["allow_insecure_transport"] = False
    with pytest.raises(ConfigValidationError, match="allow_insecure_transport"):
        load_config_dict(cfg)


def test_msi_string_boolean_is_rejected():
    cfg = minimal_config()
    cfg["manager"]["tls_verify"] = "false"
    with pytest.raises(ConfigValidationError, match="TOML boolean"):
        load_config_dict(cfg)


def test_proxy_pac_url_and_auto_detect_are_validated():
    cfg = minimal_config()
    cfg["manager"]["proxy_pac_url"] = "file:///unsafe.pac"
    with pytest.raises(ConfigValidationError, match="proxy_pac_url"):
        load_config_dict(cfg)

    cfg = minimal_config()
    cfg["manager"]["proxy_auto_detect"] = "true"
    with pytest.raises(ConfigValidationError, match="proxy_auto_detect"):
        load_config_dict(cfg)


def test_unknown_collection_section_is_rejected():
    cfg = minimal_config()
    cfg["collection"] = {"sections": {"not_a_windows_collector": {"enabled": True}}}
    with pytest.raises(ConfigValidationError, match="supported Windows collector"):
        load_config_dict(cfg)


@pytest.mark.parametrize("interval", [0, 604801, True, "60"])
def test_interval_bounds_and_type(interval):
    cfg = minimal_config()
    cfg["collection"] = {"sections": {"eventlog": {"interval_sec": interval}}}
    with pytest.raises(ConfigValidationError, match="interval_sec"):
        load_config_dict(cfg)


def test_file_loader_reports_toml_errors_without_dumping_content(tmp_path):
    path = tmp_path / "agent.toml"
    path.write_text("[manager\nurl = 'https://secret.example'", encoding="utf-8")
    with pytest.raises(ConfigValidationError, match="invalid TOML") as exc:
        load_config(path)
    assert "secret.example" not in str(exc.value)


def test_default_paths_are_all_present():
    paths = default_paths()
    assert set(paths) == {
        "config_dir", "security_dir", "log_dir", "spool_dir", "data_dir",
        "status_dir",
    }
