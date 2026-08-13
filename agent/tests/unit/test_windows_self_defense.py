from __future__ import annotations

from dataclasses import dataclass

from agent.os.windows.self_defense import (
    audit_self_defense,
    defender_exclusion_status,
)


@dataclass
class Acl:
    policy: str
    compliant: bool
    skipped: bool = False
    error: str | None = None


class FakeWinreg:
    HKEY_LOCAL_MACHINE = object()
    KEY_READ = 1
    KEY_WOW64_64KEY = 2

    def __init__(self, values):
        self.values = values

    def OpenKey(self, *_args):
        return object()

    def EnumValue(self, _key, index):
        if index >= len(self.values):
            raise OSError("done")
        return self.values[index], 0, 1

    def CloseKey(self, _key):
        pass


def test_defender_exclusion_detects_parent_without_leaking_value():
    result = defender_exclusion_status(
        [r"C:\Program Files\AttackLens"],
        winreg_module=FakeWinreg([r"C:\Program Files"]),
    )
    assert result["protected_path_excluded"] is True
    assert result["protected_match_count"] == 1
    assert "values" not in result


def test_self_defense_repairs_acl_drift_and_reports_config_change(tmp_path):
    config = tmp_path / "agent.toml"
    config.write_text("before", encoding="utf-8")
    from agent.os.windows.integrity import sha256_file

    digest = sha256_file(config)
    config.write_text("after", encoding="utf-8")
    calls = []

    def acl_check(_paths, *, repair):
        calls.append(repair)
        return [Acl("config_file", compliant=False)]

    def acl_repair(_paths, *, repair):
        calls.append(repair)
        return [Acl("config_file", compliant=True)]

    result = audit_self_defense(
        {},
        config_path=str(config),
        config_digest=digest,
        integrity_fn=lambda: {"status": "verified"},
        acl_check_fn=acl_check,
        acl_repair_fn=acl_repair,
        defender_fn=lambda _paths: {"supported": True, "protected_path_excluded": False},
    )
    assert calls == [False, True]
    assert result["config_integrity"]["changed"] is True
    assert result["repaired"] == ["config_file"]
    assert {item["code"] for item in result["alerts"]} == {
        "configuration_changed",
        "acl_drift_repaired",
    }


def test_self_defense_does_not_repair_compliant_acl(tmp_path):
    config = tmp_path / "agent.toml"
    config.write_text("ok", encoding="utf-8")
    from agent.os.windows.integrity import sha256_file

    result = audit_self_defense(
        {},
        config_path=str(config),
        config_digest=sha256_file(config),
        integrity_fn=lambda: {"status": "verified", "checked_files": 2},
        acl_check_fn=lambda _paths, repair: [Acl("config_file", compliant=True)],
        acl_repair_fn=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError()),
        defender_fn=lambda _paths: {"supported": True, "protected_path_excluded": False},
    )
    assert result["ok"] is True
    assert result["alerts"] == []
    assert result["install_integrity"]["checked_files"] == 2


def test_self_defense_surfaces_integrity_and_defender_failures():
    def broken():
        raise RuntimeError("hash mismatch")

    result = audit_self_defense(
        {},
        config_path=None,
        config_digest=None,
        integrity_fn=broken,
        acl_check_fn=lambda _paths, repair: [],
        defender_fn=lambda _paths: {
            "supported": True,
            "protected_path_excluded": True,
        },
    )
    assert result["ok"] is False
    assert {item["code"] for item in result["alerts"]} == {
        "install_integrity_failed",
        "agent_path_excluded_from_defender",
    }
