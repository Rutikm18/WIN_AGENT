from __future__ import annotations

import json
from pathlib import Path

from agent.os.windows.boot_persistence import (
    BootStateTracker,
    RESTART_ACTIONS,
    RESET_PERIOD_SEC,
    WATCHDOG_RESTART_ACTIONS,
    WATCHDOG_SERVICE_NAME,
    enforce_service_policy,
)


class FakeWin32Service:
    SC_MANAGER_CONNECT = 1
    SERVICE_QUERY_CONFIG = 1
    SERVICE_CHANGE_CONFIG = 2
    SERVICE_AUTO_START = 2
    SERVICE_NO_CHANGE = 0xFFFFFFFF
    SERVICE_CONFIG_FAILURE_ACTIONS = 2
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 4

    def __init__(self, *, drifted: bool = False) -> None:
        self.start_type = 3 if drifted else 2
        self.delayed = not drifted
        self.failure_flag = not drifted
        self.failure = {
            "ResetPeriod": 0 if drifted else RESET_PERIOD_SEC,
            "RebootMsg": None,
            "Command": None,
            "Actions": ((1, 60_000),) if drifted else RESTART_ACTIONS,
        }
        self.changes: list[tuple[str, object]] = []
        self.closed: list[str] = []

    def OpenSCManager(self, *_args):
        return "manager"

    def OpenService(self, *_args):
        return "service"

    def QueryServiceConfig(self, _service):
        return (16, self.start_type, 1, "agent.exe", "", 0, [], "LocalSystem", "AttackLens Agent")

    def QueryServiceConfig2(self, _service, level):
        if level == self.SERVICE_CONFIG_FAILURE_ACTIONS:
            return dict(self.failure)
        if level == self.SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
            return self.delayed
        if level == self.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            return self.failure_flag
        raise AssertionError(level)

    def ChangeServiceConfig(self, _service, _type, start, *_args):
        self.start_type = start
        self.changes.append(("start_type", start))

    def ChangeServiceConfig2(self, _service, level, value):
        if level == self.SERVICE_CONFIG_FAILURE_ACTIONS:
            self.failure = dict(value)
            self.changes.append(("failure_actions", value))
        elif level == self.SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
            self.delayed = bool(value)
            self.changes.append(("delayed", value))
        elif level == self.SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
            self.failure_flag = bool(value)
            self.changes.append(("failure_flag", value))
        else:
            raise AssertionError(level)

    def CloseServiceHandle(self, handle):
        self.closed.append(handle)


def test_compliant_scm_policy_is_a_noop() -> None:
    fake = FakeWin32Service()
    report = enforce_service_policy(win32service_module=fake)
    assert report["compliant"] is True
    assert report["repaired"] == []
    assert not any(report["drift"].values())
    assert fake.changes == []
    assert fake.closed == ["service", "manager"]


def test_drifted_scm_policy_is_fully_repaired() -> None:
    fake = FakeWin32Service(drifted=True)
    report = enforce_service_policy(win32service_module=fake)
    assert report["compliant"] is True
    assert set(report["repaired"]) == {
        "start_type",
        "delayed_auto_start",
        "failure_actions",
        "failure_actions_on_non_crash",
    }
    assert fake.start_type == fake.SERVICE_AUTO_START
    assert fake.delayed is True
    assert fake.failure_flag is True
    assert fake.failure["ResetPeriod"] == RESET_PERIOD_SEC
    assert fake.failure["Actions"] == RESTART_ACTIONS


def test_audit_only_reports_drift_without_mutation() -> None:
    fake = FakeWin32Service(drifted=True)
    report = enforce_service_policy(
        repair=False,
        win32service_module=fake,
    )
    assert report["compliant"] is False
    assert report["repaired"] == []
    assert all(report["drift"].values())
    assert fake.changes == []


def test_watchdog_policy_uses_its_own_restart_contract() -> None:
    fake = FakeWin32Service(drifted=True)
    report = enforce_service_policy(
        service_name=WATCHDOG_SERVICE_NAME,
        win32service_module=fake,
    )
    assert report["compliant"] is True
    assert fake.failure["Actions"] == WATCHDOG_RESTART_ACTIONS
    assert fake.failure_flag is True


def test_boot_state_detects_reboot_and_clean_shutdown(tmp_path: Path) -> None:
    path = tmp_path / "boot_state.json"
    first = BootStateTracker(
        path,
        boot_time_fn=lambda: 1_000,
        wall_time_fn=lambda: 2_000,
    )
    initial = first.begin_start()
    assert initial["first_start"] is True
    assert initial["boot_changed"] is False
    assert json.loads(path.read_text(encoding="utf-8"))["clean_stop"] is False

    first.mark_clean_stop("preshutdown")
    stopped = json.loads(path.read_text(encoding="utf-8"))
    assert stopped["clean_stop"] is True
    assert stopped["stop_reason"] == "preshutdown"

    second = BootStateTracker(
        path,
        boot_time_fn=lambda: 1_500,
        wall_time_fn=lambda: 2_500,
    )
    transition = second.begin_start()
    assert transition["boot_changed"] is True
    assert transition["previous_boot_time"] == 1_000
    assert transition["previous_clean_stop"] is True
    assert transition["unexpected_previous_stop"] is False


def test_boot_state_flags_unclean_same_boot_restart(tmp_path: Path) -> None:
    path = tmp_path / "boot_state.json"
    first = BootStateTracker(path, boot_time_fn=lambda: 1_000)
    first.begin_start()
    second = BootStateTracker(path, boot_time_fn=lambda: 1_000)
    transition = second.begin_start()
    assert transition["boot_changed"] is False
    assert transition["unexpected_previous_stop"] is True


def test_power_resume_wakes_delivery_and_queues_lifecycle_event(tmp_path: Path) -> None:
    from agent.os.windows.win_agent import WindowsAgent

    cfg = {
        "agent": {"id": "win-test", "name": "endpoint"},
        "manager": {"url": "http://manager.test:8080"},
        "paths": {
            "security_dir": str(tmp_path / "security"),
            "spool_dir": str(tmp_path / "spool"),
            "log_dir": str(tmp_path / "logs"),
            "data_dir": str(tmp_path / "data"),
            "status_dir": str(tmp_path / "status"),
        },
        "collection": {"sections": {}},
    }
    agent = WindowsAgent(cfg)
    queued = []
    agent._outbox = object()
    agent._queue_collected_data = lambda section, data: queued.append((section, data)) or True

    agent.handle_power_event(7)

    assert agent._send_wake.is_set()
    assert agent._connection_state == "resuming"
    assert queued[0][0] == "agent_lifecycle"
    assert queued[0][1]["event"] == "power_resume"
