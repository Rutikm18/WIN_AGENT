"""Static contract tests for Windows service lifecycle hardening."""
from __future__ import annotations

from pathlib import Path

import pytest


WINDOWS_DIR = Path(__file__).parents[2] / "os" / "windows"
SERVICE = WINDOWS_DIR / "service.py"
AGENT = WINDOWS_DIR / "win_agent.py"
WATCHDOG = WINDOWS_DIR / "watchdog_svc.py"
WIX = WINDOWS_DIR / "pkg" / "attacklens.wxs"


def test_service_reports_startup_checkpoints_until_ready():
    service_text = SERVICE.read_text(encoding="utf-8")
    agent_text = AGENT.read_text(encoding="utf-8")
    assert "_report_start_pending" in service_text
    assert "SERVICE_START_PENDING,\n                120000," in service_text
    assert "checkPoint=" not in service_text
    assert "progress_callback=self._report_start_pending" in service_text
    assert "progress_callback" in agent_text
    assert "_notify_progress(progress_callback, 5)" in agent_text


def test_service_runtime_supports_offline_start_and_has_recovery_actions():
    service_text = SERVICE.read_text(encoding="utf-8")
    watchdog_text = WATCHDOG.read_text(encoding="utf-8")
    wix_text = WIX.read_text(encoding="utf-8")
    assert '_svc_deps_: list[str] = []' in service_text
    assert '_svc_deps_: list[str] = []' in watchdog_text
    assert 'ServiceDependency Id="AttackLensAgent"' not in wix_text
    assert 'FirstFailureActionType="restart"' in wix_text
    assert 'SecondFailureActionType="restart"' in wix_text
    assert 'ThirdFailureActionType="restart"' in wix_text
    assert 'Id="CA_SetAgentRecoveryActions"' in wix_text
    assert 'actions= restart/5000/restart/10000/restart/30000' in wix_text
    assert 'Id="CA_SetAgentDelayedAutoStart"' in wix_text
    assert 'config AttackLensAgent start= delayed-auto' in wix_text
    assert 'Id="CA_SetWatchdogDelayedAutoStart"' in wix_text
    assert 'config AttackLensWatchdog start= delayed-auto' in wix_text
    assert 'Action="CA_SetAgentDelayedAutoStart" After="MsiConfigureServices"' in wix_text
    assert 'Action="CA_SetAgentRecoveryActions" After="CA_SetWatchdogDelayedAutoStart"' in wix_text
    assert 'Id="CA_SetAgentFailureFlag"' in wix_text
    assert 'failureflag AttackLensAgent 1' in wix_text
    assert 'Name="DelayedAutostart" Value="1"' in wix_text
    assert 'Name="PreshutdownTimeout" Value="180000"' in wix_text
    assert "SERVICE_START_PENDING" in watchdog_text
    assert "SERVICE_RUNNING" in watchdog_text
    assert "checkPoint=" not in watchdog_text
    assert "if not t.is_alive():" in watchdog_text


def test_shutdown_flush_and_transport_close_are_preserved():
    agent_text = AGENT.read_text(encoding="utf-8")
    assert "self._flush_queue_to_spool()" in agent_text
    assert "transport.close()" in agent_text
    assert "sender_t.join(timeout=15)" in agent_text


def _service_module():
    from agent.os.windows import service

    if not service._HAS_WIN32:
        pytest.skip("pywin32 service callbacks require Windows")
    return service


def test_service_preshutdown_callback_requests_extended_grace_period():
    service = _service_module()

    class FakeService:
        def __init__(self):
            self.calls = []

        def _request_stop(self, reason, wait_hint=30000):
            self.calls.append((reason, wait_hint))

    fake = FakeService()
    result = service.AttackLensAgentService.SvcOtherEx(
        fake,
        getattr(service.win32service, "SERVICE_CONTROL_PRESHUTDOWN", 15),
        0,
        None,
    )
    assert result == 0
    assert fake.calls == [("preshutdown", 180000)]


def test_service_power_resume_is_forwarded_to_agent():
    service = _service_module()

    class FakeAgent:
        def __init__(self):
            self.events = []

        def handle_power_event(self, event_type):
            self.events.append(event_type)

    fake = type("FakeService", (), {"_win_agent": FakeAgent()})()
    result = service.AttackLensAgentService.SvcOtherEx(
        fake,
        getattr(service.win32service, "SERVICE_CONTROL_POWEREVENT", 13),
        18,
        None,
    )
    assert result == 0
    assert fake._win_agent.events == [18]


def test_service_start_pending_reports_scm_wait_hint_and_journal_checkpoint():
    service = _service_module()

    class FakeJournal:
        def __init__(self):
            self.events = []

        def record(self, event, **fields):
            self.events.append((event, fields))

    class FakeService:
        def __init__(self):
            self._startup_journal = FakeJournal()
            self.statuses = []

        def ReportServiceStatus(self, *args):
            self.statuses.append(args)

    fake = FakeService()
    service.AttackLensAgentService._report_start_pending(fake, 4)
    assert fake.statuses == [(service.win32service.SERVICE_START_PENDING, 120000)]
    assert fake._startup_journal.events == [
        ("startup_checkpoint", {"checkpoint": 4})
    ]
