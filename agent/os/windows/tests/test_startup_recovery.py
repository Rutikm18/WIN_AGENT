from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from agent.os.windows.startup_recovery import (
    StartupJournal,
    _outbox_probe,
    _path_probe,
    classify_startup_error,
    diagnose_startup,
    safe_repair,
)
from agent.os.windows.watchdog_svc import MAX_RESTARTS, WatchdogCore


class FakeWinError(RuntimeError):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.winerror = code


def _toml(root: Path) -> str:
    def path(name: str) -> str:
        return (root / name).as_posix()

    return f'''
[agent]
id = "recovery-test"
name = "recovery-test"

[manager]
url = ""
tls_verify = true

[enrollment]
token = ""

[paths]
config_dir = "{path('config')}"
log_dir = "{path('logs')}"
spool_dir = "{path('spool')}"
data_dir = "{path('data')}"
security_dir = "{path('security')}"

[logging]
file = "{path('logs/agent.log')}"

[collection]
'''


class StartupRecoveryTests(unittest.TestCase):
    def test_non_admin_probes_report_access_denied_without_crashing(self) -> None:
        protected = Path("C:/ProgramData/AttackLens/spool/delivery-outbox.sqlite3")
        with mock.patch.object(Path, "is_file", side_effect=PermissionError("denied")):
            outbox = _outbox_probe(protected.parent)
            path = _path_probe(protected, directory=False)

        self.assertIsNone(outbox["exists"])
        self.assertTrue(outbox["inaccessible"])
        self.assertIn("PermissionError", outbox["error"])
        self.assertIsNone(path["exists"])
        self.assertIn("PermissionError", path["access_error"])

    def test_scm_errors_are_stably_classified(self) -> None:
        expected = {
            5: "access_denied",
            1053: "scm_start_timeout",
            1056: "already_running",
            1060: "service_missing",
            1067: "process_terminated",
            1068: "dependency_failure",
        }
        for code, classification in expected.items():
            with self.subTest(code=code):
                result = classify_startup_error(FakeWinError(code, "service error"))
                self.assertEqual(result["code"], classification)

    def test_journal_redacts_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            journal = StartupJournal("agent", root)
            journal.record(
                "test",
                enrollment_token="secret-token",
                nested={"api_key": "secret-key", "state": "ok"},
            )
            text = journal.path.read_text(encoding="utf-8")
            self.assertNotIn("secret-token", text)
            self.assertNotIn("secret-key", text)
            self.assertIn("<redacted>", text)

    def test_invalid_config_restores_valid_last_known_good(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            config = root / "agent.toml"
            config.write_text("broken = [toml", encoding="utf-8")
            backup = root / "agent.toml.last-known-good"
            backup.write_text(_toml(root), encoding="utf-8")

            actions = safe_repair(config)
            report = diagnose_startup(config)

            self.assertTrue(report["checks"]["config"]["valid"])
            self.assertTrue(any(
                item.action == "restore_last_known_good" and item.status == "repaired"
                for item in actions
            ))
            self.assertTrue(list(root.glob("agent.toml.invalid-*")))
            quarantine = next(
                action for action in actions
                if action.action == "quarantine_invalid_config"
            )
            self.assertIn("validation_error=", quarantine.detail)

    def test_failed_restore_never_removes_active_config(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            config = root / "agent.toml"
            original = "broken = [toml"
            config.write_text(original, encoding="utf-8")
            config.with_name("agent.toml.last-known-good").write_text(
                _toml(root), encoding="utf-8"
            )
            with mock.patch(
                "agent.os.windows.startup_recovery.shutil.copy2",
                side_effect=OSError("simulated disk failure"),
            ):
                actions = safe_repair(config)
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertTrue(any(
                action.action == "restore_last_known_good" and action.status == "failed"
                for action in actions
            ))

    def test_corrupt_runtime_is_quarantined_but_outbox_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            config = root / "agent.toml"
            config.write_text(_toml(root), encoding="utf-8")
            data = root / "data"
            spool = root / "spool"
            data.mkdir()
            spool.mkdir()
            runtime = data / "agent.runtime.json"
            runtime.write_text("{broken", encoding="utf-8")
            outbox = spool / "delivery-outbox.sqlite3"
            outbox.write_bytes(b"not-sqlite")

            actions = safe_repair(config)
            report = diagnose_startup(config)

            self.assertFalse(runtime.exists())
            self.assertTrue(list(data.glob("agent.runtime.json.corrupt-*")))
            self.assertTrue(outbox.exists())
            self.assertIn("error", report["checks"]["outbox"])
            self.assertFalse(any(item.target == str(outbox) for item in actions))

    def test_watchdog_opens_circuit_without_a_blocking_sleep(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            core = WatchdogCore(runtime_state_path=str(Path(root, "agent.runtime.json")))
            with mock.patch.object(core, "_start_agent_service", return_value=False) as start:
                # Reset exponential cooldown between calls so the sliding-window
                # circuit itself can be reached deterministically.
                for _ in range(MAX_RESTARTS):
                    core._cooldown_until = 0
                    core._attempt_restart()
                before = start.call_count
                core._cooldown_until = 0
                core._attempt_restart()

            self.assertEqual(start.call_count, before)
            self.assertGreater(core._cooldown_until, time.monotonic())

    def test_watchdog_rejects_heartbeat_far_in_the_future(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runtime = Path(root, "agent.runtime.json")
            runtime.write_text(json.dumps({
                "status": "running",
                "updated_at": int(time.time()) + 3600,
                "connection_state": "healthy",
            }), encoding="utf-8")
            core = WatchdogCore(runtime_state_path=str(runtime))
            healthy, reason = core._runtime_is_healthy()
            self.assertFalse(healthy)
            self.assertEqual(reason, "runtime_state_timestamp_in_future")


if __name__ == "__main__":
    unittest.main()
