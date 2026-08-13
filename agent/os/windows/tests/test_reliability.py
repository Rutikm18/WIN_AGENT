from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from agent.agent.crypto import decrypt, derive_keys
from agent.agent.client_key import ClientKey
from agent.os.windows.collectors.eventlog import EventLogCollector
from agent.os.windows.collectors.eventlog import _classify_eventlog_error
from agent.os.windows.collectors.eventlog import _parse_event_xml
from agent.os.windows.collectors.inventory import BinariesCollector, SbomCollector
from agent.os.windows.acl import NETWORK_SERVICE, POLICIES
from agent.os.windows.config_model import ConfigValidationError, load_config_dict
from agent.os.windows.diagnostics import _outbox_status, connectivity_test
from agent.os.windows.integrity import (
    IntegrityError,
    create_manifest,
    verify_current_install,
    verify_manifest,
    write_manifest_atomic,
)
from agent.os.windows.reliable_outbox import OutboxError, ReliableOutbox
from agent.os.windows.single_instance import (
    AlreadyRunningError,
    SingleInstanceGuard,
)
from agent.os.windows.tls_transport import _make_tls13_context
from agent.os.windows.watchdog_svc import (
    HEARTBEAT_STALE_SEC,
    WatchdogCore,
)
from agent.os.windows.win_agent import (
    WindowsAgent,
    _manager_is_loopback,
    _normalise_manager_url,
    _public_manager_endpoint,
)


def _config(root: str) -> dict:
    return {
        "agent": {"id": "test-win-agent", "name": "test-host"},
        "manager": {
            "url": "http://127.0.0.1:8080",
            "allow_insecure_transport": True,
            "tls_verify": False,
            "timeout_sec": 2,
        },
        "enrollment": {"token": ""},
        "paths": {
            "config_dir": os.path.join(root, "config"),
            "security_dir": os.path.join(root, "security"),
            "log_dir": os.path.join(root, "logs"),
            "spool_dir": os.path.join(root, "spool"),
            "data_dir": os.path.join(root, "data"),
            "status_dir": os.path.join(root, "status"),
        },
        "logging": {
            "level": "INFO",
            "file": os.path.join(root, "logs", "agent.log"),
            "max_mb": 1,
            "backups": 1,
        },
        "collection": {"sections": {}},
        "transport": {
            "initial_backoff_sec": 1,
            "max_backoff_sec": 5,
            "auth_failure_threshold": 3,
            "auto_reenroll": False,
            "min_free_mb": 16,
            "outbox_busy_timeout_ms": 1000,
        },
    }


class ManagerMigrationAndPublicStatusTests(unittest.TestCase):
    def test_manager_identity_normalises_case_default_port_and_slash(self) -> None:
        self.assertEqual(
            _normalise_manager_url("HTTPS://Manager.Example/") ,
            _normalise_manager_url("https://manager.example:443"),
        )
        self.assertTrue(_manager_is_loopback("https://127.0.0.42:8443"))

    def test_public_endpoint_strips_credentials_and_query(self) -> None:
        endpoint = _public_manager_endpoint(
            "https://operator:secret@Manager.Example:8443/base/?token=hidden"
        )
        self.assertEqual(endpoint, "https://manager.example:8443/base")
        self.assertNotIn("secret", endpoint)
        self.assertNotIn("hidden", endpoint)

    def test_manager_change_archives_old_credential_before_enrollment(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            cfg["manager"]["url"] = "https://new-manager.example"
            agent = WindowsAgent(cfg)
            key_path = os.path.join(root, "security", "client.key")
            Path(key_path).parent.mkdir(parents=True)
            Path(key_path).write_text("old credential", encoding="utf-8")
            old_key = ClientKey("host", "001", "a" * 64, "now", "https://old.example")
            response = {"api_key": "b" * 64, "agent_number": "001"}
            with mock.patch("agent.agent.auto_enroll.client_key_path", return_value=key_path), \
                    mock.patch("agent.agent.client_key.load", return_value=old_key), \
                    mock.patch("agent.agent.client_key.save") as save_key, \
                    mock.patch.object(agent, "_post_enrollment_windows", return_value=response):
                enrolled = agent._get_or_enroll_windows()
            self.assertEqual(enrolled.manager_url, "https://new-manager.example")
            self.assertTrue(Path(key_path + ".previous-manager").is_file())
            save_key.assert_called_once()

    def test_runtime_publishes_sanitized_readable_status_separately(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            cfg["manager"]["url"] = "https://manager.example:8443/base?secret=value"
            agent = WindowsAgent(cfg)
            agent._connection_state = "backoff"
            agent._delivery_stats["last_failure_reason"] = "response contained secret"
            agent._publish_runtime_state("degraded")
            protected = Path(root, "data", "agent.runtime.json")
            public = Path(root, "status", "agent-status.json")
            self.assertTrue(protected.is_file())
            status = json.loads(public.read_text(encoding="utf-8"))
            self.assertEqual(status["manager"]["endpoint"], "https://manager.example:8443/base")
            self.assertEqual(status["connection_state"], "backoff")
            self.assertNotIn("last_failure_reason", status["delivery"])
            self.assertNotIn("secret", public.read_text(encoding="utf-8"))


class ReliableOutboxTests(unittest.TestCase):
    def test_rows_survive_restart_and_delete_only_after_ack(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with mock.patch(
                "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
            ):
                outbox = ReliableOutbox(
                    os.path.join(root, "spool"),
                    os.path.join(root, "security"),
                    "agent-one",
                )
                delivery_id = outbox.enqueue(
                    {
                        "delivery_id": "delivery-one",
                        "section": "eventlog",
                        "data": {"secret_marker": "must-not-be-plaintext"},
                    }
                )
                self.assertEqual(delivery_id, "delivery-one")
                item = outbox.next_due()
                self.assertIsNotNone(item)
                self.assertEqual(
                    item.message["data"]["secret_marker"],
                    "must-not-be-plaintext",
                )
                database_bytes = outbox.path.read_bytes()
                self.assertNotIn(b"must-not-be-plaintext", database_bytes)
                outbox.retry(item, delay_sec=0, error="connection_reset")
                outbox.close()

                reopened = ReliableOutbox(
                    os.path.join(root, "spool"),
                    os.path.join(root, "security"),
                    "agent-one",
                )
                item = reopened.next_due()
                self.assertIsNotNone(item)
                self.assertEqual(item.attempts, 1)
                reopened.acknowledge(item)
                self.assertEqual(reopened.stats()["pending"], 0)
                reopened.close()

    def test_dead_letters_are_retained_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with mock.patch(
                "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
            ):
                outbox = ReliableOutbox(
                    os.path.join(root, "spool"),
                    os.path.join(root, "security"),
                    "agent-two",
                )
                outbox.enqueue(
                    {"delivery_id": "dead-one", "section": "inventory", "data": []}
                )
                item = outbox.next_due()
                self.assertIsNotNone(item)
                outbox.retain_dead_letter(
                    item, error="http_422", status_code=422
                )
                self.assertEqual(outbox.stats()["dead_letters"], 1)
                self.assertEqual(outbox.retry_dead_letters(), 1)
                self.assertIsNotNone(outbox.next_due())
                outbox.close()

    def test_pressure_pruning_removes_only_oldest_dead_letters(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            with mock.patch(
                "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
            ):
                outbox = ReliableOutbox(
                    os.path.join(root, "spool"),
                    os.path.join(root, "security"),
                    "agent-pressure",
                )
                outbox.enqueue_many([
                    {"delivery_id": f"dead-{index}", "section": "apps", "data": [index]}
                    for index in range(20)
                ], state="dead", error="manager_rejected")
                outbox.enqueue(
                    {"delivery_id": "pending-one", "section": "eventlog", "data": [1]}
                )
                reclaimed = outbox.prune_oldest_dead_letters(fraction=0.10)
                stats = outbox.stats()
                self.assertEqual(reclaimed["rows"], 2)
                self.assertGreater(reclaimed["bytes"], 0)
                self.assertEqual(stats["dead_letters"], 18)
                self.assertEqual(stats["pending"], 1)
                self.assertEqual(outbox.next_due().delivery_id, "pending-one")
                outbox.close()

    def test_diagnostics_aggregate_dead_letters_without_payload_or_detail(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            spool = os.path.join(root, "spool")
            with mock.patch(
                "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
            ):
                outbox = ReliableOutbox(
                    spool,
                    os.path.join(root, "security"),
                    "agent-diagnostics",
                )
                outbox.enqueue(
                    {
                        "delivery_id": "dead-sensitive",
                        "section": "binaries",
                        "data": {"secret_marker": "never-report-this"},
                    },
                    state="dead",
                    error="http_422:sensitive manager detail",
                )
                outbox.close()
            report = _outbox_status(spool)
            rendered = json.dumps(report)
            self.assertEqual(report["dead_letter_reasons"][0]["reason"], "http_422")
            self.assertEqual(report["dead_letter_sections"][0]["section"], "binaries")
            self.assertNotIn("sensitive manager detail", rendered)
            self.assertNotIn("never-report-this", rendered)

    def test_disk_pressure_uses_dead_letter_space_without_dropping_pending(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            agent = WindowsAgent(cfg)
            with mock.patch(
                "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
            ):
                agent._outbox = ReliableOutbox(
                    cfg["paths"]["spool_dir"],
                    cfg["paths"]["security_dir"],
                    cfg["agent"]["id"],
                )
                agent._outbox.enqueue_many([
                    {"delivery_id": f"dead-{index}", "section": "apps", "data": [index]}
                    for index in range(10)
                ], state="dead", error="manager_rejected")
                usage = type("Usage", (), {"free": 0})()
                with mock.patch(
                    "agent.os.windows.win_agent.shutil.disk_usage",
                    return_value=usage,
                ):
                    queued = agent._queue_collected_data("metrics", {"cpu": 1})
                stats = agent._outbox.stats()
                self.assertTrue(queued)
                self.assertEqual(stats["dead_letters"], 9)
                self.assertEqual(stats["pending"], 1)
                self.assertEqual(
                    agent._delivery_snapshot()["disk_pressure_evicted_dead_letters"],
                    1,
                )
                agent._outbox.close()

    def test_disk_pressure_defers_new_collection_when_no_safe_eviction_exists(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            agent = WindowsAgent(cfg)
            with mock.patch(
                "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
            ):
                agent._outbox = ReliableOutbox(
                    cfg["paths"]["spool_dir"],
                    cfg["paths"]["security_dir"],
                    cfg["agent"]["id"],
                )
                usage = type("Usage", (), {"free": 0})()
                with mock.patch(
                    "agent.os.windows.win_agent.shutil.disk_usage",
                    return_value=usage,
                ):
                    queued = agent._queue_collected_data("metrics", {"cpu": 1})
                self.assertFalse(queued)
                self.assertEqual(agent._outbox.stats()["pending"], 0)
                self.assertEqual(
                    agent._delivery_snapshot()["disk_pressure_deferred"],
                    1,
                )
                agent._outbox.close()

    def test_existing_database_never_silently_replaces_missing_key(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            spool = os.path.join(root, "spool")
            security = os.path.join(root, "security")
            with mock.patch(
                "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
            ):
                outbox = ReliableOutbox(spool, security, "agent-three")
                outbox.enqueue(
                    {
                        "delivery_id": "protected-one",
                        "section": "eventlog",
                        "data": [1],
                    }
                )
                outbox.close()
                key_path = Path(
                    security,
                    "agent-three.delivery-outbox.key",
                )
                key_path.unlink()
                with self.assertRaises(OutboxError):
                    ReliableOutbox(spool, security, "agent-three")
                self.assertFalse(key_path.exists())


class OfflineSpoolTests(unittest.TestCase):
    def _offline_agent(self, root: str) -> WindowsAgent:
        cfg = _config(root)
        cfg["manager"]["url"] = ""
        agent = WindowsAgent(load_config_dict(cfg).to_dict())
        patcher = mock.patch(
            "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        agent._outbox = ReliableOutbox(
            cfg["paths"]["spool_dir"],
            cfg["paths"]["security_dir"],
            cfg["agent"]["id"],
        )
        return agent

    def test_missing_manager_skips_network_enrollment(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = self._offline_agent(root)
            with mock.patch.object(agent, "_get_or_enroll_windows") as enroll:
                self.assertFalse(agent._enroll_if_needed())
            enroll.assert_not_called()
            self.assertEqual(agent._connection_state, "manager_unconfigured")
            diagnostic = connectivity_test(agent._cfg)
            self.assertTrue(diagnostic["offline_spool"])
            self.assertIn("not configured", diagnostic["error"])
            agent._outbox.close()

    def test_unavailable_manager_is_nonfatal_and_retried_later(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = WindowsAgent(_config(root))
            with mock.patch.object(
                agent,
                "_get_or_enroll_windows",
                side_effect=ConnectionError("manager unavailable"),
            ):
                self.assertFalse(agent._enroll_if_needed(max_attempts=1))
            self.assertEqual(agent._connection_state, "enrollment_pending")
            self.assertFalse(agent._conn_ok)

    def test_offline_collection_is_encrypted_at_rest_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = self._offline_agent(root)
            marker = "offline-secret-marker"
            with mock.patch.object(
                agent,
                "_wire_for_message",
                side_effect=AssertionError("manager keys must not be required"),
            ):
                agent._queue_collected_data("eventlog", [{"message": marker}])

            self.assertEqual(agent._outbox.stats()["pending"], 1)
            self.assertNotIn(marker.encode(), agent._outbox.path.read_bytes())
            item = agent._outbox.next_due()
            self.assertIsNotNone(item)
            assert item is not None
            self.assertEqual(item.message["agent_number"], "")

            agent._enc_key, agent._mac_key = derive_keys("f" * 64)
            agent._agent_number = "manager-agent-42"
            wire = json.loads(agent._wire_for_message(item.message))
            replayed = decrypt(wire, agent._enc_key, agent._mac_key)
            self.assertEqual(replayed["agent_number"], "manager-agent-42")
            self.assertEqual(replayed["data"][0]["message"], marker)
            agent._outbox.close()

    def test_unconfigured_sender_never_consumes_spooled_rows(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = self._offline_agent(root)
            agent._queue_collected_data("metrics", {"cpu": 1})
            sender = threading.Thread(target=agent._reliable_sender_loop)
            sender.start()
            time.sleep(0.05)
            agent.stop()
            sender.join(timeout=2)
            self.assertFalse(sender.is_alive())
            self.assertEqual(agent._outbox.stats()["pending"], 1)
            self.assertEqual(agent._connection_state, "manager_unconfigured")
            agent._outbox.close()

    def test_unsupported_section_opens_circuit_and_does_not_block_supported_data(self) -> None:
        class _Response:
            headers: dict[str, str] = {}

            def __init__(self, status: int, body: dict) -> None:
                self.status_code = status
                self._body = body
                self.text = json.dumps(body)

            def json(self):
                return self._body

        class _Transport:
            calls = 0

            def __init__(self, **_kwargs):
                pass

            def post(self, *_args, **_kwargs):
                type(self).calls += 1
                if type(self).calls == 1:
                    return _Response(
                        422,
                        {"detail": "Unsupported telemetry section: 'eventlog'"},
                    )
                return _Response(200, {"status": "ok"})

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as root:
            agent = self._offline_agent(root)
            agent._cfg["manager"]["url"] = "http://manager.example:8080"
            agent._enc_key, agent._mac_key = derive_keys("a" * 64)
            agent._outbox.enqueue_many([
                agent._new_message("eventlog", [{"event_id": index}])
                for index in range(3)
            ])
            agent._outbox.enqueue(agent._new_message("metrics", {"cpu": 1}))
            with mock.patch(
                "agent.os.windows.tls_transport.WindowsTLSTransport",
                _Transport,
            ):
                sender = threading.Thread(target=agent._reliable_sender_loop)
                sender.start()
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    if agent._outbox.stats()["pending"] == 0:
                        break
                    time.sleep(0.01)
                agent.stop()
                sender.join(timeout=2)

            stats = agent._outbox.stats()
            self.assertEqual(_Transport.calls, 2)
            self.assertEqual(stats["pending"], 0)
            self.assertEqual(stats["dead_letters"], 3)
            self.assertIn("eventlog", agent._unsupported_sections)
            self.assertFalse(
                agent._queue_collected_data("eventlog", [{"event_id": 99}])
            )
            self.assertEqual(agent._outbox.stats()["pending"], 0)
            self.assertEqual(
                agent._delivery_snapshot()["unsupported_section_suppressed"],
                1,
            )
            agent._outbox.close()


class DeliveryProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.agent = WindowsAgent(_config(self.temp.name))
        self.agent._enc_key, self.agent._mac_key = derive_keys("a" * 64)
        self.agent._agent_number = "001"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_retry_reencrypts_with_fresh_nonce_but_keeps_collection_identity(self) -> None:
        message = self.agent._new_message(
            "eventlog",
            [{"event_id": 4625}],
            collected_at=123456,
        )
        first = json.loads(self.agent._wire_for_message(message))
        second = json.loads(self.agent._wire_for_message(message))
        self.assertNotEqual(first["nonce"], second["nonce"])
        first_inner = decrypt(first, self.agent._enc_key, self.agent._mac_key)
        second_inner = decrypt(second, self.agent._enc_key, self.agent._mac_key)
        self.assertEqual(first_inner["delivery_id"], second_inner["delivery_id"])
        self.assertEqual(first_inner["collected_at"], 123456)
        self.assertEqual(first_inner["os"], "windows")

    def test_response_classes_never_discard_auth_or_transient_failures(self) -> None:
        cases = [
            (401, {"detail": "Timestamp outside allowed window"}, "retry"),
            (401, {"detail": "API key revoked"}, "auth"),
            (401, {"detail": "Duplicate nonce detected"}, "ack"),
            (429, {"detail": "queue busy"}, "retry"),
            (503, {"detail": "unavailable"}, "retry"),
            (422, {"detail": "invalid payload"}, "dead"),
            (200, {"status": "ok"}, "ack"),
        ]
        for status, body, expected in cases:
            with self.subTest(status=status, body=body):
                response = mock.Mock()
                response.status_code = status
                response.json.return_value = body
                response.text = json.dumps(body)
                response.headers = {}
                transport = mock.Mock()
                transport.post.return_value = response
                result = self.agent._send_reliable(
                    transport, b"{}", "delivery-id"
                )
                self.assertEqual(result["action"], expected)

    def test_oversized_list_is_split_without_losing_elements(self) -> None:
        message = self.agent._new_message("processes", list(range(8)))

        def fake_wire(candidate: dict) -> bytes:
            return (
                b"x" * (10 * 1024 * 1024)
                if len(candidate["data"]) > 2
                else b"x"
            )

        with mock.patch.object(
            self.agent,
            "_wire_for_message",
            side_effect=fake_wire,
        ):
            chunks, error = self.agent._prepare_messages(message)
        self.assertIsNone(error)
        self.assertEqual(len(chunks), 4)
        flattened = [
            value for chunk in chunks for value in chunk["data"]
        ]
        self.assertEqual(sorted(flattened), list(range(8)))
        self.assertTrue(all(chunk["chunk_count"] == 4 for chunk in chunks))


class CursorAndConfigTests(unittest.TestCase):
    def test_eventlog_cursor_advances_only_on_commit(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            collector = EventLogCollector(root)
            collector._pending_cursors = {"Security": 100}
            collector.rollback()
            self.assertFalse(Path(root, "eventlog-cursors.json").exists())

            collector._pending_cursors = {"Security": 100}
            collector.commit()
            persisted = json.loads(
                Path(root, "eventlog-cursors.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted["Security"], 100)

            collector._pending_cursors = {"Security": 4}
            collector._pending_resets = {"Security"}
            collector.commit()
            persisted = json.loads(
                Path(root, "eventlog-cursors.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted["Security"], 4)

    def test_auto_reenroll_requires_explicit_token(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            cfg["transport"]["auto_reenroll"] = True
            with self.assertRaises(ConfigValidationError):
                load_config_dict(cfg)

    def test_default_configuration_activates_all_collectors(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = WindowsAgent(_config(root))
            self.assertEqual(len(agent._active_intervals), 27)
            self.assertIn("persistence", agent._active_intervals)
            self.assertIn("developer_security", agent._active_intervals)
            self.assertEqual(
                set(agent._active_intervals),
                {
                    "metrics", "connections", "processes", "ports",
                    "network", "arp", "mounts", "battery", "openfiles",
                    "services", "users", "hardware", "containers",
                    "storage", "tasks", "apps", "packages", "binaries",
                    "sbom", "security", "sysctl", "configs", "sca",
                    "eventlog", "persistence", "developer_security",
                    "security_audit",
                },
            )

    def test_eventlog_errors_and_networkservice_acl_are_explicit(self) -> None:
        unavailable = OSError("event log service unavailable")
        unavailable.winerror = 1722
        self.assertEqual(
            _classify_eventlog_error(unavailable),
            "eventlog_service_unavailable",
        )
        for policy_name in (
            "secure_dir",
            "service_data_dir",
            "config_file",
            "key_file",
        ):
            principals = {
                principal for principal, _rights in POLICIES[policy_name].grants
            }
            self.assertIn(NETWORK_SERVICE, principals)

    def test_optional_eventlog_channel_is_capability_not_failure(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            collector = EventLogCollector(root)
            channel = "Microsoft-Windows-Sysmon/Operational"
            collector._record_error(
                channel,
                "channel_unavailable",
                "The specified channel could not be found.",
            )
            health = collector.health_snapshot()
            self.assertNotIn(channel, health["channel_errors"])
            self.assertEqual(
                health["channel_status"][channel]["status"],
                "not_installed",
            )
            self.assertGreater(
                health["channel_status"][channel]["retry_at"],
                health["channel_status"][channel]["last_checked_at"],
            )

    def test_binary_inventory_returns_partial_data_with_health(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            Path(root, "one.exe").write_bytes(b"first")
            Path(root, "two.exe").write_bytes(b"second")
            collector = BinariesCollector()
            collector._SCAN_DIRS = [root]
            collector._MAX_FILES = 1
            data = collector.collect()
            health = collector.health_snapshot()
            self.assertEqual(len(data), 1)
            self.assertTrue(data[0]["hash_sha256"])
            self.assertEqual(health["status"], "healthy")
            self.assertEqual(health["last_count"], 1)
            self.assertTrue(health["details"]["partial"])
            self.assertEqual(
                health["details"]["partial_reason"],
                "file_cap",
            )

    def test_binary_inventory_reports_inaccessible_roots(self) -> None:
        collector = BinariesCollector()
        collector._SCAN_DIRS = ["Z:/path-that-does-not-exist"]
        self.assertEqual(collector.collect(), [])
        health = collector.health_snapshot()
        self.assertEqual(health["status"], "error")
        self.assertIn("scan directory", health["last_error"])

    def test_sbom_uses_native_fallback_when_tools_are_absent(self) -> None:
        class _Distribution:
            metadata = {"Name": "ExampleLibrary"}
            version = "1.2.3"

        collector = SbomCollector()
        with (
            mock.patch(
                "agent.os.windows.collectors.inventory."
                "importlib_metadata.distributions",
                return_value=[_Distribution()],
            ),
            mock.patch(
                "agent.os.windows.collectors.inventory.shutil.which",
                return_value=None,
            ),
            mock.patch(
                "agent.os.windows.collectors.inventory.AppsCollector.collect",
                return_value=[{"name": "Example App", "version": "4.5"}],
            ),
        ):
            data = collector.collect()
        health = collector.health_snapshot()
        self.assertEqual(len(data), 2)
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["last_count"], 2)
        self.assertEqual(
            health["details"]["providers"]["winget"]["status"],
            "not_installed",
        )

    def test_sbom_retains_fallback_data_when_provider_fails(self) -> None:
        collector = SbomCollector()

        def which(name: str) -> str | None:
            return "npm.cmd" if name == "npm" else None

        with (
            mock.patch(
                "agent.os.windows.collectors.inventory."
                "importlib_metadata.distributions",
                return_value=[],
            ),
            mock.patch(
                "agent.os.windows.collectors.inventory.shutil.which",
                side_effect=which,
            ),
            mock.patch.object(collector, "_run", return_value="not-json"),
            mock.patch(
                "agent.os.windows.collectors.inventory.AppsCollector.collect",
                return_value=[{"name": "Fallback App", "version": "9"}],
            ),
        ):
            data = collector.collect()
        health = collector.health_snapshot()
        self.assertEqual(len(data), 1)
        self.assertEqual(health["status"], "degraded")
        self.assertIn("npm", health["last_error"])
        self.assertEqual(data[0]["source"], "windows_registry")

    def test_proxy_url_is_validated_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            cfg["manager"]["proxy_url"] = "http://proxy.example:8080"
            loaded = load_config_dict(cfg).to_dict()
            self.assertEqual(
                loaded["manager"]["proxy_url"],
                "http://proxy.example:8080",
            )
            cfg["manager"]["proxy_url"] = "file:///unsafe"
            with self.assertRaises(ConfigValidationError):
                load_config_dict(cfg)

    def test_sysmon_process_is_normalized_to_canonical_entity(self) -> None:
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon"/>
            <EventID>1</EventID><EventRecordID>42</EventRecordID>
            <TimeCreated SystemTime="2026-07-27T01:02:03.000Z"/>
            <Computer>host</Computer>
          </System>
          <EventData>
            <Data Name="ProcessId">123</Data>
            <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
            <Data Name="CommandLine">cmd.exe /c whoami</Data>
            <Data Name="ParentProcessId">10</Data>
            <Data Name="ParentImage">explorer.exe</Data>
            <Data Name="IntegrityLevel">High</Data>
          </EventData>
        </Event>"""
        record = _parse_event_xml(
            xml, "Microsoft-Windows-Sysmon/Operational"
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["category"], "process")
        self.assertEqual(record["entity"]["kind"], "process")
        self.assertEqual(record["entity"]["pid"], 123)
        self.assertEqual(record["entity"]["parent_pid"], 10)


class AdvancedResilienceTests(unittest.TestCase):
    class _Kernel:
        def __init__(self, handle: int = 123) -> None:
            self.handle = handle
            self.closed: list[int] = []
            self.released: list[int] = []
            self.created: list[tuple[object, bool, str]] = []

        def CreateMutexW(self, security, initial_owner, name):
            self.created.append((security, bool(initial_owner), str(name)))
            return self.handle

        def CloseHandle(self, handle):
            self.closed.append(handle)
            return True

        def ReleaseMutex(self, handle):
            self.released.append(handle)
            return True

    def test_single_instance_mutex_blocks_duplicate(self) -> None:
        kernel = self._Kernel()
        guard = SingleInstanceGuard(
            kernel32=kernel, get_last_error=lambda: 0
        ).acquire()
        self.assertTrue(guard.acquired)
        self.assertEqual(
            kernel.created,
            [(None, True, r"Global\AttackLensAgent")],
        )
        guard.release()
        self.assertEqual(kernel.released, [123])
        self.assertEqual(kernel.closed, [123])

        duplicate_kernel = self._Kernel()
        with self.assertRaises(AlreadyRunningError):
            SingleInstanceGuard(
                kernel32=duplicate_kernel,
                get_last_error=lambda: 183,
            ).acquire()
        self.assertEqual(
            duplicate_kernel.created,
            [(None, True, r"Global\AttackLensAgent")],
        )
        self.assertEqual(duplicate_kernel.closed, [123])

    def test_install_manifest_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            payload = Path(root, "bin", "agent.exe")
            payload.parent.mkdir()
            payload.write_bytes(b"trusted-agent")
            manifest_path = Path(root, "install-manifest.json")
            write_manifest_atomic(
                manifest_path,
                create_manifest(root, ["bin/agent.exe"]),
            )
            verified = verify_manifest(manifest_path, root)
            self.assertEqual(verified["status"], "verified")
            payload.write_bytes(b"tampered-agent")
            with self.assertRaises(IntegrityError):
                verify_manifest(manifest_path, root)

    def test_integrity_distinguishes_source_and_broken_package(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            executable = str(Path(root, "agent.exe"))
            with mock.patch.object(sys, "frozen", False, create=True):
                source = verify_current_install(executable)
            self.assertEqual(source["status"], "source_mode")
            self.assertEqual(source["checked_files"], 0)

            with mock.patch.object(sys, "frozen", True, create=True):
                with self.assertRaisesRegex(IntegrityError, "missing"):
                    verify_current_install(executable)

    def test_agent_uptime_uses_monotonic_process_clock(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = WindowsAgent(_config(root))
            agent._started_monotonic = 100.0
            with mock.patch(
                "agent.os.windows.win_agent.time.monotonic",
                return_value=145.9,
            ):
                self.assertEqual(agent._uptime_seconds(), 45)

    def test_wire_timestamp_applies_manager_clock_correction(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = WindowsAgent(_config(root))
            with mock.patch(
                "agent.os.windows.win_agent.time.time",
                return_value=1_000.0,
            ):
                agent._manager_clock_skew_sec = 30
                self.assertEqual(agent._wire_timestamp(), 1_000)
                agent._manager_clock_skew_sec = 420
                self.assertEqual(agent._wire_timestamp(), 1_420)
                agent._manager_clock_skew_sec = -420
                self.assertEqual(agent._wire_timestamp(), 580)

    def test_wall_clock_jump_is_detected_without_changing_monotonic_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = WindowsAgent(_config(root))
            agent._clock_anchor_wall = 1_000.0
            agent._clock_anchor_monotonic = 100.0
            with mock.patch(
                "agent.os.windows.win_agent.time.time",
                return_value=900.0,
            ), mock.patch(
                "agent.os.windows.win_agent.time.monotonic",
                return_value=200.0,
            ):
                event = agent._detect_clock_step()
            self.assertTrue(event["detected"])
            self.assertEqual(event["step_sec"], -200)
            self.assertEqual(agent._clock_anchor_monotonic, 200.0)

    def test_pending_delivery_stall_wakes_sender_and_is_rate_limited(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            cfg["transport"]["delivery_stall_sec"] = 300
            agent = WindowsAgent(cfg)
            agent._started_wall_time = 500.0
            with mock.patch(
                "agent.os.windows.win_agent.time.time",
                return_value=1_000.0,
            ):
                self.assertTrue(agent._check_delivery_stall({"pending": 4}))
                self.assertTrue(agent._send_wake.is_set())
                self.assertEqual(agent._connection_state, "delivery_stalled")
                self.assertEqual(
                    agent._delivery_snapshot()["delivery_stall_detected"],
                    1,
                )
                self.assertTrue(agent._check_delivery_stall({"pending": 4}))
                self.assertEqual(
                    agent._delivery_snapshot()["delivery_stall_detected"],
                    1,
                )

    def test_clean_stop_marker_classifies_previous_exit(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            agent = WindowsAgent(_config(root))
            agent._stop_reason = "preshutdown"
            agent._write_clean_stop_marker()
            previous = agent._consume_previous_lifecycle()
            self.assertFalse(previous["unexpected_stop"])
            self.assertEqual(previous["previous_stop_reason"], "preshutdown")
            runtime = Path(root, "data", "agent.runtime.json")
            runtime.write_text(
                json.dumps({"status": "running", "updated_at": int(time.time())}),
                encoding="utf-8",
            )
            previous = agent._consume_previous_lifecycle()
            self.assertTrue(previous["unexpected_stop"])

    def test_tls_floor_is_12(self) -> None:
        import ssl

        context = _make_tls13_context(False)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_connectivity_self_test_reports_dns_tcp_and_http(self) -> None:
        class _Response:
            status_code = 200

            @staticmethod
            def json():
                return {"status": "ok"}

        class _Transport:
            def __init__(self, **_kwargs):
                pass

            def get(self, _path):
                return _Response()

            def close(self):
                pass

        class _Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            with mock.patch(
                "agent.os.windows.diagnostics.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("127.0.0.1", 8080))],
            ), mock.patch(
                "agent.os.windows.diagnostics.socket.create_connection",
                return_value=_Connection(),
            ):
                result = connectivity_test(
                    cfg, transport_factory=_Transport
                )
        self.assertTrue(result["ok"])
        self.assertEqual(result["http"]["status_code"], 200)

    def test_enrollment_uses_pinning_and_explicit_proxy_transport(self) -> None:
        class _Response:
            status_code = 200

            @staticmethod
            def json():
                return {"api_key": "a" * 64}

        with tempfile.TemporaryDirectory() as root:
            cfg = _config(root)
            cfg["manager"].update({
                "proxy_url": "http://proxy.example:8080",
                "proxy_pac_url": "https://proxy.example/proxy.pac",
                "proxy_auto_detect": False,
                "spki_pin": "sha256//test-pin",
            })
            agent = WindowsAgent(cfg)
            with mock.patch(
                "agent.os.windows.tls_transport.WindowsTLSTransport"
            ) as transport_class:
                transport_class.return_value.post.return_value = _Response()
                response = agent._post_enrollment_windows(
                    {"agent_id": "test-win-agent"},
                    "enrollment-token",
                )
            self.assertEqual(response["api_key"], "a" * 64)
            self.assertEqual(
                transport_class.call_args.kwargs["proxy_url"],
                "http://proxy.example:8080",
            )
            self.assertEqual(
                transport_class.call_args.kwargs["proxy_pac_url"],
                "https://proxy.example/proxy.pac",
            )
            self.assertFalse(
                transport_class.call_args.kwargs["proxy_auto_detect"]
            )
            self.assertEqual(
                transport_class.call_args.kwargs["spki_pin"],
                "sha256//test-pin",
            )
            headers = (
                transport_class.return_value.post.call_args.kwargs[
                    "extra_headers"
                ]
            )
            self.assertEqual(
                headers["X-Enrollment-Token"], "enrollment-token"
            )


class WatchdogTests(unittest.TestCase):
    def test_stale_and_sender_crashed_runtime_are_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            state_path = Path(root, "agent.runtime.json")
            core = WatchdogCore(runtime_state_path=str(state_path))
            state_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "updated_at": int(time.time()) - HEARTBEAT_STALE_SEC - 1,
                        "connection_state": "healthy",
                    }
                ),
                encoding="utf-8",
            )
            healthy, reason = core._runtime_is_healthy()
            self.assertFalse(healthy)
            self.assertIn("stale", reason)

            state_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "updated_at": int(time.time()),
                        "connection_state": "sender_crashed",
                    }
                ),
                encoding="utf-8",
            )
            healthy, reason = core._runtime_is_healthy()
            self.assertFalse(healthy)
            self.assertEqual(reason, "sender_thread_crashed")


if __name__ == "__main__":
    unittest.main()
