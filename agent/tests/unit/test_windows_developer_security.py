"""Contract and delivery tests for the Windows DeepMesh snapshot."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from agent.os.windows.collectors.developer_security import (
    DEVSEC_CAP_ITEM_KEYS,
    REQUIRED_CAPABILITIES,
    WinDeveloperSecurityCollector,
    _MAX_FIELD,
    _MAX_SNAPSHOT,
    _bound_and_redact,
)


class _EmptyAudit:
    timeout = 6

    def __init__(self, profiles=()):
        self._profiles_value = list(profiles)
        self._deadline = float("inf")
        self._findings = []

    def _profiles(self):
        return list(self._profiles_value)

    @staticmethod
    def _loaded_user_sids(_winreg):
        return []

    @staticmethod
    def _ide_extensions(_profiles):
        return []

    @staticmethod
    def _mcp_inventory(_profiles):
        return {"servers": [], "config_files": []}

    @staticmethod
    def _browser_extensions(_profiles):
        return []

    @staticmethod
    def _native_messaging_hosts():
        return []

    @staticmethod
    def _command_inventory(_profiles):
        return []

    @staticmethod
    def _relevant_applications():
        return []

    @staticmethod
    def _listeners():
        return []

    @staticmethod
    def _relevant_processes():
        return []

    @staticmethod
    def _powershell_audit(_profiles):
        return {"profiles": [], "path": []}

    @staticmethod
    def _node_inventory(_profiles):
        return {"packages": [], "configs": []}

    @staticmethod
    def _python_inventory(_profiles):
        return {"packages": [], "configs": [], "installations": []}

    @staticmethod
    def _git_audit(_profiles):
        return {"configs": [], "repositories": []}

    @staticmethod
    def _docker_audit():
        return {
            "available": False, "daemon_reachable": False, "client": None,
            "containers": [], "images": [],
        }

    @staticmethod
    def _trusted_docker():
        return None

    @staticmethod
    def _path_is_file(path):
        return Path(path).is_file()

    @staticmethod
    def _size(path):
        try:
            return Path(path).stat().st_size
        except OSError:
            return None

    @staticmethod
    def _mtime(path):
        try:
            return int(Path(path).stat().st_mtime)
        except OSError:
            return None


def _manager_summary(snapshot):
    """Mirror raw.py's documented count preference for contract regression."""
    capabilities = snapshot.get("capabilities", {})
    counts = {}
    for capability, item_key in DEVSEC_CAP_ITEM_KEYS.items():
        value = capabilities.get(capability, {})
        counts[capability] = int(value.get("count", len(value.get(item_key, []))))
    return counts


class DeveloperSecurityContractTests(unittest.TestCase):
    def _collector(self, profiles=(), *, empty_capabilities=True):
        collector = WinDeveloperSecurityCollector(profiles, audit=_EmptyAudit(profiles))
        if empty_capabilities:
            for capability, item_key in DEVSEC_CAP_ITEM_KEYS.items():
                setattr(
                    collector,
                    f"_collect_{capability}",
                    lambda key=item_key: {key: []},
                )
        return collector

    def test_collect_emits_all_17_exact_capability_record_keys(self):
        with mock.patch("agent.os.windows.collectors.developer_security._native_scheduled_tasks", return_value=[]):
            result = self._collector().collect()
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["platform"], "windows")
        self.assertEqual(tuple(result["capabilities"]), REQUIRED_CAPABILITIES)
        self.assertEqual(len(result["capabilities"]), 17)
        for capability, item_key in DEVSEC_CAP_ITEM_KEYS.items():
            self.assertIn(item_key, result["capabilities"][capability])
            self.assertEqual(
                result["capabilities"][capability]["count"],
                len(result["capabilities"][capability][item_key]),
            )
        self.assertFalse(result["collection"]["partial"])

    def test_forced_capability_failure_is_isolated_and_reported(self):
        collector = self._collector()
        with mock.patch.object(collector, "_collect_mcp_servers", side_effect=PermissionError("secret")), \
                mock.patch("agent.os.windows.collectors.developer_security._native_scheduled_tasks", return_value=[]):
            result = collector.collect()
        self.assertEqual(result["capabilities"]["mcp_servers"], {"error": "PermissionError"})
        self.assertIn(
            {"capability": "mcp_servers", "error": "PermissionError"},
            result["collection"]["errors"],
        )
        self.assertTrue(result["collection"]["partial"])
        self.assertNotIn('"secret"', json.dumps(result))

    def test_blocked_capability_hits_deadline_without_losing_snapshot(self):
        collector = self._collector()
        blocker = threading.Event()
        with mock.patch(
            "agent.os.windows.collectors.developer_security._COMMAND_TIMEOUT", 0.01,
        ), mock.patch.object(
            collector, "_collect_git", side_effect=lambda: blocker.wait(60),
        ):
            result = collector.collect()
        self.assertEqual(result["capabilities"]["git"], {"error": "TimeoutError"})
        self.assertIn(
            {"capability": "git", "error": "TimeoutError"},
            result["collection"]["errors"],
        )
        self.assertTrue(result["collection"]["partial"])

    def test_redaction_strips_supported_secret_shapes_and_bounds_fields(self):
        raw = (
            "sk-abcdefgh ghp_abcdefghijkl AKIAABCDEFGHIJKLMNOP "
            "eyJabcde.abcdefgh.ijklmnop password=hunter2 token='tok value' "
            "api_key=topsecret"
        )
        output = _bound_and_redact(raw + ("x" * (_MAX_FIELD + 100)))
        for secret in (
            "sk-abcdefgh", "ghp_abcdefghijkl", "AKIAABCDEFGHIJKLMNOP",
            "eyJabcde.abcdefgh.ijklmnop", "hunter2", "tok value", "topsecret",
        ):
            self.assertNotIn(secret, output)
        self.assertLessEqual(len(output), _MAX_FIELD)

    def test_credential_locations_emit_paths_never_contents(self):
        with tempfile.TemporaryDirectory() as root:
            profile = Path(root) / "alice"
            credential = profile / ".aws" / "credentials"
            credential.parent.mkdir(parents=True)
            credential.write_text("aws_secret_access_key=NEVER-COLLECT-THIS", encoding="utf-8")
            collector = self._collector([profile], empty_capabilities=False)
            collector._profiles_cache = [profile]
            result = collector._collect_credential_locations()
        encoded = json.dumps(result)
        self.assertEqual(result["users"][0]["locations"][0]["path"], str(credential))
        self.assertNotIn("NEVER-COLLECT-THIS", encoded)
        self.assertFalse(result["users"][0]["locations"][0]["content_collected"])

    def test_snapshot_over_six_mib_is_trimmed_without_losing_capabilities(self):
        collector = self._collector(empty_capabilities=False)
        huge = [
            {"value": f"{index:04d}-" + ("z" * 12700)}
            for index in range(500)
        ]
        empty = []
        for method_name in (
            "_collect_editor_extensions", "_collect_browser_extensions",
            "_collect_native_messaging", "_collect_agent_cli_tools",
            "_collect_ai_applications", "_collect_listening_ports", "_collect_processes",
            "_collect_launchd",
        ):
            setattr(collector, method_name, lambda rows=empty: {"items": list(rows)})
        collector._collect_editor_extensions = lambda: {"items": list(huge)}
        collector._collect_mcp_servers = lambda: {"servers": []}
        collector._collect_cron = lambda: {"users": []}
        collector._collect_shell_startup = lambda: {"files": []}
        collector._collect_node_packages = lambda: {"users": []}
        collector._collect_python_packages = lambda: {"users": []}
        collector._collect_homebrew = lambda: {"formulae": [], "casks": []}
        collector._collect_git = lambda: {"users": []}
        collector._collect_credential_locations = lambda: {"users": []}
        collector._collect_docker = lambda: {"containers": [], "images": []}
        result = collector.collect()
        encoded = json.dumps(result, separators=(",", ":")).encode("utf-8")
        self.assertLessEqual(len(encoded), _MAX_SNAPSHOT)
        self.assertTrue(result["collection"]["payload_truncated"])
        self.assertEqual(set(result["capabilities"]), set(REQUIRED_CAPABILITIES))
        for capability, item_key in DEVSEC_CAP_ITEM_KEYS.items():
            cap = result["capabilities"][capability]
            self.assertEqual(cap["count"], len(cap[item_key]))

    def test_absent_browser_and_docker_are_empty_not_errors(self):
        collector = self._collector(empty_capabilities=False)
        self.assertEqual(collector._collect_browser_extensions(), {"items": []})
        self.assertEqual(
            collector._collect_docker(),
            {
                "installed": False, "running": False, "client": None,
                "containers": [], "images": [],
            },
        )

    def test_manager_summary_counts_nonzero_exact_record_arrays(self):
        collector = self._collector()
        for capability, item_key in DEVSEC_CAP_ITEM_KEYS.items():
            method = getattr(collector, f"_collect_{capability}")
            extra = {"casks": []} if capability == "homebrew" else {}
            setattr(collector, f"_collect_{capability}", lambda k=item_key, x=extra: {k: [{"name": "codex"}], **x})
        result = collector.collect()
        self.assertEqual(_manager_summary(result), {key: 1 for key in REQUIRED_CAPABILITIES})


class RegistryContractTests(unittest.TestCase):
    def test_run_keys_enumerate_both_wow64_views(self):
        opened_flags = []

        class Key:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        fake = types.SimpleNamespace(
            HKEY_LOCAL_MACHINE=1, HKEY_CURRENT_USER=2, HKEY_USERS=3,
            KEY_READ=0x20019, KEY_WOW64_64KEY=0x100, KEY_WOW64_32KEY=0x200,
        )

        def open_key(hive, path, _reserved=0, flags=0):
            opened_flags.append(flags)
            return Key()

        def enum_value(_key, index):
            if index:
                raise OSError
            return "Agent", "codex.exe --serve", 1

        fake.OpenKey = open_key
        fake.EnumValue = enum_value
        collector = WinDeveloperSecurityCollector([], audit=_EmptyAudit())
        with mock.patch.dict(sys.modules, {"winreg": fake}):
            rows = collector._run_registry_entries()
        self.assertTrue(any(flags & fake.KEY_WOW64_64KEY for flags in opened_flags))
        self.assertTrue(any(flags & fake.KEY_WOW64_32KEY for flags in opened_flags))
        self.assertEqual({row["registry_view"] for row in rows}, {"64", "32"})


class WiringAndDeliveryTests(unittest.TestCase):
    def test_registered_validated_normalized_and_hourly(self):
        from agent.os.windows.collectors import COLLECTORS
        from agent.os.windows.config_model import SUPPORTED_COLLECTIONS
        from agent.os.windows.normalizer import normalize
        from agent.os.windows.win_agent import _INTERVALS
        from shared.schema import validate_section
        from shared.sections import VALID_SECTION_NAMES

        self.assertIn("developer_security", COLLECTORS)
        self.assertIn("developer_security", SUPPORTED_COLLECTIONS)
        self.assertIn("developer_security", VALID_SECTION_NAMES)
        self.assertEqual(_INTERVALS["developer_security"], 3600)
        sample = {
            "schema_version": 1, "platform": "windows", "scope": {}, "privacy": {},
            "capabilities": {}, "collection": {},
        }
        self.assertIs(normalize("developer_security", sample), sample)
        self.assertEqual(validate_section("developer_security", sample), [])

    def test_durable_outbox_preserves_section_and_snapshot(self):
        from agent.os.windows.win_agent import WindowsAgent

        class CapturingOutbox:
            def __init__(self):
                self.messages = []

            def enqueue_many(self, messages, **_kwargs):
                self.messages.extend(messages)
                return [message["delivery_id"] for message in messages]

            @staticmethod
            def prune_oldest_dead_letters(**_kwargs):
                return {"rows": 0, "bytes": 0}

        with tempfile.TemporaryDirectory() as root:
            cfg = {
                "agent": {"id": "win-test", "name": "endpoint"},
                "manager": {"url": "http://manager.test:8080"},
                "paths": {
                    "security_dir": str(Path(root) / "security"),
                    "spool_dir": str(Path(root) / "spool"),
                    "log_dir": str(Path(root) / "logs"),
                    "data_dir": str(Path(root) / "data"),
                },
                "transport": {"min_free_mb": 0},
                "collection": {"sections": {}},
            }
            Path(cfg["paths"]["spool_dir"]).mkdir()
            agent = WindowsAgent(cfg)
            outbox = CapturingOutbox()
            agent._outbox = outbox
            snapshot = {"schema_version": 1, "platform": "windows", "capabilities": {}}
            self.assertTrue(agent._queue_collected_data("developer_security", snapshot))
            self.assertEqual(len(outbox.messages), 1)
            queued = outbox.messages[0]
            self.assertEqual(queued["section"], "developer_security")
            self.assertEqual(queued["data"], snapshot)

    def test_wire_encryption_round_trip_preserves_manager_payload(self):
        from agent.agent.crypto import decrypt
        from agent.os.windows.win_agent import WindowsAgent

        cfg = {
            "agent": {"id": "win-test", "name": "endpoint"},
            "manager": {"url": "http://manager.test:8080"},
            "paths": {
                "security_dir": "security", "spool_dir": "spool",
                "log_dir": "logs", "data_dir": "data",
            },
            "collection": {"sections": {}},
        }
        agent = WindowsAgent(cfg)
        agent._enc_key = b"e" * 32
        agent._mac_key = b"m" * 32
        snapshot = {
            "schema_version": 1,
            "platform": "windows",
            "capabilities": {"mcp_servers": {"servers": [{"name": "codex"}], "count": 1}},
        }
        message = agent._new_message(
            "developer_security", snapshot, collected_at=1_700_000_000,
        )
        wire = json.loads(agent._wire_for_message(message))
        restored = decrypt(wire, agent._enc_key, agent._mac_key)
        self.assertEqual(restored["section"], "developer_security")
        self.assertEqual(restored["data"], snapshot)


if __name__ == "__main__":
    unittest.main()
