from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent.os.windows.collectors.sca import ScaCollector
from agent.os.windows.normalizer import normalize
from agent.os.windows.sca.cis_windows import POLICY
from agent.os.windows.sca.engine import ScaEngine


def _policy(checks: list[dict]) -> dict:
    return {
        "id": "test",
        "name": "Test policy",
        "version": "1",
        "platform": ["windows"],
        "checks": checks,
    }


class ScaEngineSemanticsTests(unittest.TestCase):
    def _scan(self, checks: list[dict], responses: dict[str, tuple]) -> dict:
        engine = ScaEngine(
            runner=lambda command, _timeout: responses[command],
            bundled_policies=[_policy(checks)],
        )
        return engine.scan()

    def test_all_condition_preserves_conclusive_failure_when_another_rule_errors(self) -> None:
        result = self._scan(
            [{"id": "x", "rules": ["c:bad", "c:false -> yes"]}],
            {"bad": (None, "", "timeout"), "false": (0, "no", "")},
        )
        check = result["policies"][0]["checks"][0]
        self.assertEqual(check["result"], "fail")
        self.assertEqual(result["summary"]["fail"], 1)

    def test_any_condition_preserves_conclusive_pass_when_another_rule_errors(self) -> None:
        result = self._scan(
            [{"id": "x", "condition": "any", "rules": ["c:bad", "c:true -> yes"]}],
            {"bad": (None, "", "timeout"), "true": (0, "yes", "")},
        )
        self.assertEqual(result["policies"][0]["checks"][0]["result"], "pass")

    def test_unknown_is_distinct_from_failure_and_reduces_coverage(self) -> None:
        result = self._scan(
            [{
                "id": "x",
                "rules": [{
                    "id": "feature",
                    "rule": "c:feature -> enabled",
                    "unknown_when": "Unsupported",
                }],
            }],
            {"feature": (0, "Unsupported on this SKU", "")},
        )
        summary = result["summary"]
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["fail"], 0)
        self.assertEqual(summary["coverage_pct"], 0.0)
        self.assertEqual(summary["status"], "degraded")

    def test_applicability_false_produces_not_applicable(self) -> None:
        result = self._scan(
            [{
                "id": "x",
                "applicability": "c:enabled -> true",
                "rules": ["c:setting -> secure"],
            }],
            {"enabled": (0, "false", ""), "setting": (0, "insecure", "")},
        )
        check = result["policies"][0]["checks"][0]
        self.assertEqual(check["result"], "not_applicable")
        self.assertTrue(check["rules"][0]["applicability"])

    def test_unscored_checks_do_not_distort_compliance_score(self) -> None:
        result = self._scan(
            [
                {"id": "scored", "rules": ["c:good -> yes"]},
                {"id": "informational", "scored": False, "rules": ["c:bad -> yes"]},
            ],
            {"good": (0, "yes", ""), "bad": (0, "no", "")},
        )
        summary = result["summary"]
        self.assertEqual(summary["pass"], 1)
        self.assertEqual(summary["fail"], 1)
        self.assertEqual(summary["scored_checks"], 1)
        self.assertEqual(summary["score_pct"], 100.0)

    def test_evidence_is_redacted_bounded_and_stderr_is_preserved(self) -> None:
        secret = "token=super-secret " + ("x" * 2000)
        result = self._scan(
            [{"id": "x", "rules": ["c:test -> expected"]}],
            {"test": (0, secret, "diagnostic")},
        )
        evidence = result["policies"][0]["checks"][0]["rules"][0]["evidence"]
        self.assertNotIn("super-secret", evidence)
        self.assertIn("[REDACTED]", evidence)
        self.assertTrue(evidence.endswith("...[truncated]"))
        self.assertLessEqual(len(evidence), 1040)


class ScaCollectorStateTests(unittest.TestCase):
    @staticmethod
    def _document(result: str) -> dict:
        fail = int(result == "fail")
        passed = int(result == "pass")
        return {
            "policies": [{
                "policy_id": "test",
                "policy_name": "Test",
                "policy_version": "1",
                "checks": [{"id": "C-1", "title": "Check", "result": result}],
                "summary": {
                    "total": 1, "pass": passed, "fail": fail,
                    "not_applicable": 0, "error": 0, "unknown": 0,
                    "score_pct": float(passed * 100), "coverage_pct": 100.0,
                    "status": "non_compliant" if fail else "compliant",
                },
            }],
            "summary": {
                "total": 1, "pass": passed, "fail": fail,
                "not_applicable": 0, "error": 0, "unknown": 0,
                "score_pct": float(passed * 100), "coverage_pct": 100.0,
                "status": "non_compliant" if fail else "compliant",
                "policies": 1,
            },
        }

    def test_state_is_atomic_and_reports_new_and_resolved_failures(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            collector = ScaCollector(state_dir=root)
            with mock.patch(
                "agent.os.windows.sca.ScaEngine.scan",
                side_effect=[self._document("pass"), self._document("fail"), self._document("pass")],
            ):
                first = collector.collect()
                collector.commit()
                second = collector.collect()
                collector.commit()
                third = collector.collect()
                collector.commit()

            self.assertTrue(first["changes"]["baseline"])
            self.assertEqual(second["changes"]["new_failures"], ["test:C-1"])
            self.assertEqual(third["changes"]["resolved_failures"], ["test:C-1"])
            state_path = Path(root, "sca-state.json")
            self.assertTrue(state_path.is_file())
            self.assertFalse(Path(str(state_path) + ".tmp").exists())
            self.assertEqual(json.loads(state_path.read_text())["summary"]["pass"], 1)

    def test_rollback_replays_change_after_durable_enqueue_failure(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            collector = ScaCollector(state_dir=root)
            with mock.patch(
                "agent.os.windows.sca.ScaEngine.scan",
                side_effect=[
                    self._document("pass"),
                    self._document("fail"),
                    self._document("fail"),
                ],
            ):
                collector.collect()
                collector.commit()
                failed_enqueue = collector.collect()
                collector.rollback()
                retried = collector.collect()

            self.assertEqual(failed_enqueue["changes"]["new_failures"], ["test:C-1"])
            self.assertEqual(retried["changes"]["new_failures"], ["test:C-1"])
            self.assertTrue(collector.health_snapshot()["pending_commit"])

    def test_failed_state_write_stays_pending_for_retry(self) -> None:
        collector = ScaCollector(state_dir="unused")
        with mock.patch(
            "agent.os.windows.sca.ScaEngine.scan",
            return_value=self._document("pass"),
        ), mock.patch.object(collector, "_persist_state", return_value=False):
            collector.collect()
            collector.commit()
        self.assertTrue(collector.health_snapshot()["pending_commit"])

    def test_collector_failure_returns_sendable_error_document(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            collector = ScaCollector(state_dir=root)
            with mock.patch(
                "agent.os.windows.sca.ScaEngine.scan",
                side_effect=RuntimeError("sensitive internal detail"),
            ):
                result = collector.collect()
            self.assertEqual(result["summary"]["status"], "error")
            self.assertEqual(result["summary"]["error"], 1)
            self.assertEqual(result["collector_error"]["code"], "sca_scan_failed")
            self.assertNotIn("sensitive internal detail", json.dumps(result))
            self.assertEqual(collector.health_snapshot()["consecutive_failures"], 1)


class ScaPolicyAndNormalizationTests(unittest.TestCase):
    def test_bundled_policy_is_large_unique_read_only_and_versioned(self) -> None:
        checks = POLICY["checks"]
        ids = [check["id"] for check in checks]
        self.assertGreaterEqual(len(checks), 46)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("aligned", POLICY["name"].lower())
        self.assertEqual(POLICY["version"], "2.1.0")
        for check_id in (
            "W-1.9", "W-1.10", "W-1.11", "W-1.12", "W-2.10",
            "W-3.7", "W-4.7", "W-4.8", "W-4.9", "W-5.8",
        ):
            self.assertIn(check_id, ids)

        forbidden = (
            "reg add ", "reg delete ", "set-itemproperty", "new-itemproperty",
            "remove-item", "disable-", "enable-", "start-service", "stop-service",
            "sc config ", "netsh advfirewall set",
        )
        for check in checks:
            for value in ([check.get("applicability")] if check.get("applicability") else []) + list(check.get("rules") or []):
                rule = value.get("rule", "") if isinstance(value, dict) else str(value)
                lowered = rule.lower()
                self.assertFalse(
                    any(token in lowered for token in forbidden),
                    f"mutating rule in {check['id']}: {rule}",
                )

    def test_normalizer_preserves_manager_facing_assessment_fields(self) -> None:
        raw = {
            "schema_version": 2,
            "scan_id": "scan-1",
            "generated_at": 10,
            "started_at": 8,
            "completed_at": 10,
            "duration_ms": 2000,
            "changes": {"new_failures": ["test:C-1"]},
            "policies": [{
                "policy_id": "test",
                "policy_name": "Test",
                "policy_version": "2",
                "benchmark": "aligned",
                "profile": ["level_1"],
                "checks": [{
                    "id": "C-1", "title": "Control", "result": "fail",
                    "severity": "high", "profile": ["level_1"], "scored": True,
                    "duration_ms": 5,
                    "rules": [{
                        "id": "rule", "rule_type": "command", "result": "fail",
                        "return_code": 0, "duration_ms": 4, "evidence": "value=0",
                    }],
                }],
                "summary": {
                    "total": 1, "pass": 0, "fail": 1, "unknown": 0,
                    "error": 0, "not_applicable": 0, "score_pct": 0,
                    "coverage_pct": 100, "status": "non_compliant",
                },
            }],
            "summary": {
                "total": 1, "pass": 0, "fail": 1, "unknown": 0,
                "error": 0, "not_applicable": 0, "score_pct": 0,
                "coverage_pct": 100, "status": "non_compliant", "policies": 1,
            },
        }
        normalized = normalize("sca", raw)
        self.assertEqual(normalized["scan_id"], "scan-1")
        self.assertEqual(normalized["summary"]["status"], "non_compliant")
        self.assertEqual(normalized["policies"][0]["policy_version"], "2")
        self.assertEqual(normalized["policies"][0]["checks"][0]["severity"], "high")
        self.assertEqual(
            normalized["policies"][0]["checks"][0]["rules"][0]["evidence"],
            "value=0",
        )
        self.assertEqual(normalized["changes"]["new_failures"], ["test:C-1"])


class MsiHardeningTests(unittest.TestCase):
    def test_gui_properties_are_bridged_to_deferred_config_action(self) -> None:
        windows_dir = Path(__file__).resolve().parents[1]
        wix = (windows_dir / "pkg" / "attacklens.wxs").read_text(encoding="utf-8")
        bridge = (windows_dir / "pkg" / "prepare_config_data.js").read_text(
            encoding="utf-8"
        )
        generator = (windows_dir / "pkg" / "gen_config.ps1").read_text(
            encoding="utf-8"
        )

        self.assertIn('Id="CA_PrepareWriteConfig"', wix)
        self.assertIn('BinaryRef="PrepareConfigDataScript"', wix)
        self.assertIn('JScriptCall="PrepareConfigData"', wix)
        self.assertIn('Before="CA_WriteConfig"', wix)
        self.assertIn('-EncodedCustomActionData &quot;[CustomActionData]&quot;', wix)
        self.assertIn('HideTarget="yes"', wix)
        self.assertIn("Session.Property('CA_WriteConfig')", bridge)
        self.assertIn("function PrepareConfigData()", bridge)
        self.assertIn("return 1;", bridge)
        self.assertIn("['U', 'MANAGER_URL']", bridge)
        self.assertIn(
            "[Convert]::FromBase64String($EncodedCustomActionData)", generator
        )

    def test_service_sid_configuration_uses_scm_not_unreliable_msi_table(self) -> None:
        windows_dir = Path(__file__).resolve().parents[1]
        source = (windows_dir / "pkg" / "attacklens.wxs").read_text(encoding="utf-8")
        self.assertNotIn("<ServiceConfig", source)
        self.assertIn('Id="CA_SetAgentServiceSid"', source)
        self.assertIn('Id="CA_SetWatchdogServiceSid"', source)
        self.assertIn("sidtype AttackLensAgent unrestricted", source)
        self.assertIn("sidtype AttackLensWatchdog unrestricted", source)
        self.assertIn('After="InstallServices"', source)
        self.assertIn('After="CA_SetAgentServiceSid"', source)

    def test_every_installer_generator_enables_hourly_assessment(self) -> None:
        windows_dir = Path(__file__).resolve().parents[1]
        expected = {
            windows_dir / "installer" / "generate_config.ps1": "i=3600",
            windows_dir / "installer" / "install.ps1": "interval_sec = 3600",
            windows_dir / "pkg" / "generate_config.ps1": "i=3600",
            windows_dir / "pkg" / "gen_config.ps1": "interval = 3600",
        }
        for path, token in expected.items():
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn(token, source)
                self.assertNotIn("43200", source)


if __name__ == "__main__":
    unittest.main()
