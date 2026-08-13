"""Portable scenario lab for AttackLens startup diagnosis and recovery."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[4]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from agent.os.windows.startup_recovery import (
    classify_startup_error,
    diagnose_startup,
    safe_repair,
)
from agent.os.windows.self_defense import audit_self_defense


VALID_CONFIG = r'''
[agent]
id = "scenario-agent"
name = "scenario-agent"

[manager]
url = ""
tls_verify = true

[enrollment]
token = ""

[paths]
config_dir = "C:/lab/config"
log_dir = "C:/lab/logs"
spool_dir = "C:/lab/spool"
data_dir = "C:/lab/data"
security_dir = "C:/lab/security"

[logging]
level = "INFO"
file = "C:/lab/logs/agent.log"

[collection]
'''


class FakeWinError(RuntimeError):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.winerror = code


def run_all() -> dict:
    results: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="attacklens-scenarios-") as root:
        previous = os.getcwd()
        os.chdir(root)
        try:
            missing = Path("missing-agent.toml")
            report = diagnose_startup(missing)
            results["missing_config"] = {
                "passed": not report["checks"]["config"]["valid"],
                "problems": report["problems"],
            }

            config = Path("agent.toml")
            config.write_text("not = [valid", encoding="utf-8")
            backup = Path("agent.toml.last-known-good")
            backup.write_text(VALID_CONFIG, encoding="utf-8")
            actions = safe_repair(config)
            repaired = diagnose_startup(config)
            results["last_known_good_restore"] = {
                "passed": repaired["checks"]["config"]["valid"],
                "actions": [action.action for action in actions],
            }

            data_dir = Path("C:/lab/data")
            data_dir.mkdir(parents=True, exist_ok=True)
            runtime = data_dir / "agent.runtime.json"
            runtime.write_text("{broken", encoding="utf-8")
            actions = safe_repair(config)
            results["corrupt_runtime_quarantine"] = {
                "passed": not runtime.exists() and any(
                    action.action == "quarantine_runtime_state" and action.status == "repaired"
                    for action in actions
                )
            }

            spool = Path("C:/lab/spool")
            spool.mkdir(parents=True, exist_ok=True)
            (spool / "delivery-outbox.sqlite3").write_bytes(b"not-a-sqlite-database")
            report = diagnose_startup(config)
            results["corrupt_outbox_preserved"] = {
                "passed": (spool / "delivery-outbox.sqlite3").exists()
                and bool(report["checks"]["outbox"].get("error")),
                "error": report["checks"]["outbox"].get("error"),
            }

            classifications = {
                str(code): classify_startup_error(FakeWinError(code, message))["code"]
                for code, message in (
                    (5, "Access is denied"),
                    (1053, "service did not respond in a timely fashion"),
                    (1056, "service already running"),
                    (1060, "service does not exist"),
                    (1067, "process terminated unexpectedly"),
                    (1068, "dependency service failed"),
                )
            }
            results["scm_error_classification"] = {
                "passed": classifications == {
                    "5": "access_denied", "1053": "scm_start_timeout",
                    "1056": "already_running", "1060": "service_missing",
                    "1067": "process_terminated", "1068": "dependency_failure",
                },
                "classifications": classifications,
            }

            class AclResult:
                def __init__(self, compliant: bool):
                    self.policy = "config_file"
                    self.compliant = compliant
                    self.skipped = False
                    self.error = None

            acl_calls: list[bool] = []

            def acl_check(_paths, *, repair):
                acl_calls.append(bool(repair))
                return [AclResult(False)]

            def acl_repair(_paths, *, repair):
                acl_calls.append(bool(repair))
                return [AclResult(True)]

            self_defense = audit_self_defense(
                {},
                config_path=None,
                config_digest=None,
                integrity_fn=lambda: {"status": "verified", "checked_files": 2},
                acl_check_fn=acl_check,
                acl_repair_fn=acl_repair,
                defender_fn=lambda _paths: {
                    "supported": True,
                    "protected_path_excluded": True,
                },
            )
            results["self_defense_acl_and_defender"] = {
                "passed": (
                    acl_calls == [False, True]
                    and "config_file" in self_defense["repaired"]
                    and {item["code"] for item in self_defense["alerts"]}
                    == {"acl_drift_repaired", "agent_path_excluded_from_defender"}
                ),
                "alerts": self_defense["alerts"],
            }

            def integrity_failure():
                raise RuntimeError("checksum mismatch")

            integrity = audit_self_defense(
                {},
                config_path=None,
                config_digest=None,
                integrity_fn=integrity_failure,
                acl_check_fn=lambda _paths, repair: [],
                defender_fn=lambda _paths: {
                    "supported": True,
                    "protected_path_excluded": False,
                },
            )
            results["binary_integrity_stop_condition"] = {
                "passed": (
                    integrity["ok"] is False
                    and any(
                        item["code"] == "install_integrity_failed"
                        and item["severity"] == "critical"
                        for item in integrity["alerts"]
                    )
                ),
                "alerts": integrity["alerts"],
            }

            results["disk_pressure_classification"] = {
                "passed": classify_startup_error(
                    OSError("No space left on device")
                )["code"] == "disk_pressure",
            }

            db = Path("healthy.sqlite3")
            conn = sqlite3.connect(db)
            try:
                conn.execute("CREATE TABLE evidence (created_at INTEGER)")
                conn.execute("INSERT INTO evidence VALUES (?)", (int(time.time()),))
                conn.commit()
            finally:
                conn.close()
            results["scenario_engine"] = {"passed": db.is_file()}
        finally:
            os.chdir(previous)

    return {
        "ok": all(item.get("passed") for item in results.values()),
        "scenarios": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="run every startup scenario")
    parser.parse_args()
    result = run_all()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
