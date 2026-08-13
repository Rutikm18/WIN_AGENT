from __future__ import annotations

import json
import time
from unittest import mock

from agent.os.windows.diagnostics import capability_report, status_report


def _cfg(tmp_path):
    data = tmp_path / "data"
    security = tmp_path / "security"
    spool = tmp_path / "spool"
    data.mkdir()
    security.mkdir()
    spool.mkdir()
    return {
        "agent": {"id": "win-test"},
        "manager": {"url": "http://manager.test:8080", "tls_verify": False},
        "paths": {
            "data_dir": str(data),
            "security_dir": str(security),
            "spool_dir": str(spool),
        },
        "collection": {"sections": {}},
    }


def test_capabilities_describe_implemented_native_surfaces(tmp_path):
    with mock.patch(
        "agent.os.windows.diagnostics.verify_current_install",
        return_value={"status": "verified", "checked_files": 3},
    ):
        report = capability_report(_cfg(tmp_path))
    assert report["persistence"]["transactional_baseline"] is True
    assert report["posture"]["windows_cis_checks"] == 46
    assert "eventlog_push_subscription" in report["telemetry"]
    assert "realtime_etw_session" in report["telemetry"]


def test_status_reports_last_contact_and_dpapi_backend(tmp_path):
    cfg = _cfg(tmp_path)
    runtime = {
        "updated_at": int(time.time()),
        "health": {"delivery": {"last_success_at": 12345}},
    }
    (tmp_path / "data" / "agent.runtime.json").write_text(
        json.dumps(runtime), encoding="utf-8"
    )
    (tmp_path / "security" / "win-test.key.dpapi").write_bytes(b"encrypted")
    with mock.patch(
        "agent.os.windows.diagnostics.capability_report", return_value={}
    ), mock.patch(
        "agent.os.windows.diagnostics._service_status", return_value={"available": False}
    ):
        report = status_report(cfg)
    assert report["last_manager_contact_at"] == 12345
    assert report["enrollment"]["configured"] is True
    assert report["enrollment"]["backend"] == "dpapi_machine_file"
