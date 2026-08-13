"""Cross-platform tests for the centralized Windows ACL policy."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))

from agent.os.windows import acl  # noqa: E402


def completed(command, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_secure_dir_command_is_deterministic(tmp_path):
    command = acl.build_icacls_command(tmp_path, acl.policy("secure_dir"))
    assert command == [
        "icacls", os.fspath(tmp_path), "/inheritance:r",
        "/remove:g", "*S-1-1-0", "/remove:g", "*S-1-5-11",
        "/remove:g", "*S-1-5-32-545",
        "/grant:r", "*S-1-5-18:(OI)(CI)(F)",
        "/grant:r", "*S-1-5-20:(OI)(CI)(F)",
        "/grant:r", "*S-1-5-32-544:(OI)(CI)(F)",
    ]


def test_service_owned_files_allow_system_repair_and_rotation(tmp_path):
    for policy_name in ("config_file", "key_file"):
        command = acl.build_icacls_command(tmp_path, acl.policy(policy_name))
        assert "*S-1-5-18:(F)" in command
        assert "*S-1-5-18:(R)" not in command


def test_check_acl_detects_compliant_output(tmp_path):
    def runner(command, **kwargs):
        return completed(
            command,
            stdout="NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n"
                   "NT AUTHORITY\\NETWORK SERVICE:(OI)(CI)(F)\n"
                   "BUILTIN\\Administrators:(OI)(CI)(F)\n",
        )

    result = acl.check_acl(tmp_path, "secure_dir", runner=runner)
    assert result.compliant is True
    assert result.error is None


def test_check_acl_reports_drift_without_repair(tmp_path):
    def runner(command, **kwargs):
        return completed(command, stdout="NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n")

    result = acl.check_acl(tmp_path, "secure_dir", runner=runner)
    assert result.compliant is False
    assert result.error == "ACL does not match policy"


def test_repair_acl_returns_command_failure(tmp_path):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return completed(command, returncode=5, stderr="Access is denied")

    result = acl.repair_acl(tmp_path, "key_file", runner=runner)
    assert result.compliant is False
    assert "returned 5" in result.error
    assert calls and calls[0][0] == "icacls"


def test_runtime_acl_repair_creates_service_directories(tmp_path):
    paths = {
        "security_dir": str(tmp_path / "security"),
        "spool_dir": str(tmp_path / "spool"),
        "data_dir": str(tmp_path / "data"),
        "log_dir": str(tmp_path / "logs"),
        "status_dir": str(tmp_path / "status"),
    }

    def runner(command, **kwargs):
        return completed(command)

    results = acl.ensure_runtime_acls(paths, runner=runner)
    assert len(results) == 5
    assert all(result.compliant for result in results)
    assert Path(paths["security_dir"]).is_dir()


def test_public_status_is_read_only_for_local_users(tmp_path):
    command = acl.build_icacls_command(tmp_path, acl.policy("status_dir"))
    assert "*S-1-5-32-545:(OI)(CI)(RX)" in command
    assert "*S-1-5-32-545:(OI)(CI)(M)" not in command


def test_acl_is_skipped_off_windows_without_runner(tmp_path):
    result = acl.check_acl(tmp_path, "secure_dir")
    if sys.platform != "win32":
        assert result.skipped is True
        assert result.compliant is False
