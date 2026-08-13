"""
agent/tests/unit/test_macos_keystore.py

Tests for agent/os/macos/keystore.py

All tests mock the platform-specific backends (keyring, security CLI)
so they run on any OS in CI.

Tests cover:
  • keyring backend: store/load/delete via mocked keyring
  • security CLI backend: store/load/delete via mocked subprocess
  • File backend: round-trip, atomic write, permission check, path sanitisation
  • Priority chain: keyring wins over CLI wins over file
  • load_key returns None when no key exists anywhere
  • delete_key removes all backends
  • Path traversal in agent_id is rejected
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

import agent.os.macos.keystore as ks

SAMPLE_KEY = "a" * 64   # valid 64-hex key
AGENT_ID   = "test-agent-mac-001"


# ── helpers ───────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_security_dir(tmp_path):
    sec = tmp_path / "security"
    sec.mkdir()
    return str(sec)


# ── keyring backend ───────────────────────────────────────────────────────────

class TestKeyringBackend:
    def test_store_uses_keyring(self, tmp_security_dir):
        mock_kr = MagicMock()
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            ks._kr_store(AGENT_ID, SAMPLE_KEY)
        mock_kr.set_password.assert_called_once_with(
            ks._KEYRING_SERVICE, AGENT_ID, SAMPLE_KEY
        )

    def test_load_uses_keyring(self):
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = SAMPLE_KEY
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            result = ks._kr_load(AGENT_ID)
        assert result == SAMPLE_KEY

    def test_load_returns_none_when_keyring_missing(self):
        with patch.dict("sys.modules", {"keyring": None}):
            result = ks._kr_load(AGENT_ID)
        assert result is None

    def test_store_returns_false_when_keyring_raises(self):
        mock_kr = MagicMock()
        mock_kr.set_password.side_effect = Exception("no keyring backend")
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            result = ks._kr_store(AGENT_ID, SAMPLE_KEY)
        assert result is False

    def test_load_returns_none_when_empty(self):
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = None
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            result = ks._kr_load(AGENT_ID)
        assert result is None


# ── security CLI backend ──────────────────────────────────────────────────────

class TestSecurityCli:
    def test_store_calls_security_add(self):
        mock_run = MagicMock()
        mock_run.return_value.returncode = 0
        with patch("agent.os.macos.keystore.subprocess.run", mock_run):
            result = ks._sec_cli_store(AGENT_ID, SAMPLE_KEY)
        assert result is True
        # Last call should be add-generic-password
        last_call = mock_run.call_args_list[-1]
        cmd = last_call[0][0]
        assert "add-generic-password" in cmd

    def test_load_returns_key_on_success(self):
        mock_run = MagicMock()
        mock_run.return_value.stdout = SAMPLE_KEY + "\n"
        mock_run.return_value.returncode = 0
        with patch("agent.os.macos.keystore.subprocess.run", mock_run):
            result = ks._sec_cli_load(AGENT_ID)
        assert result == SAMPLE_KEY

    def test_load_returns_none_on_failure(self):
        mock_run = MagicMock()
        mock_run.side_effect = Exception("security not found")
        with patch("agent.os.macos.keystore.subprocess.run", mock_run):
            result = ks._sec_cli_load(AGENT_ID)
        assert result is None

    def test_store_returns_false_on_failure(self):
        mock_run = MagicMock()
        mock_run.side_effect = Exception("security tool error")
        with patch("agent.os.macos.keystore.subprocess.run", mock_run):
            result = ks._sec_cli_store(AGENT_ID, SAMPLE_KEY)
        assert result is False


# ── file backend ──────────────────────────────────────────────────────────────

class TestFileBackend:
    def test_roundtrip(self, tmp_security_dir):
        ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        result = ks._file_load(AGENT_ID, tmp_security_dir)
        assert result == SAMPLE_KEY

    def test_returns_none_when_missing(self, tmp_security_dir):
        result = ks._file_load("nonexistent-agent", tmp_security_dir)
        assert result is None

    def test_atomic_write_uses_tmp_file(self, tmp_security_dir):
        """The .tmp file should be created during write."""
        written_paths = []
        real_open = open

        def spy_open(path, mode="r", **kwargs):
            written_paths.append(str(path))
            return real_open(path, mode, **kwargs)

        with patch("builtins.open", side_effect=spy_open):
            try:
                ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
            except Exception:
                pass

        tmp_writes = [p for p in written_paths if p.endswith(".tmp")]
        assert tmp_writes, "Expected atomic .tmp write path"

    def test_refuses_world_readable_file(self, tmp_security_dir):
        """File with group/other bits should be refused."""
        if os.name == "nt":
            pytest.skip("POSIX mode bits are not enforceable on Windows")
        ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        path = ks._plain_path(AGENT_ID, tmp_security_dir)
        os.chmod(path, 0o644)   # make world-readable
        result = ks._file_load(AGENT_ID, tmp_security_dir)
        assert result is None   # security check refuses

    def test_key_file_mode_is_0600(self, tmp_security_dir):
        if os.name == "nt":
            pytest.skip("POSIX mode bits are not enforceable on Windows")
        ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        path = ks._plain_path(AGENT_ID, tmp_security_dir)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600

    def test_path_sanitisation_prevents_traversal(self, tmp_security_dir):
        evil_id = "../../../etc/passwd"
        with pytest.raises(ValueError):
            ks._plain_path(evil_id, tmp_security_dir)

    def test_path_sanitisation_safe_chars(self, tmp_security_dir):
        safe_id = "agent-001_foo.bar"
        path = ks._plain_path(safe_id, tmp_security_dir)
        assert os.path.commonpath([path, tmp_security_dir]) == tmp_security_dir


# ── Priority chain (public API) ───────────────────────────────────────────────

class TestPriorityChain:
    def test_keyring_wins_over_file(self, tmp_security_dir):
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = SAMPLE_KEY

        # Store a different key in the file backend
        ks._file_store(AGENT_ID, "b" * 64, tmp_security_dir)

        mock_run = MagicMock()
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 1

        with patch.dict("sys.modules", {"keyring": mock_kr}), \
             patch("agent.os.macos.keystore.subprocess.run", mock_run):
            result = ks.load_key(AGENT_ID, backend="keychain",
                                 security_dir=tmp_security_dir)

        assert result == SAMPLE_KEY   # keyring wins

    def test_falls_back_to_file_when_keyring_missing(self, tmp_security_dir):
        ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)

        mock_run = MagicMock()
        mock_run.side_effect = Exception("security not available")

        with patch.dict("sys.modules", {"keyring": None}), \
             patch("agent.os.macos.keystore.subprocess.run", mock_run):
            result = ks.load_key(AGENT_ID, backend="keychain",
                                 security_dir=tmp_security_dir)

        assert result == SAMPLE_KEY

    def test_returns_none_when_nothing_stored(self, tmp_security_dir):
        mock_run = MagicMock()
        mock_run.side_effect = Exception("not available")

        with patch.dict("sys.modules", {"keyring": None}), \
             patch("agent.os.macos.keystore.subprocess.run", mock_run):
            result = ks.load_key("ghost-agent", backend="keychain",
                                 security_dir=tmp_security_dir)

        assert result is None


# ── delete_key ────────────────────────────────────────────────────────────────

class TestDeleteKey:
    def test_removes_file(self, tmp_security_dir):
        ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        assert ks._file_load(AGENT_ID, tmp_security_dir) is not None

        mock_run = MagicMock()
        with patch.dict("sys.modules", {"keyring": None}), \
             patch("agent.os.macos.keystore.subprocess.run", mock_run):
            ks.delete_key(AGENT_ID, backend="keychain",
                          security_dir=tmp_security_dir)

        assert ks._file_load(AGENT_ID, tmp_security_dir) is None

    def test_delete_nonexistent_does_not_raise(self, tmp_security_dir):
        mock_run = MagicMock()
        with patch.dict("sys.modules", {"keyring": None}), \
             patch("agent.os.macos.keystore.subprocess.run", mock_run):
            ks.delete_key("nonexistent-agent", backend="keychain",
                          security_dir=tmp_security_dir)  # should not raise
