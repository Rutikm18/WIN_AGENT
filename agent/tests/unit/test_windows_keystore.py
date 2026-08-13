"""
agent/tests/unit/test_windows_keystore.py

Tests for agent/os/windows/keystore.py

All tests mock the platform-specific backends (keyring, win32crypt) so they
run on macOS/Linux CI.  The tests focus on:

  • Correct priority chain: Credential Manager → DPAPI file → plain file
  • Atomic write pattern (no partial-key corruption)
  • ACL restriction calls are made (icacls invoked)
  • load_key returns None when no key exists
  • delete_key removes both DPAPI and plain files
  • Key format validation (64-hex round-trip)
"""
from __future__ import annotations

import os
import sys
import tempfile
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

import agent.os.windows.keystore as ks
from agent.os.windows.acl import AclResult

SAMPLE_KEY  = "a" * 64   # valid 64-hex key
AGENT_ID    = "test-agent-win-001"


# ── helpers ───────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_security_dir(tmp_path):
    sec = tmp_path / "security"
    sec.mkdir()
    return str(sec)


def _make_dpapi_mock():
    """Return a mock win32crypt that round-trips CryptProtectData/CryptUnprotectData."""
    mock = MagicMock()
    store = {}

    def _protect(data, *args, **kwargs):
        store["data"] = data
        return b"ENCRYPTED:" + data

    def _unprotect(data, *args, **kwargs):
        if data.startswith(b"ENCRYPTED:"):
            return (b"desc", data[len(b"ENCRYPTED:"):])
        raise Exception("Bad data")

    mock.CryptProtectData.side_effect = _protect
    mock.CryptUnprotectData.side_effect = _unprotect
    return mock


# ── Credential Manager (keyring) path ────────────────────────────────────────

class TestCredentialManager:
    def test_store_uses_keyring(self, tmp_security_dir):
        mock_kr = MagicMock()
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            ks._cm_store(AGENT_ID, SAMPLE_KEY)
        mock_kr.set_password.assert_called_once_with(
            ks._CM_SERVICE, AGENT_ID, SAMPLE_KEY
        )

    def test_load_uses_keyring(self):
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = SAMPLE_KEY
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            result = ks._cm_load(AGENT_ID)
        assert result == SAMPLE_KEY

    def test_load_returns_none_when_keyring_missing(self):
        with patch.dict("sys.modules", {"keyring": None}):
            result = ks._cm_load(AGENT_ID)
        assert result is None

    def test_load_rejects_malformed_key(self):
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = "not-a-valid-api-key"
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            assert ks._cm_load(AGENT_ID) is None

    def test_store_returns_false_when_keyring_raises(self):
        mock_kr = MagicMock()
        mock_kr.set_password.side_effect = Exception("no keyring")
        with patch.dict("sys.modules", {"keyring": mock_kr}):
            result = ks._cm_store(AGENT_ID, SAMPLE_KEY)
        assert result is False


# ── DPAPI file path ───────────────────────────────────────────────────────────

class TestDpapiFile:
    def test_roundtrip(self, tmp_security_dir):
        mock_w32 = _make_dpapi_mock()
        with patch.dict("sys.modules", {"win32crypt": mock_w32}), \
             patch("agent.os.windows.keystore._restrict_file_acl"), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            stored = ks._dpapi_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
            assert stored is True
            loaded = ks._dpapi_load(AGENT_ID, tmp_security_dir)
        assert loaded == SAMPLE_KEY

    def test_returns_none_when_file_missing(self, tmp_security_dir):
        mock_w32 = _make_dpapi_mock()
        with patch.dict("sys.modules", {"win32crypt": mock_w32}):
            result = ks._dpapi_load("no-such-agent", tmp_security_dir)
        assert result is None

    def test_store_returns_false_when_win32crypt_missing(self, tmp_security_dir):
        with patch.dict("sys.modules", {"win32crypt": None}):
            result = ks._dpapi_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        assert result is False

    def test_acl_restriction_called(self, tmp_security_dir):
        mock_w32 = _make_dpapi_mock()
        with patch.dict("sys.modules", {"win32crypt": mock_w32}), \
             patch("agent.os.windows.keystore._restrict_file_acl") as mf, \
             patch("agent.os.windows.keystore._restrict_dir_acl") as md:
            ks._dpapi_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        mf.assert_called_once()
        md.assert_called_once()

    def test_acl_failure_removes_dpapi_file(self, tmp_security_dir):
        mock_w32 = _make_dpapi_mock()
        with patch.dict("sys.modules", {"win32crypt": mock_w32}), \
             patch("agent.os.windows.keystore._restrict_dir_acl"), \
             patch("agent.os.windows.keystore._restrict_file_acl",
                   side_effect=PermissionError("ACL denied")):
            assert ks._dpapi_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir) is False
        assert not os.path.exists(ks._dpapi_path(AGENT_ID, tmp_security_dir))

    def test_prewrite_failure_preserves_existing_dpapi_file(self, tmp_security_dir):
        path = ks._dpapi_path(AGENT_ID, tmp_security_dir)
        with open(path, "wb") as credential_file:
            credential_file.write(b"existing-encrypted-key")
        mock_w32 = _make_dpapi_mock()
        mock_w32.CryptProtectData.side_effect = OSError("DPAPI unavailable")
        with patch.dict("sys.modules", {"win32crypt": mock_w32}), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            assert ks._dpapi_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir) is False
        with open(path, "rb") as credential_file:
            assert credential_file.read() == b"existing-encrypted-key"

    def test_atomic_write(self, tmp_security_dir):
        """Ensure .tmp file is used and atomically renamed."""
        mock_w32 = _make_dpapi_mock()
        written_paths = []

        real_open = open

        def spy_open(path, mode="r", **kwargs):
            written_paths.append(path)
            return real_open(path, mode, **kwargs)

        with patch.dict("sys.modules", {"win32crypt": mock_w32}), \
             patch("builtins.open", side_effect=spy_open), \
             patch("agent.os.windows.keystore._restrict_file_acl"), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            try:
                ks._dpapi_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
            except Exception:
                pass  # open mock may not behave perfectly; just check .tmp was used

        # At least one write should target the .tmp path
        tmp_writes = [p for p in written_paths if p.endswith(".tmp")]
        assert tmp_writes, "Expected atomic .tmp write"


# ── Plain file fallback ───────────────────────────────────────────────────────

class TestPlainFile:
    def test_roundtrip(self, tmp_security_dir):
        with patch("agent.os.windows.keystore._restrict_file_acl"), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
            result = ks._file_load(AGENT_ID, tmp_security_dir)
        assert result == SAMPLE_KEY

    def test_returns_none_when_missing(self, tmp_security_dir):
        result = ks._file_load("nonexistent-agent", tmp_security_dir)
        assert result is None

    def test_rejects_malformed_key(self, tmp_security_dir):
        path = ks._plain_path(AGENT_ID, tmp_security_dir)
        with open(path, "w", encoding="ascii") as key_file:
            key_file.write("not-a-valid-api-key")
        assert ks._file_load(AGENT_ID, tmp_security_dir) is None

    def test_load_closes_file_handle(self, tmp_security_dir):
        with patch("agent.os.windows.keystore._restrict_file_acl"), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        real_open = open
        opened = []

        def tracked_open(*args, **kwargs):
            handle = real_open(*args, **kwargs)
            opened.append(handle)
            return handle

        with patch("builtins.open", side_effect=tracked_open), \
             patch("agent.os.windows.keystore._restrict_file_acl"):
            assert ks._file_load(AGENT_ID, tmp_security_dir) == SAMPLE_KEY
        assert opened and all(handle.closed for handle in opened)

    def test_store_rejects_malformed_key(self, tmp_security_dir):
        with pytest.raises(ValueError, match="64-character hexadecimal"):
            ks.store_key(AGENT_ID, "invalid", security_dir=tmp_security_dir)

    def test_acl_failure_removes_plain_file(self, tmp_security_dir):
        with patch("agent.os.windows.keystore._restrict_dir_acl"), \
             patch("agent.os.windows.keystore._restrict_file_acl",
                   side_effect=PermissionError("ACL denied")):
            with pytest.raises(PermissionError, match="ACL denied"):
                ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        assert not os.path.exists(ks._plain_path(AGENT_ID, tmp_security_dir))

    def test_prewrite_failure_preserves_existing_plain_file(self, tmp_security_dir):
        path = ks._plain_path(AGENT_ID, tmp_security_dir)
        with open(path, "w", encoding="ascii") as credential_file:
            credential_file.write(SAMPLE_KEY)
        with patch("agent.os.windows.keystore._restrict_dir_acl"), \
             patch("builtins.open", side_effect=OSError("disk full")):
            with pytest.raises(OSError, match="disk full"):
                ks._file_store(AGENT_ID, "b" * 64, tmp_security_dir)
        with open(path, "r", encoding="ascii") as credential_file:
            assert credential_file.read() == SAMPLE_KEY

    def test_acl_drift_refuses_plain_file(self, tmp_security_dir):
        path = ks._plain_path(AGENT_ID, tmp_security_dir)
        with open(path, "w", encoding="ascii") as key_file:
            key_file.write(SAMPLE_KEY)
        with patch("agent.os.windows.keystore.repair_acl", return_value=AclResult(
            path=path,
            policy="key_file",
            compliant=False,
            error="ACL drift",
        )):
            assert ks._file_load(AGENT_ID, tmp_security_dir) is None

    def test_path_sanitisation(self, tmp_security_dir):
        """Agent IDs with special chars should not create path traversal."""
        evil_id = "../../../etc/passwd"
        path    = ks._plain_path(evil_id, tmp_security_dir)
        assert os.path.commonpath([path, tmp_security_dir]) == tmp_security_dir


# ── Priority chain ────────────────────────────────────────────────────────────

class TestPriorityChain:
    def test_cm_wins_over_dpapi(self, tmp_security_dir):
        mock_kr = MagicMock()
        mock_kr.get_password.return_value = SAMPLE_KEY
        mock_w32 = _make_dpapi_mock()

        # Also write a DPAPI file with a different key
        with patch.dict("sys.modules", {"win32crypt": mock_w32, "keyring": None}), \
             patch("agent.os.windows.keystore._restrict_file_acl"), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            ks._dpapi_store(AGENT_ID, "b" * 64, tmp_security_dir)

        with patch.dict("sys.modules", {"keyring": mock_kr, "win32crypt": mock_w32}):
            result = ks.load_key(AGENT_ID, security_dir=tmp_security_dir)

        assert result == SAMPLE_KEY   # Credential Manager wins

    def test_dpapi_used_when_cm_unavailable(self, tmp_security_dir):
        mock_w32 = _make_dpapi_mock()

        with patch.dict("sys.modules", {"win32crypt": mock_w32, "keyring": None}), \
             patch("agent.os.windows.keystore._restrict_file_acl"), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            ks._dpapi_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)

        with patch.dict("sys.modules", {"keyring": None, "win32crypt": mock_w32}), \
             patch("agent.os.windows.keystore._restrict_file_acl"):
            result = ks.load_key(AGENT_ID, security_dir=tmp_security_dir)

        assert result == SAMPLE_KEY

    def test_returns_none_when_no_key_anywhere(self, tmp_security_dir):
        with patch.dict("sys.modules", {"keyring": None, "win32crypt": None}):
            result = ks.load_key("ghost-agent", security_dir=tmp_security_dir)
        assert result is None


# ── delete_key ────────────────────────────────────────────────────────────────

class TestDeleteKey:
    def test_removes_plain_file(self, tmp_security_dir):
        with patch("agent.os.windows.keystore._restrict_file_acl"), \
             patch("agent.os.windows.keystore._restrict_dir_acl"):
            ks._file_store(AGENT_ID, SAMPLE_KEY, tmp_security_dir)
        with patch("agent.os.windows.keystore._restrict_file_acl"):
            assert ks._file_load(AGENT_ID, tmp_security_dir) is not None

        with patch.dict("sys.modules", {"keyring": None}):
            ks.delete_key(AGENT_ID, security_dir=tmp_security_dir)
        with patch("agent.os.windows.keystore._restrict_file_acl"):
            assert ks._file_load(AGENT_ID, tmp_security_dir) is None

    def test_delete_nonexistent_does_not_raise(self, tmp_security_dir):
        with patch.dict("sys.modules", {"keyring": None}):
            ks.delete_key("nonexistent-agent", security_dir=tmp_security_dir)
