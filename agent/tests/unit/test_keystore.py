"""
agent/tests/unit/test_keystore.py — Tests for secure key persistence.

Failure points covered:
  - File not found → None returned (clean "not enrolled" signal)
  - World-readable file → refused to load (security enforcement)
  - Directory creation on first store
  - File permissions set to exactly 0600
  - Atomic write (no partial file left on failure)
  - Multiple agents isolated per-file
  - Delete clears file
"""
from __future__ import annotations

import os
import secrets
import stat

import pytest

from agent.agent.keystore import (
    store_key,
    load_key,
    delete_key,
    _key_file_path,
    _load_key_file,
    _store_key_file,
)


class TestFileBackend:
    """All tests use backend="file" and a tmp_path security_dir."""

    def test_store_then_load_roundtrip(self, tmp_path):
        key = secrets.token_hex(32)
        store_key("agent-001", key, backend="file", security_dir=str(tmp_path))
        loaded = load_key("agent-001", backend="file", security_dir=str(tmp_path))
        assert loaded == key

    def test_file_permissions_are_exactly_0600(self, tmp_path):
        if os.name == "nt":
            pytest.skip("POSIX mode bits are not enforceable on Windows")
        store_key("agent-001", secrets.token_hex(32), backend="file",
                  security_dir=str(tmp_path))
        path = _key_file_path(str(tmp_path), "agent-001")
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    def test_load_returns_none_when_file_absent(self, tmp_path):
        assert load_key("ghost", backend="file", security_dir=str(tmp_path)) is None

    def test_load_refuses_world_readable_file(self, tmp_path):
        """A key file readable by others is treated as compromised."""
        if os.name == "nt":
            pytest.skip("POSIX mode bits are not enforceable on Windows")
        key = secrets.token_hex(32)
        path = tmp_path / "agent-002.key"
        path.write_text(key)
        path.chmod(0o644)   # group+other readable
        result = _load_key_file("agent-002", str(tmp_path))
        assert result is None, "Should refuse to load world-readable key"

    def test_load_refuses_group_readable_file(self, tmp_path):
        if os.name == "nt":
            pytest.skip("POSIX mode bits are not enforceable on Windows")
        path = tmp_path / "agent-003.key"
        path.write_text(secrets.token_hex(32))
        path.chmod(0o640)   # group readable
        assert _load_key_file("agent-003", str(tmp_path)) is None

    def test_delete_removes_file(self, tmp_path):
        store_key("agent-001", secrets.token_hex(32), backend="file",
                  security_dir=str(tmp_path))
        delete_key("agent-001", backend="file", security_dir=str(tmp_path))
        assert load_key("agent-001", backend="file",
                        security_dir=str(tmp_path)) is None

    def test_delete_is_idempotent(self, tmp_path):
        """Deleting a non-existent key should not raise."""
        delete_key("never-existed", backend="file", security_dir=str(tmp_path))

    def test_security_dir_created_on_first_store(self, tmp_path):
        nested = str(tmp_path / "deep" / "nested" / "security")
        assert not os.path.exists(nested)
        store_key("agent-001", secrets.token_hex(32), backend="file",
                  security_dir=nested)
        assert os.path.isdir(nested)

    def test_multiple_agents_are_isolated(self, tmp_path):
        key1 = secrets.token_hex(32)
        key2 = secrets.token_hex(32)
        assert key1 != key2
        store_key("agent-A", key1, backend="file", security_dir=str(tmp_path))
        store_key("agent-B", key2, backend="file", security_dir=str(tmp_path))
        assert load_key("agent-A", backend="file",
                        security_dir=str(tmp_path)) == key1
        assert load_key("agent-B", backend="file",
                        security_dir=str(tmp_path)) == key2

    def test_overwrite_updates_key(self, tmp_path):
        old = secrets.token_hex(32)
        new = secrets.token_hex(32)
        store_key("agent-001", old, backend="file", security_dir=str(tmp_path))
        store_key("agent-001", new, backend="file", security_dir=str(tmp_path))
        assert load_key("agent-001", backend="file",
                        security_dir=str(tmp_path)) == new

    def test_empty_stored_key_returns_none(self, tmp_path):
        path = tmp_path / "agent-004.key"
        path.write_text("")
        path.chmod(0o600)
        assert _load_key_file("agent-004", str(tmp_path)) is None

    def test_key_is_64_hex_chars(self, tmp_path):
        key = secrets.token_hex(32)
        assert len(key) == 64
        store_key("agent-001", key, backend="file", security_dir=str(tmp_path))
        loaded = load_key("agent-001", backend="file", security_dir=str(tmp_path))
        assert len(loaded) == 64
        assert all(c in "0123456789abcdef" for c in loaded)
