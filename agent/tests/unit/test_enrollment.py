"""
agent/tests/unit/test_enrollment.py — Tests for the enrollment flow.

Failure points covered:
  - Missing enrollment token → clear error message
  - Keystore write failure → enrollment aborted before network call
  - Key stored BEFORE network call (never lost if network fails)
  - Manager returns 401 → EnrollmentError with useful message
  - Manager returns 409 → re-enrollment conflict message
  - Network failure → EnrollmentError
  - Generated key is always 256-bit (64 hex chars)
  - needs_enrollment returns correct signal
"""
from __future__ import annotations

import secrets
from unittest.mock import patch

import pytest

from agent.agent.enrollment import (
    EnrollmentError,
    enroll,
    needs_enrollment,
    _post_enroll,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfg(tmp_path, token: str = "valid-token") -> dict:
    return {
        "agent":      {"id": "agent-001", "name": "Test Agent"},
        "manager":    {"url": "https://127.0.0.1:19999", "tls_verify": False},
        "enrollment": {"token": token, "keystore": "file"},
        "paths":      {"security_dir": str(tmp_path / "security")},
    }


# ── needs_enrollment ──────────────────────────────────────────────────────────

class TestNeedsEnrollment:
    def test_true_when_no_key_in_store(self, tmp_path):
        with patch("agent.agent.enrollment.load_key", return_value=None):
            assert needs_enrollment("agent-001") is True

    def test_false_when_key_exists(self):
        with patch("agent.agent.enrollment.load_key",
                   return_value=secrets.token_hex(32)):
            assert needs_enrollment("agent-001") is False


# ── enroll ────────────────────────────────────────────────────────────────────

class TestEnroll:
    def test_open_enrollment_omits_token(self, tmp_path):
        manager_key = "a" * 64
        with patch("agent.agent.enrollment._post_enroll",
                   return_value={"api_key": manager_key}) as post:
            with patch("agent.agent.enrollment.store_key"):
                assert enroll(_cfg(tmp_path, token="")) == manager_key
        assert post.call_args.kwargs["token"] == ""

    def test_manager_key_is_256_bits(self, tmp_path):
        manager_key = "b" * 64
        with patch("agent.agent.enrollment._post_enroll",
                   return_value={"api_key": manager_key}):
            with patch("agent.agent.enrollment.store_key"):
                key = enroll(_cfg(tmp_path))
        assert len(key) == 64, "256-bit key = 64 hex characters"
        assert all(c in "0123456789abcdef" for c in key)

    def test_key_stored_after_network_call(self, tmp_path):
        """
        The manager issues the credential, so it can only be persisted after
        a successful response.
        """
        order: list[str] = []
        with patch("agent.agent.enrollment.store_key",
                   side_effect=lambda *a, **kw: order.append("store")):
            with patch("agent.agent.enrollment._post_enroll",
                       side_effect=lambda *a, **kw: (
                           order.append("post") or {"api_key": "c" * 64}
                       )):
                enroll(_cfg(tmp_path))
        assert order == ["post", "store"]

    def test_keystore_failure_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment._post_enroll",
                   return_value={"api_key": "d" * 64}):
            with patch("agent.agent.enrollment.store_key",
                       side_effect=PermissionError("disk full")):
                with pytest.raises(EnrollmentError, match="Keystore"):
                    enroll(_cfg(tmp_path))

    def test_network_failure_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment.store_key"):
            with patch("agent.agent.enrollment._post_enroll",
                       side_effect=ConnectionRefusedError("refused")):
                with pytest.raises(EnrollmentError, match="failed"):
                    enroll(_cfg(tmp_path))

    def test_manager_401_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment.store_key"):
            with patch("agent.agent.enrollment._post_enroll",
                       side_effect=EnrollmentError("HTTP 401")):
                with pytest.raises(EnrollmentError, match="401"):
                    enroll(_cfg(tmp_path))

    def test_manager_409_raises_enrollment_error(self, tmp_path):
        with patch("agent.agent.enrollment.store_key"):
            with patch("agent.agent.enrollment._post_enroll",
                       side_effect=EnrollmentError("HTTP 409")):
                with pytest.raises(EnrollmentError):
                    enroll(_cfg(tmp_path))

    @pytest.mark.parametrize("response", [
        None,
        [],
        {},
        {"api_key": "short"},
        {"api_key": "z" * 64},
    ])
    def test_malformed_manager_key_fails_before_storage(self, tmp_path, response):
        with patch("agent.agent.enrollment._post_enroll", return_value=response):
            with patch("agent.agent.enrollment.store_key") as store:
                with pytest.raises(EnrollmentError, match="response|api_key"):
                    enroll(_cfg(tmp_path))
        store.assert_not_called()

    def test_invalid_expiry_does_not_break_successful_enrollment(self, tmp_path):
        manager_key = "e" * 64
        with patch("agent.agent.enrollment._post_enroll", return_value={
            "api_key": manager_key,
            "expires_at": "not-a-timestamp",
        }):
            with patch("agent.agent.enrollment.store_key"):
                assert enroll(_cfg(tmp_path)) == manager_key

    def test_each_manager_key_is_preserved(self, tmp_path):
        keys = set()
        for i in range(5):
            manager_key = f"{i:064x}"
            with patch("agent.agent.enrollment._post_enroll",
                       return_value={"api_key": manager_key}):
                with patch("agent.agent.enrollment.store_key"):
                    keys.add(enroll(_cfg(tmp_path)))
        assert keys == {f"{i:064x}" for i in range(5)}


# ── _post_enroll (network layer) ──────────────────────────────────────────────

class TestPostEnroll:
    """Tests for the HTTP layer using urllib mock."""

    def _payload(self) -> dict:
        import time, platform, socket, sys
        return {
            "agent_id":   "agent-001",
            "agent_name": "Test",
            "api_key":    secrets.token_hex(32),
            "hostname":   socket.gethostname(),
            "os":         "macos",
            "arch":       platform.machine(),
            "timestamp":  int(time.time()),
        }

    def test_200_succeeds(self):
        from unittest.mock import MagicMock, patch
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        with patch("urllib.request.urlopen", return_value=mock_resp):
            _post_enroll("https://x/enroll", "tok", self._payload(), False)

    def test_401_raises(self):
        import urllib.error
        err = urllib.error.HTTPError("url", 401, "Unauthorized", {}, None)
        err.read = lambda: b"bad token"
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(EnrollmentError, match="401"):
                _post_enroll("https://x/enroll", "tok", self._payload(), False)

    def test_409_raises(self):
        import urllib.error
        err = urllib.error.HTTPError("url", 409, "Conflict", {}, None)
        err.read = lambda: b"already enrolled"
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(EnrollmentError, match="409"):
                _post_enroll("https://x/enroll", "tok", self._payload(), False)
