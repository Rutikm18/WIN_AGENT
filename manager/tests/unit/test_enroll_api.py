"""
manager/tests/unit/test_enroll_api.py — Tests for POST /api/v1/enroll.

Failure points covered:
  - Missing enrollment token → 401
  - Invalid enrollment token → 401
  - Empty enrollment token list → 401 for all requests
  - Valid token, valid body → 200 + ok=True
  - Short/malformed api_key → 400
  - Non-hex api_key → 400
  - Timestamp too far in past/future → 400
  - Key stored in DB after enrollment
  - Re-enrollment rotates key + sets rotated=True
  - agent_id too long → 400
"""
from __future__ import annotations

import asyncio
import secrets
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from manager.manager.api.enroll import make_enroll_router


# ── Mock DB ───────────────────────────────────────────────────────────────────

class MockDB:
    def __init__(self):
        self.keys: dict[str, str] = {}
        self.agents: dict[str, dict] = {}

    async def get_agent_key(self, agent_id: str) -> str | None:
        return self.keys.get(agent_id)

    async def upsert_agent_key(self, agent_id: str, api_key_hex: str,
                                enrolled_ip: str = "", expires_at: int = 0,
                                label: str = "") -> None:
        self.keys[agent_id] = api_key_hex

    async def upsert_agent(self, agent_id: str, name: str, ip: str) -> None:
        self.agents[agent_id] = {"name": name, "ip": ip}


# ── Test fixtures ─────────────────────────────────────────────────────────────

def make_app(tokens: list[str]) -> tuple[FastAPI, MockDB]:
    db  = MockDB()
    app = FastAPI()
    # These cases exercise token-gated enrollment explicitly. Production
    # passes the OPEN_ENROLLMENT setting as the third argument as well.
    app.include_router(
        make_enroll_router(db, tokens, open_enrollment=False),
        prefix="/api/v1",
    )
    return app, db


def valid_body(*, api_key: str | None = None, agent_id: str = "agent-001",
               ts_offset: int = 0) -> dict:
    return {
        "agent_id":   agent_id,
        "agent_name": "Test Agent",
        "api_key":    api_key or secrets.token_hex(32),
        "hostname":   "test-host",
        "os":         "macos",
        "arch":       "arm64",
        "timestamp":  int(time.time()) + ts_offset,
    }


# ── Authentication ────────────────────────────────────────────────────────────

class TestEnrollAuth:
    def test_valid_token_succeeds(self):
        app, _ = make_app(["tok-valid"])
        c = TestClient(app)
        r = c.post("/api/v1/enroll", json=valid_body(),
                   headers={"X-Enrollment-Token": "tok-valid"})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_invalid_token_rejected(self):
        app, _ = make_app(["tok-valid"])
        c = TestClient(app)
        r = c.post("/api/v1/enroll", json=valid_body(),
                   headers={"X-Enrollment-Token": "wrong"})
        assert r.status_code == 401

    def test_missing_token_rejected(self):
        app, _ = make_app(["tok-valid"])
        c = TestClient(app)
        r = c.post("/api/v1/enroll", json=valid_body())
        assert r.status_code == 401

    def test_empty_token_list_rejects_all(self):
        app, _ = make_app([])
        c = TestClient(app)
        r = c.post("/api/v1/enroll", json=valid_body(),
                   headers={"X-Enrollment-Token": "any-token"})
        assert r.status_code == 503


# ── Input validation ──────────────────────────────────────────────────────────

class TestEnrollValidation:
    def _client_with_valid_token(self):
        app, db = make_app(["tok"])
        return TestClient(app), db

    def test_short_api_key_rejected(self):
        c, _ = self._client_with_valid_token()
        r = c.post("/api/v1/enroll",
                   json=valid_body(api_key="tooshort"),
                   headers={"X-Enrollment-Token": "tok"})
        assert r.status_code == 400

    def test_non_hex_api_key_rejected(self):
        c, _ = self._client_with_valid_token()
        bad_key = "z" * 64   # 'z' is not hex
        r = c.post("/api/v1/enroll",
                   json=valid_body(api_key=bad_key),
                   headers={"X-Enrollment-Token": "tok"})
        assert r.status_code == 400

    def test_uppercase_hex_api_key_accepted(self):
        c, _ = self._client_with_valid_token()
        upper_key = secrets.token_hex(32).upper()
        r = c.post("/api/v1/enroll",
                   json=valid_body(api_key=upper_key),
                   headers={"X-Enrollment-Token": "tok"})
        assert r.status_code == 200

    def test_stale_timestamp_rejected(self):
        c, _ = self._client_with_valid_token()
        r = c.post("/api/v1/enroll",
                   json=valid_body(ts_offset=-400),   # > 5 min ago
                   headers={"X-Enrollment-Token": "tok"})
        assert r.status_code == 400

    def test_future_timestamp_rejected(self):
        c, _ = self._client_with_valid_token()
        r = c.post("/api/v1/enroll",
                   json=valid_body(ts_offset=400),    # > 5 min future
                   headers={"X-Enrollment-Token": "tok"})
        assert r.status_code == 400

    def test_empty_agent_id_rejected(self):
        c, _ = self._client_with_valid_token()
        r = c.post("/api/v1/enroll",
                   json=valid_body(agent_id=""),
                   headers={"X-Enrollment-Token": "tok"})
        assert r.status_code == 400

    def test_too_long_agent_id_rejected(self):
        c, _ = self._client_with_valid_token()
        r = c.post("/api/v1/enroll",
                   json=valid_body(agent_id="a" * 129),
                   headers={"X-Enrollment-Token": "tok"})
        assert r.status_code == 400


# ── Key storage ───────────────────────────────────────────────────────────────

class TestKeyStorage:
    def test_key_stored_after_enrollment(self):
        app, db = make_app(["tok"])
        c = TestClient(app)
        body = valid_body()
        c.post("/api/v1/enroll", json=body,
               headers={"X-Enrollment-Token": "tok"})
        stored = asyncio.run(db.get_agent_key("agent-001"))
        assert stored == body["api_key"].lower()

    def test_re_enrollment_rotates_key(self):
        app, db = make_app(["tok"])
        c = TestClient(app)
        old_body = valid_body()
        new_body = valid_body(api_key=secrets.token_hex(32))
        c.post("/api/v1/enroll", json=old_body,
               headers={"X-Enrollment-Token": "tok"})
        r = c.post("/api/v1/enroll", json=new_body,
                   headers={"X-Enrollment-Token": "tok"})
        assert r.json()["rotated"] is True
        stored = asyncio.run(db.get_agent_key("agent-001"))
        assert stored == new_body["api_key"].lower()

    def test_agent_registered_after_enrollment(self):
        app, db = make_app(["tok"])
        c = TestClient(app)
        c.post("/api/v1/enroll", json=valid_body(),
               headers={"X-Enrollment-Token": "tok"})
        assert "agent-001" in db.agents
