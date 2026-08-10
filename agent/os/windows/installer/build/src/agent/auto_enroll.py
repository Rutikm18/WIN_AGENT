"""
agent/agent/auto_enroll.py - Zero-touch enrollment orchestrator.

Full flow (runs once per machine, on first agent start):
────────────────────────────────────────────────────────
  1. Look for client.key in the security directory.
     - Found + valid  →  return stored token immediately (no network call).
     - Missing/bad    →  proceed to step 2.

  2. Derive agent identity:
       agent_number  =  stable machine ID  (Windows MachineGuid, /etc/machine-id, etc.)
       agent_name    =  COMPUTERNAME / hostname  (override via cfg["agent"]["name"])

  3. POST /api/v1/enroll  (open enrollment; no manual token required).
     Manager returns a 256-bit hex token.

  4. Write  security_dir/client.key  with identity + token.
     File is ACL-restricted to SYSTEM + Administrators (mode 0600 on Unix).

  5. Return token for use by the sender / crypto layer.

Re-enrollment:
  Delete client.key and restart the service.
  The agent will re-enroll and get a fresh token.

Configuration keys read from cfg:
  cfg["agent"]["id"]           - existing agent_id (from agent.toml / MachineGuid)
  cfg["agent"]["name"]         - human label (falls back to hostname)
  cfg["manager"]["url"]        - manager HTTPS endpoint
  cfg["manager"]["tls_verify"] - True / False / path-to-CA-bundle
  cfg["paths"]["security_dir"] - where client.key lives
"""
from __future__ import annotations

import logging
import platform
import socket
import sys
import time

from . import client_key as ck_mod
from .client_key import ClientKey, generate_agent_number, load, save
from .enrollment import _post_enroll, EnrollmentError

log = logging.getLogger("agent.auto_enroll")


def get_or_enroll(cfg: dict) -> ClientKey:
    """
    Return a valid ClientKey, enrolling with the manager if none exists yet.

    This is the single entry point for the Windows agent startup sequence.
    On success the returned ClientKey.token is ready for use as the HMAC key.
    Raises EnrollmentError on unrecoverable failure.
    """
    security_dir = cfg.get("paths", {}).get("security_dir", "")
    key_path     = _key_path(security_dir)

    # ── Step 1: load existing client.key ─────────────────────────────────────
    existing = load(key_path)
    if existing:
        log.info(
            "client.key found — skipping enrollment "
            "(agent_name=%r agent_number=%s)",
            existing.agent_name, existing.agent_number,
        )
        return existing

    log.info("No client.key found at %s — starting auto-enrollment", key_path)

    # ── Step 2: build identity ────────────────────────────────────────────────
    agent_number = generate_agent_number()
    agent_name   = (
        cfg.get("agent", {}).get("name", "").strip()
        or socket.gethostname()
    )
    agent_id = cfg.get("agent", {}).get("id", "").strip() or agent_number

    # ── Step 3: enroll with manager ───────────────────────────────────────────
    manager_url = cfg["manager"]["url"].rstrip("/")
    tls_verify  = cfg["manager"].get("tls_verify", True)

    log.info(
        "Enrolling: agent_name=%r agent_number=%s manager=%s",
        agent_name, agent_number, manager_url,
    )

    response = _post_enroll(
        url        = manager_url + "/api/v1/enroll",
        token      = "",           # open enrollment — no manual token needed
        payload    = {
            "agent_id":   agent_id,
            "agent_name": agent_name,
            "hostname":   socket.gethostname(),
            "os":         _os_name(),
            "arch":       platform.machine(),
            "timestamp":  int(time.time()),
        },
        tls_verify = tls_verify,
    )

    api_key = response.get("api_key", "").strip()
    if not api_key or len(api_key) != 64:
        raise EnrollmentError(
            f"Manager returned invalid api_key in enrollment response: {api_key!r}"
        )

    # ── Step 4: write client.key ──────────────────────────────────────────────
    issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    new_key = ClientKey(
        agent_name   = agent_name,
        agent_number = agent_number,
        token        = api_key,
        issued_at    = issued_at,
        manager_url  = manager_url,
    )

    save(key_path, new_key)

    log.info(
        "Auto-enrollment complete: agent_name=%r agent_number=%s "
        "key_path=%s issued_at=%s",
        agent_name, agent_number, key_path, issued_at,
    )
    return new_key


def client_key_path(cfg: dict) -> str:
    """Return the expected path of client.key for this config."""
    return _key_path(cfg.get("paths", {}).get("security_dir", ""))


# ── Internal ──────────────────────────────────────────────────────────────────

def _key_path(security_dir: str) -> str:
    import os
    if not security_dir:
        import os as _os
        base = _os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        security_dir = _os.path.join(base, "Jarvis", "security")
    return os.path.join(security_dir, "client.key")


def _os_name() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"
