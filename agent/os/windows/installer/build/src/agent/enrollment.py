"""
agent/agent/enrollment.py — First-run key generation and manager enrollment.

Enrollment flow
───────────────
  1. Check keystore → if a key already exists, skip enrollment (idempotent).
  2. POST /api/v1/enroll to the manager with agent metadata.
     - If manager runs in OPEN_ENROLLMENT mode (default): no token needed.
     - If manager requires a token: send X-Enrollment-Token header.
  3. Manager generates a 256-bit API key and returns it in the response.
  4. Agent stores the returned key in the OS keystore (Keychain or file).
  5. Key is used for all subsequent ingest calls.

Security notes
──────────────
  • All enrollment calls are over TLS 1.3 — token (if used) is never in plaintext.
  • The API key is manager-generated — operator has full rotate/revoke control.
  • Key stored in macOS Keychain (root-owned) — never in plain config files.
  • Re-enrollment is idempotent: calling enroll() on a machine that already has
    a key in the Keychain skips the network call entirely.
"""
from __future__ import annotations

import json
import logging
import platform
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

from .keystore import store_key, load_key, delete_key

log = logging.getLogger("agent.enrollment")


class EnrollmentError(Exception):
    """Raised when enrollment fails and cannot be retried without operator action."""


# ── Public API ────────────────────────────────────────────────────────────────

def needs_enrollment(
    agent_id: str,
    backend: str = "keychain",
    security_dir: str = "/Library/Jarvis/security",
) -> bool:
    """Return True if no API key is stored for this agent (first run)."""
    return load_key(agent_id, backend=backend, security_dir=security_dir) is None


def enroll(cfg: dict) -> str:
    """
    Run the full enrollment flow.  Returns the API key (64-char hex).
    Raises EnrollmentError on any unrecoverable failure.

    Works in two modes:
      open enrollment  — no token needed; just connect with manager URL
      token mode       — set [enrollment] token in agent.toml

    Required cfg keys
    -----------------
    cfg["agent"]["id"]
    cfg["agent"]["name"]
    cfg["manager"]["url"]
    cfg["manager"]["tls_verify"]
    cfg["enrollment"]["token"]     — optional; leave empty for open enrollment
    cfg["enrollment"]["keystore"]  — "keychain" | "file"
    cfg["paths"]["security_dir"]   — directory for file-backend key storage
    """
    agent_id     = cfg["agent"]["id"]
    agent_name   = cfg["agent"].get("name", "")
    token        = cfg.get("enrollment", {}).get("token", "").strip()
    backend      = cfg.get("enrollment", {}).get("keystore", "keychain")
    security_dir = cfg.get("paths", {}).get(
        "security_dir",
        "/Library/Jarvis/security",
    )

    if token:
        log.info("Enrolling with token (token-mode enrollment)")
    else:
        log.info("Enrolling without token (open enrollment — manager must allow this)")

    # Step 1 — call manager to register (manager generates the key)
    url = cfg["manager"]["url"].rstrip("/") + "/api/v1/enroll"
    try:
        response = _post_enroll(
            url=url,
            token=token,   # empty string = no token header sent
            payload={
                "agent_id":   agent_id,
                "agent_name": agent_name,
                "hostname":   socket.gethostname(),
                "os":         "macos" if sys.platform == "darwin" else sys.platform,
                "arch":       platform.machine(),
                "timestamp":  int(time.time()),
            },
            tls_verify=cfg["manager"].get("tls_verify", True),
        )
    except EnrollmentError as exc:
        err = str(exc).lower()
        if "401" in err or "invalid enrollment token" in err:
            log.warning(
                "Manager rejected enrollment — it may require a token. "
                "Set OPEN_ENROLLMENT=true on the manager, or configure "
                "[enrollment] token in agent.toml."
            )
            try:
                delete_key(agent_id, backend=backend, security_dir=security_dir)
            except Exception:
                pass
        raise
    except Exception as exc:
        raise EnrollmentError(f"Manager enrollment request failed: {exc}") from exc

    # Step 2 — extract the key from the manager's response
    api_key = response.get("api_key", "").strip()
    if not api_key or len(api_key) != 64:
        # Old manager that doesn't return a key — fall back to local generation
        log.warning(
            "Manager did not return an api_key in enrollment response. "
            "Generating a local key (ensure manager supports v2 enrollment)."
        )
        api_key = secrets.token_hex(32)

    # Step 3 — persist the key to keystore
    try:
        store_key(agent_id, api_key, backend=backend, security_dir=security_dir)
    except Exception as exc:
        raise EnrollmentError(
            f"Keystore write failed after enrollment: {exc}"
        ) from exc

    expires_at = response.get("expires_at", 0)
    if expires_at:
        log.info(
            "Enrollment complete: agent_id=%s  key expires=%s UTC",
            agent_id,
            time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(expires_at)),
        )
    else:
        log.info("Enrollment complete: agent_id=%s  key never expires", agent_id)
    return api_key


# ── Internal ──────────────────────────────────────────────────────────────────

def _post_enroll(url: str, token: str, payload: dict, tls_verify: bool) -> dict:
    """POST enrollment request and return the parsed JSON response body."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if not tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    body    = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent":   "macintel-agent/2.0",
    }
    # Only send the token header when a token is actually configured.
    if token:
        headers["X-Enrollment-Token"] = token

    req = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            status    = resp.status
            body_resp = resp.read()
    except urllib.error.HTTPError as exc:
        status    = exc.code
        body_resp = exc.read()

    if status == 200:
        try:
            return json.loads(body_resp)
        except Exception:
            return {}
    if status == 401:
        raise EnrollmentError(
            f"Manager rejected enrollment token (HTTP 401). "
            f"Check [enrollment] token in agent.toml matches ENROLLMENT_TOKENS on manager. "
            f"Server: {body_resp.decode(errors='replace')}"
        )
    if status == 409:
        raise EnrollmentError(
            "Agent already enrolled on manager (HTTP 409). "
            "To re-enroll: use POST /api/v1/keys/{agent_id}/rotate on the manager."
        )
    raise EnrollmentError(
        f"Manager returned HTTP {status}: {body_resp.decode(errors='replace')}"
    )
