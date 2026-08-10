"""
agent/os/macos/keystore.py — macOS ARM64 secure API-key persistence.

Storage priority (3-tier, same contract as Windows keystore.py):
  1. macOS Keychain  (keyring → Security framework)  — Keychain Access visible
  2. Keychain via Security CLI (security add-generic-password)  — fallback #1
  3. ACL-restricted file  (<security_dir>/<id>.key, mode 0600)  — fallback #2

Rules
─────
  • Key is written BEFORE the network call — never lost on network failure.
  • File backend refuses a key whose permissions include group/other bits.
  • security_dir is chmod 700 (owner root only).
  • All paths sanitise agent_id to prevent directory traversal.
  • delete_key removes all three backends.

Public API (mirrors Windows keystore.py)
─────────────────────────────────────────
  store_key(agent_id, key_hex, backend, security_dir) → None / raises
  load_key (agent_id, backend, security_dir) → str | None
  delete_key(agent_id, backend, security_dir) → None
"""
from __future__ import annotations

import logging
import os
import re
import stat
import subprocess

log = logging.getLogger("agent.os.macos.keystore")

_KEYRING_SERVICE = "com.jarvis.agent"

# ── Public API ────────────────────────────────────────────────────────────────

def store_key(
    agent_id: str,
    key_hex: str,
    backend: str = "keychain",
    security_dir: str = "/Library/Jarvis/security",
) -> None:
    """Persist the API key. Raises on total failure."""
    if backend == "keychain":
        if _kr_store(agent_id, key_hex):
            return
        if _sec_cli_store(agent_id, key_hex):
            return
    _file_store(agent_id, key_hex, security_dir)


def load_key(
    agent_id: str,
    backend: str = "keychain",
    security_dir: str = "/Library/Jarvis/security",
) -> str | None:
    """Return the stored API key, or None if not found."""
    if backend == "keychain":
        k = _kr_load(agent_id)
        if k:
            return k
        k = _sec_cli_load(agent_id)
        if k:
            return k
    return _file_load(agent_id, security_dir)


def delete_key(
    agent_id: str,
    backend: str = "keychain",
    security_dir: str = "/Library/Jarvis/security",
) -> None:
    """Remove all stored copies of the key."""
    _kr_delete(agent_id)
    _sec_cli_delete(agent_id)
    path = _plain_path(agent_id, security_dir)
    if os.path.exists(path):
        os.unlink(path)
        log.info("Key file deleted: %s", path)


# ── Backend 1: keyring (Python library → macOS Security framework) ────────────

def _kr_store(agent_id: str, key_hex: str) -> bool:
    try:
        import keyring  # type: ignore[import]
        keyring.set_password(_KEYRING_SERVICE, agent_id, key_hex)
        log.info("Key stored in Keychain via keyring (account=%s)", agent_id)
        return True
    except Exception as exc:
        log.debug("keyring store failed (%s)", exc)
        return False


def _kr_load(agent_id: str) -> str | None:
    try:
        import keyring  # type: ignore[import]
        key = keyring.get_password(_KEYRING_SERVICE, agent_id)
        if key:
            log.debug("Key loaded from Keychain via keyring")
            return key
    except Exception as exc:
        log.debug("keyring load failed (%s)", exc)
    return None


def _kr_delete(agent_id: str) -> None:
    try:
        import keyring  # type: ignore[import]
        keyring.delete_password(_KEYRING_SERVICE, agent_id)
        log.info("Key deleted from Keychain via keyring")
    except Exception:
        pass


# ── Backend 2: /usr/bin/security CLI (no Python deps) ────────────────────────

def _sec_cli_store(agent_id: str, key_hex: str) -> bool:
    """
    Uses the macOS `security` command-line tool to write to the System Keychain.
    Requires root when writing to the system keychain; falls back to user keychain.
    """
    try:
        # Delete existing entry first (update is not atomic otherwise)
        subprocess.run(
            ["security", "delete-generic-password",
             "-s", _KEYRING_SERVICE, "-a", agent_id],
            capture_output=True, check=False,
        )
        r = subprocess.run(
            ["security", "add-generic-password",
             "-s", _KEYRING_SERVICE,
             "-a", agent_id,
             "-w", key_hex,
             "-T", "",          # allow only this app
             "-U",              # update if exists
             "/Library/Keychains/System.keychain"],
            capture_output=True, check=True, timeout=10,
        )
        log.info("Key stored in System Keychain via security CLI (account=%s)", agent_id)
        return True
    except Exception as exc:
        log.debug("security CLI store failed (%s)", exc)
        return False


def _sec_cli_load(agent_id: str) -> str | None:
    try:
        r = subprocess.run(
            ["security", "find-generic-password",
             "-s", _KEYRING_SERVICE,
             "-a", agent_id,
             "-w",   # print password only
             "/Library/Keychains/System.keychain"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        key = r.stdout.strip()
        if key:
            log.debug("Key loaded from System Keychain via security CLI")
            return key
    except Exception as exc:
        log.debug("security CLI load failed (%s)", exc)
    return None


def _sec_cli_delete(agent_id: str) -> None:
    try:
        subprocess.run(
            ["security", "delete-generic-password",
             "-s", _KEYRING_SERVICE,
             "-a", agent_id,
             "/Library/Keychains/System.keychain"],
            capture_output=True, check=False, timeout=10,
        )
    except Exception:
        pass


# ── Backend 3: ACL-restricted file ────────────────────────────────────────────

def _plain_path(agent_id: str, security_dir: str) -> str:
    # Reject IDs that contain path separators or parent-dir components
    # before any sanitisation — these are always traversal attempts.
    if os.sep in agent_id or "/" in agent_id or "\\" in agent_id or ".." in agent_id:
        raise ValueError(f"Path traversal attempt in agent_id: {agent_id!r}")
    safe_id = re.sub(r"[^a-zA-Z0-9_\-.]", "_", agent_id)
    path = os.path.realpath(os.path.join(security_dir, f"{safe_id}.key"))
    real_sec = os.path.realpath(security_dir)
    if not path.startswith(real_sec + os.sep):
        raise ValueError(f"Path traversal attempt: {agent_id!r}")
    return path


def _file_store(agent_id: str, key_hex: str, security_dir: str) -> None:
    os.makedirs(security_dir, exist_ok=True)
    # Tighten directory: root-owned, 0700
    try:
        os.chmod(security_dir, stat.S_IRWXU)
    except Exception:
        pass
    path = _plain_path(agent_id, security_dir)
    tmp  = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(key_hex)
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)   # 0600
    os.replace(tmp, path)                          # atomic rename
    log.info("Key stored in file: %s (mode 0600)", path)


def _file_load(agent_id: str, security_dir: str) -> str | None:
    try:
        path = _plain_path(agent_id, security_dir)
    except ValueError:
        return None
    if not os.path.exists(path):
        return None
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        log.error(
            "SECURITY: key file %s has unsafe permissions %o — refusing to load. "
            "Fix with: chmod 600 %s", path, mode, path,
        )
        return None
    with open(path) as f:
        return f.read().strip() or None
