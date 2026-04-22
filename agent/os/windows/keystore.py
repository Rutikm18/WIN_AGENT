"""
agent/os/windows/keystore.py — Windows DPAPI-backed API key storage.

Priority chain
──────────────
1. Windows Credential Manager (keyring WinVault backend — DPAPI-protected,
   survives reboots, scoped to the machine + account that enrolled the agent)
2. DPAPI-encrypted file at security_dir\\{agent_id}.key.dpapi
   (CryptProtectData with CRYPTPROTECT_LOCAL_MACHINE flag — any service account
   on this machine can decrypt it, but no other machine can)
3. Graceful degradation: if pywin32 is not installed, falls back to a
   plain 0600-equivalent ACL-restricted file (same behaviour as macOS file fallback)

Security properties
───────────────────
• DPAPI keys are tied to the Windows machine key (and optionally user key).
  An attacker with a copy of the drive but not the machine's TPM cannot decrypt.
• The Credential Manager path uses DPAPI transparently — no raw key bytes on disk.
• CRYPTPROTECT_LOCAL_MACHINE means ANY process running on this host as SYSTEM
  or the service account can decrypt — appropriate for an endpoint agent binary.
• Plain-file fallback uses icacls to restrict to SYSTEM + Administrators only.

This module is imported by agent/agent/keystore.py when sys.platform == 'win32'.
It exposes the same store_key / load_key / delete_key interface.
"""
from __future__ import annotations

import logging
import os
import subprocess

log = logging.getLogger("agent.windows.keystore")

# ── DPAPI constants ───────────────────────────────────────────────────────────
_CRYPTPROTECT_LOCAL_MACHINE = 0x4   # any account on this machine can decrypt


# ── Public API ────────────────────────────────────────────────────────────────

def store_key(agent_id: str, key_hex: str,
              security_dir: str = "") -> None:
    if not security_dir:
        import os as _os
        security_dir = _os.path.join(
            _os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Jarvis", "security"
        )
    """Persist API key with DPAPI. Falls back to ACL-restricted file."""
    # Try Credential Manager first
    if _cm_store(agent_id, key_hex):
        log.debug("Key stored in Windows Credential Manager for agent_id=%s", agent_id)
        return
    # DPAPI file
    if _dpapi_store(agent_id, key_hex, security_dir):
        log.debug("Key stored in DPAPI-encrypted file for agent_id=%s", agent_id)
        return
    # ACL-restricted plain file (last resort)
    _file_store(agent_id, key_hex, security_dir)
    log.warning("Key stored in ACL-restricted file (DPAPI unavailable) for agent_id=%s", agent_id)


def load_key(agent_id: str,
             security_dir: str = "") -> str | None:
    if not security_dir:
        import os as _os
        security_dir = _os.path.join(
            _os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Jarvis", "security"
        )
    """Load API key. Returns None if no key found."""
    # Credential Manager
    key = _cm_load(agent_id)
    if key:
        return key
    # DPAPI file
    key = _dpapi_load(agent_id, security_dir)
    if key:
        return key
    # Plain file
    return _file_load(agent_id, security_dir)


def delete_key(agent_id: str,
               security_dir: str = "") -> None:
    if not security_dir:
        import os as _os
        security_dir = _os.path.join(
            _os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Jarvis", "security"
        )
    """Remove stored key (re-enrollment / uninstall)."""
    _cm_delete(agent_id)
    for path in [
        _dpapi_path(agent_id, security_dir),
        _plain_path(agent_id, security_dir),
    ]:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


# ── Windows Credential Manager ────────────────────────────────────────────────

_CM_SERVICE = "com.jarvis.agent"


def _cm_store(agent_id: str, key_hex: str) -> bool:
    try:
        import keyring
        keyring.set_password(_CM_SERVICE, agent_id, key_hex)
        return True
    except Exception as exc:
        log.debug("Credential Manager store failed: %s", exc)
        return False


def _cm_load(agent_id: str) -> str | None:
    try:
        import keyring
        return keyring.get_password(_CM_SERVICE, agent_id)
    except Exception:
        return None


def _cm_delete(agent_id: str) -> None:
    try:
        import keyring
        keyring.delete_password(_CM_SERVICE, agent_id)
    except Exception:
        pass


# ── DPAPI-encrypted file ──────────────────────────────────────────────────────

def _dpapi_path(agent_id: str, security_dir: str) -> str:
    safe_id = "".join(c if c.isalnum() or c in "-_." else "_" for c in agent_id)
    return os.path.join(security_dir, f"{safe_id}.key.dpapi")


def _dpapi_store(agent_id: str, key_hex: str, security_dir: str) -> bool:
    try:
        import win32crypt
        os.makedirs(security_dir, exist_ok=True)
        _restrict_dir_acl(security_dir)
        encrypted = win32crypt.CryptProtectData(
            key_hex.encode("ascii"),
            f"mac_intel:{agent_id}",   # description (displayed in Credential Manager)
            None,                       # optional entropy
            None,                       # reserved
            None,                       # prompt struct
            _CRYPTPROTECT_LOCAL_MACHINE,
        )
        path = _dpapi_path(agent_id, security_dir)
        # Atomic write
        tmp  = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(encrypted)
        os.replace(tmp, path)
        _restrict_file_acl(path)
        return True
    except Exception as exc:
        log.debug("DPAPI store failed: %s", exc)
        return False


def _dpapi_load(agent_id: str, security_dir: str) -> str | None:
    path = _dpapi_path(agent_id, security_dir)
    if not os.path.isfile(path):
        return None
    try:
        import win32crypt
        with open(path, "rb") as f:
            data = f.read()
        _description, plaintext = win32crypt.CryptUnprotectData(
            data, None, None, None, _CRYPTPROTECT_LOCAL_MACHINE
        )
        return plaintext.decode("ascii").strip()
    except Exception as exc:
        log.debug("DPAPI load failed: %s", exc)
        return None


# ── ACL-restricted plain file (last resort) ───────────────────────────────────

def _plain_path(agent_id: str, security_dir: str) -> str:
    safe_id = "".join(c if c.isalnum() or c in "-_." else "_" for c in agent_id)
    return os.path.join(security_dir, f"{safe_id}.key")


def _file_store(agent_id: str, key_hex: str, security_dir: str) -> None:
    os.makedirs(security_dir, exist_ok=True)
    _restrict_dir_acl(security_dir)
    path = _plain_path(agent_id, security_dir)
    tmp  = path + ".tmp"
    with open(tmp, "w", encoding="ascii") as f:
        f.write(key_hex)
    os.replace(tmp, path)
    _restrict_file_acl(path)


def _file_load(agent_id: str, security_dir: str) -> str | None:
    path = _plain_path(agent_id, security_dir)
    if not os.path.isfile(path):
        return None
    try:
        key = open(path, "r", encoding="ascii").read().strip()
        return key if key else None
    except Exception:
        return None


# ── ACL helpers ───────────────────────────────────────────────────────────────

def _restrict_file_acl(path: str) -> None:
    """Restrict file to SYSTEM + Administrators read-only, remove Everyone."""
    try:
        subprocess.run(
            ["icacls", path,
             "/inheritance:r",
             "/grant:r", "NT AUTHORITY\\SYSTEM:(R)",
             "/grant:r", "BUILTIN\\Administrators:(R)"],
            capture_output=True,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
            timeout=10,
        )
    except Exception as exc:
        log.debug("icacls file failed: %s", exc)


def _restrict_dir_acl(path: str) -> None:
    """Restrict directory to SYSTEM + Administrators full control only."""
    try:
        subprocess.run(
            ["icacls", path,
             "/inheritance:r",
             "/grant:r", "NT AUTHORITY\\SYSTEM:(OI)(CI)(F)",
             "/grant:r", "BUILTIN\\Administrators:(OI)(CI)(F)"],
            capture_output=True,
            creationflags=0x08000000,
            timeout=10,
        )
    except Exception as exc:
        log.debug("icacls dir failed: %s", exc)
