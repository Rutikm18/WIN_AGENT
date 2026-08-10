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

from agent.os.windows.acl import repair_acl

log = logging.getLogger("agent.windows.keystore")

# ── DPAPI constants ───────────────────────────────────────────────────────────
_CRYPTPROTECT_LOCAL_MACHINE = 0x4   # any account on this machine can decrypt


def _is_valid_key(key: object) -> bool:
    return (
        isinstance(key, str)
        and len(key) == 64
        and all(character in "0123456789abcdefABCDEF" for character in key)
    )


# ── Public API ────────────────────────────────────────────────────────────────

def store_key(agent_id: str, key_hex: str,
              security_dir: str = "") -> None:
    """Persist API key with DPAPI. Falls back to ACL-restricted file."""
    if not _is_valid_key(key_hex):
        raise ValueError("API key must be a 64-character hexadecimal string")
    if not security_dir:
        import os as _os
        security_dir = _os.path.join(
            _os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "AttackLens", "security"
        )
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
    """Load API key. Returns None if no key found."""
    if not security_dir:
        import os as _os
        security_dir = _os.path.join(
            _os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "AttackLens", "security"
        )
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
    """Remove stored key (re-enrollment / uninstall)."""
    if not security_dir:
        import os as _os
        security_dir = _os.path.join(
            _os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "AttackLens", "security"
        )
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

_CM_SERVICE = "com.attacklens.agent"


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
        key = keyring.get_password(_CM_SERVICE, agent_id)
        if key is not None and not _is_valid_key(key):
            log.error("Credential Manager returned an invalid API key for agent_id=%s",
                      agent_id)
            return None
        return key
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
    path = _dpapi_path(agent_id, security_dir)
    tmp = path + ".tmp"
    replaced = False
    try:
        import win32crypt
        os.makedirs(security_dir, exist_ok=True)
        _restrict_dir_acl(security_dir)
        encrypted = win32crypt.CryptProtectData(
            key_hex.encode("ascii"),
            f"attacklens:{agent_id}",   # description (displayed in Credential Manager)
            None,                       # optional entropy
            None,                       # reserved
            None,                       # prompt struct
            _CRYPTPROTECT_LOCAL_MACHINE,
        )
        # Atomic write
        with open(tmp, "wb") as f:
            f.write(encrypted)
        os.replace(tmp, path)
        replaced = True
        _restrict_file_acl(path)
        return True
    except Exception as exc:
        log.debug("DPAPI store failed: %s", exc)
        incomplete_paths = [tmp]
        if replaced:
            incomplete_paths.append(path)
        for incomplete_path in incomplete_paths:
            try:
                if os.path.exists(incomplete_path):
                    os.remove(incomplete_path)
            except OSError:
                log.warning("Could not remove insecure DPAPI credential: %s",
                            incomplete_path)
        return False


def _dpapi_load(agent_id: str, security_dir: str) -> str | None:
    path = _dpapi_path(agent_id, security_dir)
    if not os.path.isfile(path):
        return None
    try:
        _restrict_file_acl(path)
        import win32crypt
        with open(path, "rb") as f:
            data = f.read()
        _description, plaintext = win32crypt.CryptUnprotectData(
            data, None, None, None, _CRYPTPROTECT_LOCAL_MACHINE
        )
        key = plaintext.decode("ascii").strip()
        # Validate: API key must be a 64-character hex string.
        if len(key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in key):
            log.error("DPAPI load: decrypted content is not a valid 64-hex API key "
                      "— file may be corrupted. Delete it to trigger re-enrollment.")
            return None
        return key
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
    replaced = False
    try:
        with open(tmp, "w", encoding="ascii") as f:
            f.write(key_hex)
        os.replace(tmp, path)
        replaced = True
        _restrict_file_acl(path)
    except Exception:
        incomplete_paths = [tmp]
        if replaced:
            incomplete_paths.append(path)
        for incomplete_path in incomplete_paths:
            try:
                if os.path.exists(incomplete_path):
                    os.remove(incomplete_path)
            except OSError:
                log.warning("Could not remove insecure plain credential: %s",
                            incomplete_path)
        raise


def _file_load(agent_id: str, security_dir: str) -> str | None:
    path = _plain_path(agent_id, security_dir)
    if not os.path.isfile(path):
        return None
    try:
        _restrict_file_acl(path)
        with open(path, "r", encoding="ascii") as key_file:
            key = key_file.read().strip()
        if not _is_valid_key(key):
            log.error("Plain key file contains an invalid API key: %s", path)
            return None
        return key
    except (OSError, UnicodeError) as exc:
        log.debug("Plain key file load failed path=%s error=%s", path, exc)
        return None


# ── ACL helpers ───────────────────────────────────────────────────────────────

def _restrict_file_acl(path: str) -> None:
    """Compatibility wrapper delegating to the central key-file policy."""
    result = repair_acl(path, "key_file")
    if result.skipped:
        log.debug("key-file ACL repair skipped off Windows: %s", path)
    elif not result.compliant:
        raise PermissionError(
            f"key-file ACL is not protected path={path} error={result.error}"
        )


def _restrict_dir_acl(path: str) -> None:
    """Compatibility wrapper delegating to the central secure-dir policy."""
    result = repair_acl(path, "secure_dir")
    if result.skipped:
        log.debug("security-dir ACL repair skipped off Windows: %s", path)
    elif not result.compliant:
        raise PermissionError(
            f"security-dir ACL is not protected path={path} error={result.error}"
        )
