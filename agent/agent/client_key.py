"""
agent/agent/client_key.py - client.key file: agent identity + session token.

The client.key file is written automatically on first enrollment and read on
every subsequent start.  It lives in the security directory (ACL-restricted to
SYSTEM + Administrators on Windows, mode-0600 on Unix).

File format (TOML-compatible key=value):
    # Jarvis Agent Identity
    # Auto-generated on first run. Do not edit manually.

    [identity]
    agent_name   = "WORKSTATION-01"
    agent_number = "win-a1b2c3d4e5f6789012345678901234ab"
    issued_at    = "2026-04-22T10:30:00Z"
    manager_url  = "https://1.2.3.4:8443"

    [auth]
    token = "64hexcharacters..."

agent_number is derived from the Windows MachineGUID (stable across reboots
and reinstalls on the same hardware).  It uniquely identifies this machine.

token is the 256-bit API key issued by the manager after enrollment.  It is
used as the HMAC key for all subsequent ingest payloads.
"""
from __future__ import annotations

import logging
import os
import platform
import re
import stat
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("agent.client_key")

_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class ClientKey:
    agent_name:   str
    agent_number: str          # stable machine identifier
    token:        str          # 64-hex API key for ingest auth
    issued_at:    str          # ISO-8601 timestamp of enrollment
    manager_url:  str

    def is_valid(self) -> bool:
        return (
            bool(self.agent_name)
            and bool(self.agent_number)
            and bool(_TOKEN_RE.match(self.token))
            and bool(self.manager_url)
        )


# ── Read ──────────────────────────────────────────────────────────────────────

def load(path: str) -> Optional[ClientKey]:
    """Load client.key from path.  Returns None if missing or invalid."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        ck = _parse(raw)
        if not ck.is_valid():
            log.warning("client.key at %s is malformed — re-enrolling", path)
            return None
        log.debug(
            "Loaded client.key: agent_name=%r agent_number=%s",
            ck.agent_name, ck.agent_number,
        )
        return ck
    except Exception as exc:
        log.warning("Cannot read client.key (%s): %s — re-enrolling", path, exc)
        return None


# ── Write ─────────────────────────────────────────────────────────────────────

def save(path: str, ck: ClientKey) -> None:
    """Write client.key atomically with strict file permissions."""
    content = _serialise(ck)
    dir_ = os.path.dirname(path)
    if dir_:
        os.makedirs(dir_, exist_ok=True)

    # Write to a temp file then rename — atomic on all platforms
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
        _restrict_permissions(path)
        log.info(
            "client.key written: agent_name=%r agent_number=%s path=%s",
            ck.agent_name, ck.agent_number, path,
        )
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── Agent number generation ───────────────────────────────────────────────────

def generate_agent_number() -> str:
    """
    Derive a stable, unique machine identifier.

    Windows: uses HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
    Linux:   uses /etc/machine-id
    macOS:   uses platform.node() + a fixed prefix (IOKit not available here)
    """
    try:
        if platform.system() == "Windows":
            return _win_agent_number()
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id") as fh:
                mid = fh.read().strip().lower()
            return f"lnx-{mid[:32]}"
        return f"host-{_safe(platform.node())}"
    except Exception as exc:
        import secrets as _s
        fallback = _s.token_hex(16)
        log.warning("Could not derive stable agent number (%s) — using random: %s", exc, fallback)
        return f"rnd-{fallback}"


def _win_agent_number() -> str:
    import winreg
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Cryptography",
    )
    guid, _ = winreg.QueryValueEx(key, "MachineGuid")
    winreg.CloseKey(key)
    return f"win-{guid.lower().replace('-', '')}"


# ── Internal ──────────────────────────────────────────────────────────────────

def _parse(raw: str) -> ClientKey:
    """Parse the key=value pairs from a client.key file."""
    vals: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip().strip('"').strip("'")
    return ClientKey(
        agent_name   = vals.get("agent_name", ""),
        agent_number = vals.get("agent_number", ""),
        token        = vals.get("token", ""),
        issued_at    = vals.get("issued_at", ""),
        manager_url  = vals.get("manager_url", ""),
    )


def _serialise(ck: ClientKey) -> str:
    return (
        "# AttackLens Agent Identity\n"
        "# Auto-generated on first enrollment. Do not edit manually.\n"
        "# To re-enroll: delete this file and restart the AttackLensAgent service.\n"
        "\n"
        "[identity]\n"
        f'agent_name   = "{ck.agent_name}"\n'
        f'agent_number = "{ck.agent_number}"\n'
        f'issued_at    = "{ck.issued_at}"\n'
        f'manager_url  = "{ck.manager_url}"\n'
        "\n"
        "[auth]\n"
        f'token = "{ck.token}"\n'
    )


def _restrict_permissions(path: str) -> None:
    """Restrict file to owner-only on Unix; apply icacls on Windows."""
    try:
        if platform.system() == "Windows":
            import subprocess
            subprocess.run(
                [
                    "icacls", path,
                    "/inheritance:r",
                    "/grant:r", "NT AUTHORITY\\SYSTEM:(R)",
                    "/grant:r", "BUILTIN\\Administrators:(R)",
                ],
                check=False, capture_output=True,
            )
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except Exception as exc:
        log.warning("Could not restrict client.key permissions: %s", exc)


def _safe(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())[:24]
