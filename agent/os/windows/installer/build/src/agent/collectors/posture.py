"""
agent/agent/collectors/posture.py — Security posture collectors (1 hr interval).

  security — SIP, Gatekeeper, FileVault, Firewall, XProtect version
  sysctl   — Kernel security parameters (net.*, security.*, kern.*)
  configs  — Shell rc, SSH config, authorized_keys, /etc/hosts (4 KiB cap each)

Security note: configs reads sensitive files. The 4 KiB cap prevents
accidentally shipping large credential dumps. The collected data is
encrypted on the wire with AES-256-GCM + HMAC-SHA256.
"""
from __future__ import annotations

import os

from .base import BaseCollector, CollectorResult, _run


class SecurityCollector(BaseCollector):
    name = "security"

    def collect(self) -> dict:
        return {
            "sip": _run(["csrutil", "status"]).strip(),
            "gatekeeper": _run(["spctl", "--status"]).strip(),
            "filevault": _run(["fdesetup", "status"]).strip(),
            "firewall": _run([
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--getglobalstate",
            ]).strip(),
            "dev_tools_security": _run(["DevToolsSecurity", "-status"]).strip(),
            "xprotect": _run([
                "defaults", "read",
                "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
                "/Contents/Info.plist",
                "CFBundleShortVersionString",
            ]).strip(),
        }


class SysctlCollector(BaseCollector):
    name = "sysctl"

    # Only collect parameters relevant to security posture
    _KEEP_PREFIXES = (
        "kern.hostname",
        "kern.osversion",
        "kern.bootargs",
        "net.inet",
        "hw.model",
        "hw.memsize",
        "vm.loadavg",
        "security.",
        "machdep.cpu.brand_string",
    )

    def collect(self) -> dict:
        keep: dict[str, str] = {}
        for line in _run(["sysctl", "-a"]).splitlines():
            if any(line.startswith(p) for p in self._KEEP_PREFIXES):
                if "=" in line:
                    k, _, v = line.partition(" = ")
                    keep[k.strip()] = v.strip()
        return keep


class ConfigsCollector(BaseCollector):
    name = "configs"

    # Hard cap per file — no accidental secret dumps
    _READ_LIMIT = 4096

    @property
    def _config_paths(self) -> list[str]:
        home = os.path.expanduser("~")
        return [
            f"{home}/.zshrc",
            f"{home}/.bashrc",
            f"{home}/.zprofile",
            f"{home}/.ssh/config",
            "/etc/hosts",
            "/etc/zshrc",
        ]

    def collect(self) -> dict:
        result: dict[str, str] = {}
        for path in self._config_paths:
            try:
                with open(path) as f:
                    result[path] = f.read(self._READ_LIMIT)
            except OSError:
                pass
        return result
