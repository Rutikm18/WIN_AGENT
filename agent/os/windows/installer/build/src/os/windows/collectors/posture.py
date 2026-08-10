"""
agent/os/windows/collectors/posture.py — Security posture collectors (1 hr).

sections: security, sysctl, configs

Security philosophy
───────────────────
• Read-only: all checks use non-destructive registry queries and CLI tools.
• Privileged-graceful: missing permissions return None rather than crashing.
• Defense-in-depth checks:
    Defender RTP, UAC level, BitLocker, Windows Firewall profile state,
    Secure Boot, Credential Guard, WDAC/AppLocker, auto-update policy.
• sysctl = Windows registry security parameters (TCP hardening, LSA config,
    NtLmSettings, SMBv1 status, LSASS PPL) — the Windows equivalent of
    macOS `sysctl -a | grep security`.
• configs = sensitive plaintext files: hosts, sshd_config, PS profiles,
    authorized_keys — hashed and flagged with simple heuristics.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.posture")


# ── security ──────────────────────────────────────────────────────────────────

class SecurityCollector(WinBaseCollector):
    name    = "security"
    timeout = 30

    def collect(self) -> dict:
        defender, av_installed = self._defender()
        uac         = self._uac()
        bitlocker   = self._bitlocker()
        firewall    = self._firewall()
        secure_boot = self._secure_boot()
        auto_update = self._auto_update()
        raw = {
            "credential_guard":   self._credential_guard(),
            "wdac_enabled":       self._wdac(),
            "smb1_enabled":       self._smb1(),
            "lsass_ppl":          self._lsass_ppl(),
            "last_patch_days":    self._last_patch_age(),
            # New Windows-specific security posture checks
            "ntlm_level":         self._ntlm_level(),
            "defender_exclusions": self._defender_exclusions(),
            "wmi_persistence":    self._wmi_persistence(),
        }
        return {
            # macOS fields — always None on Windows (data point schema alignment)
            "sip":         None,
            "gatekeeper":  None,
            "filevault":   None,
            "xprotect":    None,
            # cross-platform
            "firewall":     firewall,
            "secure_boot":  secure_boot,
            "av_installed": av_installed,
            "av_product":   "Windows Defender" if av_installed else None,
            "os_patched":   (raw["last_patch_days"] is not None and raw["last_patch_days"] <= 30),
            "auto_update":  auto_update,
            # Linux fields — None on Windows
            "selinux":  None,
            "apparmor": None,
            "ufw":      None,
            # Windows-specific
            "uac":       uac,
            "bitlocker": bitlocker,
            "defender":  defender,
            "_raw":      raw,
        }

    # ── individual checks ─────────────────────────────────────────────────────

    def _wmi_persistence(self) -> list[dict]:
        """
        Enumerate WMI event subscriptions — a common fileless persistence technique
        (T1546.003).  Legitimate software rarely uses this; any finding warrants review.

        Checks root\\subscription namespace for:
          __EventFilter          (trigger — e.g. timer or process creation)
          CommandLineEventConsumer / ActiveScriptEventConsumer  (action — runs code)
          __FilterToConsumerBinding  (wires filter to consumer)
        """
        subscriptions: list[dict] = []
        ps = (
            "try {"
            " $ns='root\\\\subscription';"
            " $f=Get-CimInstance -Namespace $ns -ClassName __EventFilter -EA SilentlyContinue;"
            " $c=Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -EA SilentlyContinue;"
            " $a=Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer -EA SilentlyContinue;"
            " $b=Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -EA SilentlyContinue;"
            " @{filters=@($f|%{$_.Name});consumers=@($c|%{$_.Name});"
            "   script_consumers=@($a|%{$_.Name});bindings=($b|Measure-Object).Count}"
            " | ConvertTo-Json -Compress"
            "} catch { '{}' }"
        )
        import json as _json
        try:
            out = self._run_ps(ps)
            d   = _json.loads(out.strip() or "{}")
            filters   = [str(x) for x in (d.get("filters") or []) if x]
            consumers = [str(x) for x in (d.get("consumers") or []) if x]
            scripts   = [str(x) for x in (d.get("script_consumers") or []) if x]
            bindings  = int(d.get("bindings") or 0)
            if filters or consumers or scripts or bindings:
                subscriptions.append({
                    "filters":          filters,
                    "cmd_consumers":    consumers,
                    "script_consumers": scripts,
                    "binding_count":    bindings,
                })
        except Exception:
            pass
        return subscriptions

    def _defender_exclusions(self) -> dict:
        """
        Read Windows Defender exclusion lists from registry.

        Attackers commonly add exclusions to bypass real-time protection
        (T1562.001 — Impair Defenses: Disable or Modify Tools).
        Any non-empty list is a high-fidelity indicator worth alerting on.
        """
        import json as _json
        exc_root = r"SOFTWARE\Microsoft\Windows Defender\Exclusions"
        result: dict[str, list[str]] = {
            "paths":      [],
            "extensions": [],
            "processes":  [],
        }
        try:
            import winreg
            hklm = winreg.HKEY_LOCAL_MACHINE
            for sub, key in (("Paths", "paths"), ("Extensions", "extensions"),
                             ("Processes", "processes")):
                vals = self.reg_get(hklm, f"{exc_root}\\{sub}")
                if isinstance(vals, dict):
                    result[key] = list(vals.keys())
        except Exception:
            pass
        return result

    def _ntlm_level(self) -> int | None:
        """
        LmCompatibilityLevel controls the weakest NTLM authentication accepted.

        0-2: accept LM/NTLMv1 (vulnerable to pass-the-hash / relay attacks)
        3-4: NTLMv2 required for outgoing; LMv2 accepted inbound
        5:   NTLMv2 required everywhere (CIS Level 2 recommended value)

        Absence of the key (None) means the Windows default applies (varies by
        OS version; Win10+ defaults to 3).
        """
        v = self.reg_get(
            _HKLM,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel",
        )
        if v is None:
            return None
        try:
            return int(v)
        except Exception:
            return None

    def _defender(self) -> tuple[str, bool]:
        """Returns (defender_status, av_installed)."""
        out = self._run_ps(
            "try { Get-MpComputerStatus | Select-Object "
            "AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled "
            "| ConvertTo-Json -Compress } catch { '{}' }"
        )
        try:
            d = json.loads(out.strip() or "{}")
            av = bool(d.get("AntivirusEnabled"))
            enabled = bool(d.get("AMServiceEnabled") and d.get("RealTimeProtectionEnabled"))
            return ("enabled" if enabled else "disabled"), av
        except Exception:
            return "unknown", False

    def _uac(self) -> str | None:
        v = self.reg_get(
            _HKLM,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        )
        if v is None:
            return None
        try:
            return "enabled" if int(v) == 1 else "disabled"
        except Exception:
            return None

    def _bitlocker(self) -> str:
        """Check BitLocker on C: via manage-bde; fall back to PowerShell."""
        out = self._run(["manage-bde", "-status", "C:"])
        if out:
            if re.search(r"Protection\s+Status\s*:\s*Protection On", out, re.I):
                return "on"
            if re.search(r"Percentage\s+Encrypted\s*:\s*100", out, re.I):
                return "on"
            return "off"
        # PowerShell fallback (requires BitLocker module — may not be present)
        ps = self._run_ps(
            "try { (Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus } catch { 'Off' }"
        ).strip()
        return "on" if ps.lower() in ("on", "protected") else "off"

    def _firewall(self) -> str:
        out = self._run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if re.search(r"\bON\b", out, re.I):
            return "on"
        return "off"

    def _secure_boot(self) -> str | None:
        # Registry check
        v = self.reg_get(
            _HKLM,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
        )
        if v is not None:
            return "full" if int(v) == 1 else "none"
        # PowerShell fallback
        out = self._run_ps(
            "try { Confirm-SecureBootUEFI } catch { 'False' }"
        ).strip().lower()
        if "true" in out:
            return "full"
        if "false" in out:
            return "none"
        return None

    def _auto_update(self) -> bool | None:
        v = self.reg_get(
            _HKLM,
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "NoAutoUpdate",
        )
        if v is not None:
            return (int(v) == 0)
        # Default: auto-update enabled unless explicitly blocked
        return True

    def _credential_guard(self) -> bool | None:
        v = self.reg_get(_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags")
        if v is None:
            return None
        return int(v) in (1, 2)   # 1=Enabled, 2=Enabled without lock

    def _wdac(self) -> bool | None:
        """Windows Defender Application Control policy presence check."""
        policy_path = r"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"
        return os.path.isfile(policy_path) or None

    def _smb1(self) -> bool | None:
        v = self.reg_get(
            _HKLM,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        )
        if v is None:
            # Not explicitly set — Windows 10 1709+ disables SMBv1 by default
            return None
        return bool(int(v))

    def _lsass_ppl(self) -> bool | None:
        """LSASS Protected Process Light — mitigates credential dumping."""
        v = self.reg_get(
            _HKLM,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
        )
        if v is None:
            return None
        return int(v) >= 1

    def _last_patch_age(self) -> int | None:
        """Days since most recent QFE (hotfix) was installed."""
        out = self._run_ps(
            "try { "
            "(Get-HotFix | Sort-Object InstalledOn -Descending | "
            "Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd') "
            "} catch { '' }"
        ).strip()
        if not out:
            return None
        try:
            from datetime import date
            parts = out.split("-")
            d     = date(int(parts[0]), int(parts[1]), int(parts[2]))
            return (date.today() - d).days
        except Exception:
            return None


# ── sysctl (registry security parameters) ────────────────────────────────────

class SysctlCollector(WinBaseCollector):
    """
    Enumerate Windows registry keys that map to macOS sysctl security knobs.

    Security-relevant hive paths and what they control
    ───────────────────────────────────────────────────
    Tcpip\\Parameters       : TCP stack hardening (SYN cookies, PMTU, timestamps)
    Lsa                     : credential protection, PPL, NTLM settings
    Policies\\System        : UAC levels, secure desktop
    LanmanServer\\Parameters: SMB configuration (SMBv1, signing required)
    Lsa\\MSV1_0            : NTLM auth restrictions
    WindowsUpdate\\AU       : automatic update policy
    SecureBoot\\State       : UEFI boot policy
    """
    name    = "sysctl"
    timeout = 15

    _HIVE_PATHS = [
        (None, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",                True),
        (None, r"SYSTEM\CurrentControlSet\Control\Lsa",                             True),
        (None, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",        True),
        (None, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",        True),
        (None, r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",                     True),
        (None, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",            False),
        (None, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",               True),
        (None, r"SYSTEM\CurrentControlSet\Services\MrxSmb10",                      True),
        (None, r"SYSTEM\CurrentControlSet\Control\Terminal Server",                False),
    ]

    def collect(self) -> list:
        try:
            import winreg
            hklm = winreg.HKEY_LOCAL_MACHINE
        except ImportError:
            return []

        records: list[dict] = []
        for _, path, sec_rel in self._HIVE_PATHS:
            vals = self.reg_get(hklm, path)
            if not vals:
                continue
            for name, value in vals.items():
                records.append({
                    "key":               f"HKLM\\{path}\\{name}",
                    "value":             str(value),
                    "security_relevant": sec_rel,
                })
        return records


# ── configs ───────────────────────────────────────────────────────────────────

class ConfigsCollector(WinBaseCollector):
    """
    Hash and inspect sensitive plaintext config files.

    Suspicious heuristics
    ─────────────────────
    • hosts: non-loopback entries that could redirect traffic
    • authorized_keys: any content (key should normally be empty or absent)
    • PS profile: download-cradle patterns (IEX, WebClient, DownloadString)
    • sshd_config: PermitRootLogin yes / PasswordAuthentication yes
    """
    name    = "configs"
    timeout = 15
    _CAP    = 4096   # max bytes to read per file

    _STATIC_FILES: list[tuple[str, str]] = [
        (r"C:\Windows\System32\drivers\etc\hosts",              "hosts"),
        (r"C:\ProgramData\ssh\sshd_config",                     "ssh_config"),
        (r"C:\ProgramData\ssh\administrators_authorized_keys",  "authorized_keys"),
    ]

    def collect(self) -> list:
        results: list[dict] = []
        paths = list(self._STATIC_FILES)

        # Per-user PowerShell profile (running user context)
        ps_prof = os.path.expandvars(
            r"%USERPROFILE%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
        )
        paths.append((ps_prof, "shell_rc"))
        # All-users PS profile
        paths.append((
            r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
            "shell_rc",
        ))
        # SSH user config
        paths.append((
            os.path.expandvars(r"%USERPROFILE%\.ssh\config"),
            "ssh_config",
        ))

        for path, ftype in paths:
            path = os.path.expandvars(str(path))
            if not os.path.isfile(path):
                continue
            try:
                st = os.stat(path)
                with open(path, "rb") as fh:
                    data = fh.read(self._CAP)
                sha  = hashlib.sha256(data).hexdigest()
                text = data.decode("utf-8", errors="replace")
                suspicious, note = self._check(ftype, text, path)
                results.append({
                    "path":        path,
                    "type":        ftype,
                    "hash":        sha,
                    "size_bytes":  st.st_size,
                    "modified_at": int(st.st_mtime),
                    "owner":       None,   # getpwuid not available on Windows
                    "permissions": None,
                    "suspicious":  suspicious,
                    "note":        note,
                })
            except (PermissionError, OSError):
                continue

        return results

    @staticmethod
    def _check(ftype: str, text: str, path: str) -> tuple[bool, str | None]:
        if ftype == "hosts":
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if parts and parts[0] not in ("127.0.0.1", "::1", "0.0.0.0"):
                    return True, f"Non-loopback hosts entry: {stripped[:80]}"

        elif ftype == "authorized_keys":
            if text.strip():
                return True, "Unexpected content in administrators_authorized_keys"

        elif ftype == "shell_rc":
            # Download-cradle and common persistence patterns
            patterns = [
                (r"IEX\s*\(", "IEX (Invoke-Expression) in PS profile"),
                (r"DownloadString",  "DownloadString in PS profile"),
                (r"WebClient",       "WebClient in PS profile"),
                (r"Invoke-WebRequest.*-Exec", "Invoke-WebRequest+Exec in PS profile"),
                (r"FromBase64String",  "Base64 decode in PS profile"),
            ]
            for pat, msg in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return True, msg

        elif ftype == "ssh_config":
            for line in text.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("permitrootlogin") and "yes" in stripped:
                    return True, "PermitRootLogin yes in sshd_config"
                if stripped.startswith("passwordauthentication") and "yes" in stripped:
                    return True, "PasswordAuthentication yes in sshd_config"

        return False, None


# Module-level HKLM handle — winreg only exists on Windows; on other platforms
# this stays None and reg_get() will silently return None (safe fallback).
try:
    import winreg as _winreg
    _HKLM = _winreg.HKEY_LOCAL_MACHINE
except ImportError:
    _HKLM = None
