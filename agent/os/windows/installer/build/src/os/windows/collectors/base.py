"""
agent/os/windows/collectors/base.py — Windows base collector.

Mirrors agent/agent/collectors/base.py but adds Windows-specific subprocess
flags (CREATE_NO_WINDOW, PowerShell runner) and a winreg helper.

Every Windows collector:
  1. Subclasses WinBaseCollector
  2. Declares `name` as a class attribute matching the agent.toml section key
  3. Implements `collect()` — returns dict or list, MUST NEVER RAISE
  4. Is callable via __call__

Design notes
────────────
• CREATE_NO_WINDOW suppresses the cmd.exe flash in PyInstaller single-file EXE.
• _run() and _run_ps() both return "" on any error — callers must be defensive.
• _reg_get() returns None rather than raising on missing keys / access denied.
"""
from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Union

log = logging.getLogger("agent.windows.collectors")

# Suppress visible console window when spawning child processes from a
# PyInstaller windowed binary or a Windows Service context.
CREATE_NO_WINDOW: int = 0x08000000

CollectorResult = Union[dict, list]


class WinBaseCollector(ABC):
    """Abstract base for all Windows data collectors."""

    timeout: int = 15   # seconds — override per-collector for slow queries

    @property
    @abstractmethod
    def name(self) -> str:
        """Section name — must match the key in COLLECTORS and agent.toml."""
        ...

    @abstractmethod
    def collect(self) -> CollectorResult:
        """
        Collect section data.
        Must return {} or [] on failure — must never raise.
        """
        ...

    def __call__(self) -> CollectorResult:
        return self.collect()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} section={self.name!r}>"

    # ── subprocess helpers ────────────────────────────────────────────────────

    def _run(self, cmd: list[str]) -> str:
        """
        Run a command, return stdout as str.
        Suppresses the console window. Returns "" on any error.
        """
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                errors="replace",
                creationflags=CREATE_NO_WINDOW,
            )
            return r.stdout or ""
        except FileNotFoundError:
            log.debug("Command not found: %s", cmd[0] if cmd else "?")
            return ""
        except subprocess.TimeoutExpired:
            log.debug("Timed out after %ds: %s", self.timeout, cmd[0] if cmd else "?")
            return ""
        except Exception as exc:
            log.debug("_run [%s] failed: %s", " ".join(cmd) if cmd else "?", exc)
            return ""

    def _run_ps(self, script: str) -> str:
        """
        Run a PowerShell expression non-interactively. Returns stdout as str.
        Uses -ExecutionPolicy Bypass to avoid policy blocks in constrained environments.
        """
        return self._run([
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", script,
        ])

    # ── registry helper ───────────────────────────────────────────────────────

    @staticmethod
    def reg_get(hive, path: str, name: str | None = None):
        """
        Read one value (name != None) or all values (name=None) from a registry key.
        Returns None / {} on PermissionError or missing key — never raises.
        Requests KEY_WOW64_64KEY so 32-bit PyInstaller EXEs see the real 64-bit hive.
        """
        try:
            import winreg
            flags = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            with winreg.OpenKey(hive, path, 0, flags) as key:
                if name is None:
                    result: dict = {}
                    i = 0
                    while True:
                        try:
                            n, v, _ = winreg.EnumValue(key, i)
                            result[n] = v
                            i += 1
                        except OSError:
                            break
                    return result
                val, _ = winreg.QueryValueEx(key, name)
                return val
        except Exception:
            return None

    @staticmethod
    def reg_enum_keys(hive, path: str) -> list[str]:
        """Return list of subkey names under hive\\path. Returns [] on error."""
        keys: list[str] = []
        try:
            import winreg
            with winreg.OpenKey(hive, path, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                i = 0
                while True:
                    try:
                        keys.append(winreg.EnumKey(k, i))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return keys
