"""
agent/os/windows/collectors/sca.py — continuous Security Configuration Assessment.

Windows wrapper around the self-contained SCA engine (agent.os.windows.sca).
Runs the bundled CIS Windows baseline plus any operator drop-in policies under
``C:\\ProgramData\\AttackLens\\sca\\`` and returns a canonical result document
(per-check pass/fail plus a summary score).

Each rule command is dispatched through ``_route_command`` which decides between
PowerShell (Get-* / Confirm-* / pipes / expressions) and cmd.exe (reg / sc /
netsh / auditpol / wmic). Everything is read-only and bounded by a per-rule
timeout under the collector's 600 s budget. The collector never raises.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
import uuid

from .base import WinBaseCollector, CREATE_NO_WINDOW

log = logging.getLogger("agent.windows.collectors.sca")

# Operator drop-in policies (JSON always; YAML when PyYAML is installed).
POLICY_DIR = r"C:\ProgramData\AttackLens\sca"

# Console-native tools that must run under cmd.exe rather than PowerShell.
# `sc` in particular is a PowerShell alias for Set-Content, so `sc query` MUST
# go to cmd.exe. Everything NOT in this allowlist (Get-*/try{}/expressions) is
# treated as PowerShell — a safer default than trying to enumerate every cmdlet.
_CMD_NATIVE = (
    "reg ", "sc ", "netsh ", "auditpol ", "wmic ", "manage-bde ", "schtasks ",
    "net ", "cmd ", "cmd.exe", "where ", "ipconfig", "systeminfo", "bcdedit",
    "fsutil ", "nltest ", "dism ", "vssadmin ", "query ",
)


def _tokenize(cmd: str) -> "list[str]":
    """
    Split a console command into argv, honoring double quotes and preserving
    backslashes (Windows paths). Quote characters group whitespace and are then
    dropped, so `reg query "HKLM\\Windows NT\\x" /v N` →
    ['reg','query','HKLM\\Windows NT\\x','/v','N'] and
    `auditpol /get /category:"Logon/Logoff"` → [...,'/category:Logon/Logoff'].
    Unlike shlex(posix=True) this does not treat backslash as an escape char.
    """
    args: list[str] = []
    buf: list[str] = []
    in_quote = False
    started = False
    for ch in cmd:
        if ch == '"':
            in_quote = not in_quote
            started = True
        elif ch.isspace() and not in_quote:
            if started:
                args.append("".join(buf))
                buf = []
                started = False
        else:
            buf.append(ch)
            started = True
    if started:
        args.append("".join(buf))
    return args


def _route_command(cmd: str, timeout: float) -> "tuple[int | None, str, str]":
    """
    Execute one SCA rule command; return (returncode | None, stdout, stderr).

    Console-native tools (reg/sc/netsh/…) are tokenized and invoked directly as
    ``.exe`` argv — no cmd.exe, so nothing mangles the quotes around a key path
    with spaces and `sc` cannot resolve to its PowerShell Set-Content alias.
    Everything else runs through powershell.exe, which handles its own quoting.

    returncode is None only when the command could not be executed at all
    (interpreter missing or timeout) — the engine treats that as a tri-state
    error rather than a failed check.
    """
    cmd = cmd.strip()
    low = cmd.lower()
    is_cmd_native = any(low.startswith(p) for p in _CMD_NATIVE)
    if is_cmd_native:
        proc_cmd = _tokenize(cmd)
        if not proc_cmd:
            return None, "", "empty command"
    else:
        proc_cmd = [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", cmd,
        ]

    try:
        p = subprocess.run(
            proc_cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except FileNotFoundError:
        log.debug("SCA: interpreter not found for command: %s", cmd[:80])
        return None, "", "interpreter not found"
    except subprocess.TimeoutExpired:
        log.warning("SCA: command timed out after %.0fs: %s", timeout, cmd[:80])
        return None, "", f"command timed out after {timeout:.0f}s"
    except Exception as exc:
        log.debug("SCA: command failed [%s]: %s", cmd[:80], exc)
        return None, "", f"{type(exc).__name__}: {exc}"


class ScaCollector(WinBaseCollector):
    name    = "sca"
    timeout = 600   # 10 min budget for a full baseline scan

    # Per-rule wall-clock cap; several rules run within the section budget above.
    _rule_timeout = 15.0

    def __init__(self, state_dir: "str | None" = None):
        self._state_path = os.path.join(state_dir, "sca-state.json") if state_dir else None
        self._lock = threading.Lock()
        self._pending_state: "dict | None" = None
        self._health = {
            "status": "not_run",
            "last_scan_at": 0,
            "last_duration_ms": 0,
            "last_score_pct": None,
            "last_fail_count": 0,
            "last_error_count": 0,
            "last_unknown_count": 0,
            "consecutive_failures": 0,
            "pending_commit": False,
            "state_committed_at": 0,
        }

    def collect(self) -> dict:
        started_wall = int(time.time())
        started_mono = time.monotonic()
        scan_id = str(uuid.uuid4())
        try:
            from ..sca import ScaEngine, BUNDLED_POLICIES
        except Exception as exc:
            log.warning("SCA engine unavailable: %s", exc)
            return self._error_document(scan_id, started_wall, started_mono, exc)

        try:
            result = ScaEngine(
                runner=_route_command,
                extra_policy_dirs=[POLICY_DIR],
                platform="windows",
                rule_timeout=self._rule_timeout,
                bundled_policies=BUNDLED_POLICIES,
            ).scan()
            completed_at = int(time.time())
            result.update({
                "schema_version": 2,
                "scan_id": scan_id,
                "generated_at": completed_at,
                "started_at": started_wall,
                "completed_at": completed_at,
                "duration_ms": max(
                    int(result.get("duration_ms") or 0),
                    int(round((time.monotonic() - started_mono) * 1000.0)),
                ),
            })
            result["changes"] = self._calculate_changes(result)
            # Commit the comparison baseline only after the assessment has
            # reached the durable outbox. The agent invokes commit/rollback.
            with self._lock:
                self._pending_state = result
            self._update_health(result)
            return result
        except Exception as exc:
            log.warning("SCA scan failed: %s", exc)
            return self._error_document(scan_id, started_wall, started_mono, exc)

    def health_snapshot(self) -> dict:
        with self._lock:
            value = dict(self._health)
            value["pending_commit"] = self._pending_state is not None
            return value

    def commit(self) -> None:
        """Advance the baseline only after durable outbox enqueue succeeds."""
        with self._lock:
            pending = self._pending_state
        if pending is None:
            return
        if not self._persist_state(pending):
            return
        with self._lock:
            if self._pending_state is pending:
                self._pending_state = None
                self._health["pending_commit"] = False
                self._health["state_committed_at"] = int(time.time())

    def rollback(self) -> None:
        """Forget an unqueued baseline so its change is retried next scan."""
        with self._lock:
            self._pending_state = None
            self._health["pending_commit"] = False

    def _calculate_changes(self, result: dict) -> dict:
        previous = self._read_state()
        old = _check_results(previous)
        current = _check_results(result)
        changed = [
            {"check_id": key, "previous": old[key], "current": value}
            for key, value in sorted(current.items())
            if key in old and old[key] != value
        ]
        return {
            "baseline": not bool(old),
            "changed_count": len(changed),
            "new_failures": [
                key for key, value in sorted(current.items())
                if value == "fail" and old.get(key) not in (None, "fail")
            ],
            "resolved_failures": [
                key for key, value in sorted(current.items())
                if old.get(key) == "fail" and value == "pass"
            ],
            "items": changed[:200],
        }

    def _read_state(self) -> dict:
        if not self._state_path:
            return {}
        try:
            with open(self._state_path, "r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except (FileNotFoundError, PermissionError, OSError, ValueError):
            return {}

    def _persist_state(self, result: dict) -> bool:
        if not self._state_path:
            return True
        directory = os.path.dirname(self._state_path)
        temporary = self._state_path + ".tmp"
        try:
            os.makedirs(directory, exist_ok=True)
            with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(result, handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._state_path)
            return True
        except (PermissionError, OSError) as exc:
            log.warning("SCA state persistence failed: %s", exc)
            try:
                if os.path.exists(temporary):
                    os.remove(temporary)
            except OSError:
                pass
            return False

    def _update_health(self, result: dict) -> None:
        summary = result.get("summary") or {}
        with self._lock:
            self._health.update({
                "status": str(summary.get("status") or "unknown"),
                "last_scan_at": int(result.get("completed_at") or time.time()),
                "last_duration_ms": int(result.get("duration_ms") or 0),
                "last_score_pct": summary.get("score_pct"),
                "last_fail_count": int(summary.get("fail") or 0),
                "last_error_count": int(summary.get("error") or 0),
                "last_unknown_count": int(summary.get("unknown") or 0),
                "consecutive_failures": 0,
                "state_path": self._state_path,
                "pending_commit": True,
            })

    def _error_document(
        self,
        scan_id: str,
        started_wall: int,
        started_mono: float,
        exc: Exception,
    ) -> dict:
        completed_at = int(time.time())
        error_type = type(exc).__name__
        with self._lock:
            failures = int(self._health.get("consecutive_failures") or 0) + 1
            self._health.update({
                "status": "error",
                "last_scan_at": completed_at,
                "last_duration_ms": int(round((time.monotonic() - started_mono) * 1000.0)),
                "last_error": error_type,
                "consecutive_failures": failures,
            })
        return {
            "schema_version": 2,
            "scan_id": scan_id,
            "generated_at": completed_at,
            "started_at": started_wall,
            "completed_at": completed_at,
            "duration_ms": int(round((time.monotonic() - started_mono) * 1000.0)),
            "policies": [],
            "summary": {
                "total": 0,
                "pass": 0,
                "fail": 0,
                "not_applicable": 0,
                "error": 1,
                "unknown": 0,
                "score_pct": None,
                "coverage_pct": 0.0,
                "status": "error",
                "policies": 0,
            },
            "changes": {
                "baseline": False,
                "changed_count": 0,
                "new_failures": [],
                "resolved_failures": [],
                "items": [],
            },
            "collector_error": {
                "code": "sca_scan_failed",
                "type": error_type,
                "retryable": True,
            },
        }


def _check_results(document: dict) -> dict[str, str]:
    found: dict[str, str] = {}
    if not isinstance(document, dict):
        return found
    for policy in document.get("policies") or []:
        if not isinstance(policy, dict):
            continue
        policy_id = str(policy.get("policy_id") or "policy")
        for check in policy.get("checks") or []:
            if not isinstance(check, dict):
                continue
            check_id = str(check.get("id") or "")
            if check_id:
                found[f"{policy_id}:{check_id}"] = str(check.get("result") or "error")
    return found
