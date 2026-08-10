"""Startup diagnosis and conservative self-recovery for Windows services.

This module intentionally has no pywin32 dependency so the packaged binaries,
the support CLI, tests, and the Docker scenario lab can all use the same rules.
Automatic recovery is limited to reversible local-state operations.  It never
deletes credentials or telemetry, changes TLS policy, or rewrites SCM entries.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
import time
import traceback
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping


_SENSITIVE_KEYS = {
    "api_key", "authorization", "enroll_token", "enrollment_token",
    "manager_api_key", "password", "secret", "spki_pin", "token",
}


def _default_root() -> Path:
    return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AttackLens"


def redact(value: Any, *, key: str = "") -> Any:
    """Return a JSON-safe copy with secrets removed."""
    lowered = key.lower()
    if any(part in lowered for part in _SENSITIVE_KEYS):
        return "<redacted>" if value not in (None, "") else value
    if isinstance(value, Mapping):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, key=key) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    temp.write_text(
        json.dumps(redact(dict(value)), indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    os.replace(temp, path)


@dataclass(frozen=True)
class RecoveryAction:
    action: str
    target: str
    status: str
    detail: str = ""


def classify_startup_error(exc: BaseException | str) -> dict[str, str]:
    """Map common service failures to stable codes and operator actions."""
    text = str(exc)
    lowered = text.lower()
    winerror = getattr(exc, "winerror", None)
    if winerror is None and getattr(exc, "args", None):
        first = exc.args[0]
        winerror = first if isinstance(first, int) else None

    rules: list[tuple[bool, str, str, str]] = [
        (winerror == 2 or "file not found" in lowered or "cannot find the file" in lowered,
         "missing_file", "fatal", "Repair or reinstall the package; verify the SCM ImagePath and config path."),
        (winerror in {5, 1314} or "access is denied" in lowered or "permission" in lowered,
         "access_denied", "fatal", "Run the elevated repair command and verify service-account ACLs."),
        (winerror == 1053 or "timely fashion" in lowered or "checkpoint" in lowered,
         "scm_start_timeout", "fatal", "Inspect startup-diagnosis.json and update/reinstall the service binary."),
        (winerror == 1056 or "already running" in lowered,
         "already_running", "benign", "No recovery is required; re-query the service state."),
        (winerror == 1060 or "service does not exist" in lowered,
         "service_missing", "fatal", "Run the elevated repair command to recreate both services."),
        (winerror == 1067 or "terminated unexpectedly" in lowered,
         "process_terminated", "fatal", "Inspect the startup journal, agent log, and Application event log."),
        (winerror == 1068 or "dependency" in lowered,
         "dependency_failure", "repairable", "Remove legacy network dependencies with the elevated repair command."),
        ("toml" in lowered or "configuration" in lowered or "config" in lowered,
         "config_invalid", "repairable", "Validate agent.toml or restore the last-known-good configuration."),
        ("sqlite" in lowered or "outbox" in lowered or "database" in lowered,
         "outbox_unavailable", "fatal", "Preserve the outbox and collect a support bundle; do not delete the database."),
        ("disk" in lowered or "no space" in lowered or "free space" in lowered,
         "disk_pressure", "repairable", "Free disk space; the encrypted outbox is intentionally preserved."),
        ("dns" in lowered or "connection" in lowered or "tls" in lowered or "certificate" in lowered,
         "manager_unreachable", "degraded", "Keep collecting offline; repair DNS/TCP/TLS without resetting identity."),
        ("another agent instance" in lowered or "mutex" in lowered,
         "duplicate_instance", "repairable", "Stop the duplicate process and let SCM own the only instance."),
    ]
    for matched, code, severity, action in rules:
        if matched:
            return {"code": code, "severity": severity, "action": action, "detail": text[:1024]}
    return {
        "code": "unexpected_startup_error",
        "severity": "fatal",
        "action": "Collect a support bundle and inspect the structured startup journal.",
        "detail": text[:1024],
    }


class StartupJournal:
    """Append-only, secret-redacted JSONL evidence available before main logging."""

    def __init__(self, component: str, root: str | os.PathLike[str] | None = None):
        self.component = component
        self.root = Path(root) if root else _default_root()
        self.path = self.root / "logs" / f"{component}-startup.jsonl"

    def record(self, event: str, **fields: Any) -> None:
        payload = {
            "timestamp": int(time.time()),
            "component": self.component,
            "event": event,
            "pid": os.getpid(),
            **fields,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(redact(payload), sort_keys=True, default=str) + "\n")
        except Exception:
            # Journaling must never become a new reason for a service to fail.
            pass

    def failure(self, phase: str, exc: BaseException) -> dict[str, str]:
        diagnosis = classify_startup_error(exc)
        self.record(
            "failure",
            phase=phase,
            diagnosis=diagnosis,
            exception_type=type(exc).__name__,
            traceback="".join(traceback.format_exception(exc))[-8192:],
        )
        return diagnosis


def _config_paths(config_path: Path) -> tuple[dict[str, str], dict[str, Any] | None, str | None]:
    defaults = {
        "config_dir": str(config_path.parent),
        "log_dir": str(_default_root() / "logs"),
        "spool_dir": str(_default_root() / "spool"),
        "data_dir": str(_default_root() / "data"),
        "security_dir": str(_default_root() / "security"),
    }
    try:
        from agent.os.windows.config_model import load_config

        cfg = load_config(str(config_path)).to_dict()
        defaults.update({str(k): str(v) for k, v in cfg.get("paths", {}).items()})
        return defaults, cfg, None
    except Exception as exc:
        return defaults, None, f"{type(exc).__name__}: {exc}"


def _path_probe(path: Path, *, directory: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": None,
        "readable": False,
        "writable": False,
    }
    try:
        exists = path.is_dir() if directory else path.is_file()
        result["exists"] = exists
        if exists:
            result["readable"] = os.access(path, os.R_OK)
        result["writable"] = os.access(path if directory else path.parent, os.W_OK)
    except OSError as exc:
        # Diagnostic commands are intentionally usable by standard users.  A
        # protected ProgramData path must be reported as inaccessible instead
        # of crashing the diagnostic process.
        result["access_error"] = f"{type(exc).__name__}: {exc}"
    try:
        usage_target = path if result["exists"] else path.parent
        usage = shutil.disk_usage(usage_target)
        result["disk_free_mb"] = int(usage.free / (1024 * 1024))
    except Exception as exc:
        result["probe_error"] = f"{type(exc).__name__}: {exc}"
    return result


def _outbox_probe(spool_dir: Path) -> dict[str, Any]:
    path = spool_dir / "delivery-outbox.sqlite3"
    result: dict[str, Any] = {"path": str(path), "exists": None}
    try:
        result["exists"] = path.is_file()
    except OSError as exc:
        result["inaccessible"] = True
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    if not result["exists"]:
        return result
    conn = None
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2)
        row = conn.execute("PRAGMA quick_check").fetchone()
        result["quick_check"] = row[0] if row else "unknown"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            conn.close()
    return result


def diagnose_startup(config_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Return an offline-first startup report even when config parsing fails."""
    config = Path(config_path)
    paths, cfg, config_error = _config_paths(config)
    checks = {
        "config": _path_probe(config, directory=False),
        "paths": {
            name: _path_probe(Path(path), directory=True)
            for name, path in paths.items()
            if name.endswith("_dir")
        },
        "outbox": _outbox_probe(Path(paths["spool_dir"])),
    }
    checks["config"]["valid"] = config_error is None
    if config_error:
        checks["config"]["error"] = config_error
    runtime_path = Path(paths["data_dir"]) / "agent.runtime.json"
    runtime, runtime_error = None, None
    try:
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        runtime_error = "not found"
    except Exception as exc:
        runtime_error = f"{type(exc).__name__}: {exc}"

    problems: list[dict[str, str]] = []
    if config_error:
        problems.append(classify_startup_error(config_error))
    for name, probe in checks["paths"].items():
        if not probe["exists"] or not probe["writable"]:
            problems.append(classify_startup_error(f"permission or missing directory: {name} {probe['path']}"))
    if checks["outbox"].get("error") or checks["outbox"].get("quick_check") not in (None, "ok"):
        problems.append(classify_startup_error(f"outbox database error: {checks['outbox']}"))

    return redact({
        "schema_version": 1,
        "generated_at": int(time.time()),
        "ok": not any(item["severity"] == "fatal" for item in problems),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "frozen": bool(getattr(sys, "frozen", False)),
        },
        "config_path": str(config),
        "manager_url": (cfg or {}).get("manager", {}).get("url"),
        "checks": checks,
        "runtime": runtime,
        "runtime_error": runtime_error,
        "problems": problems,
    })


def safe_repair(config_path: str | os.PathLike[str]) -> list[RecoveryAction]:
    """Apply reversible file-state repairs; never touch identity or outbox data."""
    config = Path(config_path)
    last_good = config.with_name(config.name + ".last-known-good")
    paths, cfg, config_error = _config_paths(config)
    actions: list[RecoveryAction] = []

    if config_error and last_good.is_file():
        _, backup_cfg, backup_error = _config_paths(last_good)
        if backup_cfg is not None and backup_error is None:
            restore_temp = config.with_name(config.name + f".{os.getpid()}.restore.tmp")
            try:
                broken = config.with_name(config.name + f".invalid-{int(time.time())}")
                # Prepare the replacement completely before touching the active
                # config. A disk/ACL failure must leave the original in place.
                shutil.copy2(last_good, restore_temp)
                if config.exists():
                    shutil.copy2(config, broken)
                    actions.append(RecoveryAction(
                        "quarantine_invalid_config",
                        str(config),
                        "repaired",
                        f"quarantined={broken}; validation_error={config_error}",
                    ))
                os.replace(restore_temp, config)
                paths, cfg, config_error = _config_paths(config)
                actions.append(RecoveryAction("restore_last_known_good", str(config), "repaired"))
            except Exception as exc:
                actions.append(RecoveryAction("restore_last_known_good", str(config), "failed", str(exc)))
            finally:
                try:
                    restore_temp.unlink(missing_ok=True)
                except OSError:
                    pass

    if cfg is not None:
        backup_temp = last_good.with_name(last_good.name + f".{os.getpid()}.tmp")
        try:
            config.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(config, backup_temp)
            os.replace(backup_temp, last_good)
            actions.append(RecoveryAction("refresh_last_known_good", str(last_good), "ok"))
        except Exception as exc:
            actions.append(RecoveryAction("refresh_last_known_good", str(last_good), "skipped", str(exc)))
        finally:
            try:
                backup_temp.unlink(missing_ok=True)
            except OSError:
                pass

    for name, value in paths.items():
        if not name.endswith("_dir"):
            continue
        target = Path(value)
        try:
            target.mkdir(parents=True, exist_ok=True)
            actions.append(RecoveryAction("ensure_directory", str(target), "ok", name))
        except Exception as exc:
            actions.append(RecoveryAction("ensure_directory", str(target), "failed", f"{name}: {exc}"))

    data_dir = Path(paths["data_dir"])
    for name in ("agent.runtime.json.tmp", "watchdog.runtime.json.tmp"):
        temp = data_dir / name
        try:
            if temp.is_file() and time.time() - temp.stat().st_mtime > 300:
                temp.unlink()
                actions.append(RecoveryAction("remove_stale_temp", str(temp), "repaired"))
        except Exception as exc:
            actions.append(RecoveryAction("remove_stale_temp", str(temp), "failed", str(exc)))

    runtime = data_dir / "agent.runtime.json"
    try:
        if runtime.is_file():
            value = json.loads(runtime.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("runtime root is not an object")
    except Exception as exc:
        try:
            quarantined = runtime.with_name(runtime.name + f".corrupt-{int(time.time())}")
            os.replace(runtime, quarantined)
            actions.append(RecoveryAction("quarantine_runtime_state", str(runtime), "repaired", f"{exc}; {quarantined}"))
        except Exception as move_exc:
            actions.append(RecoveryAction("quarantine_runtime_state", str(runtime), "failed", str(move_exc)))

    return actions


def write_diagnosis(config_path: str | os.PathLike[str], report_path: str | os.PathLike[str] | None = None) -> Path:
    report = diagnose_startup(config_path)
    if report_path:
        target = Path(report_path)
    else:
        paths, _, _ = _config_paths(Path(config_path))
        target = Path(paths["log_dir"]) / "startup-diagnosis.json"
    _atomic_json(target, report)
    return target


def actions_as_dict(actions: list[RecoveryAction]) -> list[dict[str, str]]:
    return [asdict(action) for action in actions]
