"""
agent/os/windows/collectors/inventory.py — Software inventory (10 min – 24 hr).

sections: storage, tasks, apps, packages, binaries, sbom

Design notes
────────────
• apps     — reads the Uninstall registry hive directly via winreg (three locations:
              HKLM 64-bit, HKLM WoW64 32-bit, HKCU) to enumerate all installed software.
• tasks    — Get-ScheduledTask PowerShell; schtasks /query CSV fallback.
• packages — pip, npm, choco, winget, scoop — each is optional; missing tools are
             silently skipped.
• binaries — walks %ProgramFiles%, %ProgramFiles(x86)%, %SystemRoot%\\System32 for
             .exe files; complete SHA-256 is streamed with a scan deadline.
• sbom     — aggregates pip, npm, choco, winget into purl-formatted records.
"""
from __future__ import annotations

import copy
import csv
import hashlib
import importlib.metadata as importlib_metadata
import io
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time

import psutil

try:  # Task Scheduler COM is optional on non-Windows test hosts.
    import pythoncom
    import win32com.client as win32com_client
except ImportError:  # pragma: no cover - feature-detected at runtime
    pythoncom = win32com_client = None

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.inventory")


class _CollectorHealth:
    """Thread-safe inventory health shared with the health publisher."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: dict = {
            "status": "never_run",
            "last_started_at": None,
            "last_success_at": None,
            "last_error_at": None,
            "last_error": None,
            "last_count": 0,
            "last_duration_ms": 0,
            "details": {},
        }

    def begin(self) -> float:
        with self._lock:
            self._state["last_started_at"] = int(time.time())
        return time.monotonic()

    def complete(
        self,
        *,
        started: float,
        status: str,
        count: int,
        details: dict | None = None,
        error: str | None = None,
    ) -> None:
        now = int(time.time())
        with self._lock:
            self._state.update({
                "status": status,
                "last_count": max(0, int(count)),
                "last_duration_ms": max(
                    0, int((time.monotonic() - started) * 1000)
                ),
                "details": details or {},
                "last_error": error,
            })
            if count > 0:
                self._state["last_success_at"] = now
            if error:
                self._state["last_error_at"] = now

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._state)


# ── storage ───────────────────────────────────────────────────────────────────

class StorageCollector(WinBaseCollector):
    name    = "storage"
    timeout = 15

    def collect(self) -> list:
        results: list[dict] = []
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                except (PermissionError, OSError):
                    continue
                results.append({
                    "device":     part.device,
                    "mountpoint": part.mountpoint,
                    "fstype":     part.fstype or None,
                    "total_gb":   round(usage.total / 1e9, 3),
                    "used_gb":    round(usage.used  / 1e9, 3),
                    "free_gb":    round(usage.free  / 1e9, 3),
                    "pct":        round(usage.percent, 2),
                })
        except Exception as exc:
            log.debug("storage: %s", exc)
        return results


# ── tasks ─────────────────────────────────────────────────────────────────────

_TASK_TRIGGER_NAMES = {
    0: "event", 1: "time", 2: "daily", 3: "weekly", 4: "monthly",
    5: "monthly_dow", 6: "idle", 7: "registration", 8: "boot",
    9: "logon", 11: "session_state", 12: "custom",
}


def _com_items(collection) -> list:
    if collection is None:
        return []
    try:
        return list(collection)
    except (TypeError, AttributeError):
        pass
    result = []
    count = int(getattr(collection, "Count", 0) or 0)
    for index in range(1, count + 1):
        result.append(collection.Item(index))
    return result


def _com_epoch(value) -> int | None:
    if value is None:
        return None
    try:
        timestamp = int(value.timestamp())
        # Task Scheduler represents "never" using its zero/1899 COM date.
        return timestamp if timestamp > 0 else None
    except (AttributeError, TypeError, ValueError, OverflowError, OSError):
        return None


def _task_command(definition) -> str | None:
    commands: list[str] = []
    try:
        actions = _com_items(definition.Actions)
    except Exception:
        actions = []
    for action in actions:
        try:
            # TASK_ACTION_EXEC = 0. Other action types are intentionally not
            # coerced from localized COM descriptions.
            if int(getattr(action, "Type", -1)) != 0:
                continue
            executable = str(getattr(action, "Path", "") or "").strip()
            arguments = str(getattr(action, "Arguments", "") or "").strip()
            command = f"{executable} {arguments}".strip()
            if command:
                commands.append(command)
        except Exception:
            continue
    return " ; ".join(commands) or None


def _task_schedule(definition) -> str | None:
    schedules: list[str] = []
    try:
        triggers = _com_items(definition.Triggers)
    except Exception:
        triggers = []
    for trigger in triggers:
        try:
            kind = _TASK_TRIGGER_NAMES.get(int(getattr(trigger, "Type", -1)), "unknown")
            start = str(getattr(trigger, "StartBoundary", "") or "").strip()
            schedules.append(f"{kind}:{start}" if start else kind)
        except Exception:
            continue
    return " ; ".join(schedules) or None


def _native_scheduled_tasks(dispatch=None, com_runtime=None) -> list[dict]:
    dispatch = dispatch or (win32com_client.Dispatch if win32com_client else None)
    com_runtime = com_runtime or pythoncom
    if dispatch is None:
        raise RuntimeError("Task Scheduler COM support is unavailable")

    initialized = False
    scheduler = folder = task = definition = principal = None
    pending: list = []
    tasks: list = []
    if com_runtime is not None:
        com_runtime.CoInitialize()
        initialized = True
    try:
        scheduler = dispatch("Schedule.Service")
        scheduler.Connect()
        pending = [scheduler.GetFolder("\\")]
        visited: set[str] = set()
        result: list[dict] = []
        while pending:
            folder = pending.pop()
            folder_path = str(getattr(folder, "Path", "") or "")
            key = folder_path.casefold()
            if key in visited:
                continue
            visited.add(key)
            try:
                pending.extend(_com_items(folder.GetFolders(0)))
            except Exception as exc:
                log.debug("task folder traversal failed path=%s error=%s", folder_path, exc)
            try:
                tasks = _com_items(folder.GetTasks(1))  # TASK_ENUM_HIDDEN
            except Exception as exc:
                log.debug("task enumeration failed path=%s error=%s", folder_path, exc)
                continue
            for task in tasks:
                try:
                    definition = task.Definition
                    principal = getattr(definition, "Principal", None)
                    result.append({
                        "name": str(getattr(task, "Path", "") or getattr(task, "Name", "")),
                        "type": "schtasks",
                        "schedule": _task_schedule(definition),
                        "command": _task_command(definition),
                        "user": str(getattr(principal, "UserId", "") or "") or None,
                        "enabled": bool(getattr(task, "Enabled", False)),
                        "last_run": _com_epoch(getattr(task, "LastRunTime", None)),
                        "next_run": _com_epoch(getattr(task, "NextRunTime", None)),
                    })
                except Exception as exc:
                    log.debug("task record unavailable folder=%s error=%s", folder_path, exc)
        return result
    finally:
        if initialized:
            # Release all apartment-bound wrappers before CoUninitialize.
            # Otherwise pywin32 reports IUnknown release failures when the
            # collector's worker thread exits.
            tasks.clear()
            pending.clear()
            task = definition = principal = folder = scheduler = None
            import gc
            gc.collect()
            com_runtime.CoUninitialize()


class TasksCollector(WinBaseCollector):
    name    = "tasks"
    timeout = 45

    def collect(self) -> list:
        try:
            return _native_scheduled_tasks()
        except Exception as exc:
            log.debug("Task Scheduler COM collection failed: %s", exc)
            return []


# ── apps ──────────────────────────────────────────────────────────────────────

class AppsCollector(WinBaseCollector):
    """
    Read installed applications from the Windows Uninstall registry hives.

    Three hive locations cover 64-bit apps, 32-bit apps (WoW64 redirect),
    and per-user installs respectively.
    """
    name    = "apps"
    timeout = 20

    def collect(self) -> list:
        try:
            import winreg
        except ImportError:
            return []

        hklm = winreg.HKEY_LOCAL_MACHINE
        hkcu = winreg.HKEY_CURRENT_USER
        UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        apps: list[dict] = []
        seen: set[tuple[str, str, str]] = set()

        # Explicit views avoid relying on the bitness of the PyInstaller host.
        # HKCU can also contain view-specific registrations, so inspect both.
        for hive, path, view in [
            (hklm, UNINSTALL, winreg.KEY_WOW64_64KEY),
            (hklm, UNINSTALL, winreg.KEY_WOW64_32KEY),
            (hkcu, UNINSTALL, winreg.KEY_WOW64_64KEY),
            (hkcu, UNINSTALL, winreg.KEY_WOW64_32KEY),
        ]:
            for key_name in _registry_subkeys(hive, path, view):
                sub = f"{path}\\{key_name}"
                name = _rv(hive, sub, "DisplayName", view)
                if not name:
                    continue
                version   = _rv(hive, sub, "DisplayVersion", view)
                publisher = _rv(hive, sub, "Publisher", view)
                inst_loc  = _rv(hive, sub, "InstallLocation", view)
                inst_date = _rv(hive, sub, "InstallDate", view)
                identity = (
                    str(name).casefold(), str(version or "").casefold(),
                    str(inst_loc or "").casefold(),
                )
                if identity in seen:
                    continue
                seen.add(identity)

                installed_at = None
                if inst_date:
                    try:
                        from datetime import datetime
                        installed_at = int(
                            datetime.strptime(str(inst_date).strip(), "%Y%m%d").timestamp()
                        )
                    except Exception:
                        pass

                apps.append({
                    "name":         name,
                    "version":      version,
                    "bundle_id":    None,   # macOS concept
                    "path":         inst_loc or None,
                    "signed":       None,   # Authenticode check would add latency
                    "notarized":    None,   # macOS only
                    "vendor":       publisher,
                    "installed_at": installed_at,
                })

        return apps


# ── packages ──────────────────────────────────────────────────────────────────

class PackagesCollector(WinBaseCollector):
    name    = "packages"
    timeout = 60

    def collect(self) -> list:
        packages: list[dict] = []
        packages.extend(self._pip())
        packages.extend(self._npm())
        packages.extend(self._choco())
        packages.extend(self._winget())
        packages.extend(self._scoop())
        return packages

    def _pip(self) -> list:
        out = self._run(["pip", "list", "--format=json"])
        try:
            return [
                {"manager": "pip", "name": p["name"], "version": p.get("version"),
                 "latest": None, "outdated": None, "installed_at": None}
                for p in (json.loads(out) or [])
            ]
        except Exception:
            return []

    def _npm(self) -> list:
        out = self._run(["npm", "list", "-g", "--depth=0", "--json"])
        try:
            d = json.loads(out)
            return [
                {"manager": "npm", "name": name, "version": info.get("version"),
                 "latest": None, "outdated": None, "installed_at": None}
                for name, info in (d.get("dependencies") or {}).items()
            ]
        except Exception:
            return []

    def _choco(self) -> list:
        # --local-only was removed in Chocolatey v2; try it first (v1 compat),
        # fall back to plain `list` which is local-only by default in v2+.
        out = self._run(["choco", "list", "--local-only", "--limit-output"])
        if not out.strip():
            out = self._run(["choco", "list", "--limit-output"])
        results: list[dict] = []
        for line in out.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                results.append({
                    "manager": "choco", "name": parts[0], "version": parts[1],
                    "latest": None, "outdated": None, "installed_at": None,
                })
        return results

    def _winget(self) -> list:
        out = self._run(["winget", "list",
                         "--accept-source-agreements", "--disable-interactivity"])
        results: list[dict] = []
        lines  = out.splitlines()
        # winget list column order: Name | Id | Version | Available | Source
        # Find the separator row (dashes) to locate data rows.
        data_start = next(
            (i for i, l in enumerate(lines) if re.match(r"^-{3,}", l.strip())), -1
        )
        if data_start < 0:
            return results
        for line in lines[data_start + 1:]:
            line = line.strip()
            if not line:
                continue
            # Fixed-width columns; split on 2+ spaces is more reliable than
            # fixed offsets because localized column headers vary in width.
            parts = re.split(r"\s{2,}", line)
            if len(parts) < 2:
                continue
            # parts[0]=Name, parts[1]=Id, parts[2]=Version (if present)
            results.append({
                "manager": "winget", "name": parts[0],
                "version": parts[2] if len(parts) > 2 else None,
                "latest": None, "outdated": None, "installed_at": None,
            })
        return results

    def _scoop(self) -> list:
        out = self._run(["scoop", "list"])
        results: list[dict] = []
        for line in out.strip().splitlines()[2:]:   # skip header rows
            parts = line.split()
            if len(parts) >= 2:
                results.append({
                    "manager": "scoop", "name": parts[0], "version": parts[1],
                    "latest": None, "outdated": None, "installed_at": None,
                })
        return results


# ── binaries ──────────────────────────────────────────────────────────────────

class BinariesCollector(WinBaseCollector):
    """
    Walk standard binary directories for PE (.exe) files.

    SHA-256 is streamed over the complete file. The deadline is checked between
    chunks so a large or slow file cannot wedge the collector.
    """
    name    = "binaries"
    timeout = 90

    _MAX_FILES: int = 500
    _MAX_DURATION_SEC: int = 75

    _SCAN_DIRS: list[str] = [
        os.environ.get("ProgramFiles",      r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("SystemRoot",        r"C:\Windows") + r"\System32",
    ]

    def __init__(self) -> None:
        self._health = _CollectorHealth()

    def collect(self) -> list:
        started = self._health.begin()
        results: list[dict] = []
        seen: set[str]      = set()
        scanned_dirs: list[str] = []
        skipped_files = 0
        walk_errors = 0
        deadline_hit = False
        file_cap_hit = False

        def on_walk_error(_exc: OSError) -> None:
            nonlocal walk_errors
            walk_errors += 1

        try:
            deadline = started + self._MAX_DURATION_SEC
            for base_dir in self._SCAN_DIRS:
                if not base_dir or not os.path.isdir(base_dir):
                    continue
                scanned_dirs.append(base_dir)
                for root, dirs, files in os.walk(
                    base_dir, onerror=on_walk_error
                ):
                    if time.monotonic() >= deadline:
                        deadline_hit = True
                        break
                    dirs[:] = [d for d in dirs if d.lower() != "winsxs"]
                    for fname in files:
                        if not fname.lower().endswith(".exe"):
                            continue
                        if len(results) >= self._MAX_FILES:
                            file_cap_hit = True
                            break
                        if time.monotonic() >= deadline:
                            deadline_hit = True
                            break
                        fpath = os.path.join(root, fname)
                        path_key = os.path.normcase(fpath)
                        if path_key in seen:
                            continue
                        seen.add(path_key)
                        try:
                            st  = os.stat(fpath)
                            sha = _sha256_file(fpath, deadline)
                            if sha is None:
                                if time.monotonic() >= deadline:
                                    deadline_hit = True
                                    break
                                skipped_files += 1
                                continue
                            results.append({
                                "path":          fpath,
                                "name":          fname,
                                "hash_sha256":   sha,
                                "size_bytes":    st.st_size,
                                "modified_at":   int(st.st_mtime),
                                "signed":        None,
                                "notarized":     None,
                                "permissions":   None,
                                "owner":         None,
                                "suid":          None,
                                "sgid":          None,
                                "world_writable":None,
                            })
                        except (PermissionError, OSError):
                            skipped_files += 1
                    if file_cap_hit or deadline_hit:
                        break
                if file_cap_hit or deadline_hit:
                    break
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._health.complete(
                started=started,
                status="error" if not results else "degraded",
                count=len(results),
                details={
                    "scanned_dirs": scanned_dirs,
                    "skipped_files": skipped_files,
                    "walk_errors": walk_errors,
                },
                error=error,
            )
            log.warning("binaries collection failed: %s", error)
            return results

        details = {
            "scanned_dirs": scanned_dirs,
            "skipped_files": skipped_files,
            "walk_errors": walk_errors,
            "partial": file_cap_hit or deadline_hit,
            "partial_reason": (
                "file_cap" if file_cap_hit
                else "deadline" if deadline_hit
                else None
            ),
            "max_files": self._MAX_FILES,
            "deadline_sec": self._MAX_DURATION_SEC,
        }
        if not scanned_dirs:
            status = "error"
            error = "no configured binary scan directory is accessible"
        elif not results:
            status = "error"
            error = "no readable executable files were collected"
        elif deadline_hit:
            status = "degraded"
            error = "binary scan deadline reached; partial inventory retained"
        else:
            status = "healthy"
            error = None
        self._health.complete(
            started=started,
            status=status,
            count=len(results),
            details=details,
            error=error,
        )
        if error:
            log.warning("binaries: %s", error)
        return results

    def health_snapshot(self) -> dict:
        return self._health.snapshot()


# ── sbom ──────────────────────────────────────────────────────────────────────

class SbomCollector(WinBaseCollector):
    """Software Bill of Materials — aggregates pip, npm, choco, winget."""
    name    = "sbom"
    timeout = 60

    def __init__(self) -> None:
        self._health = _CollectorHealth()

    def _collect_legacy(self) -> list:
        components: list[dict] = []

        # pip
        out = self._run(["pip", "list", "--format=json"])
        try:
            for p in json.loads(out) or []:
                name = p.get("name", "")
                ver  = p.get("version")
                components.append({
                    "type":    "library",
                    "name":    name,
                    "version": ver,
                    "purl":    f"pkg:pypi/{name.lower()}@{ver}" if ver else None,
                    "license": None,
                    "source":  "pip",
                    "cpe":     None,
                })
        except Exception:
            pass

        # npm
        out = self._run(["npm", "list", "-g", "--depth=0", "--json"])
        try:
            d = json.loads(out)
            for name, info in (d.get("dependencies") or {}).items():
                ver = info.get("version")
                components.append({
                    "type":    "library",
                    "name":    name,
                    "version": ver,
                    "purl":    f"pkg:npm/{name}@{ver}" if ver else None,
                    "license": None,
                    "source":  "npm",
                    "cpe":     None,
                })
        except Exception:
            pass

        # choco — --local-only removed in v2+; fall back to plain list
        out = self._run(["choco", "list", "--local-only", "--limit-output"])
        if not out.strip():
            out = self._run(["choco", "list", "--limit-output"])
        for line in out.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                name, ver = parts[0], parts[1]
                components.append({
                    "type":    "application",
                    "name":    name,
                    "version": ver,
                    "purl":    f"pkg:chocolatey/{name.lower()}@{ver}",
                    "license": None,
                    "source":  "choco",
                    "cpe":     None,
                })

        # winget
        out = self._run(["winget", "export", "-o", "-",
                         "--accept-source-agreements",
                         "--disable-interactivity"])
        try:
            d = json.loads(out)
            for src in d.get("Sources", []):
                for pkg in src.get("Packages", []):
                    pid  = pkg.get("PackageIdentifier", "")
                    ver  = pkg.get("Version")
                    components.append({
                        "type":    "application",
                        "name":    pid,
                        "version": ver,
                        "purl":    f"pkg:winget/{pid}@{ver}" if ver else None,
                        "license": None,
                        "source":  "winget",
                        "cpe":     None,
                    })
        except Exception:
            pass

        return components

    def collect(self) -> list:
        started = self._health.begin()
        components: list[dict] = []
        providers: dict[str, dict] = {}

        # Native metadata works without pip on PATH, including service context.
        try:
            count_before = len(components)
            for distribution in importlib_metadata.distributions():
                name = str(
                    distribution.metadata.get("Name")
                    or distribution.metadata.get("Summary")
                    or ""
                ).strip()
                version = str(distribution.version or "").strip() or None
                if not name:
                    continue
                components.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": (
                        f"pkg:pypi/{name.lower()}@{version}"
                        if version else None
                    ),
                    "license": None,
                    "source": "python",
                    "cpe": None,
                })
            providers["python"] = {
                "status": "available",
                "count": len(components) - count_before,
            }
        except Exception as exc:
            providers["python"] = {
                "status": "error",
                "count": 0,
                "error": f"{type(exc).__name__}: {exc}",
            }

        if shutil.which("npm") is None:
            providers["npm"] = {"status": "not_installed", "count": 0}
        else:
            out = self._run(["npm", "list", "-g", "--depth=0", "--json"])
            try:
                count_before = len(components)
                parsed = json.loads(out)
                for name, info in (parsed.get("dependencies") or {}).items():
                    version = info.get("version")
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": version,
                        "purl": (
                            f"pkg:npm/{name}@{version}"
                            if version else None
                        ),
                        "license": None,
                        "source": "npm",
                        "cpe": None,
                    })
                providers["npm"] = {
                    "status": "available",
                    "count": len(components) - count_before,
                }
            except Exception as exc:
                providers["npm"] = {
                    "status": "error",
                    "count": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                }

        if shutil.which("choco") is None:
            providers["choco"] = {"status": "not_installed", "count": 0}
        else:
            out = self._run(["choco", "list", "--limit-output"])
            count_before = len(components)
            for line in out.strip().splitlines():
                parts = line.split("|")
                if len(parts) >= 2:
                    name, version = parts[0], parts[1]
                    components.append({
                        "type": "application",
                        "name": name,
                        "version": version,
                        "purl": (
                            f"pkg:chocolatey/{name.lower()}@{version}"
                        ),
                        "license": None,
                        "source": "choco",
                        "cpe": None,
                    })
            providers["choco"] = {
                "status": "available" if out.strip() else "error",
                "count": len(components) - count_before,
            }
            if not out.strip():
                providers["choco"]["error"] = "command returned no data"

        if shutil.which("winget") is None:
            providers["winget"] = {"status": "not_installed", "count": 0}
        else:
            fd, export_path = tempfile.mkstemp(
                prefix="attacklens-sbom-", suffix=".json"
            )
            os.close(fd)
            os.unlink(export_path)
            try:
                self._run([
                    "winget", "export", "--output", export_path,
                    "--include-versions",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ])
                count_before = len(components)
                with open(export_path, "r", encoding="utf-8-sig") as handle:
                    parsed = json.load(handle)
                for source in parsed.get("Sources", []):
                    for package in source.get("Packages", []):
                        package_id = package.get("PackageIdentifier", "")
                        version = package.get("Version")
                        if not package_id:
                            continue
                        components.append({
                            "type": "application",
                            "name": package_id,
                            "version": version,
                            "purl": (
                                f"pkg:winget/{package_id}@{version}"
                                if version else None
                            ),
                            "license": None,
                            "source": "winget",
                            "cpe": None,
                        })
                providers["winget"] = {
                    "status": "available",
                    "count": len(components) - count_before,
                }
            except Exception as exc:
                providers["winget"] = {
                    "status": "error",
                    "count": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            finally:
                try:
                    os.unlink(export_path)
                except OSError:
                    pass

        # Registry inventory is boot-safe under LocalSystem and ensures useful
        # data when optional per-user package managers are unavailable.
        try:
            count_before = len(components)
            for application in AppsCollector().collect():
                name = str(application.get("name") or "").strip()
                if not name:
                    continue
                components.append({
                    "type": "application",
                    "name": name,
                    "version": application.get("version"),
                    "purl": None,
                    "license": None,
                    "source": "windows_registry",
                    "cpe": None,
                })
            providers["windows_registry"] = {
                "status": "available",
                "count": len(components) - count_before,
            }
        except Exception as exc:
            providers["windows_registry"] = {
                "status": "error",
                "count": 0,
                "error": f"{type(exc).__name__}: {exc}",
            }

        deduplicated: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for component in components:
            key = (
                str(component.get("source") or "").casefold(),
                str(component.get("name") or "").casefold(),
                str(component.get("version") or "").casefold(),
            )
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(component)

        provider_errors = sorted(
            name for name, state in providers.items()
            if state.get("status") == "error"
        )
        if not deduplicated:
            status = "error"
            error = "all SBOM providers returned no components"
        elif provider_errors:
            status = "degraded"
            error = "provider errors: " + ", ".join(provider_errors)
        else:
            status = "healthy"
            error = None
        self._health.complete(
            started=started,
            status=status,
            count=len(deduplicated),
            details={"providers": providers},
            error=error,
        )
        if error:
            log.warning("sbom: %s", error)
        return deduplicated

    def health_snapshot(self) -> dict:
        return self._health.snapshot()


# ── helpers ───────────────────────────────────────────────────────────────────

def _registry_subkeys(hive, path: str, view_flag: int) -> list[str]:
    try:
        import winreg
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view_flag) as key:
            result: list[str] = []
            index = 0
            while True:
                try:
                    result.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    return result
    except Exception:
        return []


def _rv(hive, path: str, name: str, view_flag: int | None = None):
    """Read a single registry value; return None on error."""
    try:
        import winreg
        if view_flag is None:
            view_flag = winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view_flag) as k:
            val, _ = winreg.QueryValueEx(k, name)
            return val
    except Exception:
        return None


def _sha256_file(path: str, deadline: float | None = None) -> str | None:
    """Stream a complete SHA-256 hash, respecting the scan deadline."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    return None
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None
