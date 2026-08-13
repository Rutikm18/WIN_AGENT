"""Native Windows persistence inventory with transactional baseline diffing.

The collector intentionally uses Win32 registry, SCM, Task Scheduler COM and
WMI APIs.  It never shells out, never parses localized command output, and
does not mutate the endpoint.  Baseline state is committed only after the
agent has durably queued the corresponding telemetry envelope.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Iterable
from xml.etree import ElementTree

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.persistence")


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = ";".join(str(part) for part in value)
    result = str(value).strip()
    return result or None


def _entry(
    surface: str,
    location: str,
    name: str,
    *,
    command: Any = None,
    user: Any = None,
    enabled: bool | None = None,
    privileged: bool | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    identity = json.dumps(
        [surface.casefold(), location.casefold(), str(name).casefold()],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return {
        "entry_id": hashlib.sha256(identity).hexdigest(),
        "surface": surface,
        "location": location,
        "name": str(name),
        "command": _text(command),
        "user": _text(user),
        "enabled": enabled,
        "privileged": privileged,
        "status": "present",
        "change": "unchanged",
        "first_seen": None,
        "last_seen": None,
        "metadata": metadata or {},
    }


def _fingerprint(record: dict[str, Any]) -> str:
    material = {
        key: record.get(key)
        for key in ("command", "user", "enabled", "privileged", "metadata")
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _iter_key_values(winreg, hive, path: str, view: int) -> list[tuple[str, Any, int]]:
    values: list[tuple[str, Any, int]] = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
            index = 0
            while True:
                try:
                    values.append(winreg.EnumValue(key, index))
                    index += 1
                except OSError:
                    break
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return values


def _iter_subkeys(winreg, hive, path: str, view: int) -> list[str]:
    names: list[str] = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
            index = 0
            while True:
                try:
                    names.append(str(winreg.EnumKey(key, index)))
                    index += 1
                except OSError:
                    break
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return names


def _registry_value(winreg, hive, path: str, name: str, view: int) -> Any:
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
            return winreg.QueryValueEx(key, name)[0]
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _registry_entries() -> list[dict[str, Any]]:
    try:
        import winreg
    except ImportError:
        return []

    views = (
        ("64", getattr(winreg, "KEY_WOW64_64KEY", 0)),
        ("32", getattr(winreg, "KEY_WOW64_32KEY", 0)),
    )
    rows: list[dict[str, Any]] = []
    run_paths = (
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    )

    # HKCU in Session 0 is LocalSystem.  Enumerate every loaded interactive
    # user hive as well; do not load offline NTUSER.DAT files or mutate hives.
    hives: list[tuple[Any, str, str]] = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", ""),
        (winreg.HKEY_CURRENT_USER, "HKCU", ""),
    ]
    for sid in _iter_subkeys(winreg, winreg.HKEY_USERS, "", 0):
        if sid.startswith("S-1-5-21-") or sid.startswith("S-1-12-1-"):
            hives.append((winreg.HKEY_USERS, f"HKU\\{sid}", f"{sid}\\"))

    seen: set[str] = set()
    for hive, hive_label, prefix in hives:
        for view_name, view in views:
            for relative in run_paths:
                path = f"{prefix}{relative}"
                location = f"{hive_label}\\{relative} [{view_name}]"
                for name, value, value_type in _iter_key_values(winreg, hive, path, view):
                    record = _entry(
                        "run_key", location, name or "(Default)", command=value,
                        user=hive_label if hive_label.startswith("HKU\\") else None,
                        enabled=True,
                        privileged=hive == winreg.HKEY_LOCAL_MACHINE,
                        metadata={"registry_type": int(value_type), "view": view_name},
                    )
                    if record["entry_id"] not in seen:
                        seen.add(record["entry_id"]); rows.append(record)

    # Machine-wide registry persistence surfaces.
    machine_values = (
        ("appinit", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
         ("AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs")),
        ("winlogon", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
         ("Shell", "Userinit", "Taskman", "VmApplet")),
        ("lsa_package", r"SYSTEM\CurrentControlSet\Control\Lsa",
         ("Authentication Packages", "Security Packages", "Notification Packages")),
        ("security_provider", r"SYSTEM\CurrentControlSet\Control\SecurityProviders",
         ("SecurityProviders",)),
    )
    for surface, path, names in machine_values:
        for view_name, view in views:
            for name in names:
                value = _registry_value(winreg, winreg.HKEY_LOCAL_MACHINE, path, name, view)
                if value is not None:
                    rows.append(_entry(
                        surface, f"HKLM\\{path} [{view_name}]", name,
                        command=value, enabled=True, privileged=True,
                        metadata={"view": view_name},
                    ))

    # IFEO debugger hijacks, Winlogon Notify, print monitors and netsh helpers.
    subkey_surfaces = (
        ("ifeo", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "Debugger"),
        ("winlogon_notify", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify", "DLLName"),
        ("print_monitor", r"SYSTEM\CurrentControlSet\Control\Print\Monitors", "Driver"),
        ("netsh_helper", r"SOFTWARE\Microsoft\NetSh", ""),
    )
    for surface, base, value_name in subkey_surfaces:
        for view_name, view in views:
            for child in _iter_subkeys(winreg, winreg.HKEY_LOCAL_MACHINE, base, view):
                child_path = f"{base}\\{child}"
                value = _registry_value(
                    winreg, winreg.HKEY_LOCAL_MACHINE, child_path, value_name, view
                )
                if value is None and value_name:
                    continue
                rows.append(_entry(
                    surface, f"HKLM\\{child_path} [{view_name}]", child,
                    command=value, enabled=True, privileged=True,
                    metadata={"view": view_name},
                ))

    # Per-user COM registrations override machine registrations and are the
    # high-signal COM-hijack surface. Enumerating HKLM's thousands of legitimate
    # registrations would add no override signal and can exceed ingest limits.
    for hive, hive_label, prefix in hives[1:]:
        for view_name, view in views:
            base = f"{prefix}Software\\Classes\\CLSID"
            for clsid in _iter_subkeys(winreg, hive, base, view):
                for server_kind in ("InprocServer32", "LocalServer32"):
                    path = f"{base}\\{clsid}\\{server_kind}"
                    command = _registry_value(winreg, hive, path, "", view)
                    if command is None:
                        continue
                    rows.append(_entry(
                        "com_hijack", f"{hive_label}\\Software\\Classes\\CLSID\\{clsid}\\{server_kind} [{view_name}]",
                        clsid, command=command, user=hive_label, enabled=True,
                        privileged=False, metadata={"server_kind": server_kind, "view": view_name},
                    ))
    return rows


def _startup_entries() -> list[dict[str, Any]]:
    roots: list[tuple[Path, str, str | None, bool]] = []
    program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
    roots.append((
        program_data / r"Microsoft\Windows\Start Menu\Programs\Startup",
        "all_users", None, True,
    ))
    system_drive = os.environ.get("SystemDrive", "C:")
    users_root = Path(system_drive + "\\Users")
    try:
        profiles = list(users_root.iterdir())
    except (OSError, PermissionError):
        profiles = []
    for profile in profiles:
        if profile.is_dir():
            roots.append((
                profile / r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                "user", profile.name, False,
            ))

    rows: list[dict[str, Any]] = []
    for root, scope, user, privileged in roots:
        try:
            files = sorted(path for path in root.iterdir() if path.is_file())
        except (OSError, PermissionError):
            continue
        for path in files:
            try:
                stat = path.stat()
                metadata = {"scope": scope, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
            except OSError:
                metadata = {"scope": scope}
            rows.append(_entry(
                "startup_folder", str(root), path.name, command=str(path),
                user=user, enabled=True, privileged=privileged, metadata=metadata,
            ))
    return rows


def _service_entries() -> list[dict[str, Any]]:
    try:
        import win32service
    except ImportError:
        return []
    rows: list[dict[str, Any]] = []
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    try:
        entries = win32service.EnumServicesStatusEx(
            scm, win32service.SERVICE_WIN32 | win32service.SERVICE_DRIVER,
            win32service.SERVICE_STATE_ALL,
        )
        for item in entries:
            status = item if isinstance(item, dict) else item[2]
            name = status.get("ServiceName", "") if isinstance(item, dict) else item[0]
            display = status.get("DisplayName", name) if isinstance(item, dict) else item[1]
            handle = None
            try:
                handle = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_CONFIG)
                config = win32service.QueryServiceConfig(handle)
                service_type, start_type, error_control, binary = map(
                    lambda value: value, config[:4]
                )
                account = config[7] if len(config) > 7 else None
                enabled = int(start_type) != win32service.SERVICE_DISABLED
                is_driver = bool(int(service_type) & win32service.SERVICE_DRIVER)
                rows.append(_entry(
                    "driver" if is_driver else "service", "SCM", str(name),
                    command=binary, user=account, enabled=enabled,
                    privileged=True,
                    metadata={
                        "display_name": str(display or name),
                        "service_type": int(service_type),
                        "start_type": int(start_type),
                        "error_control": int(error_control),
                    },
                ))
            except Exception as exc:
                log.debug("persistence service config unavailable name=%s error=%s", name, exc)
            finally:
                if handle is not None:
                    win32service.CloseServiceHandle(handle)
    finally:
        win32service.CloseServiceHandle(scm)
    return rows


def _task_entries() -> list[dict[str, Any]]:
    try:
        import pythoncom
        import win32com.client
    except ImportError:
        return []
    initialized = False
    scheduler = folder = task = tasks = children = None
    pending: list[Any] = []
    task_items: list[Any] = []
    try:
        pythoncom.CoInitialize(); initialized = True
        scheduler = win32com.client.Dispatch("Schedule.Service"); scheduler.Connect()
        pending = [scheduler.GetFolder("\\")]
        rows: list[dict[str, Any]] = []
        visited: set[str] = set()
        while pending:
            folder = pending.pop()
            folder_path = str(getattr(folder, "Path", "") or "")
            if folder_path.casefold() in visited:
                continue
            visited.add(folder_path.casefold())
            try:
                children = folder.GetFolders(0)
                pending.extend(children.Item(index) for index in range(1, int(children.Count) + 1))
            except Exception:
                pass
            try:
                tasks = folder.GetTasks(1)
                task_items = [tasks.Item(index) for index in range(1, int(tasks.Count) + 1)]
            except Exception:
                task_items = []
            for task in task_items:
                try:
                    xml = str(getattr(task, "Xml", "") or "")
                    root = ElementTree.fromstring(xml) if xml else None
                    values: dict[str, list[str]] = {}
                    if root is not None:
                        for element in root.iter():
                            tag = element.tag.rsplit("}", 1)[-1]
                            if element.text and element.text.strip():
                                values.setdefault(tag, []).append(element.text.strip())
                    commands = values.get("Command", [])
                    arguments = values.get("Arguments", [])
                    command = " ; ".join(
                        f"{cmd} {arguments[index] if index < len(arguments) else ''}".strip()
                        for index, cmd in enumerate(commands)
                    ) or None
                    path = str(getattr(task, "Path", "") or getattr(task, "Name", ""))
                    rows.append(_entry(
                        "scheduled_task", "Task Scheduler", path,
                        command=command,
                        user=(values.get("UserId") or values.get("GroupId") or [None])[0],
                        enabled=bool(getattr(task, "Enabled", False)),
                        privileged=(values.get("RunLevel") or [""])[0].casefold() == "highestavailable",
                        metadata={
                            "triggers": sorted({
                                element.tag.rsplit("}", 1)[-1]
                                for element in root.iter()
                                if root is not None and element.tag.rsplit("}", 1)[-1].endswith("Trigger")
                            }) if root is not None else [],
                            "actions": commands,
                            "last_result": int(getattr(task, "LastTaskResult", 0) or 0),
                            "xml_sha256": hashlib.sha256(xml.encode("utf-8")).hexdigest() if xml else None,
                        },
                    ))
                except Exception as exc:
                    log.debug("persistence task parse failed folder=%s error=%s", folder_path, exc)
        return rows
    except Exception as exc:
        log.debug("Task Scheduler persistence enumeration unavailable: %s", exc)
        return []
    finally:
        if initialized:
            pending.clear(); task_items.clear()
            task = tasks = children = folder = scheduler = None
            import gc
            gc.collect(); pythoncom.CoUninitialize()


def _wmi_entries() -> list[dict[str, Any]]:
    try:
        import pythoncom
        import win32com.client
    except ImportError:
        return []
    initialized = False
    service = objects = obj = None
    try:
        pythoncom.CoInitialize(); initialized = True
        service = win32com.client.GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\subscription")
        rows: list[dict[str, Any]] = []
        classes = (
            ("wmi_filter", "__EventFilter", "Name", "Query"),
            ("wmi_consumer", "CommandLineEventConsumer", "Name", "CommandLineTemplate"),
            ("wmi_consumer", "ActiveScriptEventConsumer", "Name", "ScriptText"),
            ("wmi_binding", "__FilterToConsumerBinding", "__RELPATH", "Consumer"),
        )
        for surface, class_name, name_attr, command_attr in classes:
            try:
                objects = service.ExecQuery(f"SELECT * FROM {class_name}")
                for obj in objects:
                    name = _text(getattr(obj, name_attr, None)) or _text(getattr(obj, "Path_", None)) or class_name
                    rows.append(_entry(
                        surface, r"WMI:root\subscription", name,
                        command=getattr(obj, command_attr, None), enabled=True,
                        privileged=True, metadata={"class": class_name},
                    ))
            except Exception as exc:
                log.debug("WMI persistence class unavailable class=%s error=%s", class_name, exc)
        return rows
    except Exception as exc:
        log.debug("WMI persistence enumeration unavailable: %s", exc)
        return []
    finally:
        if initialized:
            obj = objects = service = None
            import gc
            gc.collect(); pythoncom.CoUninitialize()


class PersistenceCollector(WinBaseCollector):
    """Inventory Windows autostarts and emit baseline-aware change records."""

    name = "persistence"
    timeout = 120

    def __init__(self, state_dir: str | os.PathLike[str] | None = None) -> None:
        base = Path(state_dir) if state_dir is not None else Path(
            os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        ) / "AttackLens" / "data"
        self.baseline_path = base / "baseline" / "persistence.json"
        self._pending_baseline: dict[str, Any] | None = None
        self._last_counts: dict[str, int] = {}
        self._last_error: str | None = None

    def _snapshot(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for probe in (
            _registry_entries, _startup_entries, _service_entries,
            _task_entries, _wmi_entries,
        ):
            try:
                rows.extend(probe())
            except Exception as exc:
                log.warning("persistence probe failed probe=%s error=%s", probe.__name__, exc)
        # A duplicate can arise when 32/64-bit views resolve to the same key.
        return list({row["entry_id"]: row for row in rows}.values())

    def _load_baseline(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.baseline_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("entries"), dict):
                return raw
        except FileNotFoundError:
            pass
        except Exception as exc:
            self._last_error = f"baseline_read: {type(exc).__name__}: {exc}"
        return {"schema": 1, "created_at": None, "entries": {}}

    def collect(self) -> list[dict[str, Any]]:
        now = int(time.time())
        current = self._snapshot()
        baseline = self._load_baseline()
        previous: dict[str, Any] = baseline.get("entries", {})
        first_run = baseline.get("created_at") is None
        output: list[dict[str, Any]] = []
        next_entries: dict[str, Any] = {}

        for row in current:
            entry_id = row["entry_id"]
            fingerprint = _fingerprint(row)
            prior = previous.get(entry_id) if isinstance(previous, dict) else None
            if first_run:
                change, first_seen = "baseline", now
            elif prior is None:
                change, first_seen = "added", now
            elif prior.get("fingerprint") != fingerprint:
                change, first_seen = "modified", int(prior.get("first_seen") or now)
                row["metadata"] = dict(row["metadata"])
                row["metadata"]["previous_fingerprint"] = prior.get("fingerprint")
            else:
                change, first_seen = "unchanged", int(prior.get("first_seen") or now)
            row["change"] = change
            row["first_seen"] = first_seen
            row["last_seen"] = now
            output.append(row)
            next_entries[entry_id] = {
                "fingerprint": fingerprint,
                "first_seen": first_seen,
                "last_seen": now,
                "record": {key: value for key, value in row.items() if key != "change"},
            }

        if not first_run:
            for entry_id, prior in previous.items():
                if entry_id in next_entries or not isinstance(prior, dict):
                    continue
                old = dict(prior.get("record") or {})
                if not old:
                    continue
                old.update({
                    "entry_id": entry_id,
                    "status": "removed",
                    "change": "removed",
                    "first_seen": int(prior.get("first_seen") or now),
                    "last_seen": now,
                })
                output.append(old)

        self._pending_baseline = {
            "schema": 1,
            "created_at": int(baseline.get("created_at") or now),
            "updated_at": now,
            "entries": next_entries,
        }
        counts: dict[str, int] = {}
        for row in output:
            counts[row["change"]] = counts.get(row["change"], 0) + 1
        self._last_counts = counts
        return sorted(output, key=lambda row: (row["surface"], row["location"], row["name"]))

    def commit(self) -> None:
        if self._pending_baseline is None:
            return
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.baseline_path.with_suffix(".json.tmp")
        try:
            with temp.open("w", encoding="utf-8") as handle:
                json.dump(self._pending_baseline, handle, separators=(",", ":"), sort_keys=True)
                handle.flush(); os.fsync(handle.fileno())
            os.replace(temp, self.baseline_path)
            self._pending_baseline = None
            self._last_error = None
        except Exception as exc:
            self._last_error = f"baseline_write: {type(exc).__name__}: {exc}"
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def rollback(self) -> None:
        self._pending_baseline = None

    def health_snapshot(self) -> dict[str, Any]:
        return {
            "baseline_path": str(self.baseline_path),
            "baseline_exists": self.baseline_path.is_file(),
            "pending_commit": self._pending_baseline is not None,
            "changes": dict(self._last_counts),
            "last_error": self._last_error,
        }


__all__ = ["PersistenceCollector"]
