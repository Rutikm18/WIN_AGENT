"""
agent/os/windows/collectors/system.py — System state collectors (2 min).

sections: battery, openfiles, services, users, hardware, containers

Key Windows decisions
─────────────────────
• battery   — psutil.sensors_battery() + WMI Win32_Battery for capacity detail
• openfiles — num_handles() as proxy (true open-file enumeration requires SeDebugPrivilege)
• services  — psutil.win_service_iter() (clean, no subprocess); sc query fallback
• users     — Get-LocalUser PowerShell + net localgroup for admin membership
• hardware  — Get-PnpDevice PowerShell (covers USB, BT, GPU, audio — no WMI quirks)
• containers— docker / podman JSON output (same cross-platform approach as macOS)
"""
from __future__ import annotations

import json
import logging
import re
import time

import psutil

try:  # Optional on non-Windows unit-test hosts.
    import win32service
except ImportError:  # pragma: no cover - feature-detected at runtime
    win32service = None

try:
    import win32net
    import win32netcon
    import win32security
except ImportError:  # pragma: no cover - feature-detected at runtime
    win32net = win32netcon = win32security = None

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.system")


# ── battery ───────────────────────────────────────────────────────────────────

class BatteryCollector(WinBaseCollector):
    name    = "battery"
    timeout = 10

    def collect(self) -> dict:
        bat = None
        try:
            bat = psutil.sensors_battery()
        except Exception:
            pass

        if bat is None:
            return {
                "present":      False,
                "charging":     None,
                "charge_pct":   None,
                "cycle_count":  None,
                "condition":    None,
                "capacity_mah": None,
                "design_mah":   None,
                "voltage_mv":   None,
            }

        # Extra detail from WMI Win32_Battery
        capacity_mah = design_mah = voltage_mv = None
        ps_out = self._run_ps(
            "try { Get-CimInstance -ClassName Win32_Battery | "
            "Select-Object FullChargeCapacity,DesignCapacity,DesignVoltage "
            "| ConvertTo-Json -Compress } catch { '{}' }"
        )
        try:
            d = json.loads(ps_out.strip() or "{}")
            if isinstance(d, list):
                d = d[0] if d else {}
            capacity_mah = d.get("FullChargeCapacity")
            design_mah   = d.get("DesignCapacity")
            voltage_mv   = d.get("DesignVoltage")
        except Exception:
            pass

        return {
            "present":      True,
            "charging":     bool(bat.power_plugged),
            "charge_pct":   int(bat.percent),
            "cycle_count":  None,   # Win32_Battery does not expose CycleCount
            "condition":    "Normal",
            "capacity_mah": int(capacity_mah) if capacity_mah is not None else None,
            "design_mah":   int(design_mah)   if design_mah   is not None else None,
            "voltage_mv":   int(voltage_mv)   if voltage_mv   is not None else None,
        }


# ── openfiles ─────────────────────────────────────────────────────────────────

class OpenFilesCollector(WinBaseCollector):
    """
    Top processes by Windows handle count.

    True file-descriptor enumeration on Windows requires SeDebugPrivilege and
    NtQuerySystemInformation, which is unreliable in unprivileged contexts.
    num_handles() (from NtQueryInformationProcess) is available without extra
    privileges for processes the agent can see.
    """
    name    = "openfiles"
    timeout = 15

    def collect(self) -> list:
        results: list[dict] = []
        try:
            for p in psutil.process_iter(["pid", "name", "username"]):
                try:
                    handles = p.num_handles()
                    results.append({
                        "pid":      p.pid,
                        "process":  p.info.get("name") or "",
                        "fd_count": handles,
                        "user":     p.info.get("username"),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            log.debug("openfiles: %s", exc)

        results.sort(key=lambda x: x["fd_count"], reverse=True)
        return results[:60]


# ── services ──────────────────────────────────────────────────────────────────

_SERVICE_STATE_NAMES = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "running",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}


def _native_services(api=None) -> list[dict]:
    """Enumerate SCM records without localized output or subprocesses."""
    api = api or win32service
    if api is None:
        raise RuntimeError("pywin32 win32service is unavailable")

    scm = api.OpenSCManager(None, None, api.SC_MANAGER_ENUMERATE_SERVICE)
    records: list[dict] = []
    try:
        entries = api.EnumServicesStatusEx(
            scm,
            api.SERVICE_WIN32 | api.SERVICE_DRIVER,
            api.SERVICE_STATE_ALL,
        )
        for entry in entries:
            # Current pywin32 returns a dict; older releases returned
            # (service_name, display_name, status_dict). Support both shapes.
            if isinstance(entry, dict):
                status = entry
                service_name = status.get("ServiceName", "")
                display_name = status.get("DisplayName", service_name)
            else:
                service_name, display_name, status = entry
            current_state = int(status.get("CurrentState", 0))
            service_type = int(status.get("ServiceType", 0))
            pid = int(status.get("ProcessId", 0)) or None
            start_type = None
            service_handle = None
            try:
                service_handle = api.OpenService(
                    scm,
                    service_name,
                    api.SERVICE_QUERY_CONFIG,
                )
                start_type = int(api.QueryServiceConfig(service_handle)[1])
            except Exception as exc:
                log.debug("service config unavailable name=%s error=%s", service_name, exc)
            finally:
                if service_handle is not None:
                    try:
                        api.CloseServiceHandle(service_handle)
                    except Exception:
                        pass

            disabled = start_type == getattr(api, "SERVICE_DISABLED", 4)
            manual = start_type == getattr(api, "SERVICE_DEMAND_START", 3)
            is_driver = bool(service_type & getattr(api, "SERVICE_DRIVER", 0x0B))
            records.append({
                "name": str(service_name),
                "status": "disabled" if disabled else _SERVICE_STATE_NAMES.get(
                    current_state, "unknown"
                ),
                "enabled": None if start_type is None else not (disabled or manual),
                "pid": pid,
                "type": "windriver" if is_driver else "winsvc",
                "description": str(display_name or service_name),
            })
        return records
    finally:
        api.CloseServiceHandle(scm)


class ServicesCollector(WinBaseCollector):
    name    = "services"
    timeout = 20

    def collect(self) -> list:
        try:
            return _native_services()
        except Exception as exc:
            log.debug("native SCM service enumeration failed: %s", exc)
            return []


# ── users ─────────────────────────────────────────────────────────────────────

def _paged_net_call(call, *args) -> list[dict]:
    """Drain a pywin32 Net* pagination API while guarding bad resume tokens."""
    rows: list[dict] = []
    resume = 0
    seen: set[int] = set()
    while True:
        batch, _total, next_resume = call(*args, resume)
        rows.extend(batch or [])
        next_resume = int(next_resume or 0)
        if not next_resume or next_resume in seen:
            return rows
        seen.add(next_resume)
        resume = next_resume


def _native_local_users(net=None, constants=None, security=None) -> list[dict]:
    """Return local user accounts through NetAPI32-backed pywin32 calls."""
    net = net or win32net
    constants = constants or win32netcon
    security = security or win32security
    if net is None or constants is None or security is None:
        raise RuntimeError("pywin32 account APIs are unavailable")

    admin_names: set[str] = set()
    try:
        admin_sid = security.ConvertStringSidToSid("S-1-5-32-544")
        admin_group, _domain, _use = security.LookupAccountSid(None, admin_sid)
        members = _paged_net_call(
            net.NetLocalGroupGetMembers,
            None,
            admin_group,
            2,
        )
        for member in members:
            account = str(member.get("domainandname") or member.get("name") or "")
            if account:
                admin_names.add(account.rsplit("\\", 1)[-1].casefold())
    except Exception as exc:
        log.debug("local Administrators membership unavailable: %s", exc)

    accounts = _paged_net_call(
        net.NetUserEnum,
        None,
        3,
        constants.FILTER_NORMAL_ACCOUNT,
    )
    disabled_flag = int(getattr(constants, "UF_ACCOUNTDISABLE", 0x0002))
    lockout_flag = int(getattr(constants, "UF_LOCKOUT", 0x0010))
    rows: list[dict] = []
    for account in accounts:
        name = str(account.get("name") or "")
        if not name:
            continue
        flags = int(account.get("flags") or 0)
        last_logon = int(account.get("last_logon") or 0) or None
        home = str(account.get("home_dir") or "").strip() or f"C:\\Users\\{name}"
        rows.append({
            "name": name,
            "uid": None,
            "gid": None,
            "shell": None,
            "home": home,
            "last_login": last_logon,
            "admin": name.casefold() in admin_names,
            "locked": bool(flags & (disabled_flag | lockout_flag)),
        })
    return rows


class UsersCollector(WinBaseCollector):
    name    = "users"
    timeout = 20

    def collect(self) -> list:
        try:
            rows = _native_local_users()
        except Exception as exc:
            log.debug("native local-account enumeration failed: %s", exc)
            return []

        # NetUserEnum last_logon can lag behind an active interactive session.
        sessions: dict[str, int] = {}
        try:
            for session in psutil.users():
                sessions[session.name.rsplit("\\", 1)[-1].casefold()] = int(session.started)
        except Exception:
            pass
        for row in rows:
            if row["last_login"] is None:
                row["last_login"] = sessions.get(row["name"].casefold())
        return rows


# ── hardware ──────────────────────────────────────────────────────────────────

class HardwareCollector(WinBaseCollector):
    """
    Enumerate connected hardware via Get-PnpDevice PowerShell.

    Covers: USB peripherals, Bluetooth devices, GPUs, audio devices.
    Get-PnpDevice is available on Windows 8+ without needing WMI DCOM.
    """
    name    = "hardware"
    timeout = 20

    _CLASSES = "USB,Bluetooth,Monitor,Display,AudioEndpoint,Media,HIDClass,DiskDrive,CDRom"

    def collect(self) -> list:
        devices: list[dict] = []
        ps_out = self._run_ps(
            f"Get-PnpDevice -PresentOnly -Class {self._CLASSES} -ErrorAction SilentlyContinue | "
            "Select-Object Class,FriendlyName,Manufacturer,DeviceID,Status | "
            "ConvertTo-Json -Compress"
        )
        try:
            raw = json.loads(ps_out.strip() or "[]")
            if isinstance(raw, dict):
                raw = [raw]
            for d in raw or []:
                cls     = (d.get("Class") or "").lower()
                dev_id  = d.get("DeviceID") or ""
                name    = d.get("FriendlyName") or dev_id

                # Map Windows class → canonical bus type
                if "bluetooth" in cls:
                    bus = "bluetooth"
                elif cls in ("monitor", "display"):
                    bus = "pci"
                elif cls in ("audioendpoint", "media"):
                    bus = "pci"
                else:
                    bus = "usb"

                vid = pid_str = None
                if "VID_" in dev_id:
                    try:
                        vid = dev_id.split("VID_")[1][:4].upper()
                    except Exception:
                        pass
                if "PID_" in dev_id:
                    try:
                        pid_str = dev_id.split("PID_")[1][:4].upper()
                    except Exception:
                        pass

                devices.append({
                    "bus":        bus,
                    "name":       name,
                    "vendor":     d.get("Manufacturer"),
                    "product_id": pid_str,
                    "vendor_id":  vid,
                    "serial":     None,   # GetDeviceProperty call needed; skip for now
                    "connected":  (d.get("Status") or "").upper() == "OK",
                })
        except Exception as exc:
            log.debug("hardware: %s", exc)

        return devices


# ── containers ────────────────────────────────────────────────────────────────

class ContainersCollector(WinBaseCollector):
    """Docker for Windows / Podman on WSL2 — identical to macOS."""
    name    = "containers"
    timeout = 15

    def collect(self) -> list:
        containers: list[dict] = []
        for runtime in ("docker", "podman"):
            out = self._run([runtime, "ps", "--all", "--no-trunc",
                             "--format", "{{json .}}"])
            for line in out.strip().splitlines():
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                ports_raw = d.get("Ports") or d.get("ports") or ""
                ports     = [p.strip() for p in ports_raw.split(",") if p.strip()] if ports_raw else []
                created_at = None
                try:
                    ts = str(d.get("CreatedAt") or d.get("Created") or "")
                    # e.g. "2026-03-31 10:00:00 +0000 UTC"
                    from datetime import datetime, timezone
                    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%SZ"):
                        try:
                            created_at = int(datetime.strptime(ts[:25], fmt)
                                             .replace(tzinfo=timezone.utc).timestamp())
                            break
                        except Exception:
                            pass
                except Exception:
                    pass
                containers.append({
                    "id":         (d.get("ID") or d.get("Id") or "")[:12],
                    "name":       (d.get("Names") or d.get("Name") or "").lstrip("/"),
                    "image":      d.get("Image"),
                    "status":     (d.get("State") or d.get("Status") or "unknown").lower(),
                    "runtime":    runtime,
                    "ports":      ports,
                    "created_at": created_at,
                })
        return containers
