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

class ServicesCollector(WinBaseCollector):
    name    = "services"
    timeout = 20

    def collect(self) -> list:
        services: list[dict] = []

        try:
            for svc in psutil.win_service_iter():
                try:
                    si = svc.as_dict()
                    raw_status = (si.get("status") or "unknown").lower()
                    start_type = (si.get("start_type") or "").lower()
                    # Map psutil start_type → enabled bool
                    enabled = start_type not in ("disabled", "manual")
                    services.append({
                        "name":        si.get("name", ""),
                        "status":      raw_status,
                        "enabled":     enabled,
                        "pid":         si.get("pid"),
                        "type":        "winsvc",
                        "description": si.get("display_name") or si.get("name"),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            # Fallback: parse sc query output
            out = self._run(["sc", "query", "type=", "all", "state=", "all"])
            curr: dict = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SERVICE_NAME:"):
                    if curr.get("name"):
                        services.append(curr)
                    curr = {
                        "name": line.split(":", 1)[-1].strip(),
                        "status": "unknown", "enabled": None,
                        "pid": None, "type": "winsvc", "description": None,
                    }
                elif "STATE" in line and curr:
                    if "RUNNING" in line:
                        curr["status"] = "running"
                    elif "STOPPED" in line:
                        curr["status"] = "stopped"
                    elif "PAUSED" in line:
                        curr["status"] = "paused"
                elif line.startswith("DISPLAY_NAME:") and curr:
                    curr["description"] = line.split(":", 1)[-1].strip()
            if curr.get("name"):
                services.append(curr)

        return services


# ── users ─────────────────────────────────────────────────────────────────────

class UsersCollector(WinBaseCollector):
    name    = "users"
    timeout = 20

    def collect(self) -> list:
        # Currently logged-in sessions (for last_login fallback)
        sessions: dict[str, psutil._common.suser] = {}
        try:
            for u in psutil.users():
                sessions[u.name.split("\\")[-1].lower()] = u
        except Exception:
            pass

        # Admin group members
        admin_names: set[str] = set()
        adm_out = self._run_ps(
            "try { Get-LocalGroupMember -Group 'Administrators' | "
            "Select-Object -ExpandProperty Name | ConvertTo-Json } catch { '[]' }"
        )
        try:
            raw = json.loads(adm_out.strip() or "[]")
            if isinstance(raw, str):
                raw = [raw]
            for entry in raw or []:
                admin_names.add(str(entry).split("\\")[-1].lower())
        except Exception:
            pass

        # All local accounts
        users: list[dict] = []
        ps_out = self._run_ps(
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon,"
            "PasswordLastSet,Description | ConvertTo-Json"
        )
        try:
            accts = json.loads(ps_out.strip() or "[]")
            if isinstance(accts, dict):
                accts = [accts]
            for a in accts or []:
                name      = a.get("Name", "")
                name_low  = name.lower()
                last_login = None
                try:
                    # PowerShell serialises DateTime as "/Date(ms)/"
                    ll = str(a.get("LastLogon") or "")
                    m  = re.search(r"/Date\((-?\d+)\)", ll)
                    if m:
                        last_login = int(m.group(1)) // 1000
                except Exception:
                    pass
                sess = sessions.get(name_low)
                users.append({
                    "name":       name,
                    "uid":        None,   # no UID concept on Windows
                    "gid":        None,
                    "shell":      None,
                    "home":       f"C:\\Users\\{name}",
                    "last_login": last_login or (int(sess.started) if sess else None),
                    "admin":      name_low in admin_names,
                    "locked":     not bool(a.get("Enabled", True)),
                })
        except Exception as exc:
            log.debug("users PS parse: %s", exc)
            # Fallback: net user
            out = self._run(["net", "user"])
            for line in out.splitlines():
                line = line.strip()
                if (not line or line.startswith("-") or
                        "User accounts" in line or
                        "command completed" in line.lower()):
                    continue
                for token in line.split():
                    name_low = token.lower()
                    users.append({
                        "name": token, "uid": None, "gid": None,
                        "shell": None, "home": f"C:\\Users\\{token}",
                        "last_login": None,
                        "admin": name_low in admin_names,
                        "locked": None,
                    })

        return users


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
