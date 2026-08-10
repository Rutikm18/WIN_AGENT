"""
agent/os/macos/collectors/system.py — System state collectors (2 min interval).

  battery    — Charge %, cycle count, condition, power source (pmset + system_profiler -json)
  openfiles  — Top 60 processes by open FD count (psutil; lsof fallback)
  services   — Running launchd daemons/agents (launchctl list -j)
  users      — Local accounts, admins, active sessions (dscl, who, last)
  hardware   — USB, Thunderbolt, Bluetooth, GPU, Apple Silicon chip info
               (system_profiler -json SPUSBDataType etc.)
  containers — Docker / Podman running containers (docker ps --format json)
"""
from __future__ import annotations

import json
import re

from .base import BaseCollector, CollectorResult, _run, _run_json, _sp_json

try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _psutil = None       # type: ignore[assignment]
    _HAS_PSUTIL = False


class BatteryCollector(BaseCollector):
    name = "battery"

    def collect(self) -> dict:
        result: dict = {
            "present":      False,
            "charging":     None,
            "charge_pct":   None,
            "cycle_count":  None,
            "condition":    None,
            "capacity_mah": None,
            "design_mah":   None,
            "voltage_mv":   None,
        }

        # psutil fast path
        if _HAS_PSUTIL:
            bat = _psutil.sensors_battery()
            if bat:
                result["present"]    = True
                result["charge_pct"] = round(bat.percent, 1)
                result["charging"]   = bat.power_plugged

        # system_profiler JSON for cycle count, condition, capacity
        sp = _sp_json("SPPowerDataType", timeout=20)
        if sp:
            for section in sp.get("SPPowerDataType", []):
                bat_info = section.get("sppower_battery_model_info", {})
                health   = section.get("sppower_battery_health_info", {})
                charge   = section.get("sppower_battery_charge_info", {})

                if bat_info or health:
                    result["present"] = True

                cycles = bat_info.get("sppower_battery_cycle_count") or \
                         health.get("sppower_battery_cycle_count")
                if cycles is not None:
                    try:
                        result["cycle_count"] = int(cycles)
                    except (ValueError, TypeError):
                        pass

                cond = health.get("sppower_battery_health")
                if cond:
                    result["condition"] = cond

                cap = bat_info.get("sppower_battery_capacity_mah")
                if cap:
                    try:
                        result["capacity_mah"] = int(str(cap).replace(",", ""))
                    except (ValueError, TypeError):
                        pass

                if not result["charging"] and charge:
                    src = charge.get("sppower_battery_power_source_state")
                    if src:
                        result["charging"] = (src != "Battery Power")

                pct = charge.get("sppower_battery_remaining_capacity_percent")
                if pct and result["charge_pct"] is None:
                    try:
                        result["charge_pct"] = float(str(pct).rstrip("%"))
                    except (ValueError, TypeError):
                        pass

        return result


class OpenFilesCollector(BaseCollector):
    name = "openfiles"

    def collect(self) -> list:
        if _HAS_PSUTIL:
            rows = []
            try:
                for p in _psutil.process_iter(["pid", "name", "open_files"]):
                    try:
                        fds = len(p.info.get("open_files") or [])
                        if fds > 0:
                            rows.append({
                                "pid":     p.info["pid"],
                                "process": p.info["name"] or "",
                                "fd_count": fds,
                            })
                    except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                        pass
            except Exception:
                pass
            return sorted(rows, key=lambda r: r["fd_count"], reverse=True)[:60]

        # lsof fallback
        out    = _run(["lsof"], timeout=30)
        counts: dict[str, int] = {}
        names:  dict[str, str] = {}
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) >= 2:
                key = parts[1]   # pid
                counts[key] = counts.get(key, 0) + 1
                names[key]  = parts[0]
        return [
            {"pid": int(k), "process": names.get(k, ""), "fd_count": v}
            for k, v in sorted(counts.items(), key=lambda x: -x[1])[:60]
        ]


class ServicesCollector(BaseCollector):
    name = "services"

    def collect(self) -> list:
        rows: list[dict] = []

        # launchctl list outputs tab-delimited: pid status label
        out = _run(["launchctl", "list"])
        for line in out.splitlines()[1:]:   # skip header
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pid_str, status_str, label = parts[0], parts[1], parts[2]
            try:
                pid = int(pid_str)
            except ValueError:
                pid = None
            try:
                exit_code = int(status_str)
            except ValueError:
                exit_code = None
            rows.append({
                "name":     label,
                "status":   "running" if pid is not None else "stopped",
                "enabled":  True,
                "pid":      pid,
                "type":     "launchd",
                "description": None,
            })

        return rows


class UsersCollector(BaseCollector):
    name = "users"

    def collect(self) -> list:
        rows: list[dict] = []

        # All local accounts via dscl
        all_users = [
            u.strip() for u in
            _run(["dscl", ".", "list", "/Users"]).splitlines()
            if u.strip() and not u.strip().startswith("_")
        ]

        # Admin group members
        admin_raw = _run(["dscl", ".", "read", "/Groups/admin", "GroupMembership"])
        admins: set[str] = set()
        for line in admin_raw.splitlines():
            for tok in line.replace("GroupMembership:", "").split():
                admins.add(tok.strip())

        # Last logins
        last_raw = _run(["last", "-20"])
        last_login: dict[str, int] = {}
        for line in last_raw.splitlines():
            parts = line.split()
            if parts and parts[0] not in ("wtmp", "reboot"):
                last_login.setdefault(parts[0], 0)

        for user in all_users:
            uid_raw  = _run(["dscl", ".", "read", f"/Users/{user}", "UniqueID"])
            gid_raw  = _run(["dscl", ".", "read", f"/Users/{user}", "PrimaryGroupID"])
            home_raw = _run(["dscl", ".", "read", f"/Users/{user}", "NFSHomeDirectory"])

            uid = gid = None
            home = None
            for line in uid_raw.splitlines():
                m = re.search(r"UniqueID:\s*(\d+)", line)
                if m:
                    uid = int(m.group(1))
            for line in gid_raw.splitlines():
                m = re.search(r"PrimaryGroupID:\s*(\d+)", line)
                if m:
                    gid = int(m.group(1))
            for line in home_raw.splitlines():
                m = re.search(r"NFSHomeDirectory:\s*(\S+)", line)
                if m:
                    home = m.group(1)

            rows.append({
                "name":       user,
                "uid":        uid,
                "gid":        gid,
                "admin":      user in admins,
                "locked":     False,
                "home":       home,
                "last_login": last_login.get(user),
            })

        return rows


class HardwareCollector(BaseCollector):
    name = "hardware"

    def collect(self) -> list:
        rows: list[dict] = []
        rows.extend(self._from_sp("SPUSBDataType",         "usb"))
        rows.extend(self._from_sp("SPBluetoothDataType",   "bluetooth"))
        rows.extend(self._from_sp("SPThunderboltDataType", "thunderbolt"))
        rows.extend(self._from_sp("SPDisplaysDataType",    "gpu"))
        rows.extend(self._chip_info())
        return rows

    def _from_sp(self, data_type: str, bus: str) -> list:
        sp = _sp_json(data_type, timeout=25)
        if not sp:
            return []
        items = []
        for top in sp.get(data_type, []):
            # USB has nested _items
            for dev in top.get("_items", [top]):
                name = dev.get("_name") or dev.get("device_name") or ""
                if not name:
                    continue
                items.append({
                    "bus":        bus,
                    "name":       name,
                    "vendor":     dev.get("manufacturer") or dev.get("vendor_name"),
                    "product_id": dev.get("product_id"),
                    "vendor_id":  dev.get("vendor_id"),
                    "serial":     dev.get("serial_num"),
                    "revision":   dev.get("bcd_device") or dev.get("version"),
                })
        return items

    def _chip_info(self) -> list:
        sp = _sp_json("SPHardwareDataType", timeout=15)
        if not sp:
            return []
        rows = []
        for hw in sp.get("SPHardwareDataType", []):
            chip = hw.get("chip_type") or hw.get("cpu_type") or ""
            rows.append({
                "bus":        "soc",
                "name":       chip,
                "vendor":     "Apple",
                "product_id": hw.get("machine_model"),
                "vendor_id":  None,
                "serial":     hw.get("serial_number"),
                "revision":   hw.get("os_loader_version"),
            })
        return rows


class ContainersCollector(BaseCollector):
    name = "containers"

    def collect(self) -> list:
        rows: list[dict] = []
        rows.extend(self._docker())
        rows.extend(self._podman())
        return rows

    def _docker(self) -> list:
        out = _run([
            "docker", "ps", "-a",
            "--format", '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}",'
                        '"status":"{{.Status}}","ports":"{{.Ports}}","created":"{{.CreatedAt}}"}',
        ])
        rows = []
        for line in out.splitlines():
            try:
                d = json.loads(line)
                rows.append({
                    "id":         d.get("id"),
                    "name":       d.get("name"),
                    "image":      d.get("image"),
                    "status":     d.get("status"),
                    "runtime":    "docker",
                    "ports":      d.get("ports"),
                    "created_at": d.get("created"),
                })
            except (json.JSONDecodeError, KeyError):
                pass
        return rows

    def _podman(self) -> list:
        raw = _run_json(["podman", "ps", "-a", "--format", "json"])
        if not isinstance(raw, list):
            return []
        rows = []
        for c in raw:
            rows.append({
                "id":         c.get("Id") or c.get("ID"),
                "name":       (c.get("Names") or [""])[0],
                "image":      c.get("Image"),
                "status":     c.get("State"),
                "runtime":    "podman",
                "ports":      str(c.get("Ports") or ""),
                "created_at": c.get("Created"),
            })
        return rows
