"""
agent/agent/collectors/system.py — System state collectors (2 min interval).

  battery    — Charge %, cycle count, condition, power source
  openfiles  — Top 60 processes by open file descriptor count
  services   — Running launchd daemons, plist paths, login items
  users      — Local users, admins, groups, login history
  hardware   — USB, Thunderbolt, Bluetooth
  containers — Docker / Podman: running containers and images
"""
from __future__ import annotations

from .base import BaseCollector, CollectorResult, _run


class BatteryCollector(BaseCollector):
    name = "battery"

    def collect(self) -> dict:
        return {
            "pmset":           _run(["pmset", "-g", "batt"]).strip(),
            "system_profiler": _run(["system_profiler", "SPPowerDataType"]).strip(),
        }


class OpenFilesCollector(BaseCollector):
    name = "openfiles"

    def collect(self) -> list:
        out = _run(["lsof"], timeout=30)
        counts: dict[str, int] = {}
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) >= 2:
                key = f"{parts[1]}:{parts[0]}"   # pid:proc
                counts[key] = counts.get(key, 0) + 1
        return [
            {"pid_proc": k, "count": v}
            for k, v in sorted(counts.items(), key=lambda x: -x[1])[:60]
        ]


class ServicesCollector(BaseCollector):
    name = "services"

    def collect(self) -> dict:
        return {
            "launchctl": _run(["launchctl", "list"]),
            "daemons":   _run(["ls", "/Library/LaunchDaemons/"]),
            "agents":    _run(["ls", "/Library/LaunchAgents/"]),
        }


class UsersCollector(BaseCollector):
    name = "users"

    def collect(self) -> dict:
        return {
            "users": _run(["dscl", ".", "list", "/Users"]).strip(),
            "who":   _run(["who"]).strip(),
            "last":  _run(["last", "-20"]).strip(),
        }


class HardwareCollector(BaseCollector):
    name = "hardware"

    def collect(self) -> dict:
        return {
            "usb":         _run(["system_profiler", "SPUSBDataType"],         timeout=20),
            "bluetooth":   _run(["system_profiler", "SPBluetoothDataType"],   timeout=20),
            "thunderbolt": _run(["system_profiler", "SPThunderboltDataType"], timeout=20),
        }


class ContainersCollector(BaseCollector):
    name = "containers"

    def collect(self) -> dict:
        return {
            "docker_containers": _run([
                "docker", "ps", "-a",
                "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}",
            ]),
            "docker_images": _run([
                "docker", "images",
                "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.ID}}",
            ]),
            "podman": _run(["podman", "ps", "-a"]),
        }
