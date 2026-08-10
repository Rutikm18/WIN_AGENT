"""
agent/agent/collectors/inventory.py — Software inventory collectors.

  storage  — Disk usage per volume, diskutil list (10 min)
  tasks    — Crontabs, periodic scripts, launchd timers (10 min)
  apps     — Installed .app bundles + versions (24 hr)
  packages — brew, pip, npm, gems (24 hr)
  binaries — All executables in known bin dirs (24 hr, disabled by default)
  sbom     — Full SBOM across all package managers (24 hr)
"""
from __future__ import annotations

import os

from .base import BaseCollector, CollectorResult, _run


class StorageCollector(BaseCollector):
    name = "storage"

    def collect(self) -> dict:
        return {
            "df":       _run(["df", "-h"]),
            "diskutil": _run(["diskutil", "list"]),
            "iostat":   _run(["iostat", "-d"]),
        }


class TasksCollector(BaseCollector):
    name = "tasks"

    def collect(self) -> dict:
        return {
            "crontab": _run(["crontab", "-l"]),
        }


class AppsCollector(BaseCollector):
    name = "apps"

    def collect(self) -> list:
        out = _run(["ls", "-1", "/Applications/"])
        return [{"name": a} for a in out.splitlines() if a]


class PackagesCollector(BaseCollector):
    name = "packages"

    def collect(self) -> dict:
        return {
            "brew": _run(["brew", "list", "--versions"]),
            "pip3": _run(["pip3", "list", "--format=columns"]),
            "npm":  _run(["npm", "list", "-g", "--depth=0"]),
            "gems": _run(["gem", "list"]),
        }


class BinariesCollector(BaseCollector):
    name = "binaries"

    _BIN_DIRS = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~/.cargo/bin"),
    ]

    def collect(self) -> dict:
        result: dict[str, list[str]] = {}
        for d in self._BIN_DIRS:
            if os.path.isdir(d):
                result[d] = sorted(os.listdir(d))
        return result


class SbomCollector(BaseCollector):
    name = "sbom"

    def collect(self) -> dict:
        items: list[dict] = []

        # Homebrew
        for line in _run(["brew", "list", "--versions"]).splitlines():
            parts = line.split()
            if parts:
                items.append({
                    "name": parts[0],
                    "version": parts[1] if len(parts) > 1 else "",
                    "type": "brew", "source": "Homebrew",
                })

        # pip
        for line in _run(["pip3", "list", "--format=columns"]).splitlines()[2:]:
            parts = line.split()
            if parts:
                items.append({
                    "name": parts[0],
                    "version": parts[1] if len(parts) > 1 else "",
                    "type": "pip", "source": "PyPI",
                })

        # macOS packages
        for pkg in _run(["pkgutil", "--pkgs"]).splitlines():
            ver_out = _run(["pkgutil", "--pkg-info", pkg]).split("version:")
            items.append({
                "name": pkg,
                "version": ver_out[1].strip().split("\n")[0] if len(ver_out) > 1 else "",
                "type": "macos-pkg", "source": "Apple",
            })

        return {"items": items, "total": len(items)}
