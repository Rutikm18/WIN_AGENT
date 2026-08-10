"""
agent/os/macos/collectors/inventory.py — Software inventory collectors.

  storage   — Disk volumes: capacity, used, free (psutil; df fallback)  10 min
  tasks     — crontab entries + launchd recurring timers                  10 min
  apps      — Installed .app bundles (/Applications, ~/Applications)      24 hr
  packages  — brew, pip3, npm, gem, cargo                                 24 hr
  binaries  — SHA-256 of executables in key PATH directories              24 hr
  sbom      — Full software bill of materials (pip, brew, npm, gem)       24 hr
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time

from .base import BaseCollector, CollectorResult, _run, _run_json, _sp_json

try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _psutil = None       # type: ignore[assignment]
    _HAS_PSUTIL = False


class StorageCollector(BaseCollector):
    name = "storage"

    def collect(self) -> list:
        if _HAS_PSUTIL:
            rows = []
            for part in _psutil.disk_partitions(all=False):
                try:
                    usage = _psutil.disk_usage(part.mountpoint)
                    rows.append({
                        "device":     part.device,
                        "mountpoint": part.mountpoint,
                        "fstype":     part.fstype,
                        "total_gb":   round(usage.total / (1024 ** 3), 2),
                        "used_gb":    round(usage.used  / (1024 ** 3), 2),
                        "free_gb":    round(usage.free  / (1024 ** 3), 2),
                        "pct":        usage.percent,
                    })
                except (PermissionError, OSError):
                    rows.append({
                        "device":     part.device,
                        "mountpoint": part.mountpoint,
                        "fstype":     part.fstype,
                        "total_gb":   None, "used_gb": None,
                        "free_gb":    None, "pct":    None,
                    })
            return rows

        # df -H fallback
        out  = _run(["df", "-H", "-x", "devfs"])
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split(None, 8)
            if len(parts) >= 9:
                def _gb(s: str):
                    s = s.rstrip("BKMGTPE")
                    try:
                        return float(s)
                    except ValueError:
                        return None
                rows.append({
                    "device":     parts[0],
                    "fstype":     None,
                    "total_gb":   _gb(parts[1]),
                    "used_gb":    _gb(parts[2]),
                    "free_gb":    _gb(parts[3]),
                    "pct":        float(parts[4].rstrip("%")) if parts[4].rstrip("%").isdigit() else None,
                    "mountpoint": parts[8],
                })
        return rows


class TasksCollector(BaseCollector):
    name = "tasks"

    def collect(self) -> list:
        rows: list[dict] = []
        rows.extend(self._crontabs())
        rows.extend(self._launchd_timers())
        return rows

    def _crontabs(self) -> list:
        rows = []
        for src, cmd in [
            ("root",  ["crontab", "-l"]),
            ("user",  ["crontab", "-l", "-u", os.environ.get("USER", "")]),
            ("etc",   ["cat", "/etc/crontab"]),
        ]:
            out = _run(cmd)
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 5)
                if len(parts) >= 6:
                    schedule = " ".join(parts[:5])
                    command  = parts[5]
                    rows.append({
                        "name":     command[:80],
                        "type":     "cron",
                        "schedule": schedule,
                        "command":  command,
                        "user":     src,
                        "enabled":  True,
                        "last_run": None,
                        "next_run": None,
                    })
        return rows

    def _launchd_timers(self) -> list:
        rows = []
        search_dirs = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ]
        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            for fname in os.listdir(d):
                if not fname.endswith(".plist"):
                    continue
                path = os.path.join(d, fname)
                try:
                    raw = _run(["plutil", "-convert", "json", "-o", "-", path])
                    obj = json.loads(raw)
                except Exception:
                    continue
                if "StartCalendarInterval" not in obj and "StartInterval" not in obj:
                    continue
                prog = obj.get("Program") or (obj.get("ProgramArguments") or [""])[0]
                rows.append({
                    "name":     obj.get("Label", fname),
                    "type":     "launchd",
                    "schedule": str(obj.get("StartCalendarInterval") or
                                   obj.get("StartInterval") or ""),
                    "command":  prog,
                    "user":     obj.get("UserName", "root"),
                    "enabled":  not obj.get("Disabled", False),
                    "last_run": None,
                    "next_run": None,
                })
        return rows


class AppsCollector(BaseCollector):
    name = "apps"

    _APP_DIRS = [
        "/Applications",
        "/System/Applications",
        os.path.expanduser("~/Applications"),
    ]

    def collect(self) -> list:
        rows = []
        seen: set[str] = set()
        for app_dir in self._APP_DIRS:
            if not os.path.isdir(app_dir):
                continue
            for fname in os.listdir(app_dir):
                if not fname.endswith(".app"):
                    continue
                path = os.path.join(app_dir, fname)
                if path in seen:
                    continue
                seen.add(path)
                rows.append(self._app_info(path))
        return [r for r in rows if r.get("name")]

    def _app_info(self, path: str) -> dict:
        name    = os.path.basename(path)[:-4]   # strip .app
        plist_p = os.path.join(path, "Contents", "Info.plist")
        version = bundle_id = vendor = None
        signed = notarized = None
        installed_at = None

        # Info.plist
        try:
            raw = _run(["plutil", "-convert", "json", "-o", "-", plist_p])
            obj = json.loads(raw)
            version   = obj.get("CFBundleShortVersionString") or obj.get("CFBundleVersion")
            bundle_id = obj.get("CFBundleIdentifier")
            vendor    = obj.get("NSHumanReadableCopyright") or obj.get("CFBundleGetInfoString")
        except Exception:
            pass

        # codesign
        cs = _run(["codesign", "-dvv", "--", path], timeout=8)
        signed = bool(cs and "Identifier=" in cs)
        notarized = "notarized" in cs.lower() or "trusted" in cs.lower()

        # Install time from filesystem
        try:
            installed_at = int(os.path.getmtime(path))
        except OSError:
            pass

        return {
            "name":         name,
            "version":      version,
            "bundle_id":    bundle_id,
            "path":         path,
            "vendor":       vendor,
            "signed":       signed,
            "notarized":    notarized,
            "installed_at": installed_at,
        }


class PackagesCollector(BaseCollector):
    name = "packages"

    def collect(self) -> list:
        rows: list[dict] = []
        rows.extend(self._brew())
        rows.extend(self._pip())
        rows.extend(self._npm())
        rows.extend(self._gem())
        rows.extend(self._cargo())
        return rows

    def _brew(self) -> list:
        raw = _run_json(["brew", "info", "--installed", "--json=v2"])
        if not isinstance(raw, dict):
            return []
        rows = []
        for f in raw.get("formulae", []):
            installed = f.get("installed") or [{}]
            ver       = installed[0].get("version") if installed else None
            rows.append({
                "manager":      "brew",
                "name":         f.get("name"),
                "version":      ver,
                "latest":       f.get("versions", {}).get("stable"),
                "outdated":     f.get("outdated", False),
                "installed_at": None,
            })
        for c in raw.get("casks", []):
            rows.append({
                "manager":      "brew-cask",
                "name":         c.get("token"),
                "version":      c.get("installed"),
                "latest":       c.get("version"),
                "outdated":     c.get("outdated", False),
                "installed_at": None,
            })
        return rows

    def _pip(self) -> list:
        raw = _run_json(["pip3", "list", "--format=json"])
        if not isinstance(raw, list):
            return []
        return [{
            "manager": "pip3", "name": p.get("name"),
            "version": p.get("version"), "latest": None, "outdated": None,
            "installed_at": None,
        } for p in raw if p.get("name")]

    def _npm(self) -> list:
        raw = _run_json(["npm", "list", "-g", "--json", "--depth=0"])
        if not isinstance(raw, dict):
            return []
        deps = raw.get("dependencies", {})
        return [{
            "manager": "npm", "name": name,
            "version": info.get("version"), "latest": None, "outdated": None,
            "installed_at": None,
        } for name, info in deps.items()]

    def _gem(self) -> list:
        out  = _run(["gem", "list", "--no-versions"])
        rows = []
        for line in out.splitlines():
            name = line.strip()
            if name:
                rows.append({
                    "manager": "gem", "name": name,
                    "version": None, "latest": None, "outdated": None,
                    "installed_at": None,
                })
        return rows

    def _cargo(self) -> list:
        raw = _run_json(["cargo", "install", "--list", "--message-format=json"])
        if not isinstance(raw, list):
            # cargo install --list has non-JSON output format; parse text
            out = _run(["cargo", "install", "--list"])
            rows = []
            for line in out.splitlines():
                m = re.match(r"^(\S+)\s+v(\S+):", line)
                if m:
                    rows.append({
                        "manager": "cargo", "name": m.group(1),
                        "version": m.group(2), "latest": None, "outdated": None,
                        "installed_at": None,
                    })
            return rows
        return [{
            "manager": "cargo", "name": item.get("name"),
            "version": item.get("version"), "latest": None, "outdated": None,
            "installed_at": None,
        } for item in raw if item.get("name")]


class BinariesCollector(BaseCollector):
    name = "binaries"

    _SCAN_DIRS = [
        "/usr/bin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/Library/Jarvis/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
    ]
    _MAX_FILES  = 500
    _HASH_BYTES = 4 * 1024 * 1024   # SHA-256 of first 4 MiB

    def collect(self) -> list:
        rows: list[dict] = []
        for d in self._SCAN_DIRS:
            if not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    if len(rows) >= self._MAX_FILES:
                        break
                    path = os.path.join(d, fname)
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    # Only executable files
                    if not (st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                        continue
                    rows.append({
                        "path":          path,
                        "name":          fname,
                        "hash_sha256":   self._sha256(path),
                        "size_bytes":    st.st_size,
                        "permissions":   oct(st.st_mode)[-4:],
                        "suid":          bool(st.st_mode & stat.S_ISUID),
                        "sgid":          bool(st.st_mode & stat.S_ISGID),
                        "world_writable": bool(st.st_mode & stat.S_IWOTH),
                    })
            except PermissionError:
                pass
        return rows

    def _sha256(self, path: str) -> str | None:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                h.update(f.read(self._HASH_BYTES))
            return h.hexdigest()
        except OSError:
            return None


class SbomCollector(BaseCollector):
    name = "sbom"

    def collect(self) -> list:
        rows: list[dict] = []
        rows.extend(self._pip())
        rows.extend(self._brew())
        rows.extend(self._npm())
        rows.extend(self._gem())
        return rows

    def _pip(self) -> list:
        raw = _run_json(["pip3", "list", "--format=json"])
        if not isinstance(raw, list):
            return []
        return [{
            "type":    "library",
            "name":    p.get("name"),
            "version": p.get("version"),
            "purl":    f"pkg:pypi/{p.get('name', '')}@{p.get('version', '')}",
            "license": None,
            "source":  "pip3",
            "cpe":     None,
        } for p in raw if p.get("name")]

    def _brew(self) -> list:
        raw = _run_json(["brew", "info", "--installed", "--json=v2"])
        if not isinstance(raw, dict):
            return []
        rows = []
        for f in raw.get("formulae", []):
            installed = (f.get("installed") or [{}])
            ver       = installed[0].get("version") if installed else None
            name      = f.get("name") or ""
            rows.append({
                "type":    "library",
                "name":    name,
                "version": ver,
                "purl":    f"pkg:brew/{name}@{ver}" if ver else f"pkg:brew/{name}",
                "license": (f.get("license") or None),
                "source":  "brew",
                "cpe":     None,
            })
        return rows

    def _npm(self) -> list:
        raw = _run_json(["npm", "list", "-g", "--json", "--depth=0"])
        if not isinstance(raw, dict):
            return []
        rows = []
        for name, info in raw.get("dependencies", {}).items():
            ver = info.get("version") or ""
            rows.append({
                "type":    "library",
                "name":    name,
                "version": ver,
                "purl":    f"pkg:npm/{name}@{ver}",
                "license": None,
                "source":  "npm",
                "cpe":     None,
            })
        return rows

    def _gem(self) -> list:
        out  = _run(["gem", "list", "--local"])
        rows = []
        for line in out.splitlines():
            m = re.match(r"^(\S+)\s+\(([^)]+)\)", line)
            if m:
                name = m.group(1)
                ver  = m.group(2).split(",")[0].strip()
                rows.append({
                    "type":    "library",
                    "name":    name,
                    "version": ver,
                    "purl":    f"pkg:gem/{name}@{ver}",
                    "license": None,
                    "source":  "gem",
                    "cpe":     None,
                })
        return rows
