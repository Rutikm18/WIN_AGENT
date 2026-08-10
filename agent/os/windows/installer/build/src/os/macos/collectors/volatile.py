"""
agent/os/macos/collectors/volatile.py — High-frequency collectors (10 s interval).

  metrics     — CPU %, RAM, swap, load average (psutil primary, sysctl fallback)
  connections — Established TCP connections (psutil; lsof fallback)
  processes   — Top 80 processes by CPU (psutil; ps fallback)
"""
from __future__ import annotations

import threading
import time

from .base import BaseCollector, CollectorResult, _run

# Shared lock so psutil/lsof calls don't race on the same socket table
_NET_LOCK = threading.Lock()

# psutil is optional but strongly recommended (ARM64 native wheel available)
try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _psutil = None       # type: ignore[assignment]
    _HAS_PSUTIL = False


class MetricsCollector(BaseCollector):
    name = "metrics"

    def collect(self) -> dict:
        if _HAS_PSUTIL:
            return self._collect_psutil()
        return self._collect_cli()

    def _collect_psutil(self) -> dict:
        cpu     = _psutil.cpu_percent(interval=1)
        mem     = _psutil.virtual_memory()
        swap    = _psutil.swap_memory()
        load    = _psutil.getloadavg()
        boot    = _psutil.boot_time()
        return {
            "cpu_pct":      cpu,
            "mem_pct":      mem.percent,
            "mem_used_mb":  mem.used // (1024 * 1024),
            "mem_total_mb": mem.total // (1024 * 1024),
            "swap_pct":     swap.percent,
            "swap_used_mb": swap.used // (1024 * 1024),
            "swap_total_mb": swap.total // (1024 * 1024),
            "load_1m":      load[0],
            "load_5m":      load[1],
            "load_15m":     load[2],
            "cpu_cores":    _psutil.cpu_count(logical=True),
            "uptime_sec":   int(time.time() - boot),
        }

    def _collect_cli(self) -> dict:
        # Two-pass top for accurate CPU
        cpu_lines = _run(["top", "-l", "2", "-n", "0"]).split("\n")
        cpu_line  = next((l for l in reversed(cpu_lines) if "CPU usage" in l), "")
        return {
            "cpu":     cpu_line.strip(),
            "load":    _run(["sysctl", "-n", "vm.loadavg"]).strip(),
            "vmstat":  _run(["vm_stat"]).strip(),
            "swap":    _run(["sysctl", "-n", "vm.swapusage"]).strip(),
        }


class ConnectionsCollector(BaseCollector):
    name = "connections"

    def collect(self) -> list:
        with _NET_LOCK:
            if _HAS_PSUTIL:
                return self._collect_psutil()
            return self._collect_lsof()

    def _collect_psutil(self) -> list:
        # Build pid→name map once
        pid_name: dict[int, str] = {}
        try:
            for p in _psutil.process_iter(["pid", "name"]):
                pid_name[p.info["pid"]] = p.info["name"] or ""
        except Exception:
            pass

        try:
            conns = _psutil.net_connections(kind="tcp")
        except Exception:
            # macOS requires elevated privileges — fall back to lsof
            return self._collect_lsof()

        rows = []
        for c in conns:
            try:
                if c.status != "ESTABLISHED":
                    continue
                if not c.raddr:
                    continue
                rows.append({
                    "proto":       "tcp",
                    "local_addr":  c.laddr.ip if c.laddr else "",
                    "local_port":  c.laddr.port if c.laddr else 0,
                    "remote_addr": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "state":       c.status,
                    "pid":         c.pid,
                    "process":     pid_name.get(c.pid or -1, ""),
                })
            except Exception:
                continue
        return rows

    def _collect_lsof(self) -> list:
        out  = _run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        rows = []
        for line in out.splitlines()[1:]:
            # Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (STATUS)
            parts = line.split()
            if len(parts) < 9:
                continue
            # NAME is col 8, strip trailing (ESTABLISHED) if present
            name = parts[8].split(" ")[0]  # drop any status suffix attached
            rows.append({"proc": parts[0], "pid": parts[1], "addr": name})
        return rows


class ProcessesCollector(BaseCollector):
    name = "processes"

    def collect(self) -> list:
        if _HAS_PSUTIL:
            return self._collect_psutil()
        return self._collect_ps()

    def _collect_psutil(self) -> list:
        attrs = ["pid", "ppid", "name", "username", "cpu_percent",
                 "memory_percent", "memory_info", "status", "create_time", "cmdline"]
        procs = []
        try:
            # Warm-up pass for accurate cpu_percent (system-wide)
            _psutil.cpu_percent(interval=None)
            for p in _psutil.process_iter(attrs):
                try:
                    i = p.info
                    mem_info = i.get("memory_info")
                    # Avoid private _common.pmem — just check for .rss attribute safely
                    rss = getattr(mem_info, "rss", 0) or 0
                    cmd = " ".join(i.get("cmdline") or []) or i.get("name") or ""
                    procs.append({
                        "pid":        i["pid"],
                        "ppid":       i.get("ppid"),
                        "name":       i.get("name") or "",
                        "user":       i.get("username") or "",
                        "cpu_pct":    round(p.cpu_percent(interval=None), 2),
                        "mem_pct":    round(i.get("memory_percent") or 0.0, 3),
                        "mem_rss_mb": rss // (1024 * 1024),
                        "status":     i.get("status") or "",
                        "started_at": int(i.get("create_time") or 0),
                        "cmdline":    cmd[:512],
                    })
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    pass
                except Exception:
                    pass
        except Exception:
            return self._collect_ps()
        return sorted(procs, key=lambda x: x["cpu_pct"], reverse=True)[:80]

    def _collect_ps(self) -> list:
        out  = _run(["ps", "-axo", "pid=,ppid=,user=,pcpu=,pmem=,rss=,stat=,lstart=,comm="])
        rows = []
        for line in out.splitlines():
            parts = line.split(None, 8)
            if len(parts) == 9:
                rows.append({
                    "pid": parts[0], "ppid": parts[1], "user": parts[2],
                    "cpu_pct": parts[3], "mem_pct": parts[4],
                    "mem_rss_mb": str(int(parts[5]) // 1024),
                    "status": parts[6], "name": parts[8],
                })
        return sorted(rows,
                      key=lambda r: float(r["cpu_pct"]) if r["cpu_pct"].replace(".", "").isdigit() else 0,
                      reverse=True)[:80]
