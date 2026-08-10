"""
agent/os/windows/collectors/volatile.py — High-frequency collectors (10 s).

sections: metrics, connections, processes

Uses psutil throughout — it is fully supported on Windows and avoids the
brittle wmic/PowerShell path for hot-loop data.
"""
from __future__ import annotations

import logging
import time

import psutil

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.volatile")


# ── metrics ───────────────────────────────────────────────────────────────────

class MetricsCollector(WinBaseCollector):
    name    = "metrics"
    timeout = 5

    def collect(self) -> dict:
        try:
            cpu     = psutil.cpu_percent(interval=1)
            mem     = psutil.virtual_memory()
            swap    = psutil.swap_memory()
            boot_ts = psutil.boot_time()
        except Exception as exc:
            log.warning("metrics baseline failed: %s", exc)
            return {"cpu_pct": 0.0, "mem_pct": 0.0, "mem_used_mb": 0, "mem_total_mb": 0}

        disk_read = disk_write = net_recv = net_sent = None
        try:
            di = psutil.disk_io_counters()
            if di:
                disk_read  = di.read_bytes  // 1024
                disk_write = di.write_bytes // 1024
        except Exception:
            pass
        try:
            ni = psutil.net_io_counters()
            if ni:
                net_recv = ni.bytes_recv // 1024
                net_sent = ni.bytes_sent // 1024
        except Exception:
            pass

        return {
            "cpu_pct":       round(float(cpu), 2),
            "cpu_cores":     psutil.cpu_count(logical=True),
            "mem_pct":       round(mem.percent, 2),
            "mem_used_mb":   mem.used    // (1024 * 1024),
            "mem_total_mb":  mem.total   // (1024 * 1024),
            "swap_pct":      round(swap.percent, 2) if swap.total else None,
            "swap_used_mb":  swap.used  // (1024 * 1024) if swap.total else None,
            "swap_total_mb": swap.total // (1024 * 1024) if swap.total else None,
            # Windows has no UNIX load average — field is optional (None OK)
            "load_1m":  None,
            "load_5m":  None,
            "load_15m": None,
            "uptime_sec": int(time.time() - boot_ts),
            # Extra Windows counters in _raw (not canonical, manager ignores them)
            "_raw": {
                "disk_read_kb":  disk_read,
                "disk_write_kb": disk_write,
                "net_recv_kb":   net_recv,
                "net_sent_kb":   net_sent,
                "cpu_freq_mhz":  (psutil.cpu_freq().current if psutil.cpu_freq() else None),
            },
        }


# ── connections ───────────────────────────────────────────────────────────────

class ConnectionsCollector(WinBaseCollector):
    name    = "connections"
    timeout = 10

    def collect(self) -> list:
        conns: list[dict] = []

        # Build pid→name map once (avoids per-connection process lookup)
        pid_names: dict[int, str] = {}
        try:
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    pid_names[p.pid] = p.info["name"] or ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.status != "ESTABLISHED":
                    continue
                conns.append({
                    "proto":       "tcp",
                    "local_addr":  c.laddr.ip   if c.laddr else "",
                    "local_port":  c.laddr.port if c.laddr else 0,
                    "remote_addr": c.raddr.ip   if c.raddr else None,
                    "remote_port": c.raddr.port if c.raddr else None,
                    "state":       c.status,
                    "pid":         c.pid,
                    "process":     pid_names.get(c.pid or 0),
                })
        except Exception as exc:
            log.debug("connections: %s", exc)

        return conns


# ── processes ─────────────────────────────────────────────────────────────────

class ProcessesCollector(WinBaseCollector):
    name    = "processes"
    timeout = 15

    _ATTRS = [
        "pid", "ppid", "name", "username",
        "cpu_percent", "memory_percent", "memory_info",
        "status", "create_time", "cmdline",
    ]

    def collect(self) -> list:
        procs: list[dict] = []

        try:
            for p in psutil.process_iter(self._ATTRS):
                try:
                    info = p.info
                    rss  = None
                    if info.get("memory_info"):
                        rss = info["memory_info"].rss // (1024 * 1024)

                    cmdline = None
                    raw_cmd = info.get("cmdline")
                    if raw_cmd:
                        cmdline = " ".join(raw_cmd)[:512]

                    procs.append({
                        "pid":        info["pid"],
                        "ppid":       info.get("ppid"),
                        "name":       info.get("name") or "",
                        "user":       info.get("username"),
                        "cpu_pct":    round(float(info.get("cpu_percent") or 0.0), 2),
                        "mem_pct":    round(float(info.get("memory_percent") or 0.0), 4),
                        "mem_rss_mb": rss,
                        "status":     info.get("status"),
                        "started_at": int(info["create_time"]) if info.get("create_time") else None,
                        "cmdline":    cmdline,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            log.debug("processes: %s", exc)

        # Top 80 by CPU descending
        procs.sort(key=lambda x: x["cpu_pct"], reverse=True)
        return procs[:80]
