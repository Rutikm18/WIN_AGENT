"""
agent/agent/collectors/volatile.py — High-frequency collectors (10 s interval).

  metrics     — CPU %, RAM, swap, load average, I/O counters
  connections — Established TCP connections (lsof)
  processes   — Top 80 processes by CPU + RAM (ps)
"""
from __future__ import annotations

from .base import BaseCollector, CollectorResult, _run


class MetricsCollector(BaseCollector):
    name = "metrics"

    def collect(self) -> dict:
        # top -l 2 gives two snapshots; the second has accurate CPU %
        cpu_lines = _run(["top", "-l", "2", "-n", "0"]).split("\n")
        cpu = next((l for l in reversed(cpu_lines) if "CPU usage" in l), "")
        return {
            "cpu":     cpu.strip(),
            "load":    _run(["sysctl", "-n", "vm.loadavg"]).strip(),
            "vmstat":  _run(["vm_stat"]).strip(),
            "swap":    _run(["sysctl", "-n", "vm.swapusage"]).strip(),
            "iostat":  _run(["iostat", "-d", "1", "2"]).strip(),
            "netstat": _run(["netstat", "-ib"]).strip(),
        }


class ConnectionsCollector(BaseCollector):
    name = "connections"

    def collect(self) -> list:
        out = _run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        rows = []
        for line in out.splitlines()[1:]:          # skip header
            parts = line.split(None, 9)
            if len(parts) >= 9:
                rows.append({"proc": parts[0], "pid": parts[1], "addr": parts[-1]})
        return rows


class ProcessesCollector(BaseCollector):
    name = "processes"

    def collect(self) -> list:
        out = _run(["ps", "-axo", "pid=,user=,pcpu=,pmem=,rss=,comm="])
        rows = []
        for line in sorted(
            out.splitlines(),
            key=lambda l: float(l.split()[2]) if len(l.split()) > 2 else 0,
            reverse=True,
        )[:80]:
            parts = line.split(None, 5)
            if len(parts) == 6:
                rows.append({
                    "pid":  parts[0], "user": parts[1],
                    "cpu":  parts[2], "mem":  parts[3],
                    "rss":  parts[4], "cmd":  parts[5],
                })
        return rows
