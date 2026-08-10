"""
agent/agent/collectors/network.py — Network state collectors.

  ports   — All TCP LISTEN + UDP sockets (30 s)
  network — Interface IPs, MACs, DNS, WiFi SSID, routes (2 min)
  arp     — ARP table — hosts visible on the local segment (2 min)
  mounts  — Active filesystem mounts (2 min)
"""
from __future__ import annotations

from .base import BaseCollector, CollectorResult, _run


class PortsCollector(BaseCollector):
    name = "ports"

    def collect(self) -> list:
        rows = []
        # TCP LISTEN
        for line in _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).splitlines()[1:]:
            parts = line.split(None, 8)
            if len(parts) >= 9:
                rows.append({"proc": parts[0], "pid": parts[1],
                             "proto": "TCP", "addr": parts[-1]})
        # UDP (all)
        for line in _run(["lsof", "-nP", "-iUDP"]).splitlines()[1:]:
            parts = line.split(None, 8)
            if len(parts) >= 9:
                rows.append({"proc": parts[0], "pid": parts[1],
                             "proto": "UDP", "addr": parts[-1]})
        return rows


class NetworkCollector(BaseCollector):
    name = "network"

    def collect(self) -> dict:
        return {
            "ifconfig": _run(["ifconfig"]),
            "dns":      _run(["scutil", "--dns"]),
            "proxy":    _run(["scutil", "--proxy"]),
            "routes":   _run(["netstat", "-rn"]),
        }


class ArpCollector(BaseCollector):
    name = "arp"

    def collect(self) -> list:
        rows = []
        for line in _run(["arp", "-a"]).splitlines():
            parts = line.split()
            if len(parts) >= 4:
                rows.append({"host": parts[0], "ip": parts[1], "mac": parts[3]})
        return rows


class MountsCollector(BaseCollector):
    name = "mounts"

    def collect(self) -> list:
        rows = []
        for line in _run(["mount"]).splitlines():
            parts = line.split()
            if len(parts) >= 3 and not line.startswith(("devfs", "map ")):
                rows.append({
                    "device":     parts[0],
                    "mountpoint": parts[2],
                    "type":       parts[4] if len(parts) > 4 else "",
                })
        return rows
