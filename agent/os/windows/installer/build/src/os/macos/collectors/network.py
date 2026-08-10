"""
agent/os/macos/collectors/network.py — Network state collectors (30 s – 2 min).

  ports    — LISTEN sockets (psutil; lsof fallback)
  network  — Interfaces, DNS, gateway, WiFi SSID/BSSID/RSSI
  arp      — ARP table (arp -a)
  mounts   — Filesystem mounts (psutil; df fallback)
"""
from __future__ import annotations

import re

import logging
import threading
from .base import BaseCollector, CollectorResult, _run, _run_json

log = logging.getLogger(__name__)

# Shared with volatile.py — but imported separately, so we use a module-level lock here too
_NET_LOCK = threading.Lock()

try:
    import psutil as _psutil
    _HAS_PSUTIL = True
except ImportError:
    _psutil = None       # type: ignore[assignment]
    _HAS_PSUTIL = False


class PortsCollector(BaseCollector):
    name = "ports"

    def collect(self) -> list:
        with _NET_LOCK:
            if _HAS_PSUTIL:
                return self._collect_psutil()
            return self._collect_lsof()

    def _collect_psutil(self) -> list:
        pid_name: dict[int, str] = {}
        try:
            for p in _psutil.process_iter(["pid", "name"]):
                pid_name[p.info["pid"]] = p.info["name"] or ""
        except Exception:
            pass

        rows = []
        try:
            conns = _psutil.net_connections(kind="inet")
        except Exception:
            # macOS requires elevated privileges for net_connections — use lsof
            log.debug("psutil.net_connections unavailable (permission denied?) — using lsof")
            return self._collect_lsof()

        for c in conns:
            try:
                if c.status not in ("LISTEN", "BOUND") and not (
                    c.type and c.type.name == "SOCK_DGRAM"
                ):
                    continue
                laddr = c.laddr
                if not laddr:
                    continue
                if c.family and c.family.name in ("AF_INET6",):
                    proto = "tcp6" if c.type and c.type.name == "SOCK_STREAM" else "udp6"
                else:
                    proto = "tcp" if c.type and c.type.name == "SOCK_STREAM" else "udp"
                rows.append({
                    "proto":      proto,
                    "port":       laddr.port,
                    "bind_addr":  laddr.ip or "0.0.0.0",
                    "state":      c.status or "LISTEN",
                    "pid":        c.pid,
                    "process":    pid_name.get(c.pid or -1, ""),
                })
            except Exception:
                continue
        return rows

    def _collect_lsof(self) -> list:
        out  = _run(["lsof", "-nP", "-iUDP", "-iTCP", "-sTCP:LISTEN"])
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                rows.append({"proc": parts[0], "pid": parts[1], "proto": parts[7], "addr": parts[8]})
        return rows


class NetworkCollector(BaseCollector):
    name = "network"

    def collect(self) -> dict:
        ifaces     = self._interfaces()
        dns        = self._dns_servers()
        gw         = self._default_gw()
        wifi       = self._wifi()
        hostname   = _run(["hostname", "-f"]).strip() or _run(["hostname"]).strip()
        return {
            "interfaces":  ifaces,
            "dns_servers": dns,
            "default_gw":  gw,
            "hostname":    hostname,
            "domain":      self._domain(),
            "wifi_ssid":   wifi.get("ssid"),
            "wifi_bssid":  wifi.get("bssid"),
            "wifi_rssi":   wifi.get("rssi"),
            "wifi_channel": wifi.get("channel"),
        }

    def _interfaces(self) -> list:
        if _HAS_PSUTIL:
            ifaces = []
            stats  = _psutil.net_if_stats()
            addrs  = _psutil.net_if_addrs()
            for name, stat in stats.items():
                ipv4 = ipv6 = mac = None
                for addr in addrs.get(name, []):
                    import socket
                    if addr.family == socket.AF_INET:
                        ipv4 = addr.address
                    elif addr.family == socket.AF_INET6:
                        ipv6 = addr.address.split("%")[0]   # strip scope
                    elif addr.family == _psutil.AF_LINK:
                        mac = addr.address
                ifaces.append({
                    "name":   name,
                    "mac":    mac,
                    "ipv4":   ipv4,
                    "ipv6":   ipv6,
                    "status": "up" if stat.isup else "down",
                    "mtu":    stat.mtu,
                    "speed":  stat.speed,
                })
            return ifaces

        # Fallback: parse ifconfig
        out   = _run(["ifconfig", "-a"])
        ifaces: list = []
        cur: dict | None = None
        for line in out.splitlines():
            m = re.match(r"^(\S+):", line)
            if m:
                if cur:
                    ifaces.append(cur)
                cur = {"name": m.group(1), "mac": None, "ipv4": None, "ipv6": None,
                       "status": "up" if "<UP," in line else "down", "mtu": None}
                mtu = re.search(r"mtu (\d+)", line)
                if mtu and cur:
                    cur["mtu"] = int(mtu.group(1))
            elif cur:
                if "inet " in line:
                    ip = re.search(r"inet (\S+)", line)
                    if ip:
                        cur["ipv4"] = ip.group(1)
                elif "inet6 " in line:
                    ip6 = re.search(r"inet6 (\S+)", line)
                    if ip6:
                        cur["ipv6"] = ip6.group(1).split("%")[0]
                elif "ether " in line:
                    mac = re.search(r"ether (\S+)", line)
                    if mac:
                        cur["mac"] = mac.group(1)
        if cur:
            ifaces.append(cur)
        return ifaces

    def _dns_servers(self) -> list[str]:
        out = _run(["scutil", "--dns"])
        servers: list[str] = []
        seen: set[str] = set()
        for line in out.splitlines():
            m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
            if m:
                ip = m.group(1)
                if ip not in seen:
                    seen.add(ip)
                    servers.append(ip)
        return servers

    def _default_gw(self) -> str | None:
        out = _run(["route", "-n", "get", "default"])
        m   = re.search(r"gateway:\s*(\S+)", out)
        return m.group(1) if m else None

    def _domain(self) -> str | None:
        out = _run(["scutil", "--get", "LocalHostName"])
        return out.strip() or None

    def _wifi(self) -> dict:
        # airport utility path on macOS
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework"
            "/Versions/Current/Resources/airport"
        )
        out = _run([airport, "-I"])
        info: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k = k.strip().lower()
            v = v.strip()
            if k == "ssid":
                info["ssid"] = v
            elif k == "bssid":
                info["bssid"] = v
            elif k == "agrctlrssi":
                try:
                    info["rssi"] = int(v)
                except ValueError:
                    pass
            elif k == "channel":
                info["channel"] = v
        return info


class ArpCollector(BaseCollector):
    name = "arp"

    def collect(self) -> list:
        out  = _run(["arp", "-a", "-n"])
        rows = []
        for line in out.splitlines():
            # ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
            m = re.match(
                r"\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)",
                line,
            )
            if m:
                mac = m.group(2)
                rows.append({
                    "ip":        m.group(1),
                    "mac":       None if mac in ("(incomplete)", "") else mac,
                    "interface": m.group(3),
                    "state":     "incomplete" if "(incomplete)" in line else "reachable",
                })
        return rows


class MountsCollector(BaseCollector):
    name = "mounts"

    def collect(self) -> list:
        if _HAS_PSUTIL:
            rows = []
            for p in _psutil.disk_partitions(all=False):
                rows.append({
                    "device":     p.device,
                    "mountpoint": p.mountpoint,
                    "fstype":     p.fstype,
                    "options":    p.opts,
                })
            return rows

        out  = _run(["mount"])
        rows = []
        for line in out.splitlines():
            # /dev/disk1s1 on / (apfs, local, read-only, journaled)
            m = re.match(r"^(\S+)\s+on\s+(\S+)\s+\(([^)]+)\)", line)
            if m:
                parts   = m.group(3).split(",")
                fstype  = parts[0].strip() if parts else ""
                options = ",".join(p.strip() for p in parts[1:])
                rows.append({
                    "device":     m.group(1),
                    "mountpoint": m.group(2),
                    "fstype":     fstype,
                    "options":    options,
                })
        return rows
