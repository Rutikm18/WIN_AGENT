"""
agent/os/windows/collectors/network.py — Network state collectors (30 s – 2 min).

sections: ports, network, arp, mounts

Strategy
────────
• ports   — psutil.net_connections (kernel-level, no privilege needed for own procs)
• network — psutil for interfaces + netsh for DNS/WiFi + route for gateway
• arp     — `arp -a` (identical syntax across Windows versions)
• mounts  — psutil.disk_partitions for local volumes + `net use` for network shares
"""
from __future__ import annotations

import logging
import ctypes
import ipaddress
import re
import socket

import psutil

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.network")


# ── ports ─────────────────────────────────────────────────────────────────────

class PortsCollector(WinBaseCollector):
    name    = "ports"
    timeout = 10

    def collect(self) -> list:
        ports: list[dict] = []

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
            for c in psutil.net_connections(kind="all"):
                # LISTEN for TCP; stateless for UDP (status == "")
                is_listen = (c.status == "LISTEN")
                is_udp    = (c.status == "" and c.type and "DGRAM" in str(c.type))
                if not (is_listen or is_udp):
                    continue
                if not c.laddr:
                    continue

                fam  = getattr(c, "family", None)
                kind = getattr(c, "type", None)
                if kind and "DGRAM" in str(kind):
                    proto = "udp6" if fam and "6" in str(fam) else "udp"
                else:
                    proto = "tcp6" if fam and "6" in str(fam) else "tcp"

                ports.append({
                    "proto":     proto,
                    "port":      c.laddr.port,
                    "bind_addr": c.laddr.ip or "0.0.0.0",
                    "state":     "LISTEN" if is_listen else "BOUND",
                    "pid":       c.pid,
                    "process":   pid_names.get(c.pid or 0),
                })
        except Exception as exc:
            log.debug("ports: %s", exc)

        return ports


# ── network ───────────────────────────────────────────────────────────────────

class NetworkCollector(WinBaseCollector):
    name    = "network"
    timeout = 15

    def collect(self) -> dict:
        interfaces = self._get_interfaces()
        dns_servers = self._get_dns()
        wifi_ssid, wifi_rssi = self._get_wifi()
        default_gw = self._get_gateway()
        domain = self._get_domain()

        return {
            "interfaces":  interfaces,
            "dns_servers": dns_servers,
            "default_gw":  default_gw,
            "hostname":    socket.gethostname(),
            "domain":      domain,
            "wifi_ssid":   wifi_ssid,
            "wifi_rssi":   wifi_rssi,
        }

    def _get_interfaces(self) -> list:
        ifaces: list[dict] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name, addr_list in addrs.items():
                ipv4 = ipv6 = mac = None
                for a in addr_list:
                    fam = a.family.name if hasattr(a.family, "name") else str(a.family)
                    if fam == "AF_INET":
                        ipv4 = a.address
                    elif fam == "AF_INET6":
                        # Strip zone-id suffix (e.g. %10)
                        ipv6 = a.address.split("%")[0]
                    elif fam in ("AF_LINK", "AF_PACKET", "-1"):
                        mac = a.address
                st = stats.get(name)
                ifaces.append({
                    "name":   name,
                    "mac":    mac,
                    "ipv4":   ipv4,
                    "ipv6":   ipv6,
                    "status": "up" if (st and st.isup) else "down",
                    "mtu":    st.mtu if st else None,
                })
        except Exception as exc:
            log.debug("interfaces: %s", exc)
        return ifaces

    def _get_dns(self) -> list[str]:
        dns: list[str] = []
        out = self._run(["netsh", "interface", "ip", "show", "dnsservers"])
        # Lines like: "    DNS Servers: 8.8.8.8"  or  "            8.8.4.4"
        ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
        for line in out.splitlines():
            for ip in ip_re.findall(line):
                if ip not in dns and not ip.startswith("0."):
                    dns.append(ip)
        return dns

    def _get_wifi(self) -> tuple[str | None, int | None]:
        ssid = rssi = None
        out = self._run(["netsh", "wlan", "show", "interfaces"])
        for line in out.splitlines():
            s = line.strip()
            if re.match(r"^SSID\s*:", s, re.IGNORECASE) and "BSSID" not in s.upper():
                val = s.split(":", 1)[-1].strip()
                ssid = val if val else None
            if re.match(r"^Signal\s*:", s, re.IGNORECASE):
                try:
                    pct  = int(s.split(":", 1)[-1].strip().replace("%", ""))
                    rssi = int(-100 + pct / 2)   # % → approximate dBm
                except Exception:
                    pass
        return ssid, rssi

    def _get_gateway(self) -> str | None:
        out = self._run(["route", "print", "0.0.0.0"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0":
                return parts[2]
        return None

    def _get_domain(self) -> str | None:
        out = self._run_ps("(Get-CimInstance Win32_ComputerSystem).Domain")
        d = out.strip()
        return d if d and d.lower() != "workgroup" else None


# ── arp ───────────────────────────────────────────────────────────────────────

_IF_MAX_PHYS_ADDRESS_LENGTH = 32
_NEIGHBOR_STATES = {
    0: "unreachable",
    1: "incomplete",
    2: "probe",
    3: "delay",
    4: "stale",
    5: "reachable",
    6: "permanent",
}


class _SockaddrInet(ctypes.Union):
    _fields_ = [("raw", ctypes.c_ubyte * 28), ("family", ctypes.c_ushort)]


class _ReachabilityTime(ctypes.Union):
    _fields_ = [
        ("last_reachable", ctypes.c_ulong),
        ("last_unreachable", ctypes.c_ulong),
    ]


class _MibIpNetRow2(ctypes.Structure):
    _fields_ = [
        ("address", _SockaddrInet),
        ("interface_index", ctypes.c_ulong),
        ("interface_luid", ctypes.c_ulonglong),
        ("physical_address", ctypes.c_ubyte * _IF_MAX_PHYS_ADDRESS_LENGTH),
        ("physical_address_length", ctypes.c_ulong),
        ("state", ctypes.c_int),
        ("flags", ctypes.c_ubyte),
        ("_padding", ctypes.c_ubyte * 3),
        ("reachability_time", _ReachabilityTime),
    ]


class _MibIpNetTable2(ctypes.Structure):
    _fields_ = [
        ("num_entries", ctypes.c_ulong),
        ("table", _MibIpNetRow2 * 1),
    ]


def _neighbor_address(row: _MibIpNetRow2) -> str | None:
    family = int(row.address.family)
    raw = bytes(row.address.raw)
    try:
        if family == socket.AF_INET:
            return socket.inet_ntop(socket.AF_INET, raw[4:8])
        if family == socket.AF_INET6:
            return socket.inet_ntop(socket.AF_INET6, raw[8:24])
    except OSError:
        return None
    return None


def _row_to_neighbor(row: _MibIpNetRow2) -> dict | None:
    address = _neighbor_address(row)
    if not address:
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    # GetIpNetTable2 also exposes protocol-created multicast, broadcast and
    # loopback rows.  They are not learned L2 neighbours and otherwise flood
    # ARP telemetry with entries such as 224.0.0.251 and ff02::fb.
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        return None
    physical_length = min(
        int(row.physical_address_length),
        _IF_MAX_PHYS_ADDRESS_LENGTH,
    )
    physical = bytes(row.physical_address[:physical_length])
    if not physical or physical == b"\x00" * physical_length:
        return None
    # Reject group/broadcast hardware addresses: only unicast neighbours are
    # useful to the ARP-inventory and spoofing rules.
    if physical[0] & 1:
        return None
    mac = ":".join(f"{byte:02x}" for byte in physical)
    interface_index = int(row.interface_index)
    try:
        interface = socket.if_indextoname(interface_index)
    except (AttributeError, OSError):
        interface = str(interface_index)
    return {
        "ip": address,
        "mac": mac,
        "interface": interface,
        "state": _NEIGHBOR_STATES.get(int(row.state), "unknown"),
    }


def _native_neighbors(iphlpapi: object | None = None) -> list[dict]:
    if iphlpapi is None:
        if not hasattr(ctypes, "WinDLL"):
            return []
        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    get_table = getattr(iphlpapi, "GetIpNetTable2")
    free_table = getattr(iphlpapi, "FreeMibTable")
    try:
        get_table.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_void_p)]
        get_table.restype = ctypes.c_ulong
        free_table.argtypes = [ctypes.c_void_p]
        free_table.restype = None
    except (AttributeError, TypeError):
        pass

    table_pointer = ctypes.c_void_p()
    status = int(get_table(socket.AF_UNSPEC, ctypes.byref(table_pointer)))
    if status != 0 or not table_pointer.value:
        log.debug("GetIpNetTable2 failed status=%d", status)
        return []
    try:
        header = ctypes.cast(
            table_pointer,
            ctypes.POINTER(_MibIpNetTable2),
        ).contents
        first_row = int(table_pointer.value) + _MibIpNetTable2.table.offset
        rows = ctypes.cast(first_row, ctypes.POINTER(_MibIpNetRow2))
        result: list[dict] = []
        for index in range(int(header.num_entries)):
            row = rows[index]
            parsed = _row_to_neighbor(row)
            if parsed is not None:
                result.append(parsed)
        return result
    finally:
        free_table(table_pointer)


class ArpCollector(WinBaseCollector):
    name    = "arp"
    timeout = 10

    def collect(self) -> list:
        try:
            return _native_neighbors()
        except Exception as exc:
            log.debug("GetIpNetTable2 neighbor collection failed: %s", exc)
            return []


# ── mounts ────────────────────────────────────────────────────────────────────

class MountsCollector(WinBaseCollector):
    name    = "mounts"
    timeout = 10

    def collect(self) -> list:
        mounts: list[dict] = []
        seen: set[str] = set()

        # Local volumes
        try:
            for part in psutil.disk_partitions(all=False):
                key = part.device
                if key in seen:
                    continue
                seen.add(key)
                opts = getattr(part, "opts", None)
                mounts.append({
                    "device":     part.device,
                    "mountpoint": part.mountpoint,
                    "fstype":     part.fstype or None,
                    "options":    opts,
                })
        except Exception as exc:
            log.debug("disk_partitions: %s", exc)

        # Network shares via `net use`
        out = self._run(["net", "use"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            # Look for lines with a UNC path (\\server\share)
            unc = next((p for p in parts if p.startswith("\\\\")), None)
            if not unc:
                continue
            # Drive letter is in parts[1] if pattern is "OK  Z:  \\server\share"
            drive = next((p for p in parts if re.match(r"^[A-Z]:$", p, re.I)), None)
            if unc in seen:
                continue
            seen.add(unc)
            mounts.append({
                "device":     unc,
                "mountpoint": drive,
                "fstype":     "cifs",
                "options":    None,
            })
        return mounts
