"""
agent/os/windows/collectors/volatile.py — High-frequency collectors (10 s).

sections: metrics, connections, processes

Uses psutil throughout — it is fully supported on Windows and avoids the
brittle wmic/PowerShell path for hot-loop data.

Windows enrichments beyond the shared macOS baseline
────────────────────────────────────────────────────
• metrics.cpu_per_core   — per-logical-core utilisation (list[float])
• connections.direction  — inbound/outbound/listen derived from the live
                           listening-port set; connections.service — well-known
                           service name for the local port
• processes.signed        — Authenticode trust state (signed/unsigned/invalid)
                           via WinVerifyTrust, bounded-cached by (path, mtime, size)
"""
from __future__ import annotations

import logging
import os
import sys
import time

import psutil

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.volatile")


# Well-known local-port → service name map (mirrors the macOS agent's table).
_PORT_SERVICES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 464: "kpasswd", 465: "smtps",
    514: "syslog", 587: "submission", 593: "rpc-http", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3268: "ldap-gc", 3269: "ldap-gc-ssl", 3306: "mysql", 3389: "rdp",
    5060: "sip", 5432: "postgresql", 5555: "adb", 5601: "kibana",
    5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9000: "sonarqube", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


# ── metrics ───────────────────────────────────────────────────────────────────

class MetricsCollector(WinBaseCollector):
    name    = "metrics"
    timeout = 5

    def collect(self) -> dict:
        try:
            # One sampling window yields both aggregate and per-core figures.
            per_core = psutil.cpu_percent(interval=1, percpu=True) or []
            cpu = round(sum(per_core) / len(per_core), 2) if per_core \
                else float(psutil.cpu_percent(interval=None))
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
            "cpu_per_core":  [round(float(c), 2) for c in per_core],
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

    def __init__(self, event_provider=None) -> None:
        if event_provider is None:
            from agent.os.windows.etw.dns_provider import DnsEtwProvider
            event_provider = DnsEtwProvider()
        self._event_provider = event_provider

    def start_stream(self) -> bool:
        return bool(self._event_provider.start())

    def stop_stream(self) -> None:
        self._event_provider.stop()

    def health_snapshot(self) -> dict:
        return {"dns_etw": self._event_provider.health_snapshot()}

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
            sockets = psutil.net_connections(kind="inet")
        except Exception as exc:
            log.debug("connections: %s", exc)
            sockets = []

        # First pass: collect the local ports we are LISTENing on so that an
        # ESTABLISHED connection can be labelled inbound (we are the server) vs
        # outbound (we initiated it).
        listen_ports: set[int] = set()
        for c in sockets:
            if c.status == psutil.CONN_LISTEN and c.laddr:
                listen_ports.add(c.laddr.port)

        for c in sockets:
            try:
                is_tcp = (c.type == 1)  # SOCK_STREAM
                status = c.status or ""
                if is_tcp:
                    if status not in ("ESTABLISHED", psutil.CONN_LISTEN):
                        continue
                # UDP sockets are stateless (status == "" / NONE) — keep bound ones.
                if not c.laddr:
                    continue

                fam   = getattr(c, "family", None)
                is_v6 = fam is not None and "6" in str(fam)
                if is_tcp:
                    proto = "tcp6" if is_v6 else "tcp"
                else:
                    proto = "udp6" if is_v6 else "udp"

                if status == psutil.CONN_LISTEN:
                    direction = "listen"
                elif is_tcp and status == "ESTABLISHED":
                    direction = "inbound" if c.laddr.port in listen_ports else "outbound"
                else:
                    direction = None  # UDP — no connection direction

                conns.append({
                    "proto":       proto,
                    "local_addr":  c.laddr.ip   if c.laddr else "",
                    "local_port":  c.laddr.port if c.laddr else 0,
                    "remote_addr": c.raddr.ip   if c.raddr else None,
                    "remote_port": c.raddr.port if c.raddr else None,
                    "state":       status or "NONE",
                    "direction":   direction,
                    "service":     _PORT_SERVICES.get(c.laddr.port if c.laddr else -1),
                    "pid":         c.pid,
                    "process":     pid_names.get(c.pid or 0),
                })
            except Exception:
                continue

        for event in self._event_provider.drain(256):
            pid = event.get("pid")
            process = pid_names.get(pid or 0)
            if not process and pid:
                try:
                    process = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
            dns_server = event.get("dns_server")
            # A server list may contain multiple addresses; retain it in _win
            # and use only an unambiguous single address canonically.
            remote = dns_server if dns_server and ";" not in dns_server else None
            conns.append({
                "proto": "dns",
                "local_addr": "",
                "local_port": 0,
                "remote_addr": remote,
                "remote_port": 53 if remote else None,
                "state": str(event.get("event") or "query").upper(),
                "direction": "outbound",
                "service": "dns",
                "pid": pid,
                "process": process,
                "_win": {
                    "source": "etw",
                    "event_id": event.get("event_id"),
                    "event_at": event.get("timestamp"),
                    "query_name": event.get("query_name"),
                    "query_type": event.get("query_type"),
                    "query_status": event.get("status"),
                    "query_results": event.get("results"),
                    "dns_server": dns_server,
                    "interface": event.get("interface"),
                    "interface_index": event.get("interface_index"),
                },
            })

        return conns


# ── processes ─────────────────────────────────────────────────────────────────

class ProcessesCollector(WinBaseCollector):
    name    = "processes"
    timeout = 15

    _ATTRS = [
        "pid", "ppid", "name", "username",
        "cpu_percent", "memory_percent", "memory_info",
        "status", "create_time", "cmdline", "exe",
    ]

    def __init__(self, event_provider=None) -> None:
        if event_provider is None:
            from agent.os.windows.etw.process_provider import ProcessEtwProvider
            event_provider = ProcessEtwProvider()
        self._event_provider = event_provider

    def start_stream(self) -> bool:
        return bool(self._event_provider.start())

    def stop_stream(self) -> None:
        self._event_provider.stop()

    def health_snapshot(self) -> dict:
        return {"etw": self._event_provider.health_snapshot()}

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
                        "_exe":       info.get("exe"),   # internal — dropped after signing
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            log.debug("processes: %s", exc)

        # Top 80 by CPU descending
        procs.sort(key=lambda x: x["cpu_pct"], reverse=True)
        top = procs[:80]

        # Authenticode signature only for the top slice we actually emit — the
        # check is bounded-cached, so steady-state cost is a dict lookup.
        for row in top:
            row["signed"] = _authenticode_status(row.pop("_exe", None))

        # Preserve the periodic snapshot while adding start/stop events for
        # processes that may exist for less than one collection interval.
        for event in self._event_provider.drain(128):
            pid = event.get("pid")
            if pid is None:
                continue
            image_path = event.get("image_path")
            name = event.get("name") or ""
            user = cmdline = None
            if event.get("event") == "start":
                try:
                    process = psutil.Process(pid)
                    image_path = process.exe() or image_path
                    name = process.name() or name
                    user = process.username()
                    cmdline = " ".join(process.cmdline())[:512] or None
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
            top.append({
                "pid": pid,
                "ppid": event.get("ppid"),
                "name": name,
                "user": user,
                "cpu_pct": 0.0,
                "mem_pct": 0.0,
                "mem_rss_mb": None,
                "status": "running" if event.get("event") == "start" else "stopped",
                "started_at": event.get("started_at"),
                "cmdline": cmdline,
                "signed": _authenticode_status(image_path),
                "_win": {
                    "source": "etw",
                    "event": event.get("event"),
                    "event_at": event.get("event_at"),
                    "image_path": image_path,
                    "integrity_level": event.get("integrity_level"),
                    "elevated": event.get("elevated"),
                    "sequence": event.get("sequence"),
                    "session_id": event.get("session_id"),
                    "exit_code": event.get("exit_code"),
                },
            })

        return top


# ── Authenticode signature verification (WinVerifyTrust) ──────────────────────
#
# Returns "signed" (trusted), "unsigned" (no embedded signature), "invalid"
# (present but not trusted — expired/revoked/tampered), or None (unknown / not
# on Windows / path inaccessible). Results are cached by (path, mtime, size) so a
# stable binary is verified once. Never raises.

_SIG_CACHE: dict[tuple, "str | None"] = {}
_SIG_CACHE_MAX = 8192

# Lazily-initialised WinVerifyTrust binding; None once we know it is unavailable.
_wintrust = None
_wintrust_ready = False


def _authenticode_status(exe: "str | None") -> "str | None":
    if not exe or sys.platform != "win32":
        return None
    try:
        st = os.stat(exe)
        key = (exe, int(st.st_mtime), st.st_size)
    except OSError:
        return None

    cached = _SIG_CACHE.get(key)
    if cached is not None or key in _SIG_CACHE:
        return cached

    result = _verify_trust(exe)

    if len(_SIG_CACHE) >= _SIG_CACHE_MAX:
        _SIG_CACHE.clear()   # simple bounded reset — signatures are cheap to recompute
    _SIG_CACHE[key] = result
    return result


def _init_wintrust():
    """Build the ctypes WinVerifyTrust binding once. Sets globals; never raises."""
    global _wintrust, _wintrust_ready
    _wintrust_ready = True
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes, POINTER, Structure, c_void_p

        class GUID(Structure):
            _fields_ = [("Data1", wintypes.DWORD),
                        ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD),
                        ("Data4", ctypes.c_ubyte * 8)]

        class WINTRUST_FILE_INFO(Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hFile", wintypes.HANDLE),
                        ("pgKnownSubject", c_void_p)]

        class WINTRUST_DATA(Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("pPolicyCallbackData", c_void_p),
                        ("pSIPClientData", c_void_p),
                        ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD),
                        ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", POINTER(WINTRUST_FILE_INFO)),
                        ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE),
                        ("pwszURLReference", wintypes.LPWSTR),
                        ("dwProvFlags", wintypes.DWORD),
                        ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", c_void_p)]

        # {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        guid = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

        wintrust_dll = ctypes.WinDLL("wintrust")
        fn = wintrust_dll.WinVerifyTrust
        fn.restype = ctypes.c_long

        _wintrust = {
            "ctypes": ctypes, "GUID": guid,
            "WINTRUST_FILE_INFO": WINTRUST_FILE_INFO,
            "WINTRUST_DATA": WINTRUST_DATA,
            "fn": fn, "byref": ctypes.byref, "sizeof": ctypes.sizeof,
        }
    except Exception as exc:  # pragma: no cover — platform/loader specific
        log.debug("WinVerifyTrust unavailable: %s", exc)
        _wintrust = None


def _verify_trust(exe: str) -> "str | None":
    if not _wintrust_ready:
        _init_wintrust()
    w = _wintrust
    if not w:
        return None
    try:
        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_STATEACTION_VERIFY = 1
        WTD_STATEACTION_CLOSE = 2
        WTD_SAFER_FLAG = 0x100
        TRUST_E_NOSIGNATURE = -2146762496          # 0x800B0100
        TRUST_E_SUBJECT_FORM_UNKNOWN = -2146762477  # 0x800B0003

        file_info = w["WINTRUST_FILE_INFO"]()
        file_info.cbStruct = w["sizeof"](file_info)
        file_info.pcwszFilePath = exe
        file_info.hFile = None
        file_info.pgKnownSubject = None

        data = w["WINTRUST_DATA"]()
        data.cbStruct = w["sizeof"](data)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.dwProvFlags = WTD_SAFER_FLAG
        data.pFile = w["ctypes"].pointer(file_info)

        ret = w["fn"](None, w["byref"](w["GUID"]), w["byref"](data))

        # Always release the state data we asked WinVerifyTrust to allocate.
        try:
            data.dwStateAction = WTD_STATEACTION_CLOSE
            w["fn"](None, w["byref"](w["GUID"]), w["byref"](data))
        except Exception:
            pass

        if ret == 0:
            return "signed"
        if ret in (TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN):
            return "unsigned"
        return "invalid"
    except Exception as exc:
        log.debug("signature check failed for %s: %s", exe, exc)
        return None
