"""
agent/os/macos/normalizer.py — macOS ARM64 → canonical schema normalizer.

Converts raw macOS collector output to the OS-agnostic canonical schema
(shared/schema.py). Runs on any platform — no macOS dependencies at import time.

dispatch: normalize(section, raw) → canonical dict or list
  • Unknown sections: returned unchanged
  • Wrong input type for a section: returned unchanged
  • All helpers are safe (never raise, use defaults on bad values)
"""
from __future__ import annotations

import re
from typing import Any

# ── Type-coercion helpers ─────────────────────────────────────────────────────

def _f(v: Any, default: float = 0.0) -> float:
    """Coerce to float; return default on failure."""
    if v is None:
        return default
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


def _i(v: Any, default: int = 0) -> int:
    """Coerce to int; return default on failure."""
    if v is None:
        return default
    try:
        return int(float(str(v).replace(",", "")))
    except (ValueError, TypeError):
        return default


def _f_opt(v: Any) -> float | None:
    """Coerce to float or None."""
    if v is None:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def _i_opt(v: Any) -> int | None:
    """Coerce to int or None."""
    if v is None:
        return None
    try:
        return int(float(str(v).replace(",", "")))
    except (ValueError, TypeError):
        return None


def _s_opt(v: Any) -> str | None:
    """Coerce to stripped str or None."""
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _b_opt(v: Any) -> bool | None:
    """Coerce to bool or None."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return bool(v)
    if isinstance(v, str):
        return v.lower() in ("1", "true", "yes", "on")
    return None


# ── CLI text parsers (used when collectors return raw CLI output strings) ─────

def _parse_cpu_line(line: str) -> float:
    """Parse 'CPU usage: 12.5% user, 3.1% sys, ...' → total used %"""
    m = re.search(r"(\d+\.\d+)%\s+user.*?(\d+\.\d+)%\s+sys", line)
    if m:
        return round(float(m.group(1)) + float(m.group(2)), 2)
    return 0.0


def _parse_vm_stat(text: str) -> dict:
    """Parse vm_stat output → {pages_free, pages_wired, pages_active, page_size}"""
    out: dict = {"pages_free": 0, "pages_wired": 0, "pages_active": 0, "page_size": 4096}
    for line in text.splitlines():
        m = re.search(r"Pages free:\s+(\d+)", line)
        if m:
            out["pages_free"] = int(m.group(1))
        m = re.search(r"Pages wired down:\s+(\d+)", line)
        if m:
            out["pages_wired"] = int(m.group(1))
        m = re.search(r"Pages active:\s+(\d+)", line)
        if m:
            out["pages_active"] = int(m.group(1))
        m = re.search(r"page size of (\d+) bytes", line)
        if m:
            out["page_size"] = int(m.group(1))
    return out


def _parse_loadavg(text: str) -> tuple[float | None, float | None, float | None]:
    """Parse '{ 0.45 0.62 0.71 }' → (1m, 5m, 15m)"""
    nums = re.findall(r"\d+\.\d+", text)
    if len(nums) >= 3:
        return float(nums[0]), float(nums[1]), float(nums[2])
    return None, None, None


def _parse_swap(text: str) -> dict:
    """Parse 'vm.swapusage: total = 2048.00M  used = 512.00M  free = 1536.00M'"""
    out = {"total_mb": 0, "used_mb": 0, "free_mb": 0}

    def _mb(s: str) -> int:
        m = re.match(r"([\d.]+)([KMGT]?)", s.strip())
        if not m:
            return 0
        val = float(m.group(1))
        unit = m.group(2).upper()
        mult = {"K": 1/1024, "M": 1, "G": 1024, "T": 1024*1024}.get(unit, 1)
        return int(val * mult)

    m = re.search(r"total\s*=\s*([\d.]+[KMGT]?)", text, re.I)
    if m:
        out["total_mb"] = _mb(m.group(1))
    m = re.search(r"used\s*=\s*([\d.]+[KMGT]?)", text, re.I)
    if m:
        out["used_mb"] = _mb(m.group(1))
    m = re.search(r"free\s*=\s*([\d.]+[KMGT]?)", text, re.I)
    if m:
        out["free_mb"] = _mb(m.group(1))
    return out


# ── Per-section normalizers ───────────────────────────────────────────────────

def _norm_metrics(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return raw   # pass-through malformed input

    # psutil path: already structured
    if "cpu_pct" in raw:
        total_mb = _i_opt(raw.get("mem_total_mb"))
        used_mb  = _i_opt(raw.get("mem_used_mb"))
        return {
            "cpu_pct":       _f(raw.get("cpu_pct")),
            "mem_pct":       _f(raw.get("mem_pct")),
            "mem_used_mb":   _i(raw.get("mem_used_mb")),
            "mem_total_mb":  _i(raw.get("mem_total_mb")),
            "swap_pct":      _f_opt(raw.get("swap_pct")),
            "swap_used_mb":  _i_opt(raw.get("swap_used_mb")),
            "swap_total_mb": _i_opt(raw.get("swap_total_mb")),
            "load_1m":       _f_opt(raw.get("load_1m")),
            "load_5m":       _f_opt(raw.get("load_5m")),
            "load_15m":      _f_opt(raw.get("load_15m")),
            "cpu_cores":     _i_opt(raw.get("cpu_cores")),
            "uptime_sec":    _i_opt(raw.get("uptime_sec")),
        }

    # CLI text path: parse raw strings
    cpu   = _parse_cpu_line(raw.get("cpu", ""))
    load  = _parse_loadavg(raw.get("load", ""))
    vm    = _parse_vm_stat(raw.get("vmstat", ""))
    swap  = _parse_swap(raw.get("swap", ""))
    ps    = vm["page_size"]

    total_pages  = vm["pages_wired"] + vm["pages_active"] + vm["pages_free"]
    total_mb     = (total_pages * ps) // (1024 * 1024) if total_pages > 0 else 0
    used_mb      = ((total_pages - vm["pages_free"]) * ps) // (1024 * 1024)
    mem_pct      = round(used_mb / total_mb * 100, 1) if total_mb > 0 else 0.0

    return {
        "cpu_pct":       cpu,
        "mem_pct":       mem_pct,
        "mem_used_mb":   used_mb,
        "mem_total_mb":  total_mb,
        "swap_pct":      round(swap["used_mb"] / swap["total_mb"] * 100, 1)
                         if swap["total_mb"] > 0 else None,
        "swap_used_mb":  swap["used_mb"] or None,
        "swap_total_mb": swap["total_mb"] or None,
        "load_1m":       load[0],
        "load_5m":       load[1],
        "load_15m":      load[2],
        "cpu_cores":     None,
        "uptime_sec":    None,
    }


def _norm_connections(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw

    rows = []
    for c in raw:
        if not isinstance(c, dict):
            continue
        # psutil path: already structured
        if "remote_addr" in c:
            rows.append({
                "proto":       _s_opt(c.get("proto")) or "tcp",
                "local_addr":  _s_opt(c.get("local_addr")),
                "local_port":  _i_opt(c.get("local_port")),
                "remote_addr": _s_opt(c.get("remote_addr")),
                "remote_port": _i_opt(c.get("remote_port")),
                "state":       _s_opt(c.get("state")),
                "pid":         _i_opt(c.get("pid")),
                "process":     _s_opt(c.get("process")),
            })
            continue
        # lsof text path: {"proc": "...", "pid": "...", "addr": "..."}
        addr = c.get("addr", "")
        local = remote = None
        if "->" in addr:
            local, _, remote = addr.partition("->")
        else:
            local = addr

        def _split(a: str):
            if not a:
                return None, None
            m = re.match(r"(.*):(\d+)$", a)
            if m:
                return m.group(1), int(m.group(2))
            return a, None

        lip, lport = _split(local.strip())
        rip, rport = _split(remote.strip()) if remote else (None, None)
        rows.append({
            "proto":       "tcp",
            "local_addr":  lip,
            "local_port":  lport,
            "remote_addr": rip,
            "remote_port": rport,
            "state":       "ESTABLISHED",
            "pid":         _i_opt(c.get("pid")),
            "process":     _s_opt(c.get("proc")),
        })
    return rows


def _norm_processes(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        rows.append({
            "pid":        _i_opt(p.get("pid")),
            "ppid":       _i_opt(p.get("ppid")),
            "name":       _s_opt(p.get("name") or p.get("cmd")),
            "user":       _s_opt(p.get("user")),
            "cpu_pct":    _f(p.get("cpu_pct") or p.get("cpu")),
            "mem_pct":    _f_opt(p.get("mem_pct") or p.get("mem")),
            "mem_rss_mb": _i_opt(p.get("mem_rss_mb") or p.get("rss")),
            "status":     _s_opt(p.get("status")),
            "started_at": _i_opt(p.get("started_at")),
            "cmdline":    _s_opt(p.get("cmdline")),
        })
    return rows


def _norm_ports(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        # psutil path
        if "port" in p:
            rows.append({
                "proto":     _s_opt(p.get("proto")) or "tcp",
                "port":      _i(p.get("port")),
                "bind_addr": _s_opt(p.get("bind_addr")) or "0.0.0.0",
                "state":     _s_opt(p.get("state")) or "LISTEN",
                "pid":       _i_opt(p.get("pid")),
                "process":   _s_opt(p.get("process")),
            })
            continue
        # lsof text path
        addr  = p.get("addr", "")
        m     = re.match(r"(.*):(\d+)$", addr)
        bind  = m.group(1) if m else "0.0.0.0"
        port  = int(m.group(2)) if m else 0
        proto = _s_opt(p.get("proto")) or "tcp"
        rows.append({
            "proto":     proto.lower().split("/")[0],
            "port":      port,
            "bind_addr": bind or "0.0.0.0",
            "state":     "LISTEN",
            "pid":       _i_opt(p.get("pid")),
            "process":   _s_opt(p.get("proc")),
        })
    return rows


def _norm_network(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return raw
    ifaces = raw.get("interfaces") or []
    normed_ifaces = []
    for iface in (ifaces if isinstance(ifaces, list) else []):
        if not isinstance(iface, dict):
            continue
        normed_ifaces.append({
            "name":   _s_opt(iface.get("name")),
            "mac":    _s_opt(iface.get("mac")),
            "ipv4":   _s_opt(iface.get("ipv4")),
            "ipv6":   _s_opt(iface.get("ipv6")),
            "status": _s_opt(iface.get("status")) or "unknown",
            "mtu":    _i_opt(iface.get("mtu")),
            "speed":  _i_opt(iface.get("speed")),
        })
    return {
        "interfaces":   normed_ifaces,
        "dns_servers":  raw.get("dns_servers") if isinstance(raw.get("dns_servers"), list) else [],
        "default_gw":   _s_opt(raw.get("default_gw")),
        "hostname":     _s_opt(raw.get("hostname")),
        "domain":       _s_opt(raw.get("domain")),
        "wifi_ssid":    _s_opt(raw.get("wifi_ssid")),
        "wifi_bssid":   _s_opt(raw.get("wifi_bssid")),
        "wifi_rssi":    _i_opt(raw.get("wifi_rssi")),
        "wifi_channel": _s_opt(raw.get("wifi_channel")),
    }


def _norm_arp(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for r in raw:
        if not isinstance(r, dict):
            continue
        rows.append({
            "ip":        _s_opt(r.get("ip")),
            "mac":       _s_opt(r.get("mac")),
            "interface": _s_opt(r.get("interface")),
            "state":     _s_opt(r.get("state")) or "unknown",
        })
    return rows


def _norm_mounts(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for m in raw:
        if not isinstance(m, dict):
            continue
        rows.append({
            "device":     _s_opt(m.get("device")),
            "mountpoint": _s_opt(m.get("mountpoint")),
            "fstype":     _s_opt(m.get("fstype")),
            "options":    _s_opt(m.get("options")),
        })
    return rows


def _norm_battery(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return raw
    return {
        "present":      _b_opt(raw.get("present")) if raw.get("present") is not None else False,
        "charging":     _b_opt(raw.get("charging")),
        "charge_pct":   _f_opt(raw.get("charge_pct")),
        "cycle_count":  _i_opt(raw.get("cycle_count")),
        "condition":    _s_opt(raw.get("condition")),
        "capacity_mah": _i_opt(raw.get("capacity_mah")),
        "design_mah":   _i_opt(raw.get("design_mah")),
        "voltage_mv":   _i_opt(raw.get("voltage_mv")),
    }


def _norm_openfiles(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for r in raw:
        if not isinstance(r, dict):
            continue
        # structured path
        if "fd_count" in r:
            rows.append({
                "pid":      _i_opt(r.get("pid")),
                "process":  _s_opt(r.get("process")),
                "fd_count": _i(r.get("fd_count")),
            })
        else:
            # legacy: {"pid_proc": "1234:chrome", "count": 42}
            pp = str(r.get("pid_proc", ""))
            rows.append({
                "pid":      _i_opt(pp.split(":")[0]) if ":" in pp else None,
                "process":  pp.split(":")[-1] if ":" in pp else pp,
                "fd_count": _i(r.get("count")),
            })
    return rows


def _norm_services(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    _STATUS_MAP = {
        "running": "running",
        "stopped": "stopped",
        "paused":  "stopped",
        "idle":    "stopped",
    }
    rows = []
    for s in raw:
        if not isinstance(s, dict):
            continue
        status = _s_opt(s.get("status")) or "stopped"
        rows.append({
            "name":        _s_opt(s.get("name")),
            "status":      _STATUS_MAP.get(status.lower(), "stopped"),
            "enabled":     _b_opt(s.get("enabled")) if s.get("enabled") is not None else None,
            "pid":         _i_opt(s.get("pid")),
            "type":        _s_opt(s.get("type")) or "launchd",
            "description": _s_opt(s.get("description")),
        })
    return rows


def _norm_users(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for u in raw:
        if not isinstance(u, dict):
            continue
        rows.append({
            "name":       _s_opt(u.get("name")),
            "uid":        _i_opt(u.get("uid")),
            "gid":        _i_opt(u.get("gid")),
            "admin":      _b_opt(u.get("admin")),
            "locked":     _b_opt(u.get("locked")),
            "home":       _s_opt(u.get("home")),
            "last_login": _i_opt(u.get("last_login")),
        })
    return rows


def _norm_hardware(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for h in raw:
        if not isinstance(h, dict):
            continue
        rows.append({
            "bus":        _s_opt(h.get("bus")),
            "name":       _s_opt(h.get("name")),
            "vendor":     _s_opt(h.get("vendor")),
            "product_id": _s_opt(h.get("product_id")),
            "vendor_id":  _s_opt(h.get("vendor_id")),
            "serial":     _s_opt(h.get("serial")),
            "revision":   _s_opt(h.get("revision")),
        })
    return rows


def _norm_containers(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for c in raw:
        if not isinstance(c, dict):
            continue
        rows.append({
            "id":         _s_opt(c.get("id")),
            "name":       _s_opt(c.get("name")),
            "image":      _s_opt(c.get("image")),
            "status":     _s_opt(c.get("status")),
            "runtime":    _s_opt(c.get("runtime")),
            "ports":      _s_opt(c.get("ports")),
            "created_at": _s_opt(c.get("created_at")),
        })
    return rows


def _norm_security(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return raw
    return {
        # macOS-specific
        "sip":          _s_opt(raw.get("sip")),
        "gatekeeper":   _s_opt(raw.get("gatekeeper")),
        "filevault":    _s_opt(raw.get("filevault")),
        "firewall":     _s_opt(raw.get("firewall")),
        "xprotect":     _s_opt(raw.get("xprotect")),
        "secure_boot":  _s_opt(raw.get("secure_boot")),
        "lockdown_mode": _b_opt(raw.get("lockdown_mode")),
        # Windows-specific (always None on macOS)
        "uac":          None,
        "bitlocker":    None,
        "defender":     None,
        # Linux-specific (always None on macOS)
        "selinux":      None,
        "apparmor":     None,
        "ufw":          None,
        # Cross-platform
        "av_installed": _b_opt(raw.get("av_installed")),
        "av_product":   _s_opt(raw.get("av_product")),
        "os_patched":   _b_opt(raw.get("os_patched")),
        "auto_update":  _b_opt(raw.get("auto_update")),
    }


def _norm_sysctl(raw: Any) -> list:
    # macOS sysctl collector returns a list[{key, value, security_relevant}]
    # or a legacy dict[str, str]
    if isinstance(raw, dict):
        # legacy dict form → convert to list
        return [
            {"key": k, "value": str(v), "security_relevant": True}
            for k, v in raw.items() if k
        ]
    if not isinstance(raw, list):
        return raw
    rows = []
    for r in raw:
        if not isinstance(r, dict):
            continue
        key = _s_opt(r.get("key"))
        if not key:
            continue
        rows.append({
            "key":              key,
            "value":            _s_opt(r.get("value")),
            "security_relevant": _b_opt(r.get("security_relevant")),
        })
    return rows


def _norm_configs(raw: Any) -> list:
    # legacy dict form {"path": "content"}
    if isinstance(raw, dict):
        return [
            {"path": k, "content": v, "suspicious": False}
            for k, v in raw.items()
        ]
    if not isinstance(raw, list):
        return raw
    rows = []
    for r in raw:
        if not isinstance(r, dict):
            continue
        rows.append({
            "path":       _s_opt(r.get("path")),
            "content":    _s_opt(r.get("content")),
            "suspicious": _b_opt(r.get("suspicious")),
        })
    return rows


def _norm_storage(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for s in raw:
        if not isinstance(s, dict):
            continue
        rows.append({
            "device":     _s_opt(s.get("device")),
            "mountpoint": _s_opt(s.get("mountpoint")),
            "fstype":     _s_opt(s.get("fstype")),
            "total_gb":   _f_opt(s.get("total_gb")),
            "used_gb":    _f_opt(s.get("used_gb")),
            "free_gb":    _f_opt(s.get("free_gb")),
            "pct":        _f_opt(s.get("pct")),
        })
    return rows


def _norm_tasks(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for t in raw:
        if not isinstance(t, dict):
            continue
        rows.append({
            "name":     _s_opt(t.get("name")),
            "type":     _s_opt(t.get("type")) or "cron",
            "schedule": _s_opt(t.get("schedule")),
            "command":  _s_opt(t.get("command")),
            "user":     _s_opt(t.get("user")),
            "enabled":  _b_opt(t.get("enabled")),
            "last_run": _i_opt(t.get("last_run")),
            "next_run": _i_opt(t.get("next_run")),
        })
    return rows


def _norm_apps(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for a in raw:
        if not isinstance(a, dict):
            continue
        if not _s_opt(a.get("name")):
            continue
        rows.append({
            "name":         _s_opt(a.get("name")),
            "version":      _s_opt(a.get("version")),
            "bundle_id":    _s_opt(a.get("bundle_id")),
            "path":         _s_opt(a.get("path")),
            "vendor":       _s_opt(a.get("vendor")),
            "signed":       _b_opt(a.get("signed")),
            "notarized":    _b_opt(a.get("notarized")),
            "installed_at": _i_opt(a.get("installed_at")),
        })
    return rows


def _norm_packages(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        rows.append({
            "manager":      _s_opt(p.get("manager")),
            "name":         _s_opt(p.get("name")),
            "version":      _s_opt(p.get("version")),
            "latest":       _s_opt(p.get("latest")),
            "outdated":     _b_opt(p.get("outdated")),
            "installed_at": _i_opt(p.get("installed_at")),
        })
    return rows


def _norm_binaries(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for b in raw:
        if not isinstance(b, dict):
            continue
        if not _s_opt(b.get("path")):
            continue
        rows.append({
            "path":           _s_opt(b.get("path")),
            "name":           _s_opt(b.get("name")),
            "hash_sha256":    _s_opt(b.get("hash_sha256")),
            "size_bytes":     _i_opt(b.get("size_bytes")),
            "permissions":    _s_opt(b.get("permissions")),
            "suid":           _b_opt(b.get("suid")),
            "sgid":           _b_opt(b.get("sgid")),
            "world_writable": _b_opt(b.get("world_writable")),
        })
    return rows


def _norm_sbom(raw: Any) -> list:
    if not isinstance(raw, list):
        return raw
    rows = []
    for c in raw:
        if not isinstance(c, dict):
            continue
        rows.append({
            "type":    _s_opt(c.get("type")) or "library",
            "name":    _s_opt(c.get("name")),
            "version": _s_opt(c.get("version")),
            "purl":    _s_opt(c.get("purl")),
            "license": _s_opt(c.get("license")),
            "source":  _s_opt(c.get("source")),
            "cpe":     _s_opt(c.get("cpe")),
        })
    return rows


# ── Dispatch table ────────────────────────────────────────────────────────────

_NORMALIZERS: dict[str, Any] = {
    "metrics":     _norm_metrics,
    "connections": _norm_connections,
    "processes":   _norm_processes,
    "ports":       _norm_ports,
    "network":     _norm_network,
    "arp":         _norm_arp,
    "mounts":      _norm_mounts,
    "battery":     _norm_battery,
    "openfiles":   _norm_openfiles,
    "services":    _norm_services,
    "users":       _norm_users,
    "hardware":    _norm_hardware,
    "containers":  _norm_containers,
    "security":    _norm_security,
    "sysctl":      _norm_sysctl,
    "configs":     _norm_configs,
    "storage":     _norm_storage,
    "tasks":       _norm_tasks,
    "apps":        _norm_apps,
    "packages":    _norm_packages,
    "binaries":    _norm_binaries,
    "sbom":        _norm_sbom,
}


def normalize(section: str, raw: Any) -> Any:
    """
    Normalize raw macOS collector output to the canonical schema.

    • Unknown sections → returned unchanged (pass-through).
    • Wrong input type for a section → returned unchanged.
    • Never raises.
    """
    fn = _NORMALIZERS.get(section)
    if fn is None:
        return raw
    try:
        return fn(raw)
    except Exception:
        return raw
