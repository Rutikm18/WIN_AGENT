"""
agents/linux/normalizer.py — Linux-specific normalizer.

Maps Linux collector output to the canonical section schemas in shared/schema.py.
Linux collectors use /proc, /sys, systemd, and standard CLI tools (ip, ss, lsof).

Status: SKELETON — implement collect() methods in collectors/ then fill normalizer.

To implement:
  1. Copy agent/agent/collectors/ structure
  2. Implement each collector using Linux-native APIs
  3. Fill in each normalize_*() function below
  4. Run: python3 -c "from agents.linux.normalizer import normalize; print('OK')"
"""
from __future__ import annotations

from typing import Any

# Re-use helper functions from macOS normalizer — they are OS-agnostic coercions
from agent.agent.normalizer import (
    normalize_connections, normalize_processes, normalize_ports,
    normalize_arp, normalize_mounts, normalize_openfiles,
    normalize_services, normalize_users, normalize_hardware,
    normalize_containers, normalize_storage, normalize_tasks,
    normalize_sysctl, normalize_configs, normalize_apps,
    normalize_packages, normalize_binaries, normalize_sbom,
    _f, _i, _s, _b,
)


def normalize(section: str, raw: Any) -> Any:
    fn = _NORMALIZERS.get(section)
    if fn is None:
        raise ValueError(f"No Linux normalizer for section: {section!r}")
    return fn(raw)


def normalize_metrics(raw: dict) -> dict:
    """
    Linux-specific: reads /proc/meminfo, /proc/stat, /proc/loadavg via psutil or direct.
    raw keys: cpu_percent, memory_percent, memory_used, memory_total,
              swap_percent, swap_used, swap_total, load_avg, cpu_count, uptime
    """
    load = raw.get("load_avg") or []
    return {
        "cpu_pct":      _f(raw.get("cpu_percent")),
        "mem_pct":      _f(raw.get("memory_percent")),
        "mem_used_mb":  _i(raw.get("memory_used", 0)) // (1024 * 1024)
                        if (raw.get("memory_used", 0) or 0) > 65536 else _i(raw.get("memory_used")),
        "mem_total_mb": _i(raw.get("memory_total", 0)) // (1024 * 1024)
                        if (raw.get("memory_total", 0) or 0) > 65536 else _i(raw.get("memory_total")),
        "swap_pct":     _f(raw.get("swap_percent")),
        "swap_used_mb": None,
        "swap_total_mb":None,
        "load_1m":      _f(load[0] if len(load) > 0 else None),
        "load_5m":      _f(load[1] if len(load) > 1 else None),
        "load_15m":     _f(load[2] if len(load) > 2 else None),
        "cpu_cores":    _i(raw.get("cpu_count")),
        "uptime_sec":   _i(raw.get("uptime")),
    }


def normalize_network(raw: dict) -> dict:
    """Linux: uses `ip addr`, `ip route`, /etc/resolv.conf."""
    interfaces = []
    for iface in (raw.get("interfaces") or []):
        interfaces.append({
            "name":   _s(iface.get("name")) or "",
            "mac":    _s(iface.get("mac")),
            "ipv4":   _s(iface.get("ipv4")),
            "ipv6":   _s(iface.get("ipv6")),
            "status": _s(iface.get("status")),
            "mtu":    _i(iface.get("mtu")),
        })
    return {
        "interfaces":  interfaces,
        "dns_servers": [str(x) for x in (raw.get("dns_servers") or [])],
        "default_gw":  _s(raw.get("default_gateway")),
        "hostname":    _s(raw.get("hostname")) or "",
        "domain":      _s(raw.get("domain")),
        "wifi_ssid":   _s(raw.get("wifi_ssid")),   # None on most servers
        "wifi_rssi":   None,
    }


def normalize_battery(raw: dict) -> dict:
    """Linux: reads /sys/class/power_supply/. Present=False on servers."""
    present = bool(raw.get("present", False))
    return {
        "present":      present,
        "charging":     _b(raw.get("charging")) if present else None,
        "charge_pct":   _i(raw.get("percent"))  if present else None,
        "cycle_count":  _i(raw.get("cycle_count")),
        "condition":    _s(raw.get("condition")),
        "capacity_mah": _i(raw.get("capacity")),
        "design_mah":   _i(raw.get("design_capacity")),
        "voltage_mv":   _i(raw.get("voltage")),
    }


def normalize_security(raw: dict) -> dict:
    """Linux: checks SELinux, AppArmor, UFW, auto-updates."""
    def _flag(val: Any) -> str | None:
        if val is None:
            return None
        if isinstance(val, bool):
            return "enabled" if val else "disabled"
        s = str(val).lower()
        if s in ("enabled", "on", "true", "yes", "1", "active", "enforcing"):
            return "enabled"
        if s in ("disabled", "off", "false", "no", "0", "inactive", "permissive"):
            return "disabled"
        return s

    return {
        # macOS-specific — always None on Linux
        "sip":          None,
        "gatekeeper":   None,
        "filevault":    None,
        "firewall":     None,
        "xprotect":     None,
        "secure_boot":  _s(raw.get("secure_boot")),
        # Cross-platform
        "av_installed": _b(raw.get("av_installed")),
        "av_product":   _s(raw.get("av_product")),
        "os_patched":   _b(raw.get("os_patched")),
        "auto_update":  _b(raw.get("auto_update")),
        # Linux-specific
        "selinux":      _flag(raw.get("selinux")),
        "apparmor":     _flag(raw.get("apparmor")),
        "ufw":          _flag(raw.get("ufw")),
        # Windows-specific — always None on Linux
        "uac":          None,
        "bitlocker":    None,
        "defender":     None,
    }


_NORMALIZERS: dict[str, Any] = {
    "metrics":     normalize_metrics,
    "connections": normalize_connections,   # shared — same raw format
    "processes":   normalize_processes,
    "ports":       normalize_ports,
    "network":     normalize_network,
    "arp":         normalize_arp,
    "mounts":      normalize_mounts,
    "battery":     normalize_battery,
    "openfiles":   normalize_openfiles,
    "services":    normalize_services,
    "users":       normalize_users,
    "hardware":    normalize_hardware,
    "containers":  normalize_containers,
    "storage":     normalize_storage,
    "tasks":       normalize_tasks,
    "security":    normalize_security,
    "sysctl":      normalize_sysctl,
    "configs":     normalize_configs,
    "apps":        normalize_apps,          # Linux: snap, flatpak, dpkg
    "packages":    normalize_packages,      # Linux: apt, rpm, pip, npm
    "binaries":    normalize_binaries,
    "sbom":        normalize_sbom,
}
