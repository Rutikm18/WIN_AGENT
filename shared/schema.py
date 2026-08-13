"""
shared/schema.py — Canonical section schemas (OS-agnostic normalized data model).

Every OS agent MUST map its raw collector output to these schemas before sending.
The manager is fully OS-agnostic: it only stores and queries canonical data.

Design rules:
  - All field names are snake_case strings
  - Types are Python built-ins: str, int, float, bool, list, dict, None
  - Optional fields default to None — never use a sentinel like -1 or "N/A"
  - Nested structures are plain dicts; no custom classes
  - OS-specific extra fields go in data["_raw"] (dict) — never in canonical fields

Usage:
    from shared.schema import validate_section, SCHEMAS

    errors = validate_section("metrics", data_dict)
    if errors:
        raise ValueError(errors)
"""
from __future__ import annotations

from typing import Any


# ── Canonical envelope metadata ──────────────────────────────────────────────
# These fields are present in every stored record (added by manager ingest).
ENVELOPE_META = {
    "schema":       int,    # envelope schema version (currently 1)
    "ts":           float,  # Unix epoch seconds (float)
    "agent_id":     str,    # unique agent identifier
    "agent_name":   str,    # human-readable agent name
    "os":           str,    # "macos" | "linux" | "windows"
    "os_version":   str,    # e.g. "14.4.1", "22.04", "11"
    "arch":         str,    # "arm64" | "x86_64" | "amd64"
    "hostname":     str,
    "section":      str,
    "collected_at": int,    # Unix epoch seconds (int)
}

# ── Section schemas ───────────────────────────────────────────────────────────
# Each schema is a dict mapping field_name → expected Python type.
# Required fields have a concrete type. Optional fields have (type, None).
# The validator below checks required fields are present and correct type.


# ── metrics ──────────────────────────────────────────────────────────────────
METRICS = {
    # Required
    "cpu_pct":      float,   # 0.0–100.0, system-wide CPU utilization
    "mem_pct":      float,   # 0.0–100.0, RAM utilization
    "mem_used_mb":  int,     # MB used
    "mem_total_mb": int,     # MB total physical RAM
    # Optional
    "swap_pct":     (float, None),   # swap/page file utilization
    "swap_used_mb": (int,   None),
    "swap_total_mb":(int,   None),
    "load_1m":      (float, None),   # 1-min load average (None on Windows)
    "load_5m":      (float, None),
    "load_15m":     (float, None),
    "cpu_cores":    (int,   None),
    "uptime_sec":   (int,   None),
}

# ── connections ───────────────────────────────────────────────────────────────
# data is a list of connection records
CONNECTIONS_RECORD = {
    "proto":        str,            # "tcp" | "tcp6" | "udp"
    "local_addr":   str,            # IP or "*"
    "local_port":   int,
    "remote_addr":  (str, None),    # None for LISTEN/UDP
    "remote_port":  (int, None),
    "state":        (str, None),    # "ESTABLISHED" | "LISTEN" | "TIME_WAIT" etc.
    "pid":          (int, None),
    "process":      (str, None),    # process name
    "_win":         (dict, None),   # Windows-native DNS/ETW enrichment
}

# ── processes ─────────────────────────────────────────────────────────────────
PROCESSES_RECORD = {
    "pid":          int,
    "ppid":         (int,  None),
    "name":         str,
    "user":         (str,  None),
    "cpu_pct":      float,
    "mem_pct":      float,
    "mem_rss_mb":   (int,  None),   # resident set size MB
    "status":       (str,  None),   # "running" | "sleeping" | "zombie"
    "cmdline":      (str,  None),   # full command line (may be truncated)
    "started_at":   (int,  None),   # Unix epoch
    "_win":         (dict, None),   # Windows-native ETW/security enrichment
}

# ── ports ─────────────────────────────────────────────────────────────────────
PORTS_RECORD = {
    "proto":        str,            # "tcp" | "tcp6" | "udp" | "udp6"
    "port":         int,
    "bind_addr":    str,            # "0.0.0.0" | "127.0.0.1" | "::" etc.
    "state":        (str,  None),   # "LISTEN" | "BOUND"
    "pid":          (int,  None),
    "process":      (str,  None),
}

# ── network ───────────────────────────────────────────────────────────────────
NETWORK_INTERFACE_RECORD = {
    "name":         str,            # "en0" | "eth0" | "Ethernet"
    "mac":          (str,  None),
    "ipv4":         (str,  None),
    "ipv6":         (str,  None),
    "status":       (str,  None),   # "up" | "down"
    "mtu":          (int,  None),
}

NETWORK = {
    "interfaces":   list,           # list of NETWORK_INTERFACE_RECORD
    "dns_servers":  list,           # list of str IP addresses
    "default_gw":   (str,  None),
    "hostname":     str,
    "domain":       (str,  None),
    "wifi_ssid":    (str,  None),   # None on non-WiFi or Linux server
    "wifi_rssi":    (int,  None),   # dBm; None if not connected
}

# ── arp ───────────────────────────────────────────────────────────────────────
ARP_RECORD = {
    "ip":           str,
    "mac":          (str,  None),   # None if "incomplete"
    "interface":    (str,  None),
    "state":        (str,  None),   # "REACHABLE" | "STALE" | "incomplete"
}

# ── mounts ────────────────────────────────────────────────────────────────────
MOUNTS_RECORD = {
    "device":       str,
    "mountpoint":   str,
    "fstype":       (str,  None),   # "apfs" | "ext4" | "ntfs"
    "options":      (str,  None),   # "rw,relatime,..."
}

# ── battery ───────────────────────────────────────────────────────────────────
BATTERY = {
    "present":      bool,           # False on desktops/servers
    "charging":     (bool, None),
    "charge_pct":   (int,  None),   # 0–100
    "cycle_count":  (int,  None),
    "condition":    (str,  None),   # "Normal" | "Replace Soon" | "Replace Now"
    "capacity_mah": (int,  None),
    "design_mah":   (int,  None),
    "voltage_mv":   (int,  None),
}

# ── openfiles ─────────────────────────────────────────────────────────────────
OPENFILES_RECORD = {
    "pid":          int,
    "process":      str,
    "fd_count":     int,
    "user":         (str,  None),
}

# ── services ──────────────────────────────────────────────────────────────────
SERVICES_RECORD = {
    "name":         str,
    "status":       str,    # "running" | "stopped" | "disabled" | "unknown"
    "enabled":      (bool, None),
    "pid":          (int,  None),
    "type":         (str,  None),   # "daemon" | "agent" | "systemd" | "winsvc"
    "description":  (str,  None),
}

# ── users ─────────────────────────────────────────────────────────────────────
USERS_RECORD = {
    "name":         str,
    "uid":          (int,  None),
    "gid":          (int,  None),
    "shell":        (str,  None),
    "home":         (str,  None),
    "last_login":   (int,  None),   # Unix epoch; None if never logged in
    "admin":        (bool, None),
    "locked":       (bool, None),
}

# ── hardware ──────────────────────────────────────────────────────────────────
HARDWARE_DEVICE_RECORD = {
    "bus":          str,    # "usb" | "thunderbolt" | "bluetooth" | "pci"
    "name":         str,
    "vendor":       (str,  None),
    "product_id":   (str,  None),
    "vendor_id":    (str,  None),
    "serial":       (str,  None),
    "connected":    (bool, None),
}

# ── containers ────────────────────────────────────────────────────────────────
CONTAINERS_RECORD = {
    "id":           str,    # short container ID
    "name":         str,
    "image":        (str,  None),
    "status":       str,    # "running" | "exited" | "paused" | "restarting"
    "runtime":      str,    # "docker" | "podman" | "containerd"
    "ports":        list,   # list of "host:container/proto" strings
    "created_at":   (int,  None),
}

# ── storage ───────────────────────────────────────────────────────────────────
STORAGE_RECORD = {
    "device":       str,
    "mountpoint":   str,
    "fstype":       (str,  None),
    "total_gb":     float,
    "used_gb":      float,
    "free_gb":      float,
    "pct":          float,          # 0.0–100.0
}

# ── tasks ─────────────────────────────────────────────────────────────────────
TASKS_RECORD = {
    "name":         str,
    "type":         str,    # "cron" | "launchd" | "systemd-timer" | "schtasks"
    "schedule":     (str,  None),   # cron expression or interval string
    "command":      (str,  None),
    "user":         (str,  None),
    "enabled":      (bool, None),
    "last_run":     (int,  None),   # Unix epoch
    "next_run":     (int,  None),
}

# ── security ──────────────────────────────────────────────────────────────────
SECURITY = {
    # macOS-specific — None on other OS
    "sip":          (str,  None),   # "enabled" | "disabled"
    "gatekeeper":   (str,  None),   # "enabled" | "disabled"
    "filevault":    (str,  None),   # "on" | "off"
    "firewall":     (str,  None),   # "on" | "off"
    "xprotect":     (str,  None),   # "enabled" | "disabled"
    "secure_boot":  (str,  None),   # "full" | "medium" | "none"
    # Cross-platform
    "av_installed": (bool, None),
    "av_product":   (str,  None),
    "os_patched":   (bool, None),   # True if latest security patch applied
    "auto_update":  (bool, None),
    # Linux-specific — None on other OS
    "selinux":      (str,  None),   # "enforcing" | "permissive" | "disabled"
    "apparmor":     (str,  None),   # "active" | "inactive"
    "ufw":          (str,  None),   # "active" | "inactive"
    # Windows-specific — None on other OS
    "uac":          (str,  None),   # "enabled" | "disabled"
    "bitlocker":    (str,  None),   # "on" | "off"
    "defender":     (str,  None),   # "enabled" | "disabled"
}

# ── sysctl ────────────────────────────────────────────────────────────────────
SYSCTL_RECORD = {
    "key":          str,
    "value":        str,
    "security_relevant": bool,
}

# ── configs ───────────────────────────────────────────────────────────────────
CONFIGS_RECORD = {
    "path":         str,
    "type":         str,    # "shell_rc" | "ssh_config" | "hosts" | "sudoers"
    "hash":         (str,  None),   # SHA-256 hex of file content
    "size_bytes":   (int,  None),
    "modified_at":  (int,  None),
    "owner":        (str,  None),
    "permissions":  (str,  None),   # octal string e.g. "0644"
    "suspicious":   (bool, None),   # flagged by heuristics
    "note":         (str,  None),   # human-readable reason if suspicious
}

# ── apps ──────────────────────────────────────────────────────────────────────
APPS_RECORD = {
    "name":         str,
    "version":      (str,  None),
    "bundle_id":    (str,  None),   # macOS: com.apple.Safari etc.
    "path":         (str,  None),
    "signed":       (bool, None),
    "notarized":    (bool, None),   # macOS only
    "vendor":       (str,  None),
    "installed_at": (int,  None),
}

# ── packages ──────────────────────────────────────────────────────────────────
PACKAGES_RECORD = {
    "manager":      str,    # "brew" | "pip" | "npm" | "gem" | "apt" | "rpm" | "winget"
    "name":         str,
    "version":      (str,  None),
    "latest":       (str,  None),   # latest available version; None if unknown
    "outdated":     (bool, None),
    "installed_at": (int,  None),
}

# ── binaries ──────────────────────────────────────────────────────────────────
BINARIES_RECORD = {
    "path":         str,
    "name":         str,
    "hash_sha256":  (str,  None),
    "size_bytes":   (int,  None),
    "modified_at":  (int,  None),
    "signed":       (bool, None),
    "notarized":    (bool, None),
    "permissions":  (str,  None),
    "owner":        (str,  None),
    "suid":         (bool, None),
    "sgid":         (bool, None),
    "world_writable": (bool, None),
}

# ── sbom ──────────────────────────────────────────────────────────────────────
SBOM_COMPONENT_RECORD = {
    "type":         str,    # "library" | "application" | "runtime"
    "name":         str,
    "version":      (str,  None),
    "purl":         (str,  None),   # package URL (https://github.com/package-url/purl-spec)
    "license":      (str,  None),
    "source":       str,    # "brew" | "pip" | "npm" | "gem" | "apt" | "bundle"
    "cpe":          (str,  None),   # Common Platform Enumeration
}

# ── Windows event and agent control-plane telemetry ─────────────────────────
EVENTLOG_RECORD = {
    "event_id": int,
    "timestamp": (int, None),
    "computer": (str, None),
    "channel": str,
    "category": str,
    "subject": (str, None),
    "detail": dict,
}

SCA = {
    "schema_version": int,
    "scan_id": str,
    "generated_at": int,
    "started_at": int,
    "completed_at": int,
    "duration_ms": int,
    "policies": list,
    "summary": dict,
    "changes": dict,
    "collector_error": (dict, None),
}

SECURITY_AUDIT = {
    "schema_version": int,
    "partial": bool,
    "coverage": dict,
    "findings": list,
}

DEVELOPER_SECURITY = {
    "schema_version": int,
    "platform": str,
    "scope": dict,
    "privacy": dict,
    "capabilities": dict,
    "collection": dict,
}

PERSISTENCE_RECORD = {
    "entry_id": str,
    "surface": str,
    "location": str,
    "name": str,
    "command": (str, None),
    "user": (str, None),
    "enabled": (bool, None),
    "privileged": (bool, None),
    "status": str,
    "change": str,
    "first_seen": (int, None),
    "last_seen": (int, None),
    "metadata": dict,
}

# Health and lifecycle records are versioned internally and intentionally
# extensible. The section-level contract is a dictionary; consumers validate
# event-specific fields after dispatch.
AGENT_EVENT: dict[str, type] = {}


# ── Schema registry ───────────────────────────────────────────────────────────

SCHEMAS: dict[str, dict] = {
    "metrics":     METRICS,
    "connections": CONNECTIONS_RECORD,
    "processes":   PROCESSES_RECORD,
    "ports":       PORTS_RECORD,
    "network":     NETWORK,
    "arp":         ARP_RECORD,
    "mounts":      MOUNTS_RECORD,
    "battery":     BATTERY,
    "openfiles":   OPENFILES_RECORD,
    "services":    SERVICES_RECORD,
    "users":       USERS_RECORD,
    "hardware":    HARDWARE_DEVICE_RECORD,
    "containers":  CONTAINERS_RECORD,
    "storage":     STORAGE_RECORD,
    "tasks":       TASKS_RECORD,
    "security":    SECURITY,
    "sysctl":      SYSCTL_RECORD,
    "configs":     CONFIGS_RECORD,
    "apps":        APPS_RECORD,
    "packages":    PACKAGES_RECORD,
    "binaries":    BINARIES_RECORD,
    "sbom":        SBOM_COMPONENT_RECORD,
    "eventlog":    EVENTLOG_RECORD,
    "sca":         SCA,
    "security_audit": SECURITY_AUDIT,
    "developer_security": DEVELOPER_SECURITY,
    "persistence": PERSISTENCE_RECORD,
    "agent_health": AGENT_EVENT,
    "agent_lifecycle": AGENT_EVENT,
}

# Sections where `data` is a list of records (vs a single dict)
LIST_SECTIONS: frozenset[str] = frozenset({
    "connections", "processes", "ports", "arp", "mounts",
    "openfiles", "services", "users", "hardware", "containers",
    "storage", "tasks", "sysctl", "configs", "apps", "packages",
    "binaries", "sbom", "eventlog", "persistence",
})
# Sections where `data` is a single dict (not a list)
DICT_SECTIONS: frozenset[str] = frozenset({
    "metrics", "network", "battery", "security", "sca",
    "security_audit", "developer_security", "agent_health", "agent_lifecycle",
})


# ── Validation ────────────────────────────────────────────────────────────────

def validate_section(section: str, data: Any) -> list[str]:
    """
    Validate `data` against the canonical schema for `section`.

    Returns a list of error strings. Empty list = valid.
    Does NOT raise — callers decide whether to reject or log-and-continue.
    """
    schema = SCHEMAS.get(section)
    if schema is None:
        return [f"Unknown section: {section!r}"]

    errors: list[str] = []

    if section in LIST_SECTIONS:
        if not isinstance(data, list):
            return [f"{section}: data must be a list, got {type(data).__name__}"]
        for i, record in enumerate(data[:5]):   # validate first 5 records
            errs = _check_record(record, schema, prefix=f"{section}[{i}]")
            errors.extend(errs)
    else:
        if not isinstance(data, dict):
            return [f"{section}: data must be a dict, got {type(data).__name__}"]
        errors.extend(_check_record(data, schema, prefix=section))

    return errors


def _check_record(record: Any, schema: dict, prefix: str) -> list[str]:
    if not isinstance(record, dict):
        return [f"{prefix}: expected dict, got {type(record).__name__}"]

    errors: list[str] = []
    for field, type_spec in schema.items():
        # Determine required vs optional
        if isinstance(type_spec, tuple):
            expected_types, nullable = type_spec[0], True
        else:
            expected_types, nullable = type_spec, False

        value = record.get(field)

        if value is None:
            if not nullable and field not in record:
                errors.append(f"{prefix}.{field}: required field missing")
        else:
            if not isinstance(value, expected_types):
                errors.append(
                    f"{prefix}.{field}: expected {expected_types.__name__}, "
                    f"got {type(value).__name__}"
                )
    return errors
