"""
agent/os/windows/normalizer.py — Windows collector output → canonical schema.

Thin sanitisation layer: Windows collectors already return structured dicts
(psutil + PowerShell JSON), so this is type-coercion + field completion rather
than raw-CLI parsing.

Usage (called by core.py Orchestrator._run_section):

    from agent.os.windows.normalizer import normalize
    canonical = normalize(section_name, raw_collector_output)
"""
from __future__ import annotations

from typing import Any


def normalize(section: str, raw: Any) -> Any:
    """Dispatch to the per-section normalizer. Returns raw unchanged on unknown section."""
    fn = _NORMALIZERS.get(section)
    if fn is None:
        return raw
    try:
        return fn(raw)
    except Exception:
        return raw


# ── Section normalizers ───────────────────────────────────────────────────────

def _metrics(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return raw
    per_core = raw.get("cpu_per_core")
    per_core = [_f(c, 0.0) for c in per_core] if isinstance(per_core, list) else []
    return {
        "cpu_pct":       _f(raw.get("cpu_pct"),    0.0),
        "cpu_cores":     _i_opt(raw.get("cpu_cores")),
        "cpu_per_core":  per_core,
        "mem_pct":       _f(raw.get("mem_pct"),    0.0),
        "mem_used_mb":   _i(raw.get("mem_used_mb"), 0),
        "mem_total_mb":  _i(raw.get("mem_total_mb"), 0),
        "swap_pct":      _f_opt(raw.get("swap_pct")),
        "swap_used_mb":  _i_opt(raw.get("swap_used_mb")),
        "swap_total_mb": _i_opt(raw.get("swap_total_mb")),
        "load_1m":       None,  # Windows has no load average
        "load_5m":       None,
        "load_15m":      None,
        "uptime_sec":    _i_opt(raw.get("uptime_sec")),
        "_raw":          raw.get("_raw"),
    }


def _connections(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "proto":       str(c.get("proto") or "tcp"),
            "local_addr":  str(c.get("local_addr") or ""),
            "local_port":  _i(c.get("local_port"), 0),
            "remote_addr": _s_opt(c.get("remote_addr")),
            "remote_port": _i_opt(c.get("remote_port")),
            "state":       _s_opt(c.get("state")),
            "direction":   _s_opt(c.get("direction")),
            "service":     _s_opt(c.get("service")),
            "pid":         _i_opt(c.get("pid")),
            "process":     _s_opt(c.get("process")),
        }
        for c in raw if isinstance(c, dict)
    ]


def _processes(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "pid":        _i(p.get("pid"), 0),
            "ppid":       _i_opt(p.get("ppid")),
            "name":       str(p.get("name") or ""),
            "user":       _s_opt(p.get("user")),
            "cpu_pct":    _f(p.get("cpu_pct"), 0.0),
            "mem_pct":    _f(p.get("mem_pct"), 0.0),
            "mem_rss_mb": _i_opt(p.get("mem_rss_mb")),
            "status":     _s_opt(p.get("status")),
            "started_at": _i_opt(p.get("started_at")),
            "cmdline":    _s_opt(p.get("cmdline")),
            "signed":     _s_opt(p.get("signed")),
        }
        for p in raw if isinstance(p, dict)
    ]


def _ports(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "proto":     str(p.get("proto") or "tcp"),
            "port":      _i(p.get("port"), 0),
            "bind_addr": str(p.get("bind_addr") or "0.0.0.0"),
            "state":     _s_opt(p.get("state")),
            "pid":       _i_opt(p.get("pid")),
            "process":   _s_opt(p.get("process")),
        }
        for p in raw if isinstance(p, dict)
    ]


def _network(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return raw
    ifaces = [
        {
            "name":   str(i.get("name") or ""),
            "mac":    _s_opt(i.get("mac")),
            "ipv4":   _s_opt(i.get("ipv4")),
            "ipv6":   _s_opt(i.get("ipv6")),
            "status": _s_opt(i.get("status")),
            "mtu":    _i_opt(i.get("mtu")),
        }
        for i in (raw.get("interfaces") or []) if isinstance(i, dict)
    ]
    return {
        "interfaces":  ifaces,
        "dns_servers": [str(s) for s in (raw.get("dns_servers") or []) if s],
        "default_gw":  _s_opt(raw.get("default_gw")),
        "hostname":    str(raw.get("hostname") or ""),
        "domain":      _s_opt(raw.get("domain")),
        "wifi_ssid":   _s_opt(raw.get("wifi_ssid")),
        "wifi_rssi":   _i_opt(raw.get("wifi_rssi")),
    }


def _arp(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "ip":        str(e.get("ip") or ""),
            "mac":       _s_opt(e.get("mac")),
            "interface": _s_opt(e.get("interface")),
            "state":     _s_opt(e.get("state")),
        }
        for e in raw if isinstance(e, dict) and e.get("ip")
    ]


def _mounts(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "device":     str(e.get("device") or ""),
            "mountpoint": str(e.get("mountpoint") or ""),
            "fstype":     _s_opt(e.get("fstype")),
            "options":    _s_opt(e.get("options")),
        }
        for e in raw if isinstance(e, dict)
    ]


def _battery(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return raw
    return {
        "present":      bool(raw.get("present", False)),
        "charging":     _b_opt(raw.get("charging")),
        "charge_pct":   _i_opt(raw.get("charge_pct")),
        "cycle_count":  _i_opt(raw.get("cycle_count")),
        "condition":    _s_opt(raw.get("condition")),
        "capacity_mah": _i_opt(raw.get("capacity_mah")),
        "design_mah":   _i_opt(raw.get("design_mah")),
        "voltage_mv":   _i_opt(raw.get("voltage_mv")),
    }


def _openfiles(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "pid":      _i(e.get("pid"), 0),
            "process":  str(e.get("process") or ""),
            "fd_count": _i(e.get("fd_count"), 0),
            "user":     _s_opt(e.get("user")),
        }
        for e in raw if isinstance(e, dict)
    ]


def _services(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    STATUS_MAP = {"running": "running", "stopped": "stopped",
                  "paused": "stopped", "disabled": "disabled"}
    return [
        {
            "name":        str(s.get("name") or ""),
            "status":      STATUS_MAP.get((s.get("status") or "").lower(), "unknown"),
            "enabled":     _b_opt(s.get("enabled")),
            "pid":         _i_opt(s.get("pid")),
            "type":        str(s.get("type") or "winsvc"),
            "description": _s_opt(s.get("description")),
        }
        for s in raw if isinstance(s, dict)
    ]


def _users(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "name":       str(u.get("name") or ""),
            "uid":        None,
            "gid":        None,
            "shell":      None,
            "home":       _s_opt(u.get("home")),
            "last_login": _i_opt(u.get("last_login")),
            "admin":      _b_opt(u.get("admin")),
            "locked":     _b_opt(u.get("locked")),
        }
        for u in raw if isinstance(u, dict) and u.get("name")
    ]


def _hardware(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "bus":        str(d.get("bus") or "usb"),
            "name":       str(d.get("name") or ""),
            "vendor":     _s_opt(d.get("vendor")),
            "product_id": _s_opt(d.get("product_id")),
            "vendor_id":  _s_opt(d.get("vendor_id")),
            "serial":     _s_opt(d.get("serial")),
            "connected":  _b_opt(d.get("connected")),
        }
        for d in raw if isinstance(d, dict)
    ]


def _containers(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "id":         str(c.get("id") or "")[:12],
            "name":       str(c.get("name") or ""),
            "image":      _s_opt(c.get("image")),
            "status":     str(c.get("status") or "unknown").lower(),
            "runtime":    str(c.get("runtime") or "docker"),
            "ports":      c.get("ports") if isinstance(c.get("ports"), list) else [],
            "created_at": _i_opt(c.get("created_at")),
        }
        for c in raw if isinstance(c, dict)
    ]


def _storage(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "device":     str(s.get("device") or ""),
            "mountpoint": str(s.get("mountpoint") or ""),
            "fstype":     _s_opt(s.get("fstype")),
            "total_gb":   _f(s.get("total_gb"), 0.0),
            "used_gb":    _f(s.get("used_gb"),  0.0),
            "free_gb":    _f(s.get("free_gb"),  0.0),
            "pct":        _f(s.get("pct"),       0.0),
        }
        for s in raw if isinstance(s, dict)
    ]


def _tasks(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "name":     str(t.get("name") or ""),
            "type":     str(t.get("type") or "schtasks"),
            "schedule": _s_opt(t.get("schedule")),
            "command":  _s_opt(t.get("command")),
            "user":     _s_opt(t.get("user")),
            "enabled":  _b_opt(t.get("enabled")),
            "last_run": _i_opt(t.get("last_run")),
            "next_run": _i_opt(t.get("next_run")),
        }
        for t in raw if isinstance(t, dict)
    ]


def _security(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return raw
    return {
        "sip": None, "gatekeeper": None, "filevault": None, "xprotect": None,
        "firewall":    _s_opt(raw.get("firewall")),
        "secure_boot": _s_opt(raw.get("secure_boot")),
        "av_installed":_b_opt(raw.get("av_installed")),
        "av_product":  _s_opt(raw.get("av_product")),
        "os_patched":  _b_opt(raw.get("os_patched")),
        "auto_update": _b_opt(raw.get("auto_update")),
        "selinux": None, "apparmor": None, "ufw": None,
        "uac":       _s_opt(raw.get("uac")),
        "bitlocker": _s_opt(raw.get("bitlocker")),
        "defender":  _s_opt(raw.get("defender")),
        "_raw":      raw.get("_raw"),
    }


def _sysctl(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "key":               str(r.get("key") or ""),
            "value":             str(r.get("value") or ""),
            "security_relevant": bool(r.get("security_relevant", False)),
        }
        for r in raw if isinstance(r, dict) and r.get("key")
    ]


def _configs(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "path":        str(c.get("path") or ""),
            "type":        str(c.get("type") or ""),
            "hash":        _s_opt(c.get("hash")),
            "size_bytes":  _i_opt(c.get("size_bytes")),
            "modified_at": _i_opt(c.get("modified_at")),
            "owner":       None, "permissions": None,
            "suspicious":  _b_opt(c.get("suspicious")),
            "note":        _s_opt(c.get("note")),
        }
        for c in raw if isinstance(c, dict) and c.get("path")
    ]


def _apps(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "name":         str(a.get("name") or ""),
            "version":      _s_opt(a.get("version")),
            "bundle_id":    None,
            "path":         _s_opt(a.get("path")),
            "signed":       _b_opt(a.get("signed")),
            "notarized":    None,
            "vendor":       _s_opt(a.get("vendor")),
            "installed_at": _i_opt(a.get("installed_at")),
        }
        for a in raw if isinstance(a, dict) and a.get("name")
    ]


def _packages(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "manager":      str(p.get("manager") or ""),
            "name":         str(p.get("name") or ""),
            "version":      _s_opt(p.get("version")),
            "latest":       _s_opt(p.get("latest")),
            "outdated":     _b_opt(p.get("outdated")),
            "installed_at": _i_opt(p.get("installed_at")),
        }
        for p in raw if isinstance(p, dict) and p.get("name")
    ]


def _binaries(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "path":           str(b.get("path") or ""),
            "name":           str(b.get("name") or ""),
            "hash_sha256":    _s_opt(b.get("hash_sha256")),
            "size_bytes":     _i_opt(b.get("size_bytes")),
            "modified_at":    _i_opt(b.get("modified_at")),
            "signed":         _b_opt(b.get("signed")),
            "notarized":      None,
            "permissions":    None, "owner": None,
            "suid": None, "sgid": None, "world_writable": None,
        }
        for b in raw if isinstance(b, dict) and b.get("path")
    ]


def _eventlog(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "event_id":  _i(e.get("event_id"), 0),
            "timestamp": _i_opt(e.get("timestamp")),
            "computer":  _s_opt(e.get("computer")),
            "channel":   str(e.get("channel") or ""),
            "category":  str(e.get("category") or "other"),
            "subject":   _s_opt(e.get("subject")),
            "detail":    e.get("detail") if isinstance(e.get("detail"), dict) else {},
        }
        for e in raw if isinstance(e, dict) and e.get("event_id")
    ]


def _sca(raw: dict) -> dict:
    """
    Security Configuration Assessment result.

    The SCA engine already emits canonical structure; this coerces types and
    guarantees the top-level shape so a partial/empty scan still validates.
    """
    if not isinstance(raw, dict):
        return {"policies": [], "summary": _sca_summary({})}

    policies = []
    for pol in raw.get("policies") or []:
        if not isinstance(pol, dict):
            continue
        checks = [
            {
                "id":          str(c.get("id") or ""),
                "title":       str(c.get("title") or ""),
                "result":      str(c.get("result") or "error"),
                "severity":    str(c.get("severity") or "medium"),
                "profile":     c.get("profile"),
                "scored":      bool(c.get("scored", True)),
                "rationale":   _s_opt(c.get("rationale")),
                "remediation": _s_opt(c.get("remediation")),
                "compliance":  c.get("compliance") if isinstance(c.get("compliance"), dict) else {},
                "duration_ms": _i(c.get("duration_ms"), 0),
                "rules":       _sca_rules(c.get("rules")),
            }
            for c in (pol.get("checks") or []) if isinstance(c, dict)
        ]
        policies.append({
            "policy_id":   str(pol.get("policy_id") or "policy"),
            "policy_name": str(pol.get("policy_name") or "policy"),
            "policy_version": str(pol.get("policy_version") or ""),
            "benchmark":   _s_opt(pol.get("benchmark")),
            "profile":     pol.get("profile"),
            "checks":      checks,
            "summary":     _sca_summary(pol.get("summary")),
        })

    return {
        "schema_version": _i(raw.get("schema_version"), 2),
        "scan_id": str(raw.get("scan_id") or ""),
        "generated_at": _i(raw.get("generated_at"), 0),
        "started_at": _i(raw.get("started_at"), 0),
        "completed_at": _i(raw.get("completed_at"), 0),
        "duration_ms": _i(raw.get("duration_ms"), 0),
        "policies": policies,
        "summary": _sca_summary(raw.get("summary")),
        "changes": raw.get("changes") if isinstance(raw.get("changes"), dict) else {},
        "collector_error": (
            raw.get("collector_error")
            if isinstance(raw.get("collector_error"), dict)
            else None
        ),
    }


def _sca_summary(s) -> dict:
    s = s if isinstance(s, dict) else {}
    return {
        "total":          _i(s.get("total"), 0),
        "pass":           _i(s.get("pass"), 0),
        "fail":           _i(s.get("fail"), 0),
        "not_applicable": _i(s.get("not_applicable"), 0),
        "error":          _i(s.get("error"), 0),
        "unknown":        _i(s.get("unknown"), 0),
        "scored_checks":  _i(s.get("scored_checks"), 0),
        "scored_pass":    _i(s.get("scored_pass"), 0),
        "scored_fail":    _i(s.get("scored_fail"), 0),
        "score_pct":      _f_opt(s.get("score_pct")),
        "coverage_pct":   _f_opt(s.get("coverage_pct")),
        "status":         str(s.get("status") or "unknown"),
        "policies":       _i(s.get("policies"), 0),
    }


def _sca_rules(rules) -> list:
    if not isinstance(rules, list):
        return []
    return [
        {
            "id": str(rule.get("id") or ""),
            "rule_type": str(rule.get("rule_type") or "unknown"),
            "result": str(rule.get("result") or "error"),
            "return_code": _i_opt(rule.get("return_code")),
            "duration_ms": _i(rule.get("duration_ms"), 0),
            "evidence": str(rule.get("evidence") or "")[:1040],
            "applicability": bool(rule.get("applicability", False)),
        }
        for rule in rules if isinstance(rule, dict)
    ]


def _sbom(raw: list) -> list:
    if not isinstance(raw, list):
        return raw
    return [
        {
            "type":    str(s.get("type") or "library"),
            "name":    str(s.get("name") or ""),
            "version": _s_opt(s.get("version")),
            "purl":    _s_opt(s.get("purl")),
            "license": _s_opt(s.get("license")),
            "source":  str(s.get("source") or ""),
            "cpe":     _s_opt(s.get("cpe")),
        }
        for s in raw if isinstance(s, dict) and s.get("name")
    ]


# ── Dispatch table ────────────────────────────────────────────────────────────

def _security_audit(raw: Any) -> dict:
    """Keep the nested audit schema intact while rejecting invalid roots."""
    return raw if isinstance(raw, dict) else {
        "schema_version": 1,
        "partial": True,
        "coverage": {},
        "findings": [],
    }


_NORMALIZERS: dict[str, Any] = {
    "metrics":     _metrics,     "connections": _connections,
    "processes":   _processes,   "ports":       _ports,
    "network":     _network,     "arp":         _arp,
    "mounts":      _mounts,      "battery":     _battery,
    "openfiles":   _openfiles,   "services":    _services,
    "users":       _users,       "hardware":    _hardware,
    "containers":  _containers,  "storage":     _storage,
    "tasks":       _tasks,       "security":    _security,
    "sysctl":      _sysctl,      "configs":     _configs,
    "apps":        _apps,        "packages":    _packages,
    "binaries":    _binaries,    "sbom":        _sbom,
    "sca":         _sca,         "eventlog":    _eventlog,
    "security_audit": _security_audit,
}


# ── Type coercion helpers ─────────────────────────────────────────────────────

def _f(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default

def _i(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def _f_opt(v) -> "float | None":
    try:
        return float(v)
    except (TypeError, ValueError):
        return None

def _i_opt(v) -> "int | None":
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None

def _s_opt(v) -> "str | None":
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None

def _b_opt(v) -> "bool | None":
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return bool(v)
    if isinstance(v, str):
        return v.lower() in ("true", "1", "yes", "enabled", "on")
    return None
