"""
agent/agent/normalizer.py — macOS-specific normalizer.

Parses raw macOS CLI/tool output from each collector and maps it to
the canonical section schemas defined in shared/schema.py.

Each normalize_*() function accepts what the collector actually returns
(raw strings, partially structured dicts, lists) and emits clean
typed canonical data that the dashboard and manager can consume directly.
"""
from __future__ import annotations

import re
from typing import Any


def normalize(section: str, raw: Any) -> Any:
    fn = _NORMALIZERS.get(section)
    if fn is None:
        return raw   # pass through unknown sections untouched
    try:
        return fn(raw)
    except Exception:
        return raw   # never crash the agent — pass through on error


# ── metrics ───────────────────────────────────────────────────────────────────
def normalize_metrics(raw: dict) -> dict:
    """
    raw keys: cpu (str), load (str), vmstat (str), swap (str)

    cpu   → "CPU usage: 5.12% user, 8.99% sys, 85.89% idle"
    load  → "{ 2.52 2.16 2.20 }"
    vmstat→ vm_stat multi-line output
    swap  → "total = 2048.00M  used = 1234.56M  free = 813.44M"
    """
    # CPU %
    cpu_pct = None
    cpu_str = raw.get("cpu", "")
    m = re.search(r"([\d.]+)%\s*user.*?([\d.]+)%\s*sys", cpu_str)
    if m:
        cpu_pct = round(float(m.group(1)) + float(m.group(2)), 1)

    # Load average
    load_1m = load_5m = load_15m = None
    load_str = raw.get("load", "")
    lm = re.findall(r"[\d.]+", load_str)
    if len(lm) >= 3:
        load_1m, load_5m, load_15m = float(lm[0]), float(lm[1]), float(lm[2])

    # Memory from vm_stat
    mem_pct = mem_used_mb = mem_total_mb = None
    vmstat = raw.get("vmstat", "")
    pages = {}
    for line in vmstat.splitlines():
        m2 = re.match(r"Pages\s+([\w\s]+):\s+(\d+)", line)
        if m2:
            pages[m2.group(1).strip()] = int(m2.group(2))
    page_size = 4096  # macOS default
    free   = pages.get("free", 0) + pages.get("speculative", 0)
    active = pages.get("active", 0)
    inactive = pages.get("inactive", 0)
    wired  = pages.get("wired down", 0)
    used   = active + inactive + wired
    total  = used + free
    if total > 0:
        mem_used_mb  = round(used  * page_size / (1024 * 1024))
        mem_total_mb = round(total * page_size / (1024 * 1024))
        mem_pct      = round(used / total * 100, 1)

    # Swap
    swap_pct = swap_used_mb = swap_total_mb = None
    swap_str = raw.get("swap", "")
    sm = re.search(r"total\s*=\s*([\d.]+)([MG])", swap_str, re.I)
    su = re.search(r"used\s*=\s*([\d.]+)([MG])", swap_str, re.I)
    if sm and su:
        def to_mb(val, unit):
            return round(float(val) * (1024 if unit.upper() == 'G' else 1))
        swap_total_mb = to_mb(sm.group(1), sm.group(2))
        swap_used_mb  = to_mb(su.group(1), su.group(2))
        if swap_total_mb > 0:
            swap_pct = round(swap_used_mb / swap_total_mb * 100, 1)

    return {
        "cpu_pct":      cpu_pct,
        "mem_pct":      mem_pct,
        "mem_used_mb":  mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "swap_pct":     swap_pct,
        "swap_used_mb": swap_used_mb,
        "swap_total_mb":swap_total_mb,
        "load_1m":      load_1m,
        "load_5m":      load_5m,
        "load_15m":     load_15m,
    }


# ── connections ───────────────────────────────────────────────────────────────
def normalize_connections(raw: list) -> list:
    """
    raw: [{"proc": "Slack", "pid": "1234", "addr": "10.0.0.1:443->52.1.2.3:443"}]
    """
    out = []
    for r in (raw or []):
        addr = r.get("addr", "")
        local = remote = ""
        if "->" in addr:
            local, remote = addr.split("->", 1)
        else:
            local = addr

        local_addr, local_port = _split_addr(local)
        remote_addr, remote_port = _split_addr(remote) if remote else (None, None)

        out.append({
            "proto":       "tcp",
            "local_addr":  local_addr or "*",
            "local_port":  local_port or 0,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state":       "ESTABLISHED",
            "pid":         _int(r.get("pid")),
            "process":     r.get("proc", ""),
        })
    return out


# ── processes ─────────────────────────────────────────────────────────────────
def normalize_processes(raw: list) -> list:
    """
    raw: [{"pid": "1", "user": "root", "cpu": "0.1", "mem": "0.5",
           "rss": "12345", "cmd": "/sbin/launchd"}]
    rss is in KB from ps
    """
    out = []
    for r in (raw or []):
        cmd = r.get("cmd", "")
        name = cmd.split("/")[-1].split()[0] if cmd else ""
        rss_kb = _int(r.get("rss"))
        out.append({
            "pid":        _int(r.get("pid")) or 0,
            "ppid":       None,
            "name":       name,
            "user":       r.get("user", ""),
            "cpu_pct":    _float(r.get("cpu")) or 0.0,
            "mem_pct":    _float(r.get("mem")) or 0.0,
            "mem_rss_mb": round(rss_kb / 1024) if rss_kb else None,
            "status":     "running",
            "cmdline":    cmd,
            "started_at": None,
        })
    return out


# ── ports ─────────────────────────────────────────────────────────────────────
def normalize_ports(raw: list) -> list:
    """
    raw: [{"proc": "rapportd", "pid": "123", "proto": "TCP",
           "addr": "*:1234 (LISTEN)"}]
    """
    out = []
    for r in (raw or []):
        addr_raw = r.get("addr", "").replace(" (LISTEN)", "").replace(" (BOUND)", "")
        bind_addr, port = _split_addr(addr_raw)
        out.append({
            "proto":     r.get("proto", "tcp").lower(),
            "port":      port or 0,
            "bind_addr": bind_addr or "0.0.0.0",
            "state":     "LISTEN" if r.get("proto") == "TCP" else "BOUND",
            "pid":       _int(r.get("pid")),
            "process":   r.get("proc", ""),
        })
    return out


# ── network ───────────────────────────────────────────────────────────────────
def normalize_network(raw: dict) -> dict:
    """raw keys: ifconfig (str), dns (str), proxy (str), routes (str)"""
    ifconfig = raw.get("ifconfig", "")
    interfaces = _parse_ifconfig(ifconfig)

    # DNS from scutil --dns
    dns_servers = []
    for line in raw.get("dns", "").splitlines():
        m = re.search(r"nameserver\[[\d]+\]\s*:\s*([\d.]+)", line)
        if m and m.group(1) not in dns_servers:
            dns_servers.append(m.group(1))

    # Default gateway from netstat -rn
    default_gw = None
    for line in raw.get("routes", "").splitlines():
        if line.startswith("default"):
            parts = line.split()
            if len(parts) >= 2:
                default_gw = parts[1]
                break

    # WiFi SSID from ifconfig (airport not always available)
    wifi_ssid = None
    ssid_m = re.search(r'ssid\s+(.+)', ifconfig, re.I)
    if ssid_m:
        wifi_ssid = ssid_m.group(1).strip()

    import socket
    return {
        "interfaces":  interfaces,
        "dns_servers": dns_servers[:6],
        "default_gw":  default_gw,
        "hostname":    socket.gethostname(),
        "domain":      None,
        "wifi_ssid":   wifi_ssid,
        "wifi_rssi":   None,
    }


def _parse_ifconfig(text: str) -> list:
    interfaces = []
    current = None
    for line in text.splitlines():
        # New interface block
        m = re.match(r'^(\S+):\s+flags=', line)
        if m:
            if current:
                interfaces.append(current)
            status = "up" if "UP" in line else "down"
            current = {"name": m.group(1), "mac": None, "ipv4": None,
                       "ipv6": None, "status": status, "mtu": None}
            mtu_m = re.search(r'mtu\s+(\d+)', line)
            if mtu_m:
                current["mtu"] = int(mtu_m.group(1))
        elif current:
            if "inet " in line:
                ip_m = re.search(r'inet\s+([\d.]+)', line)
                if ip_m:
                    current["ipv4"] = ip_m.group(1)
            elif "inet6 " in line and not current["ipv6"]:
                ip6_m = re.search(r'inet6\s+([0-9a-fA-F:]+)', line)
                if ip6_m and not ip6_m.group(1).startswith("fe80"):
                    current["ipv6"] = ip6_m.group(1)
            elif "ether " in line:
                mac_m = re.search(r'ether\s+([0-9a-f:]+)', line)
                if mac_m:
                    current["mac"] = mac_m.group(1)
    if current:
        interfaces.append(current)
    # Filter out loopback and empty interfaces
    return [i for i in interfaces if i["name"] not in ("lo0",) and (i["ipv4"] or i["mac"])]


# ── arp ───────────────────────────────────────────────────────────────────────
def normalize_arp(raw: list) -> list:
    """raw: [{"host": "hostname", "ip": "(10.0.0.1)", "mac": "aa:bb:cc:dd:ee:ff"}]"""
    out = []
    for r in (raw or []):
        ip = r.get("ip", "").strip("()")
        mac = r.get("mac", "")
        if ip and mac and mac != "(incomplete)":
            out.append({
                "ip":        ip,
                "mac":       mac if mac not in ("<incomplete>", "(incomplete)") else None,
                "interface": None,
                "state":     "REACHABLE",
            })
    return out


# ── mounts ────────────────────────────────────────────────────────────────────
def normalize_mounts(raw: list) -> list:
    out = []
    for r in (raw or []):
        out.append({
            "device":     r.get("device", ""),
            "mountpoint": r.get("mountpoint", ""),
            "fstype":     r.get("type", None),
            "options":    None,
        })
    return out


# ── battery ───────────────────────────────────────────────────────────────────
def normalize_battery(raw: dict) -> dict:
    """
    raw keys: pmset (str)
    pmset -g batt output:
      "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=...) 85%; discharging; 4:30 remaining present: true"
    """
    pmset = raw.get("pmset", "")
    present = "present: true" in pmset.lower() or "%" in pmset

    charge_pct = None
    m = re.search(r"(\d+)%", pmset)
    if m:
        charge_pct = int(m.group(1))

    charging = None
    if "charging" in pmset.lower():
        charging = True
    elif "discharging" in pmset.lower() or "ac power" not in pmset.lower():
        charging = False
    if "ac power" in pmset.lower():
        charging = True

    condition = None
    if "battery power" in pmset.lower():
        condition = "Normal"

    # Cycle count from system_profiler if available
    cycle_count = None
    sp = raw.get("system_profiler", "")
    cc_m = re.search(r"Cycle Count:\s*(\d+)", sp)
    if cc_m:
        cycle_count = int(cc_m.group(1))

    cap_m = re.search(r"Full Charge Capacity \(mAh\):\s*(\d+)", sp)
    design_m = re.search(r"Design Capacity:\s*(\d+)", sp)

    return {
        "present":      present,
        "charging":     charging,
        "charge_pct":   charge_pct,
        "cycle_count":  cycle_count,
        "condition":    condition,
        "capacity_mah": int(cap_m.group(1)) if cap_m else None,
        "design_mah":   int(design_m.group(1)) if design_m else None,
        "voltage_mv":   None,
    }


# ── openfiles ─────────────────────────────────────────────────────────────────
def normalize_openfiles(raw: list) -> list:
    """raw: [{"pid_proc": "1234:Slack", "count": 42}]"""
    out = []
    for r in (raw or []):
        pp = r.get("pid_proc", "")
        pid, _, proc = pp.partition(":")
        out.append({
            "pid":      _int(pid),
            "process":  proc or pid,
            "fd_count": int(r.get("count", 0)),
            "user":     None,
        })
    return out


# ── services ──────────────────────────────────────────────────────────────────
def normalize_services(raw: dict) -> list:
    """
    raw keys: launchctl (str), daemons (str), agents (str)
    launchctl list output: "PID Status Label" lines
    """
    out = []
    seen = set()
    for line in raw.get("launchctl", "").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or parts[0] == "PID":
            continue
        pid_str, status_str, label = parts
        if label in seen:
            continue
        seen.add(label)
        pid = _int(pid_str) if pid_str != "-" else None
        running = pid is not None
        out.append({
            "name":        label,
            "status":      "running" if running else "stopped",
            "enabled":     True,
            "pid":         pid,
            "type":        "daemon" if "daemon" in label.lower() else "agent",
            "description": None,
        })
    return sorted(out, key=lambda x: (x["status"] != "running", x["name"]))


# ── users ─────────────────────────────────────────────────────────────────────
def normalize_users(raw: dict) -> list:
    """
    raw keys: users (str — dscl list), who (str), last (str)
    """
    SYSTEM_USERS = {
        "_spotlight", "_mdnsresponder", "_networkd", "_nsurlsessiond",
        "_lsd", "_locationd", "_appstore", "_coreaudiod", "_timed",
        "daemon", "nobody", "root", "_uucp", "_sshd", "_www", "_mysql",
    }

    all_users = [u.strip() for u in raw.get("users", "").splitlines()
                 if u.strip() and not u.startswith("_") and u.strip() not in SYSTEM_USERS]

    # Parse last logins from `last` output
    last_login_map: dict[str, int] = {}
    for line in raw.get("last", "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] not in ("wtmp", "reboot", "shutdown"):
            user = parts[0]
            if user not in last_login_map:
                last_login_map[user] = 0   # placeholder; we don't have exact epoch

    # Currently logged in from who
    logged_in = set()
    for line in raw.get("who", "").splitlines():
        parts = line.split()
        if parts:
            logged_in.add(parts[0])

    out = []
    for u in sorted(set(all_users)):
        out.append({
            "name":       u,
            "uid":        None,
            "gid":        None,
            "shell":      None,
            "home":       f"/Users/{u}",
            "last_login": None,
            "admin":      None,
            "locked":     None,
        })
    return out


# ── hardware ──────────────────────────────────────────────────────────────────
def normalize_hardware(raw: dict) -> list:
    """
    raw keys: usb (str), bluetooth (str), thunderbolt (str)
    Parses system_profiler text output.
    """
    out = []
    out.extend(_parse_sp_devices(raw.get("usb", ""),         "usb"))
    out.extend(_parse_sp_devices(raw.get("thunderbolt", ""), "thunderbolt"))
    out.extend(_parse_sp_devices(raw.get("bluetooth", ""),   "bluetooth"))
    return out


def _parse_sp_devices(text: str, bus: str) -> list:
    devices = []
    current: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        # New device block — indented name followed by colon
        if re.match(r"^\w.+:$", stripped) and "    " not in line[:4]:
            if current and current.get("name"):
                devices.append(current)
            current = {"bus": bus, "name": stripped.rstrip(":"),
                       "vendor": None, "product_id": None,
                       "vendor_id": None, "serial": None, "connected": True}
        elif current:
            if "Manufacturer:" in stripped:
                current["vendor"] = stripped.split(":", 1)[-1].strip()
            elif "Product ID:" in stripped:
                current["product_id"] = stripped.split(":", 1)[-1].strip()
            elif "Vendor ID:" in stripped:
                current["vendor_id"] = stripped.split(":", 1)[-1].strip()
            elif "Serial Number:" in stripped:
                current["serial"] = stripped.split(":", 1)[-1].strip()
    if current and current.get("name"):
        devices.append(current)
    # Filter out section headers (e.g. "USB 3.1 Bus:")
    return [d for d in devices if "Bus" not in d["name"] and "Controller" not in d["name"]]


# ── containers ────────────────────────────────────────────────────────────────
def normalize_containers(raw: dict) -> list:
    """
    raw keys: docker_containers (tab-separated: ID Image Status Name)
    """
    out = []
    for line in raw.get("docker_containers", "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 4:
            cid, image, status, name = parts[0], parts[1], parts[2], parts[3]
            running = "Up" in status
            out.append({
                "id":         cid,
                "name":       name.strip(),
                "image":      image.strip(),
                "status":     "running" if running else "exited",
                "runtime":    "docker",
                "ports":      [],
                "created_at": None,
            })
    # Podman fallback (plain text)
    for line in raw.get("podman", "").splitlines()[1:]:
        parts = line.split(None, 6)
        if len(parts) >= 4:
            out.append({
                "id":         parts[0],
                "name":       parts[-1] if parts else "",
                "image":      parts[1] if len(parts) > 1 else "",
                "status":     "running" if "Up" in line else "exited",
                "runtime":    "podman",
                "ports":      [],
                "created_at": None,
            })
    return out


# ── storage ───────────────────────────────────────────────────────────────────
def normalize_storage(raw: dict) -> list:
    """
    raw keys: df (str)
    df -h output: Filesystem Size Used Avail Capacity iused ifree %iused Mounted
    """
    out = []
    for line in raw.get("df", "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        # df -h on macOS: Filesystem Size Used Avail Capacity iused ifree %iused Mounted
        # Simpler: last field is mountpoint, 5th field is pct
        if len(parts) >= 9:
            device, size_s, used_s, avail_s, pct_s = parts[0], parts[1], parts[2], parts[3], parts[4]
            mountpoint = parts[-1]
        elif len(parts) >= 6:
            device, size_s, used_s, avail_s, pct_s, mountpoint = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        else:
            continue

        if not mountpoint.startswith("/") or device.startswith("map "):
            continue

        def parse_size(s: str) -> float:
            s = s.replace(",", "")
            try:
                if s.endswith("T"): return float(s[:-1]) * 1024
                if s.endswith("G"): return float(s[:-1])
                if s.endswith("M"): return float(s[:-1]) / 1024
                if s.endswith("K"): return float(s[:-1]) / (1024 * 1024)
                return float(s) / (1024 ** 3)
            except ValueError:
                return 0.0

        total_gb = parse_size(size_s)
        used_gb  = parse_size(used_s)
        free_gb  = parse_size(avail_s)
        pct = float(pct_s.rstrip("%")) if pct_s.rstrip("%").replace(".", "").isdigit() else 0.0

        out.append({
            "device":     device,
            "mountpoint": mountpoint,
            "fstype":     None,
            "total_gb":   round(total_gb, 1),
            "used_gb":    round(used_gb, 1),
            "free_gb":    round(free_gb, 1),
            "pct":        round(pct, 1),
        })
    return out


# ── tasks ─────────────────────────────────────────────────────────────────────
def normalize_tasks(raw: dict) -> list:
    """raw keys: crontab (str)"""
    out = []
    crontab = raw.get("crontab", "")
    if "no crontab" in crontab.lower():
        return []
    for line in crontab.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 5)
        if len(parts) >= 6:
            schedule = " ".join(parts[:5])
            command  = parts[5]
        elif len(parts) >= 2:
            schedule = parts[0]
            command  = " ".join(parts[1:])
        else:
            continue
        out.append({
            "name":     command.split("/")[-1].split()[0][:40],
            "type":     "cron",
            "schedule": schedule,
            "command":  command,
            "user":     None,
            "enabled":  True,
            "last_run": None,
            "next_run": None,
        })
    return out


# ── security ──────────────────────────────────────────────────────────────────
def normalize_security(raw: dict) -> dict:
    """
    raw keys: various string fields from posture collector
    """
    def _enabled(val):
        if val is None: return None
        s = str(val).lower()
        if any(x in s for x in ("enabled", "on", "true", "yes", "1", "active", "enforcing")): return "enabled"
        if any(x in s for x in ("disabled", "off", "false", "no", "0", "inactive")): return "disabled"
        return str(val)

    return {
        "sip":          _enabled(raw.get("sip")),
        "gatekeeper":   _enabled(raw.get("gatekeeper")),
        "filevault":    _enabled(raw.get("filevault")),
        "firewall":     _enabled(raw.get("firewall")),
        "xprotect":     raw.get("xprotect"),
        "secure_boot":  raw.get("secure_boot"),
        "av_installed": None,
        "av_product":   None,
        "os_patched":   None,
        "auto_update":  _enabled(raw.get("auto_update")),
        "selinux":      None,
        "apparmor":     None,
        "ufw":          None,
        "uac":          None,
        "bitlocker":    None,
        "defender":     None,
    }


# ── sysctl ────────────────────────────────────────────────────────────────────
def normalize_sysctl(raw: list) -> list:
    if isinstance(raw, list):
        return [{"key": r.get("key",""), "value": str(r.get("value","")),
                 "security_relevant": bool(r.get("security_relevant", False))} for r in raw]
    return []


# ── configs ───────────────────────────────────────────────────────────────────
def normalize_configs(raw: list) -> list:
    if isinstance(raw, list):
        return raw
    return []


# ── apps ──────────────────────────────────────────────────────────────────────
def normalize_apps(raw: list) -> list:
    """raw: [{"name": "Slack.app"}] or [{"name": "Slack"}]"""
    out = []
    for r in (raw or []):
        name = r.get("name", "")
        clean = name.replace(".app", "").strip()
        if not clean:
            continue
        out.append({
            "name":         clean,
            "version":      r.get("version", None),
            "bundle_id":    None,
            "path":         f"/Applications/{name}" if name.endswith(".app") else None,
            "signed":       None,
            "notarized":    None,
            "vendor":       None,
            "installed_at": None,
        })
    return out


# ── packages ──────────────────────────────────────────────────────────────────
def normalize_packages(raw: dict) -> list:
    """
    raw keys: brew (str), pip3 (str), npm (str), gems (str)
    """
    out = []

    # Homebrew: "package version"
    for line in raw.get("brew", "").splitlines():
        parts = line.strip().split()
        if parts:
            out.append({"manager": "brew", "name": parts[0],
                        "version": parts[1] if len(parts) > 1 else None,
                        "latest": None, "outdated": None, "installed_at": None})

    # pip3: skip first two header lines, then "Package   Version"
    lines = raw.get("pip3", "").splitlines()
    skip = 2 if lines and "---" in "".join(lines[:3]) else 0
    for line in lines[skip:]:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] not in ("Package", "---"):
            out.append({"manager": "pip", "name": parts[0],
                        "version": parts[1], "latest": None,
                        "outdated": None, "installed_at": None})

    # gems: "package (version)"
    for line in raw.get("gems", "").splitlines():
        m = re.match(r"^([\w-]+)\s+\(([\d., ]+)\)", line)
        if m:
            out.append({"manager": "gem", "name": m.group(1),
                        "version": m.group(2).split(",")[0].strip(),
                        "latest": None, "outdated": None, "installed_at": None})

    # npm: "├── package@version" or "`── package@version"
    for line in raw.get("npm", "").splitlines():
        m = re.search(r"(?:├──|└──|─)\s+([@\w/-]+)@([\d.]+)", line)
        if m:
            out.append({"manager": "npm", "name": m.group(1),
                        "version": m.group(2), "latest": None,
                        "outdated": None, "installed_at": None})

    return out


# ── sbom ──────────────────────────────────────────────────────────────────────
def normalize_sbom(raw) -> list:
    """
    raw: {"items": [...], "total": N}  OR  direct list
    Each item: {"name": str, "version": str, "type": str, "source": str}
    """
    if isinstance(raw, dict):
        items = raw.get("items", [])
    elif isinstance(raw, list):
        items = raw
    else:
        return []

    out = []
    for r in items:
        out.append({
            "type":    r.get("type", "library"),
            "name":    r.get("name", ""),
            "version": r.get("version") or None,
            "purl":    None,
            "license": None,
            "source":  r.get("source", r.get("type", "")),
            "cpe":     None,
        })
    return out


# ── binaries ──────────────────────────────────────────────────────────────────
def normalize_binaries(raw: dict) -> list:
    out = []
    for directory, files in (raw or {}).items():
        for f in (files or []):
            import os
            out.append({
                "path":          os.path.join(directory, f),
                "name":          f,
                "hash_sha256":   None,
                "size_bytes":    None,
                "modified_at":   None,
                "signed":        None,
                "notarized":     None,
                "permissions":   None,
                "owner":         None,
                "suid":          None,
                "sgid":          None,
                "world_writable":None,
            })
    return out


# ── Dispatch table ────────────────────────────────────────────────────────────
_NORMALIZERS: dict = {
    "metrics":     normalize_metrics,
    "connections": normalize_connections,
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
    "apps":        normalize_apps,
    "packages":    normalize_packages,
    "binaries":    normalize_binaries,
    "sbom":        normalize_sbom,
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _int(v) -> int | None:
    try: return int(str(v).strip())
    except: return None

def _float(v) -> float | None:
    try: return float(str(v).strip())
    except: return None

def _split_addr(addr: str):
    """Split 'host:port' or '[::1]:port' or '*:port' into (host, port_int)."""
    if not addr:
        return None, None
    if addr.startswith("["):   # IPv6
        m = re.match(r"\[(.+)\]:(\d+)", addr)
        return (m.group(1), int(m.group(2))) if m else (addr, None)
    parts = addr.rsplit(":", 1)
    if len(parts) == 2:
        try: return parts[0] or "*", int(parts[1])
        except ValueError: return addr, None
    return addr, None
