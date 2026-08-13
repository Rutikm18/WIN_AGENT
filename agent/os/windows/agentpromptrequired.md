# Windows Agent — Full Implementation Prompt

> Historical implementation input. The verified result and remaining external gates are tracked in [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md); do not treat unfinished items below as current status. Startup tooling remains in [`advanced_support/`](advanced_support/README.md).

## Context

You are implementing the Windows agent for the **AttackLens** endpoint telemetry platform.
The macOS agent already ships to production. The Windows skeleton exists at
`agent/os/windows/` with stubs and docstrings. Your job is to **fill in every
unimplemented method and make every collector production-ready**, matching the
quality and depth of the macOS agent.

---

## Platform Architecture (do not change)

```
SCM
 └─ AttackLens service  (agent/os/windows/service.py)
     └─ agent.agent.core.Orchestrator  (shared with macOS)
         └─ OS-specific collectors  (agent/os/windows/collectors/)
             └─ normalizer          (agent/os/windows/normalizer.py)
```

- The **Orchestrator** (agent/agent/core.py) is OS-agnostic. It schedules
  collectors on intervals, enforces per-section timeouts, manages the circuit
  breaker, writes NDJSON+gzip payloads to the spool dir, and hands off to the sender.
- Collectors **must not** call `sys.exit`, spawn long-lived threads, or block
  longer than their declared `timeout`.
- Every collector returns either a `dict` or `list[dict]`. Never raise from
  `collect()` — catch all exceptions internally and return a partial result or `{}`.
- The normalizer (`normalizer.py`) coerces raw output to the canonical schema.
  Update it whenever a collector returns a new field.

---

## Install Path & Config

| Purpose         | Path                                                    |
|-----------------|---------------------------------------------------------|
| Binary          | `C:\Program Files (x86)\AttackLens\attacklens-agent.exe` |
| Config          | `C:\Program Files (x86)\AttackLens\config\agent.toml`  |
| Security dir    | `C:\Program Files (x86)\AttackLens\security\`           |
| Spool dir       | `C:\ProgramData\AttackLens\spool\`                      |
| Log dir         | `C:\ProgramData\AttackLens\logs\`                       |
| SCA policies    | `C:\ProgramData\AttackLens\sca\`                        |

Service account: **NETWORK SERVICE** (or a dedicated `AttackLensAgent` account).
The agent needs `SeDebugPrivilege` for full process enumeration.

---

## Privilege Model

| Privilege needed          | Why                                                |
|---------------------------|----------------------------------------------------|
| `SeDebugPrivilege`        | Full process list, LSASS protection checks         |
| Local Admin / SYSTEM      | WMI, registry HKLM writes, manage-bde, BitLocker  |
| No UAC prompt at runtime  | Service runs under SYSTEM — no interactive session |

Always call `win32api.OpenProcessToken` + `win32security.AdjustTokenPrivileges`
during service startup to elevate to `SeDebugPrivilege` when available. Degrade
gracefully (return `None` fields) when the privilege is absent.

---

## Dependencies (`agent/os/windows/requirements.txt`)

```
psutil>=5.9
pywin32>=306
wmi>=1.5.1          # optional; use winreg / PowerShell as primary
requests>=2.31
cryptography>=41
pyinstaller>=6.0    # build only
```

---

## Collector Schedule

| Section         | Interval   | File                          | Status      |
|-----------------|------------|-------------------------------|-------------|
| `metrics`       | 10 s       | volatile.py — MetricsCollector    | DONE        |
| `connections`   | 10 s       | volatile.py — ConnectionsCollector| DONE        |
| `processes`     | 10 s       | volatile.py — ProcessesCollector  | DONE        |
| `battery`       | 2 min      | system.py — BatteryCollector      | DONE        |
| `openfiles`     | 2 min      | system.py — OpenFilesCollector    | DONE        |
| `services`      | 2 min      | system.py — ServicesCollector     | DONE        |
| `users`         | 2 min      | system.py — UsersCollector        | DONE        |
| `hardware`      | 2 min      | system.py — HardwareCollector     | DONE        |
| `containers`    | 2 min      | system.py — ContainersCollector   | DONE        |
| `ports`         | 30 s       | network.py — PortsCollector       | DONE        |
| `network`       | 2 min      | network.py — NetworkCollector     | DONE        |
| `arp`           | 2 min      | network.py — ArpCollector         | NEEDS IMPL  |
| `mounts`        | 2 min      | network.py — MountsCollector      | NEEDS IMPL  |
| `storage`       | 10 min     | inventory.py — StorageCollector   | DONE        |
| `tasks`         | 10 min     | inventory.py — TasksCollector     | NEEDS IMPL  |
| `apps`          | 24 hr      | inventory.py — AppsCollector      | NEEDS IMPL  |
| `packages`      | 24 hr      | inventory.py — PackagesCollector  | NEEDS IMPL  |
| `binaries`      | 24 hr      | inventory.py — BinariesCollector  | NEEDS IMPL  |
| `sbom`          | 24 hr      | inventory.py — SbomCollector      | NEEDS IMPL  |
| `security`      | 1 hr       | posture.py — SecurityCollector    | DONE        |
| `sysctl`        | 1 hr       | posture.py — SysctlCollector      | DONE        |
| `configs`       | 1 hr       | posture.py — ConfigsCollector     | DONE        |
| `sca`           | 12 hr      | sca.py — ScaCollector             | NEEDS IMPL  |

---

## Collector Specs (what each must return)

### volatile.py — Already implemented, but complete these gaps:

**MetricsCollector** — add per-core CPU list and freq:
```python
"cpu_per_core": psutil.cpu_percent(percpu=True),   # list[float]
"cpu_freq_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else None,
```

**ConnectionsCollector** — add UDP + LISTEN sockets (macOS agent collects both):
```python
# Collect TCP ESTABLISHED + TCP LISTEN + UDP BOUND
for kind in ("tcp", "udp"):
    for c in psutil.net_connections(kind=kind):
        if kind == "tcp" and c.status not in ("ESTABLISHED", "LISTEN"):
            continue
        ...
        row["direction"] = "inbound" if (c.raddr and c.raddr.ip.startswith("0.")) else "outbound"
        row["service"] = _PORT_SERVICES.get(c.laddr.port)  # same port→name map as macOS
```

**ProcessesCollector** — add Authenticode signature check (Windows equivalent of codesign):
```python
import win32api, win32con
def _sign_status(exe: str) -> str | None:
    """Return 'signed', 'unsigned', or None on error."""
    # Use WinVerifyTrust via ctypes — do NOT shell out to sigcheck.exe
    # Cache by (exe_path, mtime) — same bounded-cache pattern as macOS
```

---

### network.py — Implement missing collectors:

**ArpCollector** — parse `arp -a` output (identical Windows/macOS syntax):
```python
class ArpCollector(WinBaseCollector):
    name = "arp"
    timeout = 10

    def collect(self) -> list:
        # `arp -a` output on Windows:
        # Interface: 192.168.1.5 --- 0x4
        #   Internet Address   Physical Address   Type
        #   192.168.1.1        aa-bb-cc-dd-ee-ff  dynamic
        out = self._run(["arp", "-a"])
        rows = []
        for line in out.splitlines():
            # Skip headers / interface lines
            m = re.match(
                r"\s*(\d+\.\d+\.\d+\.\d+)\s+"
                r"([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}"
                r"[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})\s+"
                r"(\w+)", line
            )
            if m:
                mac = m.group(2).replace("-", ":").lower()
                rows.append({
                    "ip":        m.group(1),
                    "mac":       mac,
                    "interface": None,   # arp -a groups by interface above each block
                    "state":     m.group(3).lower(),
                })
        return rows
```

**MountsCollector** — local volumes via psutil + network shares via `net use`:
```python
class MountsCollector(WinBaseCollector):
    name = "mounts"
    timeout = 15

    def collect(self) -> list:
        rows = []
        # Local + removable volumes
        for p in psutil.disk_partitions(all=False):
            rows.append({
                "device": p.device, "mountpoint": p.mountpoint,
                "fstype": p.fstype, "options": p.opts,
                "network": False,
            })
        # Network shares (UNC paths)
        out = self._run(["net", "use"])
        for line in out.splitlines():
            # OK   Z:  \\server\share   Microsoft Windows Network
            m = re.match(r"\s*\w+\s+([A-Z]:)\s+(\\\\[^\s]+)", line)
            if m:
                rows.append({
                    "device": m.group(2), "mountpoint": m.group(1),
                    "fstype": "cifs", "options": "network",
                    "network": True,
                })
        return rows
```

**WiFi detail** — complete `NetworkCollector._get_wifi()` using `netsh wlan`:
```python
def _get_wifi(self) -> tuple[str | None, int | None, str | None]:
    """Returns (ssid, rssi_dbm, bssid)."""
    out = self._run(["netsh", "wlan", "show", "interfaces"])
    ssid = bssid = rssi = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            ssid = line.split(":", 1)[-1].strip()
        elif line.startswith("BSSID"):
            bssid = line.split(":", 1)[-1].strip()
        elif "Signal" in line:
            # "Signal : 85%" → convert to rough dBm: dBm ≈ (pct/2) - 100
            try:
                pct = int(re.search(r"(\d+)%", line).group(1))
                rssi = (pct // 2) - 100
            except Exception:
                pass
    return ssid, rssi, bssid
```

---

### inventory.py — Implement missing collectors:

**AppsCollector** — enumerate installed software from three registry hives:
```python
class AppsCollector(WinBaseCollector):
    name = "apps"
    timeout = 120   # large registry hives can be slow

    _UNINSTALL_PATHS = [
        # 64-bit software
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        # 32-bit software on 64-bit Windows
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        # Per-user installs
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    def collect(self) -> list:
        import winreg
        apps: list[dict] = []
        seen: set[str] = set()
        for hive, path in self._UNINSTALL_PATHS:
            try:
                key = winreg.OpenKey(hive, path)
            except OSError:
                continue
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    sub = winreg.OpenKey(key, sub_name)
                    def _val(k):
                        try: return winreg.QueryValueEx(sub, k)[0]
                        except OSError: return None
                    name    = _val("DisplayName")
                    version = _val("DisplayVersion")
                    vendor  = _val("Publisher")
                    install = _val("InstallDate")  # "YYYYMMDD" or None
                    location= _val("InstallLocation")
                    uninstall= _val("UninstallString")
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    # Parse install date "20240315" → unix timestamp
                    installed_at = None
                    if install and len(install) == 8:
                        try:
                            from datetime import date
                            d = date(int(install[:4]),int(install[4:6]),int(install[6:]))
                            installed_at = int(d.strftime("%s")) if hasattr(d, "strftime") else None
                        except Exception:
                            pass
                    apps.append({
                        "name":         name,
                        "version":      version,
                        "vendor":       vendor,
                        "bundle_id":    sub_name,
                        "installed_at": installed_at,
                        "location":     location,
                        "signed":       None,   # signing check is expensive; skip for 24hr scan
                        "notarized":    None,
                    })
                except Exception:
                    pass
        return apps
```

**PackagesCollector** — pip, npm, choco, winget, scoop:
```python
class PackagesCollector(WinBaseCollector):
    name = "packages"
    timeout = 60

    def collect(self) -> list:
        rows: list[dict] = []
        rows.extend(self._pip())
        rows.extend(self._npm())
        rows.extend(self._choco())
        rows.extend(self._winget())
        rows.extend(self._scoop())
        return rows

    def _pip(self) -> list:
        out = self._run(["pip", "list", "--format=json"])
        try:
            pkgs = json.loads(out)
            return [{"manager":"pip","name":p["name"],"version":p["version"]} for p in pkgs]
        except Exception:
            return []

    def _npm(self) -> list:
        out = self._run(["npm", "list", "-g", "--json", "--depth=0"])
        try:
            d = json.loads(out)
            return [{"manager":"npm","name":n,"version":v.get("version")}
                    for n,v in (d.get("dependencies") or {}).items()]
        except Exception:
            return []

    def _choco(self) -> list:
        out = self._run(["choco", "list", "--local-only", "--limit-output"])
        rows = []
        for line in out.splitlines():
            # "package|1.2.3"
            parts = line.strip().split("|")
            if len(parts) == 2:
                rows.append({"manager":"choco","name":parts[0],"version":parts[1]})
        return rows

    def _winget(self) -> list:
        out = self._run(["winget", "list", "--source", "winget", "--disable-interactivity"])
        rows = []
        # Skip header lines (Name / Id / Version / Available / Source)
        in_table = False
        for line in out.splitlines():
            if line.startswith("---"):
                in_table = True
                continue
            if not in_table:
                continue
            parts = line.split()
            if len(parts) >= 3:
                rows.append({"manager":"winget","name":parts[0],"version":parts[2]})
        return rows

    def _scoop(self) -> list:
        out = self._run_ps("scoop list 2>$null | ConvertTo-Json")
        try:
            items = json.loads(out.strip() or "[]")
            if isinstance(items, dict): items = [items]
            return [{"manager":"scoop","name":i.get("Name"),"version":i.get("Version")}
                    for i in (items or []) if i.get("Name")]
        except Exception:
            return []
```

**BinariesCollector** — SHA-256 of executables in key Windows directories:
```python
class BinariesCollector(WinBaseCollector):
    name = "binaries"
    timeout = 120

    _SCAN_DIRS = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
    ]
    _EXTS = {".exe", ".dll", ".sys"}

    def collect(self) -> list:
        rows: list[dict] = []
        seen: set[str] = set()
        for d in self._SCAN_DIRS:
            if not d or not os.path.isdir(d):
                continue
            for fname in os.listdir(d):
                _, ext = os.path.splitext(fname)
                if ext.lower() not in self._EXTS:
                    continue
                path = os.path.join(d, fname)
                if path in seen:
                    continue
                seen.add(path)
                try:
                    st  = os.stat(path)
                    sha = self._sha256(path)
                    rows.append({
                        "path":       path,
                        "sha256":     sha,
                        "size_bytes": st.st_size,
                        "mode":       None,   # no chmod concept on Windows
                        "setuid":     False,
                        "setgid":     False,
                        "in_path":    True,
                    })
                except (PermissionError, OSError):
                    continue
        return rows

    @staticmethod
    def _sha256(path: str, cap: int = 4 * 1024 * 1024) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read(cap))
        return h.hexdigest()
```

**SbomCollector** — aggregate pip + npm + choco + winget into purl records:
```python
class SbomCollector(WinBaseCollector):
    name = "sbom"
    timeout = 60

    def collect(self) -> list:
        # Reuse PackagesCollector logic and convert to purl
        from .inventory import PackagesCollector
        pkgs = PackagesCollector(self._config).collect()
        rows = []
        for p in pkgs:
            mgr  = p.get("manager", "")
            name = p.get("name") or ""
            ver  = p.get("version") or ""
            # purl scheme: pkg:<manager>/<name>@<version>
            purl = f"pkg:{mgr}/{name}@{ver}" if mgr and name else None
            rows.append({
                "name":    name,
                "version": ver,
                "manager": mgr,
                "purl":    purl,
                "license": None,   # enrichment deferred
            })
        return rows
```

---

### sca.py — Implement Windows CIS benchmark checks:

The macOS SCA thin-wrapper delegates to `agent.agent.sca.ScaEngine`. Replicate
the same pattern for Windows:

```python
"""
agent/os/windows/collectors/sca.py — Security Configuration Assessment (12 hr).

Thin Windows wrapper around the OS-agnostic SCA engine
(agent.agent.sca). Runs every applicable CIS policy under
agent/agent/sca/policies/ plus operator drop-ins in
C:\ProgramData\AttackLens\sca\.

The engine's `c:` rule commands are executed via PowerShell when they
reference PS cmdlets, or cmd.exe for registry/netsh/sc queries.
"""
from __future__ import annotations
import logging
import subprocess
from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.sca")

POLICY_DIR = r"C:\ProgramData\AttackLens\sca"


def _budgeted_runner(cmd: str, timeout: float = 15.0):
    """Run a SCA check command (PowerShell or cmd) under the section budget."""
    # For PS cmdlets detected by "Get-" prefix: run via powershell -Command
    if cmd.strip().lower().startswith(("get-", "invoke-", "test-", "$")):
        proc_cmd = ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd]
    else:
        proc_cmd = ["cmd", "/c", cmd]
    try:
        p = subprocess.run(
            proc_cmd, capture_output=True, text=True, errors="replace", timeout=timeout
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        log.warning("SCA command timed out: %s", cmd)
        return None, ""
    except Exception as exc:
        log.debug("SCA command failed [%s]: %s", cmd, exc)
        return None, ""


class ScaCollector(WinBaseCollector):
    name    = "sca"
    timeout = 600   # 10 min budget for full CIS scan

    def collect(self) -> dict:
        from agent.agent.sca import ScaEngine
        return ScaEngine(
            runner=_budgeted_runner,
            extra_policy_dirs=[POLICY_DIR],
            platform="windows",
        ).scan()
```

**CIS Windows policies to write** (`agent/agent/sca/policies/cis_windows_server_2022.yaml`):

Cover at minimum:

| Check ID | Title                              | Command                                              |
|----------|------------------------------------|------------------------------------------------------|
| W-1.1    | Ensure Secure Boot is enabled      | `Confirm-SecureBootUEFI`                             |
| W-1.2    | Ensure BitLocker on C:             | `(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus` |
| W-1.3    | Ensure UAC is enabled              | `Get-ItemProperty HKLM:\...\Policies\System EnableLUA` |
| W-1.4    | Ensure Defender RTP is on          | `(Get-MpComputerStatus).RealTimeProtectionEnabled`   |
| W-1.5    | Ensure Windows Firewall all on     | `netsh advfirewall show allprofiles state`           |
| W-2.1    | Disable SMBv1                      | `Get-SmbServerConfiguration \| Select EnableSMB1Protocol` |
| W-2.2    | Require SMB signing                | `Get-SmbServerConfiguration \| Select RequireSecuritySignature` |
| W-2.3    | Disable LLMNR                      | `reg query HKLM\...\DNSClient /v EnableMulticast`    |
| W-2.4    | Disable NetBIOS over TCP/IP        | `wmic nicconfig get TcpipNetbiosOptions`             |
| W-3.1    | LSASS PPL enabled                  | `reg query HKLM\...\Lsa /v RunAsPPL`                |
| W-3.2    | Credential Guard enabled           | `reg query HKLM\...\Lsa /v LsaCfgFlags`             |
| W-3.3    | Guest account disabled             | `Get-LocalUser Guest \| Select Enabled`              |
| W-3.4    | Admin account renamed              | `Get-LocalUser Administrator \| Select Name,Enabled` |
| W-4.1    | Auto-update enabled                | `reg query HKLM\...\AU /v NoAutoUpdate`              |
| W-4.2    | Last patch ≤ 30 days               | `Get-HotFix \| Sort InstalledOn \| Select -Last 1`  |
| W-4.3    | Audit policy configured            | `auditpol /get /category:*`                          |
| W-5.1    | RDP NLA required                   | `reg query "HKLM\...\Terminal Services" /v UserAuthentication` |
| W-5.2    | Remote Registry disabled           | `sc query RemoteRegistry`                            |
| W-5.3    | Telnet service absent              | `sc query TlntSvr`                                   |

---

### normalizer.py — Add missing sections

The normalizer already handles: `metrics`, `connections`, `processes`, `battery`,
`openfiles`, `services`, `users`, `hardware`, `containers`, `ports`, `network`,
`security`, `sysctl`, `configs`, `storage`.

**Add these missing sections:**

```python
def _arp(raw: list) -> list:
    if not isinstance(raw, list): return raw
    return [{"ip": _s(r.get("ip")), "mac": _s_opt(r.get("mac")),
             "interface": _s_opt(r.get("interface")),
             "state": _s_opt(r.get("state"))} for r in raw]

def _mounts(raw: list) -> list:
    if not isinstance(raw, list): return raw
    return [{"device": _s(r.get("device")), "mountpoint": _s(r.get("mountpoint")),
             "fstype": _s_opt(r.get("fstype")), "options": _s_opt(r.get("options")),
             "network": bool(r.get("network"))} for r in raw]

def _apps(raw: list) -> list:
    if not isinstance(raw, list): return raw
    return [{"name": _s(r.get("name")), "version": _s_opt(r.get("version")),
             "vendor": _s_opt(r.get("vendor")), "bundle_id": _s_opt(r.get("bundle_id")),
             "installed_at": _i_opt(r.get("installed_at")),
             "signed": r.get("signed"), "notarized": r.get("notarized")} for r in raw]

def _packages(raw: list) -> list:
    if not isinstance(raw, list): return raw
    return [{"manager": _s(r.get("manager")), "name": _s(r.get("name")),
             "version": _s_opt(r.get("version"))} for r in raw]

def _binaries(raw: list) -> list:
    if not isinstance(raw, list): return raw
    return [{"path": _s(r.get("path")), "sha256": _s_opt(r.get("sha256")),
             "size_bytes": _i_opt(r.get("size_bytes")),
             "setuid": bool(r.get("setuid")), "setgid": bool(r.get("setgid")),
             "in_path": bool(r.get("in_path"))} for r in raw]

def _sbom(raw: list) -> list:
    if not isinstance(raw, list): return raw
    return [{"name": _s(r.get("name")), "version": _s_opt(r.get("version")),
             "manager": _s_opt(r.get("manager")), "purl": _s_opt(r.get("purl")),
             "license": _s_opt(r.get("license"))} for r in raw]

def _tasks(raw: list) -> list:
    if not isinstance(raw, list): return raw
    return [{"name": _s(r.get("name")), "type": _s(r.get("type")),
             "schedule": _s_opt(r.get("schedule")), "command": _s_opt(r.get("command")),
             "user": _s_opt(r.get("user")), "enabled": r.get("enabled"),
             "last_run": _i_opt(r.get("last_run")),
             "next_run": _i_opt(r.get("next_run"))} for r in raw]

_NORMALIZERS = {
    ...,   # existing entries
    "arp":      _arp,
    "mounts":   _mounts,
    "apps":     _apps,
    "packages": _packages,
    "binaries": _binaries,
    "sbom":     _sbom,
    "tasks":    _tasks,
    "sca":      lambda r: r,  # SCA engine returns canonical format already
}
```

---

## macOS vs Windows API Equivalents

| macOS source               | Windows equivalent                                     |
|----------------------------|--------------------------------------------------------|
| `pmset -g batt`            | `psutil.sensors_battery()` + `Win32_Battery` via CIM  |
| `codesign --verify`        | `WinVerifyTrust` (Wintrust.dll) via ctypes             |
| `system_profiler SPAirPortDataType` | `netsh wlan show interfaces`               |
| `scutil --dns`             | `netsh dns show state` or `Get-DnsClientServerAddress`|
| `route -n get default`     | `route print 0.0.0.0`                                 |
| `dscl . list /Users`       | `Get-LocalUser` PowerShell cmdlet                     |
| `launchctl list`           | `psutil.win_service_iter()` + `sc query`              |
| `plutil -convert json`     | `winreg` module (reads HKLM/HKCU directly)            |
| `sysctl -a`                | `winreg` reads of security hive paths                 |
| `csrutil status`           | `Confirm-SecureBootUEFI` / `HKLM\SecureBoot\State`   |
| `fdesetup status`          | `manage-bde -status C:` / `Get-BitLockerVolume`       |
| `spctl --status`           | SmartScreen: `HKLM\...\System\EnableSmartScreen`      |
| `launchd timer plist`      | `Get-ScheduledTask` / `schtasks /query`               |
| `brew list --json`         | `choco list --local-only` / `winget list`             |
| `pip3 list --format=json`  | `pip list --format=json` (same)                       |
| `df -H`                    | `psutil.disk_partitions()` (same)                     |
| `arp -a -n`                | `arp -a` (identical syntax)                           |
| `lsof -nP -iTCP:LISTEN`    | `psutil.net_connections()` (same)                     |
| `/etc/ssh/sshd_config`     | `C:\ProgramData\ssh\sshd_config`                      |
| `~/.ssh/authorized_keys`   | `C:\ProgramData\ssh\administrators_authorized_keys`   |
| `/etc/hosts`               | `C:\Windows\System32\drivers\etc\hosts`               |
| `.zshrc` / `.bashrc`       | PowerShell profile (`$PROFILE`)                       |
| Keychain (macOS)           | Windows Credential Manager (DPAPI) — already in keystore.py |
| `LaunchDaemon` plist       | Windows Service (SCM) — already in service.py        |

---

## WinBaseCollector — Helper methods available

`self._run(cmd: list[str]) -> str`  — runs subprocess, returns stdout, swallows errors  
`self._run_ps(ps_script: str) -> str`  — wraps `powershell -NonInteractive -NoProfile -Command`  
`self.reg_get(hive, path, name=None)` — reads one value or all values from a registry key  

If `_run_ps` is not yet implemented in `base.py`, add it:
```python
def _run_ps(self, script: str, timeout: int = 30) -> str:
    return self._run([
        "powershell", "-NonInteractive", "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ], timeout=timeout)
```

---

## Build & Package

```
# Install deps
pip install -r agent/os/windows/requirements.txt
python Scripts/pywin32_postinstall.py -install

# Build single-file EXE
pyinstaller --onefile \
  --name attacklens-agent \
  --hidden-import agent.agent.circuit_breaker \
  --hidden-import agent.os.windows.collectors \
  --hidden-import agent.os.windows.service \
  --hidden-import win32timezone \
  agent/os/windows/agent_win_entry.py

# Install as service
attacklens-agent.exe install
attacklens-agent.exe start

# Test in foreground (no UAC popup, no SCM needed)
attacklens-agent.exe debug
```

---

## Testing

Write unit tests in `agent/tests/test_windows_collectors.py`:

```python
import pytest
from unittest.mock import patch, MagicMock

# Test each collector with mocked psutil and subprocess outputs
# Use the macOS agent's test suite as the template
# Key invariants:
#   1. collect() never raises — always returns dict or list
#   2. Every required canonical field is present (may be None)
#   3. Budget-aware collectors return partial results, not empty
#   4. Normalizer output matches schema (no extra/missing top-level keys)
```

---

## What macOS Has That Windows Does NOT Need to Match

| macOS feature              | Windows decision                                        |
|----------------------------|---------------------------------------------------------|
| SIP (System Integrity Protection) | No equivalent — check Secure Boot + WDAC instead  |
| Gatekeeper                 | Check SmartScreen registry key                         |
| FileVault                  | BitLocker — already in posture.py                      |
| XProtect version           | Defender engine version: `Get-MpComputerStatus \| Select AMProductVersion` |
| `pmset` power settings     | Battery via WMI Win32_Battery — already in system.py   |
| Apple Silicon chip info    | CPU brand via `wmic cpu get name` or `psutil.cpu_freq()` |
| Notarization               | Authenticode signature via WinVerifyTrust              |
| Lockdown Mode              | No direct equivalent; check Credential Guard           |
| BSM audit (`auditd`)       | Windows Event Log / `auditpol` — add to SCA checks     |
| LaunchAgent persistence    | Task Scheduler + Registry Run keys                     |
| `brew`                     | `choco`, `winget`, `scoop`                             |

---

## Done when:

- [ ] All collectors in the schedule table above are fully implemented
- [ ] `normalizer.py` handles every section returned by collectors
- [ ] `sca.py` delegates to `ScaEngine` and CIS policy file exists
- [ ] `requirements.txt` is complete and pinned
- [ ] `pyinstaller` build produces a working single-file EXE
- [ ] Service installs, starts, and begins sending telemetry to manager
- [ ] Unit tests pass for all collector `collect()` methods
- [ ] `attacklens-agent.exe debug` produces valid NDJSON payloads on stdout
