# AttackLens Windows Agent — Installation Guide

> Startup incident guidance was updated on 2026-08-09 and consolidated in [`advanced_support/`](advanced_support/README.md).

**Applies to:** v2.0+  
**Last updated:** 2026-05-25

---

## What Gets Installed

| Component | Location |
|-----------|----------|
| Agent service binary | `C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe` |
| Watchdog service binary | `C:\Program Files\AttackLens\bin\attacklens-watchdog\attacklens-watchdog.exe` |
| Configuration file | `C:\ProgramData\AttackLens\config\agent.toml` |
| Log files | `C:\ProgramData\AttackLens\logs\agent.log` |
| API key (after enrollment) | `C:\ProgramData\AttackLens\security\client.key` |
| Offline spool buffer | `C:\ProgramData\AttackLens\spool\win_agent.spool.ndjson` |

Two Windows Services are created:

| Service name | Display name | Role |
|---|---|---|
| `AttackLensAgent` | AttackLens Agent | Collects and ships telemetry |
| `AttackLensWatchdog` | AttackLens Watchdog | Restarts agent on crash (max 5× per 5 min) |

Both services run as `LocalSystem`, start with the machine (delayed-auto), and depend on `Tcpip` + `Dnscache` so the network is ready before enrollment starts.

---

## Prerequisites

- **Windows 10 / Server 2016 or newer** (64-bit)
- **Administrator rights** on the endpoint
- **Manager is running** and reachable on the network
- **Enrollment token** from the manager (or open enrollment enabled on manager)

Verify manager reachability before installing:
```powershell
# Replace with your manager IP and port
Test-NetConnection -ComputerName "34.224.174.38" -Port 8443
```

## 2.0.11 current installer behavior

Use `pkg\dist\attacklens-agent-2.0.11-x64.msi`. The interactive page contains
one required manager-address input; IP/DNS values become HTTP/8080 and full
HTTP(S) URLs are preserved. GUI values are staged in a Secure+Hidden MSI
property before elevation. Binaries/tools install to Program Files; config,
logs, security, spool, data, status, and support install to ProgramData.

The protected TOML is editable from Administrator PowerShell through
`tools\edit-agent-config.ps1`; manager-only repair uses
`tools\configure-manager.ps1 -ManagerUrl <IP-or-DNS>`.

## 2.0.10 installed operator tools

- `C:\Program Files\AttackLens\RUNTIME_LOCATION.txt` documents every mutable path.
- `tools\attacklens-status.ps1` reads sanitized public status without exposing secrets.
- `tools\configure-manager.ps1` atomically repairs manager/TLS/enrollment settings from an Administrator terminal.
- `tools\edit-agent-config.ps1` provides elevated staged editing with validation, backup, rollback, and service restart.
- `C:\ProgramData\AttackLens\status\agent-status.json` distinguishes running,
  enrollment-pending, backoff, authentication failure, and manager-unconfigured states.

---

## Option A — MSI Install (Recommended for Production)

The MSI is the signed, upgrade-safe production installer.

### Step 1 — Build the MSI

From the `agent\os\windows\pkg\` directory (on a developer machine):

```powershell
# Full build: PyInstaller → WiX → MSI
.\build_attacklens_msi.ps1 -Version "2.0.10"

# Quick rebuild (reuse existing EXEs, rebuild MSI only)
.\build_attacklens_msi.ps1 -Version "2.0.10" -SkipBuild

# Signed build for enterprise deployment
.\build_attacklens_msi.ps1 -Version "2.0.10" -SignIdentity "CN=AttackLens Inc"
```

**Build prerequisites** (developer machine only — not needed on endpoints):
```powershell
pip install pyinstaller pywin32 psutil requests cryptography keyring tomli
dotnet tool install --global wix
wix extension add WixToolset.Util.wixext
```

Output: `pkg\dist\attacklens-agent-2.0.10-x64.msi`

---

### Step 2 — Run the MSI on the Endpoint

#### HTTP compatibility deployment (default)

```cmd
msiexec /i "attacklens-agent-2.0.10-x64.msi" /qn ^
    MANAGER_IP="34.224.174.38" ^
    MANAGER_PORT="8080" ^
    ALLOW_INSECURE_TRANSPORT="true" ^
    ENROLL_TOKEN="sk-enroll-abc123" ^
    /l*v "%TEMP%\attacklens-install.log"
```

#### Production / Valid CA Certificate

```cmd
msiexec /i "attacklens-agent-2.0.10-x64.msi" /qn ^
    MANAGER_IP="manager.corp.example" ^
    MANAGER_PORT="443" ^
    TLS_VERIFY="true" ^
    ENROLL_TOKEN="sk-enroll-abc123" ^
    AGENT_NAME="WORKSTATION-01" ^
    /l*v "%TEMP%\attacklens-install.log"
```

#### PowerShell one-liner

```powershell
Start-Process msiexec -Wait -ArgumentList @(
    '/i', 'attacklens-agent-2.0.10-x64.msi',
    '/qn',
    'MANAGER_IP=34.224.174.38',
    'MANAGER_PORT=8080',
    'ALLOW_INSECURE_TRANSPORT=true',
    'ENROLL_TOKEN=sk-enroll-abc123',
    '/l*v', "$env:TEMP\attacklens-install.log"
)
```

#### MSI Properties Reference

| Property | Default | Description |
|----------|---------|-------------|
| `MANAGER_IP` | *(empty)* | Manager hostname or IP — **no scheme, no port** |
| `MANAGER_PORT` | `8080` | Default manager port |
| `TLS_VERIFY` | `false` | HTTP default; set `true` for verified HTTPS |
| `ALLOW_INSECURE_TRANSPORT` | `true` | Allows the requested HTTP default |
| `ENROLL_TOKEN` | *(empty)* | Enrollment token; empty = open enrollment |
| `AGENT_NAME` | `%COMPUTERNAME%` | Human label in the AttackLens dashboard |

> Host-only configuration builds `http://<host>:8080`. Supply an explicit
> `https://` URL and set `TLS_VERIFY=true` for encrypted production transport.

#### Silent Uninstall

```cmd
msiexec /x "attacklens-agent-2.0.10-x64.msi" /qn
```

---

## Option B — Script Install (Dev / No MSI)

Use this when deploying directly from source or pre-built EXEs without the MSI.

### Step 1 — Build EXEs Only

```powershell
cd agent\os\windows\pkg

# Build EXEs without packaging into MSI
pyinstaller attacklens-agent.spec
pyinstaller attacklens-watchdog.spec

# Output:
#   pkg\dist\attacklens-agent\attacklens-agent.exe   + _internal\
#   pkg\dist\attacklens-watchdog\attacklens-watchdog.exe + _internal\
```

### Step 2 — Run install.ps1

The install script is in `agent\os\windows\installer\`:

```powershell
cd agent\os\windows\installer

# Minimal (open enrollment, self-signed cert)
.\install.ps1 -ManagerIP "34.224.174.38"

# With token and TLS
.\install.ps1 `
    -ManagerIP   "34.224.174.38" `
    -ManagerPort 8443 `
    -TlsVerify   $false `
    -EnrollToken "sk-enroll-abc123" `
    -AgentName   "DEV-WIN-01"

# Production
.\install.ps1 `
    -ManagerIP   "manager.corp.example" `
    -ManagerPort 443 `
    -TlsVerify   $true `
    -EnrollToken "sk-enroll-abc123" `
    -AgentName   "WORKSTATION-01"
```

The script auto-detects the built EXE directories relative to itself.  
Full parameter reference: `Get-Help .\install.ps1 -Full`

### Uninstall (Script)

```powershell
# Full wipe (removes binaries, config, logs, keys)
.\uninstall.ps1

# Preserve config + API key (for reinstall without re-enrollment)
.\uninstall.ps1 -KeepData $true
```

---

## Step 3 — Verify Installation

Run these in an elevated PowerShell after installing via either method:

```powershell
# 1. Both services should show Running / Automatic
Get-Service AttackLensAgent, AttackLensWatchdog | Select Name, Status, StartType

# 2. client.key appears within ~30 s of first start (proof of enrollment)
Test-Path "C:\ProgramData\AttackLens\security\client.key"

# 3. Live log — watch for "Enrollment OK" and first successful POST
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 30 -Wait
```

**Expected log on successful startup:**
```
INFO  agent.windows      Windows agent starting  agent_id=win-XXXX  name=WORKSTATION-01
INFO  agent.auto_enroll  Enrolling: agent_name='WORKSTATION-01' ...
INFO  agent.auto_enroll  Auto-enrollment complete: ...
INFO  agent.windows      Enrollment OK  agent_name='WORKSTATION-01'
INFO  agent.windows      Agent running: 22 collector threads + sender + heartbeat (disabled=1)
```

---

## Step 4 — Day-to-Day Management

Use the `attacklens-service.ps1` management CLI (in `installer\`):

```powershell
$cli = ".\installer\attacklens-service.ps1"

# Show service status, config summary, last 10 log lines
& $cli status

# Start / stop / restart services
& $cli start
& $cli stop
& $cli restart

# Tail the live log
& $cli logs

# Run health check (connectivity, services, dirs, enrollment)
& $cli diagnose

# Auto-fix common problems (services stopped, ACLs, missing dirs, enrollment)
& $cli repair

# Change manager IP (updates config + clears old key + restarts)
& $cli set-manager "10.0.0.5"
& $cli set-manager "https://manager.corp.example:443"

# Force re-enrollment (clears API key, restarts agent)
& $cli enroll

# Show current config
& $cli config

# Show version
& $cli version
```

---

## Upgrade

### Via MSI

The MSI uses `MajorUpgrade` with `AllowSameVersionUpgrades`, so you can install
over an existing installation without uninstalling first:

```cmd
msiexec /i "attacklens-agent-2.1.0-x64.msi" /qn ^
    MANAGER_IP="34.224.174.38" ^
    MANAGER_PORT="8443" ^
    /l*v "%TEMP%\attacklens-upgrade.log"
```

The existing `agent.toml` is regenerated but your `agent_id` and `client.key`
are preserved — the agent does **not** re-enroll after an upgrade.

### Via Script

```powershell
# Stop, reinstall binaries, restart (config + key preserved)
.\uninstall.ps1 -KeepData $true
.\install.ps1 -ManagerIP "34.224.174.38" -EnrollToken "sk-enroll-abc123"
```

---

## Enterprise Deployment

### Group Policy (GPO Software Installation)

1. Place MSI on a network share: `\\fileserver\software\AttackLens\`
2. GPO: *Computer Configuration → Software Settings → Software Installation → New Package*
3. Deploy type: **Assigned** (installs at machine startup)
4. For MSI properties, deploy via a startup script instead of the Software Installation snap-in:

```bat
:: startup_install_attacklens.bat (run by GPO Computer Startup Scripts)
if exist "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" goto :done
msiexec /i "\\fileserver\software\AttackLens\attacklens-agent-2.0.10-x64.msi" /qn ^
    MANAGER_IP="34.224.174.38" MANAGER_PORT="8443" ^
    ENROLL_TOKEN="sk-enroll-abc123" ^
    /l*v "%TEMP%\attacklens-install.log"
:done
```

### Microsoft Intune (Windows LOB App)

1. Upload the `.msi` as a **Line-of-business app**
2. Install command:
   ```
   msiexec /i "attacklens-agent-2.0.10-x64.msi" /qn MANAGER_IP="34.224.174.38" MANAGER_PORT="8443" ENROLL_TOKEN="sk-enroll-abc123"
   ```
3. Uninstall command:
   ```
   msiexec /x {YOUR-PRODUCT-GUID} /qn
   ```
   *(Get GUID from `pkg\attacklens.wxs` `<Package Id=` attribute)*
4. Detection rule: **Registry** → `HKLM\SOFTWARE\AttackLens\Agent` → key exists

---

## Configuration Reference

The config file lives at `C:\ProgramData\AttackLens\config\agent.toml`.  
Edit it and restart the service to apply changes.

```toml
[agent]
id   = "win-<MachineGuid>"   # stable — do not change after enrollment
name = "WORKSTATION-01"       # display name in the dashboard

[manager]
url         = "https://34.224.174.38:8443"
tls_verify  = false            # true = require valid CA cert
timeout_sec = 30

[enrollment]
token    = ""                  # empty after first enrollment
keystore = "dpapi"             # dpapi (recommended) | file

[paths]
security_dir = "C:/ProgramData/AttackLens/security"
log_dir      = "C:/ProgramData/AttackLens/logs"
spool_dir    = "C:/ProgramData/AttackLens/spool"

[logging]
level   = "INFO"               # DEBUG | INFO | WARNING | ERROR
file    = "C:/ProgramData/AttackLens/logs/agent.log"
max_mb  = 10
backups = 5

# ── Per-section overrides (all sections default to enabled) ──────────────────
[collection.sections.binaries]
enabled = false         # disable the slow binary walk (enabled by default is false)

[collection.sections.metrics]
interval_sec = 30       # slow down metrics collection from 10 s to 30 s
```

> **TOML path syntax:** Always use forward slashes `/` or escaped backslashes `\\`  
> in path strings. A bare backslash `\` is a TOML escape character.

---

## Troubleshooting Quick Reference

| Symptom | First thing to check |
|---------|---------------------|
| Service won't start | `Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 50` |
| `client.key` not appearing after ~30 s | Manager reachable? `Test-NetConnection -ComputerName <IP> -Port <port>` |
| Manager returned HTTP 401 (enrollment) | Wrong `ENROLL_TOKEN` — check manager logs |
| Manager returned HTTP 401 (after enrollment) | API key revoked — delete `client.key` and restart |
| Spool growing, nothing sent | Manager unreachable — agent backs off 5 s → 300 s and retries |
| "service did not respond to start" | Run in debug mode: `cd "C:\Program Files\AttackLens\bin\attacklens-agent"` then `.\attacklens-agent.exe debug` |
| TLS / certificate error | Set `tls_verify = false` in agent.toml for self-signed cert |
| SPKI pin mismatch | Manager cert rotated — update `spki_pin` in agent.toml |

**Full troubleshooting guide:** `TROUBLESHOOTING.md` in this directory.

**Install log** (MSI): `%TEMP%\attacklens-install.log` — search for `CA_WriteConfig` to debug config generation failures.

---

## File Summary

```
agent/os/windows/
├── INSTALLATION.md          ← This file
├── TROUBLESHOOTING.md       ← Full troubleshooting guide
├── AGENT_ARCHITECTURE.md    ← Deep-dive: security, collectors, data flow
│
├── installer/
│   ├── install.ps1          ← Script installer (no MSI needed)
│   ├── uninstall.ps1        ← Script uninstaller
│   └── attacklens-service.ps1 ← Management CLI (status/start/stop/diagnose/...)
│
└── pkg/
    ├── build_attacklens_msi.ps1   ← PRIMARY build script
    ├── attacklens-agent.spec      ← PyInstaller spec
    ├── attacklens-watchdog.spec   ← PyInstaller spec
    ├── attacklens.wxs             ← WiX MSI definition
    └── gen_config.ps1             ← Config generator (embedded in MSI)
```
