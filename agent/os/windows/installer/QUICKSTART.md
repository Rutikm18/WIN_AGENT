# AttackLens Agent — Legacy Source-Installer Quick Start

> This folder is retained for compatibility. New 2.0.24 packages are built with
> `..\build_windows_msi.ps1`; use [../INSTALL.md](../INSTALL.md) for current
> installation commands. Versioned examples below document the legacy path.

> Service startup diagnosis, safe repair, support bundles, and Docker scenarios are consolidated in [`../advanced_support/`](../advanced_support/README.md).

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Windows | 10 21H2+ / 11 / Server 2019/2022 | x64 only |
| Python | 3.11+ | Must be in PATH or installed to a standard location |
| Administrator rights | — | Required for MSI install and service management |

---

## Install

### Silent install (recommended for deployments)

```powershell
msiexec /i attacklens-agent-2.0.7-x64.msi /qn `
    MANAGER_URL="http://34.224.174.38:8080" `
    AGENT_NAME="WORKSTATION-01" `
    /l*v install.log
```

### Interactive install (GUI wizard)

```powershell
msiexec /i attacklens-agent-2.0.7-x64.msi
```

The wizard prompts for Manager URL and Agent Name. Click Install.

### With enrollment token




### With pre-shared API key (skip enrollment)

```powershell
msiexec /i attacklens-agent-2.0.7-x64.msi /qn `
    MANAGER_URL="http://34.224.174.38:8080" `
    MANAGER_API_KEY="<64-hex-key>" `
    AGENT_NAME="LAPTOP-01"
```

### MSI Properties Reference

| Property | Default | Description |
|---|---|---|
| `MANAGER_URL` | — | Manager HTTP(S) endpoint (required) |
| `ENROLL_TOKEN` | — | One-time enrollment token |
| `MANAGER_API_KEY` | — | Pre-shared 64-hex API key (skips enrollment) |
| `TLS_VERIFY` | `true` | `true` / `false` / path-to-CA-bundle |
| `SPKI_PIN` | — | SPKI cert pin to prevent MITM via rogue CA |
| `AGENT_ID` | Machine GUID | Custom agent identifier |
| `AGENT_NAME` | Computer name | Human-readable label on dashboard |

---

## Verify install

```powershell
# Requires Administrator (open an elevated PowerShell)

attacklens-service version       # version + python info + OS build
attacklens-service status        # both services running, manager URL set
attacklens-service diagnose      # all checks green = healthy
attacklens-service logs          # live log stream (Ctrl+C to stop)
```

Expected `diagnose` output (all green):

```
  [OK]  Windows 10/11 or Server 2019/2022
  [OK]  Python 3.11+ found
  [OK]  Python package: psutil
  [OK]  Python package: cryptography
  [OK]  Python package: requests
  [OK]  Python package: keyring
  [OK]  Python package: win32service
  [OK]  Install dir exists
  [OK]  agent.toml exists
  [OK]  run_agent.py exists
  [OK]  Manager URL not placeholder
  [OK]  TCP 34.224.174.38:8080 reachable
  [OK]  Manager /health responded 200
  [OK]  Service AttackLensAgent installed
  [OK]  Service AttackLensAgent running
  [OK]  Service AttackLensWatchdog installed
  [OK]  Service AttackLensWatchdog running
  [OK]  client.key present (enrolled)

  All 18 checks passed.
```

---

## Service management

> All commands that change service state require an **Administrator** terminal.

```powershell
attacklens-service start         # start both services
attacklens-service stop          # stop both services
attacklens-service restart       # stop then start
attacklens-service reload        # reload config (restart)
attacklens-service status        # service status + config summary
attacklens-service logs          # tail agent.log in real time
attacklens-service logs -Follow:$false -Lines 200  # dump last 200 lines
attacklens-service config        # print agent.toml
attacklens-service version       # version + OS info
attacklens-service diagnose      # health check
```

---

## Change the manager

```powershell
# Accepts IP, IP:port, or full URL
attacklens-service set-manager 34.224.174.38
attacklens-service set-manager http://34.224.174.38:8080
attacklens-service set-manager https://manager.corp.example:443
```

This updates `agent.toml`, clears the stored API key, and restarts the services.
The agent will re-enroll with the new manager on next start.

---

## Force re-enrollment

```powershell
attacklens-service enroll
```

Stops the agent, deletes `security\client.key` and DPAPI key files, clears the
Windows Credential Manager entry, then restarts. The agent will enroll fresh.

---

## Update configuration

```powershell
attacklens-service update-config
```

Regenerates `agent.toml` from defaults (preserves `agent.id` and `agent.name`).
Useful after an upgrade or to reset collection intervals.

---

## Silent uninstall

```powershell
msiexec /x attacklens-agent-2.0.7-x64.msi /qn
```

Stops and removes both services. **Data in `C:\ProgramData\AttackLens\` is also
removed.** Back up `agent.toml` first if you need the agent ID.

---

## File locations

| Path | Contents |
|---|---|
| `C:\Program Files\AttackLens\src\` | Python agent source |
| `C:\Program Files\AttackLens\bin\` | `run_agent.py`, `run_watchdog.py` |
| `C:\Program Files\AttackLens\scripts\` | Management scripts (on PATH) |
| `C:\ProgramData\AttackLens\agent.toml` | Configuration |
| `C:\ProgramData\AttackLens\logs\agent.log` | Agent log |
| `C:\ProgramData\AttackLens\security\` | DPAPI keys (SYSTEM + Admins only) |
| `C:\ProgramData\AttackLens\spool\` | Offline queue (NDJSON+gzip) |
| `C:\ProgramData\AttackLens\data\` | Agent state |

---

## Windows Services

| Service | Display name | Purpose |
|---|---|---|
| `AttackLensAgent` | AttackLens Agent | Main telemetry collector |
| `AttackLensWatchdog` | AttackLens Watchdog | Restarts agent on crash |

Both services run as **LocalSystem** by default, start type **Automatic (Delayed)**.

Recovery policy: restart after 10 s (first two failures), then 60 s.

---

## Troubleshooting

| Symptom | Resolution |
|---|---|
| Service won't start | `attacklens-service logs` — check for Python import errors |
| `pywin32` not installed | `python -m pip install pywin32` + `python Scripts\pywin32_postinstall.py -install` |
| `diagnose` shows Python missing | Install Python 3.11+ and re-run `setup_services.ps1 -Action Install` |
| Agent not enrolling | Check `MANAGER_URL` in `agent.toml`, verify TCP connectivity with `diagnose` |
| `wmi` errors in log | `python -m pip install wmi` — optional, psutil fallback is used if absent |
| Antivirus blocking agent | Add `C:\Program Files\AttackLens\` and Python to AV exclusions |
| "Access Denied" in logs | Some data (open files, security events) requires LocalSystem — confirm service account |

### View Windows Event Log entries

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; Source='AttackLensAgent'} -MaxEvents 20 |
    Format-List TimeCreated, Message
```

### Check service registration

```powershell
sc.exe qc AttackLensAgent
sc.exe qc AttackLensWatchdog
```

---

## Build MSI from source

```powershell
# From agent\os\windows\installer\
.\build_msi.ps1 -Version "2.0.7"

# Signed release build
.\build_msi.ps1 -Version "2.0.7" -SignIdentity "CN=AttackLens Inc"

# Reuse existing build\src\ (faster rebuild)
.\build_msi.ps1 -SkipSource
```

Requirements: WiX v4 (`dotnet tool install --global wix`) and Python 3.11+.

---

## Deploy via Group Policy / Intune

Upload `attacklens-agent-2.0.7-x64.msi` to your MDM or GPO software distribution.

Set properties:

| Property | Value |
|---|---|
| `MANAGER_URL` | `http://34.224.174.38:8080` |
| `AGENT_NAME` | `%COMPUTERNAME%` |
| `TLS_VERIFY` | `false` (or `true` with a valid cert) |

Silent install command:

```
msiexec /i attacklens-agent-2.0.7-x64.msi /qn MANAGER_URL="http://34.224.174.38:8080" AGENT_NAME="%COMPUTERNAME%"
```
