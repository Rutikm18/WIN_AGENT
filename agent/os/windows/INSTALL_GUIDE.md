# AttackLens Agent — Windows Installation & Configuration Guide

> For service startup diagnosis, safe repair, support bundles, and Docker scenarios, use [`advanced_support/`](advanced_support/README.md).

## Overview

The AttackLens Windows Agent is a self-contained telemetry agent that:
- Collects system metrics, network activity, security posture, software inventory
- Encrypts and sends telemetry to the AttackLens Manager
- Runs as two Windows Services: `AttackLensAgent` + `AttackLensWatchdog`
- Requires **no Python** on the target machine (fully compiled EXE)

---

## File Layout (After Install)

```
C:\Program Files\AttackLens\
  attacklens-agent.exe       — Agent service binary (self-contained)
  attacklens-watchdog.exe    — Watchdog service binary
  scripts\
    attacklens-service.ps1   — Management CLI
    attacklens-service.cmd   — CMD shim (on PATH)
    generate_config.ps1      — Config generator (used by MSI)

C:\ProgramData\AttackLens\
  agent.toml                 — Configuration file
  logs\
    agent.log                — Rolling log (10 MB × 5)
  security\                  — API keys (SYSTEM + Admins only)
  spool\                     — Offline telemetry buffer
```

---

## Part 1 — Build the MSI (Developer / CI)

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.11+ | python.org |
| PyInstaller | 6+ | `pip install pyinstaller` |
| .NET SDK | 6+ | dotnet.microsoft.com |
| WiX v4 | 4.0+ | `dotnet tool install --global wix` |

### Build Steps

```powershell
# 1. Navigate to the pkg directory
cd agent\os\windows\pkg

# 2. Full build (EXEs + MSI)
.\build_attacklens_msi.ps1 -Version "2.0.10"

# 3. Skip PyInstaller if EXEs already built
.\build_attacklens_msi.ps1 -SkipBuildExe

# 4. Signed release build
.\build_attacklens_msi.ps1 -Version "2.0.10" -SignIdentity "CN=AttackLens Inc"
```

Output: `agent\os\windows\pkg\dist\attacklens-agent-2.0.10-x64.msi`

### What the Build Does

```
[1/3]  PyInstaller  → attacklens-agent.exe    (~15 MB, self-contained)
                    → attacklens-watchdog.exe  (~7 MB, self-contained)
[2/3]  WiX locate  → wix.exe (auto-installs if not found)
[3/3]  wix build   → attacklens-agent-2.0.10-x64.msi (~22 MB)
```

---

## Part 2 — Install the MSI

### 2.1 Interactive Install (GUI)

```cmd
msiexec /i attacklens-agent-2.0.10-x64.msi
```

Enter the Manager URL and optional enrollment token in the dialog, then click Install.

---

### 2.2 Silent Install — Basic

```cmd
msiexec /i attacklens-agent-2.0.10-x64.msi /qn ^
    MANAGER_URL="http://34.224.174.38" ^
    AGENT_NAME="WORKSTATION-01" ^
    /l*v install.log
```

| Property | Description | Default |
|----------|-------------|---------|
| `MANAGER_URL` | Manager HTTP(S) endpoint | *(empty; host-only input uses HTTP/8080)* |
| `AGENT_NAME` | Human label for this agent | `%COMPUTERNAME%` |
| `ENROLL_TOKEN` | One-time enrollment token | *(empty = open enrollment)* |
| `MANAGER_API_KEY` | Pre-shared 64-hex API key (skips enrollment) | *(empty)* |
| `TLS_VERIFY` | `true` / `false` / path-to-CA-bundle | `false` |
| `ALLOW_INSECURE_TRANSPORT` | Allow HTTP manager delivery | `true` |
| `SPKI_PIN` | `sha256//base64==` certificate pin | *(empty)* |
| `AGENT_ID` | Override agent ID (default: from MachineGuid) | *(auto)* |

---

### 2.3 Silent Install — With Enrollment Token

```cmd
msiexec /i attacklens-agent-2.0.10-x64.msi /qn ^
    MANAGER_URL="https://manager.corp.example:443" ^
    ENROLL_TOKEN="sk-enroll-abc123" ^
    AGENT_NAME="LAPTOP-01" ^
    TLS_VERIFY="true" ^
    /l*v install.log
```

---

### 2.4 Silent Install — Dev / Self-Signed Cert

```cmd
msiexec /i attacklens-agent-2.0.10-x64.msi /qn ^
    MANAGER_URL="http://34.224.174.38" ^
    AGENT_NAME="DEV-WIN-01" ^
    TLS_VERIFY="false" ^
    /l*v install.log
```

---

### 2.5 Silent Uninstall

```cmd
msiexec /x attacklens-agent-2.0.10-x64.msi /qn
```

Or by product code:

```cmd
msiexec /x {A1B2C3D4-E5F6-7890-ABCD-EF1234567890} /qn
```

---

### 2.6 What the MSI Does (Install Sequence)

1. Stops any running `AttackLensAgent` / `AttackLensWatchdog` services (upgrade)
2. Installs files to `C:\Program Files\AttackLens\`
3. Creates `C:\ProgramData\AttackLens\{logs,security,spool}` with ACLs
4. Runs `generate_config.ps1` → writes `C:\ProgramData\AttackLens\agent.toml`
5. Registers `AttackLensAgent` Windows Service (delayed auto-start)
6. Registers `AttackLensWatchdog` Windows Service (delayed auto-start)
7. Adds `C:\Program Files\AttackLens\scripts\` to system PATH
8. Starts both services

---

## Part 3 — Post-Install Verification

### 3.1 Check Services

```powershell
Get-Service AttackLensAgent, AttackLensWatchdog | Select Name, Status, StartType
```

Expected:
```
Name                  Status StartType
----                  ------ ---------
AttackLensAgent      Running Automatic
AttackLensWatchdog   Running Automatic
```

### 3.2 Check Logs

```powershell
# Last 50 log lines
attacklens-service logs

# Or directly
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 50 -Wait
```

Look for:
```
INFO  Enrollment complete: agent_id=win-xxxx
INFO  API key ready (keystore backend=dpapi ...)
INFO  Orchestrator started — 22 sections
INFO  Agent running. tick=5s.
DEBUG Sent connections → 200
DEBUG Sent metrics → 200
```

### 3.3 Diagnose Issues

```powershell
attacklens-service diagnose
```

Runs 18-point health check: directories, config, services, Python, connectivity to manager.

### 3.4 Check Manager Received Data

```powershell
# Hit the manager health endpoint
Invoke-RestMethod "http://34.224.174.38/health"
```

Expected:
```json
{ "status": "ok", "db": "ok", "store": { "agents": 1, ... } }
```

---

## Part 4 — Configuration

### 4.1 Config File Location

```
C:\ProgramData\AttackLens\agent.toml
```

### 4.2 Key Configuration Sections

```toml
[agent]
id   = "win-<MachineGuid>"   # Unique per machine — do not change after enrollment
name = "WORKSTATION-01"       # Display name in manager UI

[manager]
url        = "http://34.224.174.38"
tls_verify = false             # Set true for HTTPS with valid cert
timeout_sec = 30

[enrollment]
token    = ""                  # One-time token; cleared after first enrollment
keystore = "dpapi"             # dpapi (recommended) or file

[logging]
level   = "INFO"               # DEBUG | INFO | WARNING | ERROR
file    = "C:/ProgramData/AttackLens/logs/agent.log"
max_mb  = 10
backups = 5

[collection.sections.metrics]
enabled      = true
interval_sec = 10

# ... 22 total sections
```

### 4.3 Reload Config Without Restart

```powershell
attacklens-service reload
```

Sends SIGHUP equivalent — agent re-reads `agent.toml` in place.

### 4.4 Change Manager URL

```powershell
# Updates config + clears old credentials + restarts agent
attacklens-service set-manager "http://new-manager-ip"
```

---

## Part 5 — Service Management CLI

After install, `attacklens-service` is on the system PATH:

```powershell
# Service status
attacklens-service status

# Start / stop / restart
attacklens-service start
attacklens-service stop
attacklens-service restart

# Live log tail
attacklens-service logs

# Show current config
attacklens-service config

# 18-point health check (connectivity, dirs, services, enrollment)
attacklens-service diagnose

# Re-enroll with a new token
attacklens-service enroll

# Show version
attacklens-service version

# Help
attacklens-service help
```

---

## Part 6 — Upgrade

The MSI uses `MajorUpgrade` with `AllowSameVersionUpgrades="yes"`:

```cmd
# Upgrade to new version (services stopped automatically, restarted after)
msiexec /i attacklens-agent-2.1.0-x64.msi /qn ^
    MANAGER_URL="http://34.224.174.38" ^
    /l*v upgrade.log
```

Existing `agent.toml` is preserved — `generate_config.ps1` keeps the existing `agent.id` and `agent.name`.

---

## Part 7 — GPO / Intune Silent Deployment

### Group Policy (GPO)

1. Place MSI on a network share: `\\fileserver\software\AttackLens\`
2. Create a GPO: *Computer Configuration → Software Settings → Software Installation*
3. Add package, set deployment type to **Assigned**
4. Configure MSI properties via a transform (.mst) or deploy with a startup script:

```cmd
msiexec /i "\\fileserver\software\AttackLens\attacklens-agent-2.0.10-x64.msi" /qn ^
    MANAGER_URL="http://34.224.174.38" ^
    ENROLL_TOKEN="sk-enroll-abc123" ^
    /l*v "%TEMP%\attacklens-install.log"
```

### Microsoft Intune

1. Upload the MSI as a **Line-of-business app** (`.msi`)
2. Set install command:
```
msiexec /i attacklens-agent-2.0.10-x64.msi /qn MANAGER_URL="http://34.224.174.38" AGENT_NAME="%COMPUTERNAME%"
```
3. Set uninstall command:
```
msiexec /x {A1B2C3D4-E5F6-7890-ABCD-EF1234567890} /qn
```
4. Detection rule: Registry key `HKLM\SOFTWARE\AttackLens\Agent`, value `Version` = `2.0.10`

---

## Part 8 — Troubleshooting

### Services Not Starting

```powershell
# Check Windows Event Log
Get-EventLog -LogName Application -Source AttackLensAgent -Newest 20 | Format-List

# Check agent log
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 100
```

### Cannot Reach Manager

```powershell
# Test TCP connectivity
Test-NetConnection -ComputerName 34.224.174.38 -Port 80

# Test HTTP
Invoke-WebRequest "http://34.224.174.38/health" -UseBasicParsing
```

### Enrollment Failed

```powershell
# Re-trigger enrollment (clears stored credentials)
attacklens-service enroll
attacklens-service restart
```

### Config Corrupt / Reset

```powershell
# Regenerate config (preserves agent ID)
cd "C:\Program Files\AttackLens\scripts"
.\generate_config.ps1 -ManagerUrl "http://34.224.174.38" -TlsVerify "false"
attacklens-service restart
```

### Full Reinstall (Preserve Agent ID)

```powershell
# 1. Note agent ID before uninstall
$id = (Get-ItemProperty "HKLM:\SOFTWARE\AttackLens\Agent").ConfigPath
Get-Content $id | Select-String "^id"

# 2. Uninstall
msiexec /x attacklens-agent-2.0.10-x64.msi /qn

# 3. Reinstall with same ID
msiexec /i attacklens-agent-2.0.10-x64.msi /qn ^
    MANAGER_URL="http://34.224.174.38" ^
    AGENT_ID="win-10b1fbdb-00a6-4b44-8ab2-425bfdb7b5b7"
```

---

## Summary — Key Paths & Commands

| Item | Path / Command |
|------|----------------|
| MSI output | `agent\os\windows\pkg\dist\attacklens-agent-2.0.10-x64.msi` |
| Build script | `agent\os\windows\pkg\build_attacklens_msi.ps1` |
| Install dir | `C:\Program Files\AttackLens\` |
| Config | `C:\ProgramData\AttackLens\config\agent.toml` |
| Logs | `C:\ProgramData\AttackLens\logs\agent.log` |
| Security | `C:\ProgramData\AttackLens\security\` |
| CLI | `attacklens-service <command>` |
| Agent service | `AttackLensAgent` |
| Watchdog service | `AttackLensWatchdog` |
| Registry | `HKLM\SOFTWARE\AttackLens\Agent` |
| Public status | `C:\ProgramData\AttackLens\status\agent-status.json` |
| Durable outbox | `C:\ProgramData\AttackLens\spool\outbox.sqlite3` |
| Support output | `C:\ProgramData\AttackLens\support\` |

For an installed-but-disconnected agent, first run
`C:\Program Files\AttackLens\tools\attacklens-status.ps1`. Change a stale
manager only through the elevated `configure-manager.ps1` tool; it preserves
identity, collection settings, and queued data and triggers re-enrollment only
when the credential belongs to a different manager.

For other TOML changes, use the elevated `edit-agent-config.ps1` tool. It
validates a staged copy and rolls back automatically if activation or service
restart fails. Standard users intentionally cannot write a LocalSystem
security-agent configuration.

## Version 2.0.11 note

2.0.11 supersedes the 2.0.10 commands above for the GUI-manager incident. Its
single manager-address field is required in full UI mode, accepts IP/DNS/full
URL, and normalizes a bare address to `http://<host>:8080`. The UI payload is
captured before elevation in a Secure+Hidden property, so the deferred SYSTEM
configuration action receives the entered address and enrollment fields.

Validated development artifact:
`agent\os\windows\pkg\dist\attacklens-agent-2.0.11-x64.msi`, SHA-256
`FA0BD8D9BC50486BFD630F55F18CC03AAED48EB23765355BA30E6A7F1718B270`.
