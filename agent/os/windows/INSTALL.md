# AttackLens Agent — Windows Installation Guide

> For service startup diagnosis, safe repair, support bundles, and Docker scenarios, use [`advanced_support/`](advanced_support/README.md).

## What the MSI does (fully automatic)

```
msiexec /i attacklens-agent-2.0.13-x64.msi /qn  MANAGER_URL="https://manager.example.com:443"  ENROLL_TOKEN="sk-enroll-..."
```

1. Installs agent + watchdog binaries to `C:\Program Files\AttackLens\bin\`
2. Creates `C:\ProgramData\AttackLens\{config, logs, security, spool, data}\`
3. Writes `agent.toml` with your manager IP and enrollment token
4. Restricts `security\` to SYSTEM + Administrators only (DPAPI key storage)
5. Registers **AttackLensWatchdog** service → starts it
6. Registers **AttackLensAgent** service → starts it
7. Agent auto-enrolls on first start:
   - `POST /api/v1/enroll` with the enrollment token
   - Manager returns a 256-bit API key
   - Key stored in Windows DPAPI Credential Manager (`security\client.key`)
8. Enrollment never happens again — key survives reboots and upgrades

---

## Prerequisites

- Windows 10 / Server 2016 or newer (64-bit)
- Administrator rights on the endpoint
- Manager is running and reachable on the network
- Enrollment token from manager first-boot logs:
  ```
  docker compose logs manager | Select-String "sk-enroll"
  ```

---

## Single-command install

### Development / self-signed certificate

```cmd
msiexec /i "attacklens-agent-2.0.13-x64.msi" /qn ^
    MANAGER_URL="https://34.224.174.38:8443" ^
    TLS_VERIFY="false" ^
    ENROLL_TOKEN="sk-enroll-abc123def456..." ^
    /l*v install.log
```

Default values when a property is omitted:

| Property | Default | Notes |
|----------|---------|-------|
| `MANAGER_URL` | *(empty)* | Preferred full HTTP(S) manager URL; localhost is not injected |
| `MANAGER_IP` | *(empty)* | Compatibility host/FQDN property |
| `MANAGER_PORT` | `8080` | Compatibility host-only default |
| `TLS_VERIFY` | `false` | HTTP default; set `true` for production HTTPS |
| `ALLOW_INSECURE_TRANSPORT` | `true` | Explicitly records that HTTP delivery is allowed |
| `CA_BUNDLE` | *(empty)* | Optional absolute custom CA bundle |
| `SPKI_PIN` | *(empty)* | Optional `sha256//...` certificate public-key pin |
| `COLLECTION_PROFILE` | `standard` | `baseline`, `standard`, `intensive`, or `incident` |
| `ENROLL_TOKEN` | *(empty)* | Required for auto-enrollment |
| `AGENT_NAME` | `%COMPUTERNAME%` | Label shown in the dashboard |

### Production / valid CA certificate

```cmd
msiexec /i "attacklens-agent-2.0.13-x64.msi" /qn ^
    MANAGER_URL="https://manager.corp.example:443" ^
    TLS_VERIFY="true" ^
    ENROLL_TOKEN="sk-enroll-abc123def456..." ^
    AGENT_NAME="WORKSTATION-01" ^
    /l*v install.log
```

### PowerShell one-liner

```powershell
Start-Process msiexec -Wait -ArgumentList @(
    '/i', 'attacklens-agent-2.0.13-x64.msi',
    '/qn',
    'MANAGER_URL=https://manager.example.com:443',
    'TLS_VERIFY=true',
    'ENROLL_TOKEN=sk-enroll-abc123def456',
    '/l*v', 'install.log'
)
```

## Interactive GUI install

Run the MSI without `/qn` as an administrator:

```cmd
msiexec /i "attacklens-agent-2.0.13-x64.msi" /l*v install.log
```

The installer pages collect the manager HTTPS URL (or compatibility host and
port), TLS verification/custom CA/SPKI settings, hidden enrollment token and
agent name, collection profile, and repair/uninstall state choices. The same
property validation and fail-closed configuration generator is used for GUI
and silent installs. The development-only certificate-verification checkbox
should remain disabled for production managers.

The purge choice is recorded for the uninstall workflow; the full safe purge
implementation is still gated behind the Windows lifecycle milestone. Cancel
the MSI if the manager URL, token, or security choices are not confirmed.

---

## Verify installation

```powershell
# Service status
Get-Service AttackLensAgent, AttackLensWatchdog | Select-Object Name, Status

# Validate config without network or enrollment
& "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" --validate-config

# Confirm agent enrolled (client.key appears after first start)
Test-Path "C:\ProgramData\AttackLens\security\client.key"

# Tail the agent log
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 30

# Full status + config view
& "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" debug
```

---

## File layout after install

```
C:\Program Files\AttackLens\
  bin\
    attacklens-agent\
      attacklens-agent.exe          ← Windows Service binary
      _internal\                    ← Python runtime + all dependencies
    attacklens-watchdog\
      attacklens-watchdog.exe       ← Watchdog service binary
      _internal\

C:\ProgramData\AttackLens\
  config\
    agent.toml                      ← Written by MSI installer
  security\
    client.key                      ← Written on first start (enrollment)
                                      Contains agent_name, agent_number, token
  logs\
    agent.log                       ← Rotating log (10 MB × 5 backups)
  spool\
    win_agent.spool.ndjson          ← Offline buffer (50 MB cap, FIFO trim)
  data\                             ← Reserved for future use
```

---

## Operational commands

Run these as Administrator from any directory:

```powershell
# Import the management script
$mgr = "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe"

# Or use the PowerShell management script shipped with the agent:
$ps = "C:\ProgramData\AttackLens\config"   # copy manage_services.ps1 here

# Service control (restart the agent after editing agent.toml)
Restart-Service AttackLensAgent
Restart-Service AttackLensWatchdog

# Re-enroll with a new token (e.g. after key rotation on manager)
Stop-Service  AttackLensAgent
Remove-Item   "C:\ProgramData\AttackLens\security\client.key" -Force
Start-Service AttackLensAgent
# Agent auto-enrolls on next start

# View live log
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Wait
```

---

## Uninstall (silent)

```cmd
msiexec /x "attacklens-agent-2.0.13-x64.msi" /qn
```

The uninstall:
- Stops and removes both Windows services
- Removes all installed binaries and MSI-created directories
- Leaves `C:\ProgramData\AttackLens\security\client.key` intact (key survives reinstall)

To explicitly purge all AttackLens state, including the enrollment identity:

```cmd
msiexec /x "attacklens-agent-2.0.13-x64.msi" /qn PURGE_ON_UNINSTALL=1 /l*v purge.log
```

The purge action is elevated, restricted to the standard
`C:\ProgramData\AttackLens` root, and fails closed if the resolved path is
unexpected. It is irreversible; use it only when decommissioning the endpoint.

Manual removal is not required, but if the MSI is unavailable and a full clean
is authorized:

```powershell
Remove-Item "C:\ProgramData\AttackLens" -Recurse -Force
```

---

## Building the MSI

Run from `agent\os\windows\pkg\`:

```powershell
# Standard build (works on any machine — paths are relative)
.\build_msi.ps1

# Specific version
.\build_msi.ps1 -Version "2.1.0"

# Rebuild with existing binaries (skip PyInstaller step)
.\build_msi.ps1 -SkipBuild

# Full pipeline with Authenticode signing
.\build_attacklens_msi.ps1 -Version "2.1.0" -SignIdentity "CN=AttackLens Inc"
```

Output: `pkg\dist\attacklens-agent-2.0.13-x64.msi`

### Build prerequisites

```powershell
# Python 3.11+, PyInstaller, and WiX v4
pip install pyinstaller pywin32 psutil requests cryptography keyring tomli
dotnet tool install --global wix
wix extension add WixToolset.Util.wixext
wix extension add WixToolset.UI.wixext
```

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Service won't start | `Get-Content logs\agent.log -Tail 50` |
| `client.key` not appearing | Check enrollment token in `agent.toml`; verify manager is reachable |
| Manager returns 401 | Key revoked — delete `client.key` and restart service |
| Spool growing, data not sending | Manager unreachable; agent backs off and retries every 5–300 s |
| Config not written (install.log errors) | Check `CA_PrepareWriteConfig` / `CA_WriteConfig`; the sensitive payload is intentionally hidden |

**Install log location** (generated by `/l*v install.log`): look for `CA_WriteConfig` entries to debug config generation.

**Event log**: check `Application` event log for entries from `AttackLens` source — the config generator writes errors there if it fails.

## Runtime layout and manager repair (2.0.10)

The MSI places binaries/tools under `C:\Program Files\AttackLens` and mutable
machine-wide state under `C:\ProgramData\AttackLens\{config,logs,security,spool,data,status,support}`.
Protected files are intentionally unreadable to standard users. Use
`tools\attacklens-status.ps1` for sanitized health. To replace a stale manager
without deleting identity or queued telemetry, run `tools\configure-manager.ps1
-ManagerUrl <https-url>` as Administrator. An explicit manager passed during an
upgrade now overrides preserved connection fields; an upgrade with no manager
argument preserves the complete configuration.

To change the full TOML safely, run
`tools\edit-agent-config.ps1` from Administrator PowerShell. It validates a
staged copy with the installed agent, keeps a rollback copy, writes through the
existing protected file object with a durable flush, and restarts both services. Direct standard-user writes remain
blocked because this file controls a LocalSystem security service.

## 2.0.11 manager-input and protected-config fix

Interactive setup now has one required **Manager address** box. It accepts an
IP address, DNS name, or absolute HTTP(S) URL. A bare IP/name is normalized to
`http://<host>:8080`. Final GUI values are serialized before setup leaves its
UI process, transferred in a Secure+Hidden property, and consumed by the
elevated configuration action.

Install or upgrade from an Administrator terminal:

```powershell
msiexec /i "pkg\dist\attacklens-agent-2.0.11-x64.msi" /l*v "$env:TEMP\attacklens-2.0.11-install.log"
```

`agent.toml` is protected from standard users but modifiable by an elevated
Administrator. Use the transactional editor for full changes, or the shorter
manager-only command:

```powershell
& 'C:\Program Files\AttackLens\tools\edit-agent-config.ps1'
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' `
  -ManagerUrl 'MANAGER-IP-OR-DNS'
```

### 2.0.12 sequencing correction

Use `attacklens-agent-2.0.12-x64.msi`. Decompilation of 2.0.11 proved WiX had
placed the UI capture action before `ResumeDlg`, so it captured empty values.
2.0.12 explicitly sequences capture after `ProgressDlg` and before
`ExecuteAction`; the compiled-MSI verifier enforces that numeric ordering.

### 2.0.13 runtime reconfiguration and package-integrity correction

Use `attacklens-agent-2.0.13-x64.msi`. MSI installation configuration remains
a deferred LocalSystem operation and may establish the protected ACL. The
installed Administrator tools no longer call that installer-only generator:
they validate a staged TOML, stop the services, update the existing protected
file object without rewriting its DACL, durably flush, validate the live file,
restart the services, and roll back through the same file object if needed.

This separation fixes `C:\ProgramData\AttackLens\config: Access is denied`
when an elevated Administrator had Modify access to `agent.toml` but did not
have the `WRITE_DAC` right needed by the MSI ACL-hardening path. Optional
`ca_bundle` and `spki_pin` keys are preserved unless explicitly supplied, so
empty optional values can no longer invalidate an otherwise valid update.

The release gate now decompiles the finished MSI and SHA-256 compares every
critical packaged PowerShell tool with its reviewed source. It also rejects a
GUI staging action outside
`ProgressDlg -> CA_StageWriteConfigUI -> ExecuteAction`.
