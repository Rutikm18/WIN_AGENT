# Windows Agent 2.0.26 — Deployment Use Cases

This document describes the supported client deployment paths. The client
receives only `attacklens-agent-2.0.26-x64.msi`.

## 1. Interactive GUI installation

Use this when an operator is present at the endpoint.

1. Right-click the MSI and choose **Run as administrator**.
2. Accept the license.
3. Enter the manager IPv4 address, DNS name, or full HTTP(S) URL.
4. Enter the manager port when required. For the development manager,
   use `8080`.
5. Continue through enrollment, collection profile, and security pages.
6. Complete installation and verify both services are running.

The Manager page's **Next** button is available immediately after entering the
address. Validation accepts a valid bare IPv4 address such as `72.61.228.62`;
invalid addresses remain on the page with an error.

## 2. Silent or scripted installation

Use this for RMM, Intune, SCCM, GPO, or repeatable endpoint provisioning.
Run PowerShell as Administrator:

```powershell
$msi = 'C:\Temp\attacklens-agent-2.0.26-x64.msi'
Start-Process msiexec.exe -Wait -ArgumentList @(
  '/i', $msi, '/qn', 'ACCEPT_EULA=1',
  'MANAGER_URL=http://72.61.228.62:8080',
  'ALLOW_INSECURE_TRANSPORT=true',
  'ENROLL_TOKEN=sk-enroll-REPLACE_ME',
  '/l*v', "$env:TEMP\attacklens-agent-install.log"
)
```

If open enrollment is enabled, omit `ENROLL_TOKEN`. For production HTTPS,
provide an `https://` URL, enable certificate verification, and use the
manager's CA policy.

## 3. Reboot, shutdown, and startup recovery

No manual start command is needed after installation. The MSI registers:

- `AttackLensAgent` — telemetry collection and delivery
- `AttackLensWatchdog` — restart monitoring

Both services start automatically with Windows. After a shutdown or reboot,
the agent resumes collection and retries unsent records from its encrypted
offline outbox when the manager becomes reachable.

## 4. Offline manager or temporary network outage

The agent keeps encrypted telemetry locally until the manager acknowledges it.
Do not delete `C:\ProgramData\AttackLens\spool`. Once network access returns,
the service retries delivery automatically.

## 5. Verify endpoint health

```powershell
Get-Service AttackLensAgent, AttackLensWatchdog
Test-NetConnection 72.61.228.62 -Port 8080
Get-Content 'C:\ProgramData\AttackLens\config\agent.toml'
```

Logs are under `C:\ProgramData\AttackLens\logs\`. The protected enrollment
key is under `C:\ProgramData\AttackLens\security\`.

## 6. Upgrade or repair

Run the newer MSI as Administrator. Preserve-state behavior keeps the existing
identity and configuration unless the installer option explicitly requests
regeneration. No separate uninstall is required for a normal upgrade.

## 7. Uninstall

From an elevated terminal:

```powershell
msiexec /x 'C:\Temp\attacklens-agent-2.0.26-x64.msi' /qn
```

Use the documented purge option only when endpoint data must be explicitly
decommissioned.

## Client handoff checklist

- Deliver the MSI only.
- Provide the manager URL/IP, port, and enrollment token through the approved
  secure channel.
- Do not send Python, source, WiX, PyInstaller, or build folders.
- Confirm both services and manager visibility after installation.
