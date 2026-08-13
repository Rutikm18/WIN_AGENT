# AttackLens Windows Agent 2.0.26 — Client Installation

This is the client handoff procedure. The client needs only the single
`attacklens-agent-2.0.26-x64.msi` file. Python, WiX, PyInstaller, source files,
and separate scripts are not required on the client endpoint.

## Requirements

- 64-bit Windows 10/11 or supported Windows Server
- Administrator account/UAC approval
- Network access from the endpoint to the manager
- Manager address and enrollment token, if the manager requires enrollment

## Recommended terminal installation (PowerShell as Administrator)

1. Copy the MSI to the endpoint, for example `C:\Temp\`.
2. Open **Windows PowerShell as Administrator**.
3. Set the MSI path and manager values:

```powershell
$msi = 'C:\Temp\attacklens-agent-2.0.26-x64.msi'
$manager = 'http://72.61.228.62:8080'
$token = 'sk-enroll-REPLACE_WITH_MANAGER_TOKEN'
$log = "$env:TEMP\attacklens-agent-2.0.26-install.log"
```

4. Install and wait for completion:

```powershell
$args = @('/i', $msi, '/qn', 'ACCEPT_EULA=1',
  "MANAGER_URL=$manager", 'ALLOW_INSECURE_TRANSPORT=true',
  "ENROLL_TOKEN=$token", '/l*v', $log)
$p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "MSI installation failed: $($p.ExitCode)" }
```

If the manager allows open enrollment, omit the `ENROLL_TOKEN` argument. For
production HTTPS, use `MANAGER_URL=https://...`, set
`ALLOW_INSECURE_TRANSPORT=false`, and use the manager's valid CA policy.

## Verify the installation

```powershell
Get-Service AttackLensAgent, AttackLensWatchdog |
  Select-Object Name, Status, StartType
Get-Content 'C:\ProgramData\AttackLens\config\agent.toml'
```

Both services should be running. The agent starts automatically after reboot;
the watchdog restarts the agent if it stops. Enrollment credentials are stored
in the protected ProgramData security directory.

## Troubleshooting

- MSI exit details: open the log path stored in `$log`.
- Service logs: `C:\ProgramData\AttackLens\logs\`.
- Confirm manager reachability:
  `Test-NetConnection 72.61.228.62 -Port 8080`.
- Do not edit or replace the installed binaries. Re-run the same MSI for repair
  or install a newer MSI for upgrade.

## Uninstall

From an elevated PowerShell prompt:

```powershell
Start-Process msiexec.exe -ArgumentList @('/x', $msi, '/qn') -Wait
```

