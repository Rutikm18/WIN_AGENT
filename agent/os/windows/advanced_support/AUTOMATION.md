# Diagnosis, Repair, and Docker Automation

## Repair a rolled-back installation

When MSI error 1603/1722 leaves the services absent, run the support tool from
an elevated PowerShell window. It repairs only the AttackLens ProgramData ACLs
and, when binaries are absent, stops before attempting service registration:

```powershell
.\invoke-attacklens-support.ps1 -Mode Repair
```

Then install the corrected MSI with a verbose log:

```powershell
msiexec /i attacklens-agent-2.0.10-x64.msi /qn ACCEPT_EULA=1 `
  /l*v "$env:TEMP\attacklens-install-2.0.10.log"
```

Configuration-action evidence persists at
`C:\ProgramData\AttackLens\logs\installer-config.log` even if MSI rolls back.

The equivalent single-command recovery is:

```powershell
.\install-or-repair.ps1
```

The wrapper requires an Administrator shell, preserves state, writes a verbose
MSI log, verifies both services reach `Running`, and prints the relevant MSI
failure lines automatically when installation does not succeed.

## Native workflow

`invoke-attacklens-support.ps1` is idempotent for supported repair operations.

- `Diagnose` is read-only and works with missing or invalid `agent.toml`.
- `Repair` requires elevation. It repairs SID-based ACLs, creates missing service registrations when binaries exist, normalizes quoted ImagePath values, clears legacy network dependencies, configures delayed auto-start and failure actions, invokes conservative file recovery, then starts agent before watchdog.
- `Bundle` gathers redacted JSON diagnosis, recent AttackLens/Python Service Application events, service configuration, file existence/ACL evidence, and logs. It does not copy raw config, credentials, security state, or outbox content.
- `All` repairs, re-diagnoses, and creates the ZIP bundle.

Examples:

```powershell
.\invoke-attacklens-support.ps1 -Mode Diagnose
.\invoke-attacklens-support.ps1 -Mode Repair -ConfigPath 'D:\AttackLens\agent.toml'
.\invoke-attacklens-support.ps1 -Mode All
```

## Docker scenario lab

The Docker lab tests portable recovery rules without Windows privileges or network access. The image is read-only, has a temporary `/tmp`, runs with `no-new-privileges`, and uses `network_mode: none`.

```powershell
docker compose run --rm --build diagnostics
```

The single command covers missing config, last-known-good restoration, corrupt runtime quarantine, corrupt outbox detection and preservation, SCM error classification, and scenario-engine integrity. Native SCM, Event Log, DPAPI, and Windows ACL checks remain part of the PowerShell workflow because Linux containers cannot faithfully emulate the Windows Service Control Manager.

## Exit and escalation policy

Safe automated recovery never purges evidence or relaxes security controls. Repeated ACL failure, binary integrity failure, corrupt encrypted outbox, missing service binary, and untrusted TLS remain explicit stop conditions. Collect the support bundle and repair/reinstall through an approved administrative workflow.

## Installed one-command manager repair

```powershell
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' `
  -ManagerUrl 'https://manager.example.com:443' `
  -EnrollmentToken 'operator-issued-token'
```

This validates the endpoint, stops both services, atomically migrates only the
connection settings, retains `agent.toml.previous`, and restarts watchdog then
agent. Plain HTTP is rejected unless `-AllowInsecureTransport` is explicit.
