# AttackLens Windows Agent — Current Verified Implementation

Updated: 2026-08-12  
Build: 2.0.19 (unsigned development artifact)

This is the authoritative summary for the Windows implementation. Older
version notes in the surrounding documents are retained as incident history;
where they conflict with this file, this file wins.

## Outcome

The agent, watchdog, configuration tools, runtime state, native telemetry,
offline delivery, diagnostics, self-repair, and MSI are contained under
`agent/os/windows/`. Mutable installed state remains under
`C:\ProgramData\AttackLens`; binaries and operator tools remain under
`C:\Program Files\AttackLens`. Nothing intentionally targets Program Files
(x86).

The current scheduler has 26 collection sections plus `agent_health` and
`agent_lifecycle` control-plane records. Hot collectors use native APIs or
`psutil`. ETW continuously captures kernel-process and DNS-client events.
Windows Event Log uses push subscriptions with per-channel durable bookmarks.
The persistence collector covers Run/RunOnce, Startup folders, tasks,
services/drivers, WMI permanent subscriptions, IFEO, COM, AppInit, Winlogon,
LSA/security providers, print monitors, and netsh helpers. Its baseline changes
only after the collected batch is durably queued.

The Windows CIS policy contains 46 tri-state checks. Unsupported or
access-denied features report `unknown`, not false failure. Native checks cover
pending reboot, NTLM session security, advanced audit policy, password policy,
TPM, Defender/ASR, DEP, app control, and PowerShell language mode.

## Reliability and self-defense

- Named global mutex prevents a second agent instance.
- SCM start checkpoints, pre-shutdown, power-resume handling, delayed start,
  and graduated 5/10/30-second recovery actions are implemented.
- The five-minute self-repair loop reasserts SCM and protected-path ACL policy.
- Install-manifest hashes are verified at startup and every 30 minutes.
- Config changes, unreadable config, Defender exclusions covering AttackLens,
  binary-integrity failures, and ACL repair failures become health/lifecycle
  evidence. The service never silently overwrites a changed binary or an
  administrator-edited config.
- The encrypted SQLite outbox commits before collector cursors/baselines move,
  retries with fresh wire nonces, deletes only after ACK, preserves dead
  letters, trims safely under disk pressure, and wakes immediately after sleep.
- The `AttackLensAgent` Application Event Log source is registered on service
  startup using pywin32's bundled message table.

## Operator commands

Validate and diagnose the installed service:

```powershell
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' --validate-config
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' status
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' diagnose
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' self-test
```

Set a bare manager host using the default HTTP/8080 development policy:

```powershell
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' -ManagerUrl '72.61.228.62'
```

For production, provide an explicit HTTPS URL and keep certificate validation
enabled. The protected `agent.toml` is intentionally writable only by SYSTEM
and an elevated Administrator; use the installed editor/configure tools so the
write is validated, durable, and rolled back on failure.

Run all portable recovery cases with one command:

```powershell
Set-Location .\agent\os\windows\advanced_support
docker compose run --rm --build diagnostics
```

## Verification evidence

- Windows agent/platform suite: 511 passed, 7 skipped.
- Manager unit suite: 24 passed.
- Canonical MSI release gate: 384 passed, 2 skipped; 19 PowerShell scripts
  parsed; both executables rebuilt; 156 manifest files hashed.
- Live persistence inventory: 1,095 records across 13 surfaces, followed by a
  clean 1,095-record unchanged baseline pass.
- Live CIS scan: 46 checks, 24 pass, 19 fail, 3 unknown, no collector/schema
  errors. Unknowns were correct privilege/feature results in the non-SYSTEM
  test identity.
- Event Log live probe: durable bookmark created and resumed; the Security
  channel correctly reported Access Denied outside LocalSystem.
- Docker troubleshooting lab: nine scenarios passed in a read-only,
  network-disabled, no-new-privileges container.
- Defender: no threats in agent EXE, watchdog EXE, or MSI.
- WiX validation and compiled MSI contract/payload verification: passed.
- Freshly frozen binary `--validate-config`: exit 0. Packaged capability report
  confirmed ETW, push Event Log, persistence, and 46-check CIS modules.

Artifact:

```text
pkg\dist\attacklens-agent-2.0.19-x64.msi
Size:      23,734,892 bytes
SHA-256:   9A51E723476C0314B787096EDF81F10104A7D0AAA2AB44648394B28AAE7E9EC6
Signature: NotSigned (development build)
```

## Current endpoint communication observation

At 2026-08-12 05:20 IST the installed 2.0.18 agent reported the configured
endpoint `http://72.61.228.62:8080` (not localhost), but its state was
`connect_timeout`. An independent host TCP probe to port 8080 failed and
`GET /health` could not connect; ports 80 and 443 were also unreachable. The
agent therefore behaved correctly by retaining 6,958 pending records in the
encrypted outbox. Restoring the manager listener/security-group/firewall route
is required before those records can drain. This remote reachability failure
cannot be corrected by changing `agent.toml` or rebuilding the endpoint agent.

The installed endpoint was not upgraded in this non-elevated session because
its protected config correctly denied access, so its pre-upgrade hash could not
be captured safely. Run the elevated 2.0.19 command in the final handoff after
the manager endpoint is restored.

## External release gates

The code and development package are verified, but production release still
requires an Authenticode certificate with trusted timestamp, a disposable-VM
matrix for Windows 10/11 and supported Server editions, elevated install /
upgrade / repair / reboot / uninstall tests, and deployment validation through
the chosen Intune, GPO, or SCCM channel. ETW Threat Intelligence and PPL remain
unavailable until the product has the required anti-malware signing status.
