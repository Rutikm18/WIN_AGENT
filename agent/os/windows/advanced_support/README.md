# AttackLens Windows Advanced Support

> Current verified runtime/package status: [../CURRENT_IMPLEMENTATION.md](../CURRENT_IMPLEMENTATION.md). Build 2.0.19 supersedes the older incident artifacts documented below.

This folder is the single entry point for startup diagnosis, conservative repair, support-bundle collection, Docker scenario validation, root-cause evidence, and the failure matrix for `AttackLensAgent` and `AttackLensWatchdog`.

## Fastest commands

Repair a rolled-back installation, install 2.0.19 with verbose logging,
and verify both services from an Administrator PowerShell window:

```powershell
Set-Location .\agent\os\windows\advanced_support
.\install-or-repair.ps1
```

For an explicit HTTPS manager, add
`-ManagerUrl 'https://manager.example.com:443'`. Plain HTTP additionally
requires `-AllowInsecureTransport`.

Run a read-only diagnosis from an elevated PowerShell window:

```powershell
Set-Location .\agent\os\windows\advanced_support
.\invoke-attacklens-support.ps1 -Mode Diagnose
```

Apply safe file-state and SCM repairs, start the agent first, start the watchdog second, then collect evidence:

```powershell
.\invoke-attacklens-support.ps1 -Mode All
```

If a previous MSI rolled back with error 1603/1722 and both services are
missing, run `-Mode Repair` first. It repairs the preserved ProgramData ACLs
without deleting configuration, identity, credentials, or the outbox; it then
returns so the corrected MSI can restore the missing binaries and services.

Run all nine portable failure scenarios in an isolated, network-disabled container:

```powershell
docker compose run --rm --build diagnostics
```

The installed agent binary also has offline-first commands:

```powershell
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' diagnose
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' repair
```

`repair` on the executable is deliberately limited to reversible file-state repair. The PowerShell `-Mode Repair` command is required for elevated SCM policy, ImagePath, service dependency, and ACL repair.

## Safety boundaries

Automatic recovery may create required directories, remove only stale named temporary files, quarantine malformed runtime heartbeat JSON, restore a validated last-known-good configuration, and write redacted diagnostics. It never deletes the encrypted SQLite outbox, resets the client identity, removes enrollment credentials, disables certificate validation, changes the manager URL, or purges telemetry.

Artifacts are written under `C:\ProgramData\AttackLens`:

- `logs\agent-startup.jsonl`
- `logs\watchdog-startup.jsonl`
- `logs\agent-bootstrap.log`
- `logs\watchdog.log`
- `logs\startup-diagnosis.json`
- `data\watchdog.runtime.json`
- `support\attacklens-support-<timestamp>.zip`

See [ROOT_CAUSE.md](ROOT_CAUSE.md), [FAILURE_MATRIX.md](FAILURE_MATRIX.md), and [AUTOMATION.md](AUTOMATION.md).

## Validated development build

The corrected sources were rebuilt and validated on 2026-08-10 as
`pkg\dist\attacklens-agent-2.0.10-x64.msi` (x64). The canonical pipeline
rebuilt both service executables, passed 328 Windows release-pipeline tests
(2 skipped), Microsoft Defender scans, WiX MSI validation, and compiled MSI
contract verification. The complete Windows source suite passed 452 tests
(7 skipped), including manager migration, public-status redaction, lazy
collector construction, ACL, durable outbox, and recovery scenarios.

The MSI SHA-256 is
`39C52FB58FCFE12AA2366C488AF9EEDC0A49336E1A12663C93D132E13D889B27`.
It is an unsigned development artifact; production distribution still requires
the signed `-Release` workflow documented in `WINDOWS_RELEASE_TRUST.md`.
An actual SYSTEM-context install must be run from an Administrator shell; the
automated session's UAC request was cancelled, so endpoint installation is not
claimed as part of this package validation.

## 2.0.10 communication and runtime-layout fix

Read `CURRENT_INCIDENT.md` first for the verified stale-localhost root cause and
the exact recovery command. `REFERENCE_ARCHITECTURE.md` records the Microsoft,
Elastic, and Wazuh primary-source patterns used for the final layout. Version
2.0.10 installs `configure-manager.ps1`, `edit-agent-config.ps1`,
`attacklens-status.ps1`, and
`RUNTIME_LOCATION.txt`; it also creates `status` and `support` beside the
protected `config`, `logs`, `security`, `spool`, and `data` directories.
It also fixes the GUI manager-property handoff by preparing hidden Base64
`CustomActionData` before the deferred SYSTEM action runs.
Host-only manager input defaults to HTTP port 8080. Full configuration changes
use the elevated, validated `edit-agent-config.ps1` workflow.

## Validated 2.0.11 development build

`pkg\dist\attacklens-agent-2.0.11-x64.msi` supersedes 2.0.10 for this incident.
It adds secure pre-elevation full-UI staging, one unambiguous manager address,
bare-host HTTP/8080 normalization, installer capture diagnostics, and visible
last-known-good recovery reasons. The pipeline passed 328 tests (2 skipped),
both executable/MSI Defender scans, WiX validation, and compiled MSI contracts.
SHA-256:
`FA0BD8D9BC50486BFD630F55F18CC03AAED48EB23765355BA30E6A7F1718B270`.

### 2.0.12 supersedes 2.0.11

Compiled-MSI decompilation proved 2.0.11 captured before the dialogs. The
2.0.12 sequence is verified as
`ProgressDlg -> CA_StageWriteConfigUI -> ExecuteAction`. MSI SHA-256:
`33492289C0DBC1A1FA1980F259A2A6086DFE3E30E88B49B8A1FF5FC4556EF59B`.

### 2.0.13 supersedes 2.0.12

2.0.13 separates LocalSystem-only install/ACL generation from Administrator
runtime editing. `configure-manager.ps1` and `edit-agent-config.ps1` now update
the existing protected file object without replacing its security descriptor,
with staged/live validation, durable flush, service coordination, and rollback.
The release verifier also extracts the final CAB and byte-compares critical
packaged scripts with source, so stale MSI content fails the build.

The complete source suite passed 453 tests (7 skipped); the canonical release
gate passed 329 tests (2 skipped), Defender, WiX, UI-sequence, and payload-hash
checks. Artifact: `pkg\dist\attacklens-agent-2.0.13-x64.msi`, 22,582,265 bytes,
SHA-256
`E670BE12CB5FCEA2CDA60E7299F14BCC94E07BD0B7817D87A71999CF622024DA`.
It is an unsigned development MSI.
