# Installed but not communicating: 2026-08-09 diagnosis

## Verified endpoint facts

- `AttackLensAgent` and `AttackLensWatchdog` were installed, Automatic, running
  as LocalSystem, and configured with restart recovery.
- The mutable tree existed under `C:\ProgramData\AttackLens`, not under
  `C:\Program Files\AttackLens`. The standard-user session could enumerate the
  directories but correctly received Access Denied for protected config/state.
- The live agent process had a TCP `SYN_SENT` connection to
  `127.0.0.1:8443`. A preserved legacy `manager.url` therefore overrode the
  manager supplied during reinstall.
- The intended development manager at `http://13.233.122.80:8080` also timed
  out from the host during diagnosis. This is an independent manager/network
  outage; endpoint code cannot make an unreachable server accept telemetry.

## Root cause

`PRESERVE_STATE=1` previously returned immediately whenever `agent.toml`
existed. That correctly protected identity and collection policy, but also
discarded an explicit `MANAGER_URL` passed to repair/reinstall. The service was
healthy while targeting the wrong endpoint. A credential issued by the old
manager could also be reused against a new manager, producing repeated auth
failures.

## Corrected behavior in 2.0.9

1. An upgrade without a manager property preserves the complete config.
2. An explicit manager property atomically changes only connection settings;
   agent identity, collection policy, security state, and outbox remain.
3. `agent.toml.previous` is kept for rollback with the protected config ACL.
4. A credential whose recorded manager differs is archived as
   `client.key.previous-manager`, followed by re-enrollment.
5. A sanitized `status\agent-status.json` exposes service/manager/outbox health
   without exposing config, tokens, keys, raw responses, or telemetry.
6. The installed `configure-manager.ps1` command performs validated,
   administrator-only reconfiguration and controlled service restart.
7. GUI and silent MSI values are serialized while the full installer session
   exists, transferred as hidden Base64 `CustomActionData`, and explicitly
   consumed by the deferred SYSTEM configuration action.

## Confirmed 2.0.8 GUI handoff defect

The endpoint was successfully upgraded to 2.0.8 and both services were
running, but the protected configuration still contained
`https://localhost:8443`. The WiX controls correctly populated public MSI
properties; however, the deferred PowerShell EXE incorrectly expected an
environment variable named `MsiCustomActionData`. Windows Installer only
guarantees the `CustomActionData` property inside deferred execution, and an
external EXE cannot query the original installer session. Version 2.0.9 adds
an immediate preparation action and explicitly passes the hidden payload to
PowerShell. Compiled-MSI verification now fails if that bridge is absent.

## Recovery command

Run from Administrator PowerShell, substituting the manager that is actually
reachable:

```powershell
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' `
  -ManagerUrl 'https://manager.example.com:443' `
  -EnrollmentToken 'operator-issued-token'
```

For the current HTTP development endpoint only:

```powershell
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' `
  -ManagerUrl 'http://13.233.122.80:8080' `
  -AllowInsecureTransport
```

Then run the non-administrator status command:

```powershell
& 'C:\Program Files\AttackLens\tools\attacklens-status.ps1' -WaitForUpdate
```

Do not delete the spool/outbox. It drains automatically after enrollment and
manager reachability recover.

## Endpoint upgrade attempt on 2026-08-10

The validated 2.0.8 MSI was invoked silently from the automation session. It
correctly detected 2.0.7, but Windows Installer rolled back at
`RemoveExistingProducts` with Error 1730: the calling token was not an
Administrator and silent mode cannot display a credential-elevation prompt.
Registry remained 2.0.7, both services remained running, state was preserved,
and the live connection remained `::1:8443`. Run the documented command from
an Administrator PowerShell; this exact authorization boundary cannot be
safely bypassed by endpoint code.

## Current endpoint verification after the GUI report

- Registry version is 2.0.8; both services are Running and Automatic.
- The operator's protected-file check reports
  `url = "https://localhost:8443"` in `config\agent.toml`.
- The current public runtime snapshot reports
  `https://72.61.228.62:8443`, `enrollment_pending`, zero sent records, and
  26,796 queued records. This disk/runtime discrepancy remains until the
  manager is changed through the controlled tool and the services restart.
- TCP checks to both `72.61.228.62:8443` and the earlier development endpoint
  `13.233.122.80:8080` failed from this host. Manager listener, firewall,
  routing, and the authoritative endpoint must be resolved independently.
- A UAC-elevated 2.0.9 install was launched, but the consent operation was
  canceled. No 2.0.9 endpoint mutation occurred and no install log was
  created. The validated MSI is ready for an Administrator-run installation.

## 2.0.10 configuration defaults and editing

Host-only manager input now produces `http://<host>:8080`, with
`tls_verify=false` and `allow_insecure_transport=true` represented explicitly
in `agent.toml`. No localhost host is injected when the manager is blank.
Administrators can change the full TOML with the installed
`edit-agent-config.ps1` workflow, which validates a staged copy, keeps a
protected backup, swaps atomically, restores ACLs, restarts services, and
rolls back on failure. Standard-user writes remain denied to prevent a local
user from redirecting or disabling the LocalSystem security service.

## 2.0.11 resolution

The endpoint is correctly laid out in Program Files plus ProgramData; Program
Files (x86) is not referenced by either service. The apparent inability to
modify TOML was automatic last-known-good recovery: the `.invalid-*` files are
the saved, rejected edits.

2.0.11 uses one required GUI manager-address field, accepts IP/DNS/full URL,
defaults a bare address to HTTP/8080, securely stages full-UI data before the
elevation boundary, and records non-secret capture details in
`installer-config.log`. Rejected future edits include their validation reason
in `agent.log`. Use `configure-manager.ps1 -ManagerUrl <IP-or-DNS>` for manager
changes or `edit-agent-config.ps1` for transactional full-file editing.

### 2.0.12 superseding fix

2.0.11 is confirmed installed but still blank. Compiled-package reproduction
showed its staging action ran before the dialogs. Install 2.0.12, whose verified
compiled order captures values after `ProgressDlg` and before `ExecuteAction`.
The existing 2.0.11 endpoint can be repaired immediately with its installed
`configure-manager.ps1` while the upgrade is scheduled.

### 2.0.13 final runtime-tool resolution

The source-tree `configure-manager.ps1` successfully updated the live endpoint,
which proved the manager input and current runtime algorithm were correct. The
installed copy failed because the earlier MSI embedded a tool that delegated to
the LocalSystem-only ACL-hardening generator. Service shutdown could not add the
missing DACL-management right, so retries returned the same Access Denied.

Install 2.0.13, then run in Administrator PowerShell:

```powershell
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' `
  -ManagerUrl '72.61.228.62'
```

The output must report `ok: true`, endpoint
`http://72.61.228.62:8080`, and the existing-file ACL strategy. The new MSI's
compiled CAB is checked against source, preventing this class of stale packaged
script from passing release validation again.
