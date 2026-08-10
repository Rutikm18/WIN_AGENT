# Service Startup Root-Cause Analysis

## Conclusion

The source and installer history contained multiple independent ways for both services to fail. Two are high-confidence causes of the observed immediate-start failures; the others explain intermittent, machine-specific, and restart-loop cases. A machine support bundle is still the final authority for identifying which combination occurred on a particular endpoint.

## High-confidence causes found

1. The pywin32 service wrapper called `ServiceFramework.ReportServiceStatus` with a `checkPoint` keyword. That wrapper accepts a state and wait hint but does not expose that keyword. The resulting `TypeError` occurs before the watchdog worker starts and commonly surfaces through SCM as error 1053 or 1067. Both service wrappers now use the supported call shape and allow pywin32 to advance its internal checkpoint.

2. Earlier installer ACL policy granted `NT AUTHORITY\SYSTEM` only read access to `agent.toml`, while the LocalSystem agent reapplied a protected ACL during startup. On upgraded endpoints where Administrators owned the file, `icacls` could fail with access denied, and the agent correctly failed closed. The installer now reclaims SYSTEM ownership before ACL repair and grants SYSTEM the rights required to maintain the protected file. NETWORK SERVICE has explicit read/write rights appropriate to each path.

## Additional causes found and corrected

- Legacy PowerShell installers declared `Tcpip` and `Dnscache` as service dependencies. A disabled or slow DNS Client service caused dependency error 1068 even though offline collection is supported. Both services now have no network dependency.
- Installers started the watchdog before the agent. The watchdog could call `StartService` while the installer was doing the same. The script installer now starts the agent first, and the watchdog has a 45-second startup grace.
- The watchdog treated every SCM query exception as “agent stopped.” Missing service registration and access denied therefore produced pointless restart storms. Query failures are now classified and journaled without calling `StartService`.
- `StartService` returning was logged as “started successfully,” although it only means the start request was accepted. The watchdog now waits for `SERVICE_RUNNING`, detects a return to `STOPPED`, and times out with a classified diagnosis.
- A dead watchdog worker attempted to call an undefined global event-log helper, masking the original failure with a secondary `NameError`. It now invokes the core event logger and writes structured evidence.
- Previous agent startup branches returned after missing config/import/parse failures. That looked like a clean service exit and weakened SCM recovery. Fatal initialization failures now propagate as service failures.
- The watchdog assumed a fixed ProgramData heartbeat path. It now follows the agent's configured `data_dir` when the configuration is readable.

## Evidence that distinguishes cases

- 1053 plus `TypeError`/`checkPoint` in Application events: incompatible status call or an old binary.
- 1067 plus `ACL initialization failed`, `icacls`, or error 5: protected-path ACL/ownership.
- 1068: legacy service dependency; run elevated repair.
- Service missing or ImagePath file missing: partial install, upgrade rollback, antivirus quarantine, or manual deletion.
- Agent reaches RUNNING but watchdog later restarts it: stale/missing heartbeat, dead sender/health thread, blocked disk, or inaccessible data directory.
- Manager DNS/TCP/TLS failure while service remains RUNNING: degraded delivery, not a startup failure; telemetry stays in the encrypted outbox.

The root `debug.log` contains Chromium registration errors and Git sandbox warnings, not AttackLens SCM evidence; it should not be used to diagnose these services.

## Live endpoint validation — 2026-08-09

The post-implementation read-only test found both installed services registered as LocalSystem/automatic but stopped. The System log contained 41 matching Service Control Manager failures in the seven-day query window. The latest entries were Event ID 7024, and both services repeatedly exited with service-specific code `536870913` at roughly 36–40 second intervals. This confirms a restart storm rather than a one-time boot delay.

`sc.exe qc` also showed that the installed `AttackLensWatchdog` still depends on `AttackLensAgent`. That is an older/stale service registration: the corrected source and repair workflow intentionally remove this dependency so the watchdog can start when the agent cannot. The installed binaries/config could not be fully validated without an actual elevated Windows token; the sandbox-approved host command remained non-elevated and the protected config returned diagnostic exit code 2.

## Rebuild validation — 2026-08-09

Version 2.0.7 was rebuilt from the corrected sources through the canonical
Windows pipeline. The resulting compiled MSI contract reports both services as
dependency-free, contains 149 MSI file rows covering all 146 manifest entries,
and enforces the embedded EULA for unattended installation. Both newly frozen
executables returned exit code 0 and valid JSON from their offline `diagnose`
commands. Defender, WiX validation, the 442-test source suite, and all Docker
failure scenarios passed. The package is unsigned and therefore remains a
development/test artifact until the production signing gate is run.

## Confirmed 2.0.6 reinstall failure — 2026-08-09

The failed 2.0.6 reinstall is MSI error 1603 caused by custom action
`CA_WriteConfig` returning error 1722. Raw Application Event 1001 contains the
otherwise-hidden exception: `Cannot set SYSTEM owner on
C:\ProgramData\AttackLens\config\agent.toml (icacls exit 6)`.

The configuration was preserved from an earlier install with a legacy ACL.
The generator attempted to change its owner before granting SYSTEM the rights
needed to edit the security descriptor. Windows Installer consequently rolled
back the package and removed both service registrations. The corrected
migration now applies the final ACL first, uses `takeown.exe /A` plus a tightly
scoped SYSTEM bootstrap grant when legacy permissions block that operation,
and normalizes the owner only after SYSTEM has full control. File contents,
identity, credentials, and queued telemetry are not deleted. The x64 MSI also
uses `System64Folder` explicitly so configuration runs under 64-bit PowerShell.

## 2026-08-09: installed and running but targeting localhost

The running agent was verified in TCP `SYN_SENT` to `127.0.0.1:8443`. The
reinstall supplied a different manager, but the generator's unconditional
`PRESERVE_STATE=1` early return retained the old URL. Version 2.0.9 distinguishes
an ordinary upgrade from an explicit manager override, patches only manager
connection fields atomically, preserves a protected rollback copy, and
re-enrolls when the saved credential belongs to another manager. See
`CURRENT_INCIDENT.md` for endpoint evidence and recovery commands.

## 2026-08-10: GUI manager value did not reach the deferred EXE

The 2.0.8 GUI controls populated secure public MSI properties correctly, but
the deferred PowerShell EXE tried to read `%MsiCustomActionData%` as an
environment variable. Windows Installer only guarantees the
`CustomActionData` property within deferred execution, and an external EXE
cannot query the original session. Consequently the generator saw no explicit
manager override and preserved the previous localhost configuration. Version
2.0.9 prepares Base64 JSON in an immediate Binary-table JScript action, hides
the deferred target from MSI logs, and explicitly passes
`[CustomActionData]` to `gen_config.ps1`. The compiled-MSI verifier enforces
that complete contract.

## 2026-08-10: 2.0.10 GUI value loss and rejected manual edit

Registry inspection confirms version 2.0.10 with
`InstallDir=C:\Program Files\AttackLens` and
`DataDir=C:\ProgramData\AttackLens`. The SCM ImagePaths supplied by the
operator point to Program Files, so any Program Files (x86) tree is stale or
unrelated and is not the running service payload.

The active TOML stayed at 2,709 bytes while two 2,721-byte
`agent.toml.invalid-*` copies appeared after Notepad saves. This was not a
failure to write: validation quarantined each edit and restored the 2,709-byte
last-known-good config. A bare IP in runtime TOML `url` is invalid because the
runtime requires an absolute URL; 2.0.11 normalizes a bare installer address
before writing TOML.

The remaining installer defect was a single-stage bridge: 2.0.10 prepared its
Base64 payload only in the execute session. Version 2.0.11 captures final
dialog values in the full UI client as `ATTACKLENS_CONFIG_DATA`, marks it
Secure+Hidden for transfer across elevation, and assigns it to deferred
`CA_WriteConfig`. Silent/basic-UI installs keep an execute-session fallback.

### 2.0.12 correction after compiled-MSI reproduction

Decompiling the installed 2.0.11 package showed that `Before=ExecuteAction`
alone was insufficient: WiX assigned the capture action before `ResumeDlg`, so
the manager controls had not run. Version 2.0.12 authors the action after
`ProgressDlg`. Its compiled order is now exactly
`ProgressDlg -> CA_StageWriteConfigUI -> ExecuteAction`, and the MSI verifier
checks the numeric table sequence.

## 2026-08-11: workspace tool succeeds but installed MSI tool is denied

The manager address was valid. The failure was caused by conflating two
security contexts:

1. `gen_config.ps1` is an installer/migration component. It creates protected
   state and rewrites ACLs while running as a deferred LocalSystem MSI action.
2. `configure-manager.ps1` is an Administrator operator tool. It should update
   the content of an existing protected file without changing its owner/DACL.

The packaged operator tool called the installer component. `agent.toml` granted
Administrators Modify, so direct content updates were authorized, but the
generator's `icacls /inheritance:r` required security-descriptor rights not
included in Modify. This produced `C:\ProgramData\AttackLens\config: Access is
denied` regardless of whether the services were stopped.

2.0.13 separates these roles. Runtime changes validate a staged TOML, open the
existing active file exclusively, truncate/write/flush that same file object,
validate the live result, and recover the backup through the same path. No DACL
rewrite is requested. Optional CA/SPKI fields are preserved unless supplied;
empty keys are not appended. Native validator stderr is captured with its exit
code so error reporting is complete.

A second packaging gap also existed: the verifier proved that required filenames
were present but not that the CAB contained the current source. The release gate
now decompiles the completed MSI and SHA-256 compares critical scripts and the
UI bridge byte-for-byte. A negative test proves it rejects the stale 2.0.12 MSI.
