# Windows Agent Development and Test Roadmap

> Implemented startup recovery and remaining operator stop conditions are consolidated in [`advanced_support/`](advanced_support/README.md).

Scope: `PROJECT_CORE/agent/os/windows/`

Goal: build a reliable Windows endpoint agent with MSI-based GUI and CLI
installation, hardened service runtime, smart configuration, strong local
security, offline delivery, and repeatable validation.

This roadmap is intentionally ordered. Each milestone should be completed,
reviewed, and tested before starting the next milestone unless the task is
clearly independent.

## Guiding Principles

1. Prefer stable Windows-native behavior over clever shortcuts.
2. Keep installer, service runtime, collectors, transport, and diagnostics as
   separate concerns.
3. Make every install mode deterministic: GUI, silent CLI, upgrade, repair,
   uninstall, and purge.
4. Default to secure production behavior, with explicit development overrides.
5. Every feature must have a validation path that can run in CI or a Windows VM.
6. Preserve endpoint identity and operator config during normal upgrades.
7. Do not silently discard telemetry unless the manager rejects it permanently.
8. Never log secrets, tokens, API keys, or private key material.

## Milestone 0: Baseline Audit and Decision Log

Objective: establish the exact current state before changing behavior.

Development tasks:

1. Inventory all Windows-agent files under `agent/os/windows`.
2. Record current service names, install paths, config paths, registry keys, MSI
   properties, and package outputs.
3. Identify stale docs and conflicting install instructions.
4. Identify stale branding or naming in docstrings, comments, logs, registry
   values, config keys, executable names, and tests.
5. Decide final installer property model:
   - primary: `MANAGER_URL`
   - compatibility aliases: `MANAGER_IP`, `MANAGER_PORT`
   - security: `TLS_VERIFY`, `CA_BUNDLE`, `SPKI_PIN`
   - enrollment: `ENROLL_TOKEN`, optional `AGENT_NAME`
   - operations: `COLLECTION_PROFILE`, `PRESERVE_STATE`, `PURGE_ON_UNINSTALL`
6. Decide final runtime layout:
   - config: `C:\ProgramData\AttackLens\config\agent.toml`
   - logs: `C:\ProgramData\AttackLens\logs`
   - security: `C:\ProgramData\AttackLens\security`
   - spool: `C:\ProgramData\AttackLens\spool`
   - data: `C:\ProgramData\AttackLens\data`
7. Create a short decision log in `WINDOWS_AGENT_WORK_LOG.md`.

Test tasks:

1. Run current unit tests that do not require Windows-only APIs.
2. Build a list of tests that currently cannot run on this machine.
3. Verify the current MSI build command and record missing prerequisites.
4. Confirm no forbidden reference naming appears in new Windows architecture or
   roadmap docs.

Exit criteria:

- Current state is documented.
- Conflicting installer properties are listed.
- Final path and property decisions are recorded.
- No runtime behavior has been changed yet.

## Milestone 1: Naming, Encoding, and Documentation Cleanup

Objective: make Windows-agent source and docs internally consistent before
adding features.

Development tasks:

1. Replace stale service docstrings and comments with current product names.
2. Remove mojibake from Windows documentation and source comments.
3. Normalize all docs to these files:
   - `AGENT_ARCHITECTURE.md`
   - `WINDOWS_AGENT_ROADMAP.md`
   - `INSTALL.md`
   - `TROUBLESHOOTING.md`
4. Retire or rewrite conflicting install docs that describe different layouts.
5. Update command examples to use HTTPS by default.
6. Document the final MSI properties and runtime config path.

Test tasks:

1. Search Windows tree for stale names and forbidden reference terms.
2. Search Windows docs for `http://` examples and replace with HTTPS unless the
   example explicitly demonstrates a blocked/invalid configuration.
3. Run markdown link/path sanity checks manually.

Exit criteria:

- One authoritative install guide exists.
- Docs agree with the actual MSI layout.
- No stale naming remains in Windows docs or comments.

## Milestone 2: Typed Runtime Configuration

Objective: make config validation explicit and testable.

Development tasks:

1. Add `config_model.py`.
2. Implement typed config loading:
   - agent ID and name
   - manager URL
   - TLS verification mode
   - optional CA bundle
   - optional SPKI pin
   - enrollment token
   - path settings
   - logging settings
   - collection sections
   - response settings
3. Enforce HTTPS manager URL by default.
4. Allow development override only through explicit config:
   - `allow_insecure_transport = true`
   - disabled by default
5. Validate intervals, booleans, path values, and unsupported section names.
6. Add `--validate-config` CLI mode.
7. Update `win_agent.py` to consume the typed model or a validated dict.
8. Add clear startup errors for invalid config.

Test tasks:

1. Unit tests for valid minimal config.
2. Unit tests for full production config.
3. Unit tests for invalid URL scheme.
4. Unit tests for invalid booleans from MSI-generated config.
5. Unit tests for unknown collection sections.
6. Unit tests for interval bounds.
7. Unit tests for path defaults.

Exit criteria:

- The service cannot start with malformed config.
- Validation errors tell operators exactly what to fix.
- Existing valid config still loads.

## Milestone 3: Centralized Windows ACL Hardening

Objective: one ACL implementation used by installer scripts and runtime checks.

Development tasks:

1. Add `acl.py`.
2. Implement helpers:
   - secure directory: `SYSTEM` and `Administrators` full control
   - executable directory: read/execute for normal users, full control for admins
   - log directory: service write, admins read/write
   - response directory: admin-only write
3. Add ACL check mode that reports drift without changing state.
4. Add ACL repair mode for service startup and diagnostics.
5. Update `keystore.py` to call shared ACL helpers where possible.
6. Update config generator to use the same ACL semantics.
7. Add clear warnings if `icacls` fails.

Test tasks:

1. Unit tests for generated `icacls` command arguments.
2. Windows VM tests that a normal user cannot modify:
   - `agent.toml`
   - security key files
   - spool files
   - response scripts
3. Windows VM tests that `SYSTEM` can write logs, state, spool, and keys.
4. Repair test after intentionally weakening ACLs.

Exit criteria:

- ACL policy is defined once.
- Installer and runtime agree on protected locations.
- Normal users cannot tamper with privileged runtime inputs.

## Milestone 4: Smart MSI Property and Config Generation

Objective: make command-line MSI installation precise, secure, and backwards
compatible.

Development tasks:

1. Update WiX public properties:
   - `MANAGER_URL`
   - `MANAGER_IP`
   - `MANAGER_PORT`
   - `TLS_VERIFY`
   - `CA_BUNDLE`
   - `SPKI_PIN`
   - `ENROLL_TOKEN`
   - `AGENT_NAME`
   - `COLLECTION_PROFILE`
   - `PRESERVE_STATE`
   - `PURGE_ON_UNINSTALL`
2. Mark sensitive properties as secure and hidden from logs where MSI supports it.
3. Update `gen_config.ps1` to parse quoted values safely.
4. Prefer `MANAGER_URL` when supplied.
5. Build URL from `MANAGER_IP` and `MANAGER_PORT` only when `MANAGER_URL` is
   absent.
6. Always generate HTTPS unless explicit insecure development mode is set.
7. Preserve existing `agent.id` and `agent.name` on upgrade unless overridden.
8. Preserve existing TLS and collection settings on repair unless explicitly
   overridden.
9. Generate collection sections from named profiles.
10. Add config schema version to `agent.toml`.
11. Write config atomically with `.tmp` then rename.
12. Redact secrets in config generation logs.

Test tasks:

1. Unit-like PowerShell tests for `gen_config.ps1` input parsing.
2. Test with only `MANAGER_URL`.
3. Test with `MANAGER_IP` and `MANAGER_PORT`.
4. Test token containing MSI-sensitive characters.
5. Test empty token.
6. Test `TLS_VERIFY=true`, `false`, and custom CA path.
7. Test invalid URL fails install.
8. Test upgrade preserves agent ID.
9. Test repair does not overwrite operator edits.

Exit criteria:

- Silent CLI install works with the final property model.
- Existing compatibility properties still work.
- Generated config is deterministic and valid.

## Milestone 5: MSI GUI Installer

Objective: provide a safe interactive installer for admins who do not use silent
deployment.

Development tasks:

1. Add WiX UI dialog flow:
   - welcome
   - install directory
   - manager connection
   - enrollment
   - collection profile
   - security options
   - confirm
   - progress
   - completion
2. Manager connection page:
   - manager URL input
   - TLS verification checkbox
   - optional CA bundle path
   - optional SPKI pin
3. Enrollment page:
   - enrollment token input
   - agent display name input
4. Collection profile page:
   - baseline
   - standard
   - intensive
   - incident
5. Security options page:
   - preserve state on uninstall
   - enable response actions disabled by default
6. Validate required fields before install starts.
7. Hide token text in UI where possible.
8. Ensure GUI properties and CLI properties feed the same config generator.
9. Add installer icon and consistent product text.
10. Do not require network connectivity during GUI install unless an explicit
    "test connection" button is implemented.

Best choice:

- Use WiX UI for the MSI GUI, not a separate bootstrapper at first.
- Add a bootstrapper later only if prerequisites, download flows, or richer
  validation are required.

Test tasks:

1. Manual GUI install on Windows 11.
2. Manual GUI install with self-signed test manager.
3. Manual GUI install with production-style HTTPS validation.
4. GUI cancel test before file copy.
5. GUI cancel test during progress.
6. Verify GUI properties produce the same `agent.toml` shape as silent install.
7. Screenshot UI for release notes and support docs.

Exit criteria:

- GUI install produces a working service pair.
- GUI and CLI install share one config generation path.
- No secrets appear in MSI logs from GUI flow.

## Milestone 6: Service Lifecycle Hardening

Objective: make SCM behavior reliable through start, stop, crash, upgrade, and
boot.

Development tasks:

1. Confirm PyInstaller `onedir` service startup works under SCM.
2. Ensure service reports `SERVICE_RUNNING` only after critical startup checks.
3. Add service start pending checkpoints for longer initialization.
4. Ensure service stop flushes queue to spool.
5. Ensure sender closes transport on stop.
6. Add Windows Event Log source registration if needed.
7. Replace invalid event IDs with standard service log calls.
8. Ensure watchdog rate-limits restarts and logs rate-limit state.
9. Add optional service recovery actions through WiX.
10. Make service dependencies explicit:
    - `Tcpip`
    - `Dnscache`
11. Decide whether `LocalSystem` remains default or whether a dedicated service
    account is needed for production.

Test tasks:

1. Start service after clean install.
2. Stop service and verify clean shutdown log.
3. Kill service process and verify watchdog restart.
4. Trigger repeated crashes and verify watchdog rate limit.
5. Reboot VM and verify delayed auto-start.
6. Upgrade while service is running.
7. Uninstall while service is running.

Exit criteria:

- Service lifecycle is deterministic under SCM.
- Watchdog does not create restart storms.
- Upgrade and uninstall handle running services cleanly.

## Milestone 7: Installer Upgrade, Repair, Uninstall, and Purge

Objective: make all MSI maintenance modes safe and testable.

Development tasks:

1. Define upgrade behavior:
   - stop services
   - replace binaries
   - preserve config and identity
   - migrate config schema
   - re-apply ACLs
   - restart services
2. Define repair behavior:
   - restore missing files
   - re-register services
   - re-apply ACLs
   - do not re-enroll unnecessarily
3. Define default uninstall:
   - stop and remove services
   - remove binaries
   - preserve config, identity, logs, data, and spool by default
4. Define purge uninstall:
   - remove all product state only when `PURGE_ON_UNINSTALL=1`
5. Add uninstall custom action if WiX declarative behavior is insufficient.
6. Record uninstall mode in install log.
7. Add registry values for installed version, config path, and data path.

Test tasks:

1. Clean install.
2. Same-version reinstall.
3. Upgrade from previous version.
4. Repair after deleting an executable.
5. Repair after deleting registry values.
6. Default uninstall preserves state.
7. Purge uninstall removes state.
8. Reinstall after default uninstall reuses identity.
9. Reinstall after purge creates new identity.

Exit criteria:

- Every MSI mode has a documented expected result.
- State preservation is explicit and verified.

## Milestone 8: Agent CLI and Admin Tooling

Objective: ship a consistent local CLI for operators and support teams.

Development tasks:

1. Add `attacklensctl` command or package existing service helper as a real tool.
2. Commands:
   - `status`
   - `start`
   - `stop`
   - `restart`
   - `logs`
   - `config show`
   - `config validate`
   - `collect-once`
   - `diagnostics`
   - `enroll`
   - `repair-acl`
   - `version`
3. Ensure CLI works from elevated PowerShell and cmd.
4. Ensure read-only commands provide clear messages for non-admin users.
5. Add JSON output mode for automation:
   - `--json`
6. Avoid exposing secrets in `config show`.
7. Add MSI Start Menu shortcut for diagnostics or log viewer if useful.

Best choice:

- Implement a Python CLI packaged through PyInstaller so behavior is testable in
  unit tests and consistent with runtime code.
- Keep PowerShell wrappers thin.

Test tasks:

1. CLI status before install returns clear error.
2. CLI status after install returns service and config state.
3. CLI config validation catches broken TOML.
4. CLI collect-once returns JSON.
5. CLI diagnostics redacts secrets.
6. CLI commands work when launched from arbitrary directories.

Exit criteria:

- Operators have a supported local tool.
- Troubleshooting no longer depends on manual path memorization.

## Milestone 9: Diagnostics and Support Bundle

Objective: make failures diagnosable without exposing secrets.

Development tasks:

1. Add `diagnostics.py`.
2. Collect:
   - redacted config
   - service status
   - registry values
   - file layout presence
   - ACL check results
   - last 500 lines of logs
   - spool size
   - data directory summary
   - collector enablement
   - Windows version
   - manager URL hostname and port
   - last send status if available
3. Write zip bundle under `logs`.
4. Redact:
   - enrollment tokens
   - API keys
   - SPKI pin if operator chooses strict mode
   - local usernames in optional privacy mode
5. Add `attacklensctl diagnostics`.

Test tasks:

1. Bundle generation on healthy install.
2. Bundle generation when service is stopped.
3. Bundle generation with corrupt config.
4. Verify redaction through string search.
5. Verify zip does not include security key files.

Exit criteria:

- Support bundle is useful and safe to share internally.

## Milestone 10: Event Log Collector v2

Objective: move from periodic wide reads to stateful incremental collection.

Development tasks:

1. Add state store for event cursors under `data\eventlog`.
2. Track per-channel bookmark or record ID.
3. Support channels:
   - Security
   - System
   - Application
   - Windows PowerShell
   - PowerShell Operational
   - Defender Operational where present
4. Normalize high-value events:
   - logon success and failure
   - explicit credential use
   - privileged logon
   - process creation
   - service creation
   - scheduled task changes
   - account and group changes
   - audit policy changes
   - Defender alerts and configuration changes
5. Add per-cycle record cap.
6. Add parser error metrics.
7. Make channel list config-driven.

Test tasks:

1. Unit tests for event XML parsing.
2. Unit tests for missing fields.
3. Unit tests for cursor persistence.
4. Windows VM tests that generated events are collected once.
5. Restart test proves cursor resumes correctly.
6. High-volume test respects record cap.

Exit criteria:

- Event collection is incremental and does not duplicate records after restart.

## Milestone 11: File Integrity Collector

Objective: detect changes in high-value files and directories.

Development tasks:

1. Add `collectors/fim.py`.
2. Add baseline state under `data\fim`.
3. Support targets from policy/config.
4. Capture:
   - path
   - file type
   - SHA-256
   - size
   - modified time
   - owner when available
   - ACL hash
5. Emit created, modified, deleted, and ACL-changed events.
6. Add exclude patterns.
7. Add per-cycle file limit.
8. Add explicit baseline rebuild CLI command.
9. Protect baseline state with ACLs.

Test tasks:

1. Unit tests for hashing and state diff.
2. Unit tests for excludes.
3. Windows VM test for create/modify/delete.
4. Windows VM test for ACL change.
5. Performance test on large directory with cap.

Exit criteria:

- File changes are detected without unbounded default scans.

## Milestone 12: Registry Integrity Collector

Objective: detect changes in high-value registry persistence and security keys.

Development tasks:

1. Add `collectors/registry.py`.
2. Add baseline state under `data\registry`.
3. Monitor configured keys:
   - startup run keys
   - service configuration
   - logon shell and userinit
   - image file execution options
   - Defender exclusions
   - firewall policy
   - PowerShell logging policy
4. Capture value name, type, normalized value, and hash.
5. Emit created, modified, deleted events.
6. Add 32-bit and 64-bit registry view handling.
7. Add explicit baseline rebuild command.

Test tasks:

1. Unit tests for value normalization.
2. Unit tests for diff logic.
3. Windows VM tests for create/modify/delete.
4. Windows VM test for 32-bit registry view.
5. Permission failure test.

Exit criteria:

- Registry drift is reported clearly and incrementally.

## Milestone 13: Assessment Engine Hardening

Objective: make policy checks accurate, versioned, and explainable.

Development tasks:

1. Add policy metadata:
   - ID
   - version
   - supported OS editions
   - compliance mappings
2. Validate policy files before running them.
3. Separate failed check from failed collector.
4. Add evidence summaries.
5. Add remediation text.
6. Add jittered scan on start and interval scans.
7. Cache expensive check results where safe.

Test tasks:

1. Unit tests for policy parser.
2. Unit tests for pass/fail/not-applicable/error.
3. Windows VM tests on at least one client and one server OS.
4. Snapshot test for normalized assessment output.

Exit criteria:

- Assessment results are stable and operator-readable.

## Milestone 14: Local Response Framework

Objective: add controlled local response without creating a remote shell.

Development tasks:

1. Add `response.py`.
2. Default response actions to disabled.
3. Add config:
   - enabled
   - allowed response IDs
   - max runtime
   - max output bytes
4. Define signed response package format.
5. Verify signature before execution.
6. Pass arguments as structured JSON.
7. Avoid shell string concatenation.
8. Capture exit code, stdout, stderr, duration.
9. Write local `response.log`.
10. Emit `response_result` payload.
11. Add manager command polling or reuse existing control channel if available.

Test tasks:

1. Unit tests for command validation.
2. Unit tests for disallowed response IDs.
3. Unit tests for timeout.
4. Unit tests for output truncation.
5. Windows VM test with a harmless signed response.
6. Tamper test with modified response package.

Exit criteria:

- Response execution is auditable, allow-listed, signed, and bounded.

## Milestone 15: Transport and Spool Reliability

Objective: prove delivery behavior under real network failures.

Development tasks:

1. Add sender metrics:
   - last success timestamp
   - last failure reason
   - current backoff
   - spool bytes
   - dropped-by-trim count
2. Add payload size guard.
3. Add manager 4xx handling policy.
4. Add key revoked state and operator instruction.
5. Add optional compression ratio logging at debug level.
6. Add spool corruption detection.

Test tasks:

1. Unit tests for spool trim.
2. Unit tests for orphan drain recovery.
3. Unit tests for re-spool on mid-drain failure.
4. Integration test: manager down, spool grows.
5. Integration test: manager recovers, spool drains.
6. Integration test: 401 response stops retrying rejected payload.
7. Integration test: TLS pin mismatch fails closed.

Exit criteria:

- Offline behavior is deterministic and measurable.

## Milestone 16: Collection Performance and Profiles

Objective: keep default collection useful without overloading endpoints.

Development tasks:

1. Implement profile definitions:
   - baseline
   - standard
   - intensive
   - incident
2. Make profile selection available in MSI GUI and CLI.
3. Add per-collector timeout wrappers.
4. Add per-cycle record limits.
5. Add startup jitter to all expensive sections.
6. Emit collector duration metrics.
7. Disable expensive full binary scans by default.
8. Add privacy controls for sensitive fields where required.

Test tasks:

1. Unit tests for profile generation.
2. Collect-once test for each profile.
3. Performance test on Windows 11.
4. Performance test on Windows Server.
5. Verify CPU, memory, and runtime budgets.

Exit criteria:

- Standard profile is safe for broad deployment.
- Intensive profile is explicitly opt-in.

## Milestone 17: Build, Signing, and Release Pipeline

Objective: make release packages reproducible and verifiable.

Development tasks:

1. Pin Python dependencies.
2. Pin PyInstaller behavior.
3. Verify WiX v4 extension install.
4. Generate SBOM for packaged dependencies.
5. Sign service executables.
6. Sign MSI.
7. Timestamp signatures.
8. Produce checksums.
9. Generate release manifest:
   - version
   - build time
   - git commit
   - file hashes
   - signer info
10. Archive build logs.

Test tasks:

1. Build from clean checkout.
2. Build with `-SkipBuild`.
3. Verify executable signatures.
4. Verify MSI signature.
5. Install signed MSI on clean VM.
6. Confirm SmartScreen/reputation notes for release process.

Exit criteria:

- Release artifacts are signed, hashed, and reproducible.

## Milestone 18: End-to-End Windows VM Test Matrix

Objective: validate real-world Windows behavior.

Test environments:

1. Windows 10 x64.
2. Windows 11 x64.
3. Windows Server 2019.
4. Windows Server 2022.
5. Domain-joined VM if available.
6. Non-domain workgroup VM.

Scenarios:

1. GUI install.
2. Silent CLI install.
3. Install with enrollment token.
4. Install without token if manager allows open enrollment.
5. Install with custom CA.
6. Install with SPKI pin.
7. Invalid TLS config.
8. Manager unreachable at install time.
9. Manager unreachable at runtime.
10. Upgrade.
11. Repair.
12. Default uninstall.
13. Purge uninstall.
14. Reboot persistence.
15. Normal-user tamper attempt.
16. Watchdog restart.
17. Collect-once diagnostics.
18. Support bundle generation.

Exit criteria:

- Every supported OS passes clean install, runtime, upgrade, and uninstall.
- Failures are documented as bugs with logs and reproduction steps.

## Milestone 19: Enterprise Deployment

Objective: make the MSI deployable through standard Windows fleet tooling.

Development tasks:

1. Document Intune install command.
2. Document Intune uninstall command.
3. Document Intune detection rule.
4. Document GPO deployment.
5. Document SCCM deployment if required.
6. Provide sample transform or property file strategy.
7. Provide installer exit code guide.
8. Add examples for proxy and custom CA environments if supported.

Test tasks:

1. Intune-style silent install command on VM.
2. Detection rule registry validation.
3. Silent uninstall command.
4. Reinstall after uninstall.

Exit criteria:

- Enterprise admins can deploy without manual steps.

## Milestone 20: Production Readiness Review

Objective: verify the agent is safe to ship.

Review checklist:

1. No secrets in logs.
2. No plain HTTP by default.
3. Config validation blocks unsafe defaults.
4. MSI properties documented and tested.
5. GUI install tested.
6. CLI install tested.
7. Upgrade tested.
8. Repair tested.
9. Uninstall and purge tested.
10. Watchdog tested.
11. Offline spool tested.
12. Event collection tested.
13. File and registry integrity tested if enabled.
14. Response framework tested if enabled.
15. ACL tamper tests passed.
16. Signed artifacts verified.
17. Support bundle redaction verified.
18. Performance budget met.
19. All known limitations documented.
20. Release notes prepared.

Exit criteria:

- Engineering, security, and operations sign off on the release candidate.

## Recommended Execution Order

1. Milestone 0: Baseline audit and decisions.
2. Milestone 1: Naming, encoding, and docs cleanup.
3. Milestone 2: Typed config validation.
4. Milestone 3: ACL hardening.
5. Milestone 4: Smart MSI property and config generation.
6. Milestone 5: MSI GUI installer.
7. Milestone 6: Service lifecycle hardening.
8. Milestone 7: Upgrade, repair, uninstall, purge.
9. Milestone 8: Agent CLI.
10. Milestone 9: Diagnostics.
11. Milestone 15: Transport and spool reliability.
12. Milestone 16: Collection performance and profiles.
13. Milestone 10: Event collector v2.
14. Milestone 11: File integrity collector.
15. Milestone 12: Registry integrity collector.
16. Milestone 13: Assessment engine hardening.
17. Milestone 14: Local response framework.
18. Milestone 17: Build, signing, and release pipeline.
19. Milestone 18: End-to-end Windows VM matrix.
20. Milestone 19: Enterprise deployment.
21. Milestone 20: Production readiness review.

## First Implementation Slice

The first coding slice after this roadmap should be small and foundational:

1. Clean Windows docs and stale naming.
2. Add `config_model.py`.
3. Add config validation tests.
4. Update `win_agent.py` to validate config before runtime startup.
5. Update `gen_config.ps1` only enough to generate config that passes the new
   validator.

This slice gives every later installer, GUI, CLI, service, and collector change
a stable contract to build on.
