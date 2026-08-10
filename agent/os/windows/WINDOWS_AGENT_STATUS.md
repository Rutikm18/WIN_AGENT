# Windows Agent Roadmap Status

> Startup resilience status was updated on 2026-08-09; see [`advanced_support/`](advanced_support/README.md).

Updated: 2026-07-27

This status is based on the source under `agent/os/windows/`. The `pkg/`
packaging path is treated as authoritative; `installer/` and
`installer/build/` remain legacy or generated copies until they are reconciled.

## Completed or substantially implemented

- Milestone 0 baseline audit: inventory, service names, paths, MSI properties,
  build command, collector coverage, and known risks are recorded in
  `WINDOWS_AGENT_BASELINE_AUDIT.md`.
- Windows runtime foundation: `AttackLensAgent` service, watchdog service,
  collector scheduling, circuit breakers, encrypted transport, enrollment/key
  storage, normalizer, SCA, and an encrypted transactional SQLite delivery
  outbox.
- Build foundation: PyInstaller `onedir` specs and WiX v4 MSI pipeline exist;
  a prior MSI artifact is present in `pkg/dist`.
- Basic watchdog restart rate limiting and event-log error reporting exist.
- The first config-validation slice is implemented: typed model, defaults,
  HTTPS enforcement, explicit HTTP development override, TLS/CA/SPKI checks,
  interval and collector validation, startup fail-closed behavior, and
  `--validate-config`.
- MSI generation now uses the final property names in the primary WiX file,
  preserves compatibility host/port properties, supports collection profiles,
  writes schema version 1, and replaces TOML atomically.
- SCM readiness now reports `SERVICE_RUNNING` only after config, enrollment,
  collector loading, and spool initialization succeed.
- Milestone 3 implementation slice: centralized `acl.py` policies now define
  secure, executable, log, service-data, config, key, and response boundaries;
  check/repair results are structured, `icacls` failures are surfaced, the
  keystore delegates to the shared policy, and runtime startup repairs ACLs.
- Milestone 4 implementation slice: the primary MSI generator now validates
  properties, preserves existing configuration when `PRESERVE_STATE` is set,
  applies the shared ACL semantics to runtime paths, protects the config file,
  supports custom CA paths and IPv6 fallback hosts, and keeps atomic writes.
- Milestone 5 implementation slice: the primary MSI now includes interactive
  WiX pages for manager/TLS settings, enrollment, collection profile, and
  state options. GUI values use the same MSI properties and deferred,
  fail-closed generator as silent installs; the enrollment token is masked.
- Milestone 6 implementation slice: the service reports SCM startup
  checkpoints during validation, ACL repair, enrollment, collector loading,
  and spool initialization, then transitions to running only after readiness.
  Shutdown queue flushing, transport closure, network dependencies, and MSI
  recovery actions are present.
- Milestone 7 implementation slice: default uninstall preserves ProgramData
  state, while `PURGE_ON_UNINSTALL=1` invokes an elevated, path-bound purge
  action before file removal. Both authoritative MSI build scripts embed the
  GUI and purge payloads.
- Windows delivery reliability and observability: canonical payloads are
  encrypted at rest, committed before source cursors advance, re-encrypted with
  a fresh timestamp/nonce for every attempt, deleted only after manager ACK,
  split below the request limit, and retained as dead letters when rejected.
  Health reports outbox depth, dead letters, retry/auth counters, connection
  classification, clock skew, and collector diagnostics.
- Event Log continuity: Security, System, Application, Sysmon, PowerShell,
  Defender, Terminal Services, and WMI Activity channels use restart-safe
  `EventRecordID` cursors, independent retries, explicit Windows error
  classification, atomic cursor state, and log-clear detection. Equivalent
  process, network, and DNS records are normalized into canonical entities.
- Lifecycle self-healing: fatal startup errors now reach SCM, critical runtime
  thread exits fail the service, and the watchdog detects stopped services,
  stale runtime heartbeats, and running-but-crashed sender state. A global
  kernel mutex blocks duplicate instances; pre-shutdown and power-resume
  controls flush/wake delivery and publish clean/unclean lifecycle state.
- Integrity and operator diagnostics: the MSI generates a SHA-256 manifest for
  both service executables, startup verifies it before enrollment, runtime
  health detects config changes, and the executable provides `status`,
  `capabilities`, `self-test`, and `diagnose` commands.
- The Windows failure-pattern mapping and resulting controls are documented in
  `RESILIENCE_DESIGN.md`.
- Live manager communication is validated against
  `http://13.233.122.80:8080`: TCP/8080 succeeds, `/health` returns HTTP 200
  with manager/database status `ok`, and open enrollment plus encrypted
  forwarding succeeded. A broad 21-section collection and a stale-record
  replay test drained with zero pending/dead rows.
- Host-only manager configuration defaults to HTTP port 8080 and persists
  `ALLOW_INSECURE_TRANSPORT=true`; production deployments should supply an
  explicit HTTPS URL and enable certificate verification.
- The standalone config generator writes BOM-free UTF-8 TOML, and the full
  Python 3.13/PyInstaller/WiX v4 pipeline produces a fresh MSI. The package
  preserves the nested PyInstaller directory structure, installs short
  custom-action helper scripts, and passes `wix msi validate` with no ICE
  warnings or errors.

## Partially complete / needs Windows validation

- Documentation and naming cleanup: primary runtime names are AttackLens, but
  multiple install guides, generated copies, and mojibake remain.
- MSI property/config behavior: primary `pkg/` property precedence,
  preservation, validation, hidden enrollment token, custom-action contract,
  GUI source flow, default state preservation, and opt-in purge behavior are
  implemented; actual MSI install/repair/upgrade/uninstall tests still require
  Windows validation.
- ACL hardening: the central policy/check/repair implementation is present, but
  normal-user tamper and ACL-repair behavior still require Windows VM tests.
- Lifecycle hardening: service/watchdog behavior exists, but start/stop/crash/
  reboot/upgrade tests require a Windows VM; the primary SCM checkpoint slice
  is now implemented and statically covered.
- Upgrade/repair behavior: primary MSI sequencing and state-preserving config
  generation are implemented, but binary repair, registry repair, schema
  migration, and full maintenance-mode tests require a Windows VM.
- Transport/outbox reliability: unit coverage validates persistence, replay
  freshness, response classification, dead-letter retention, and cursor commit
  ordering; a full forced-outage and disk-exhaustion service test still
  requires a disposable elevated Windows environment.
- Event collection: stateful cursor behavior is implemented and unit tested;
  high-volume rollover, service restart, channel clear, and permission behavior
  still require Windows 10/11/Server VM proof.

## Not yet implemented

- Full lifecycle VM coverage: clean start/stop, forced crash, restart-rate
  limiting, reboot, upgrade while running, and uninstall while running.
- Complete upgrade/repair schema migration and Windows maintenance-mode tests.
- Packaged diagnostics/support bundle beyond the built-in executable commands.
- File-integrity collector and registry-integrity collector.
- Assessment-engine metadata/versioning hardening beyond the current SCA base.
- Signed, allow-listed local response framework.
- Named profile/per-collector timeout/performance-budget implementation beyond
  the generator's profile selection.
- Signed executables/MSI, SBOM, reproducible release manifest, and full Windows
  10/11/Server VM matrix.
- Intune/GPO/SCCM deployment documentation and production-readiness sign-off.

## Current validation limitation

The focused delivery-reliability suite passes 18/18 tests under Python 3.13.
The built executable validates the source-run configuration, a 21-section
collect-once run completes, PyInstaller builds both service executables, WiX v4
builds the MSI, and live manager enrollment/ingest/replay is verified. Actual
elevated MSI installation, SCM lifecycle, repair/upgrade, reboot, and uninstall
behavior still require a disposable Windows VM or an approved administrator
test window.

## 2.0.10 incident update

Endpoint inspection later confirmed both installed services running as
LocalSystem, the complete ProgramData tree present but protected, and the live
agent attempting `127.0.0.1:8443` because an upgrade preserved a legacy manager.
The intended HTTP development manager independently timed out from the host.
The stale-manager migration, manager-scoped re-enrollment, sanitized public
status, installed repair/status tools, and explicit status/support directories
are now implemented. Current evidence is recorded in
`advanced_support/CURRENT_INCIDENT.md`.

## 2.0.11 endpoint-config incident update

Endpoint evidence proves that 2.0.10 is installed under
`C:\Program Files\AttackLens` and mutable state is under
`C:\ProgramData\AttackLens`; the running service ImagePaths do not use Program
Files (x86). The two `agent.toml.invalid-*` files prove direct edits were saved
but rejected, after which last-known-good recovery restored the blank manager.

Version 2.0.11 stages final GUI values in a Secure+Hidden public MSI property
before elevation, uses one required manager-address field, normalizes a bare
IP/FQDN to HTTP/8080, logs non-secret installer capture provenance, and writes
config-recovery details to `agent.log`.

Validated artifact: `pkg\dist\attacklens-agent-2.0.11-x64.msi`; SHA-256
`FA0BD8D9BC50486BFD630F55F18CC03AAED48EB23765355BA30E6A7F1718B270`.

### 2.0.12 final sequencing correction

2.0.11 still generated an empty manager because compiled WiX sequencing placed
`CA_StageWriteConfigUI` before `ResumeDlg`. In 2.0.12 the compiled sequence is
`ProgressDlg -> CA_StageWriteConfigUI -> ExecuteAction`. Artifact SHA-256:
`33492289C0DBC1A1FA1980F259A2A6086DFE3E30E88B49B8A1FF5FC4556EF59B`.

### 2.0.13 packaged runtime-tool correction

The remaining `config: Access is denied` failure was reproduced independently
of SCM state. The installed manager tool reused the MSI generator, whose ACL
hardening is designed for deferred LocalSystem execution. Administrator Modify
access is sufficient to write the protected file contents, but not to rewrite
its DACL. The runtime tools now have a separate transaction: staged validation,
exclusive in-place durable write through the existing file object, live
validation, service restart, and in-place rollback. The DACL and owner remain
unchanged. Empty optional trust inputs no longer create invalid empty TOML keys.

The complete source suite passes 453 tests (7 skipped). The 2.0.13 release gate
passes 329 tests (2 skipped), parses all 19 PowerShell scripts, passes Defender
and WiX validation, verifies the GUI action order, and decompiles the compiled
MSI to byte-compare seven critical embedded assets against source. Artifact:
22,582,265 bytes; SHA-256
`E670BE12CB5FCEA2CDA60E7299F14BCC94E07BD0B7817D87A71999CF622024DA`.
