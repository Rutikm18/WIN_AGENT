# Windows Agent Release-Candidate QA Report

> Latest QA addendum: [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md). Build 2.0.19 passed 511 agent/platform tests (7 skipped), 24 manager tests, the 384-test canonical package gate (2 skipped), Defender, WiX, compiled MSI contracts, and the nine-case Docker lab. It remains an unsigned development build.

> The current startup and recovery scenario matrix is maintained in [`advanced_support/FAILURE_MATRIX.md`](advanced_support/FAILURE_MATRIX.md).

Date: 2026-07-27

Scope: `agent/os/windows` only

Verdict: **CONDITIONAL GO for lab deployment; NO-GO for production signing and
rollout until the two external release gates below are completed.**

All reproducible source, transport, diagnostics, PowerShell compatibility, and
MSI versioning failures found during this QA cycle are fixed. The rebuilt
2.0.1 agent communicates with the configured manager, and the complete
automated suite passes.

## Result summary

| Area | Result |
|---|---|
| Automated tests | PASS — 39/39 |
| Compiled agent manager self-test | PASS — DNS, TCP, HTTP 200 |
| Live encrypted delivery | PASS — 22 ACK, 0 pending, 0 dead |
| HTTPS validation matrix | PASS |
| Windows PowerShell 5.1 parsing | PASS — 13/13 scripts |
| WiX ICE validation | PASS |
| MSI manifest hashes and sizes | PASS |
| MSI version and upgrade detection | PASS — 2.0.1 detects older versions |
| Authenticode/MSI signature | NOT SIGNED — external release gate |
| Elevated install/upgrade/rollback matrix | NOT RUN — external release gate |

## Regression retest — 2026-07-28

- Automated source suite: 39/39 passed.
- Windows PowerShell parsing: 14/14 scripts passed.
- WiX XML parsing and MSI ICE validation passed.
- Nine-resolution Control Panel icon, installer bitmaps, embedded RTF license,
  acceptance gate, GUI radio values, and initial-install navigation passed
  direct MSI-table validation.
- Compiled `validate-config`, `capabilities`, `status`, and manager `self-test`
  passed; DNS, TCP port 8080, HTTP health, and database health were successful.
- Continuous agent was online and connected with 22 dashboard sections,
  2,020 stored files, and 15,772,586 stored bytes at the test checkpoint.
- Delivery health reported 4,091 durably queued and 4,091 acknowledged, with
  zero pending, dead letters, discarded records, queue-full losses, or Event
  Log parse errors. Seventeen transient failures were matched by seventeen
  scheduled retries.
- A 30-second continuity sample kept the same session, advanced last-seen,
  added five stored files, and advanced agent health, connections, metrics,
  ports, and processes.

## Fixed findings

### QA-001 — HTTPS verification-path conflict

Severity: Critical

Status: Fixed and regression-tested

The transport adapter no longer forces `verify=False` over a hostname-checking
SSL context. The Requests session and injected SSL context now use the same
validated verification setting.

Verified cases:

- Untrusted self-signed certificate is rejected.
- Custom CA with matching `localhost` identity succeeds.
- Hostname mismatch is rejected.
- Correct SPKI pin succeeds.
- Incorrect SPKI pin fails closed.
- Explicit development-only verification disable succeeds.
- TLS 1.2 remains the minimum protocol version.

### QA-002 — Same-version MSI upgrade collision

Severity: Critical

Status: Fixed in package; elevated upgrade test remains

The rebuilt artifact is version `2.0.1`:

```text
ProductVersion: 2.0.1
ProductCode:    {00DA51F4-F7DE-4251-AF1A-07C0B26DBBC0}
UpgradeCode:    {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
```

The MSI upgrade table detects versions below 2.0.1 and rejects newer-product
downgrades. A disposable elevated VM is still required to prove state
preservation and rollback against an installed older release.

### QA-004 — Service SID package configuration

Severity: High

Status: Fixed in MSI authoring; installed-service verification remains

The MSI contains `MsiServiceConfig` rows for `AttackLensAgent` and
`AttackLensWatchdog`, with service-SID type `unrestricted`. This creates
service identities without prematurely applying a write-restricted token that
could invalidate existing data-directory ACL assumptions.

Runtime SID creation must be confirmed after an elevated clean install and
upgrade.

### QA-006 — Connectivity failure schema

Severity: Medium

Status: Fixed and regression-tested

`connectivity_test()` now initializes top-level `ok: false`, so DNS and TCP
early-return paths have the same stable result schema as HTTP failures.

### QA-007 — Windows PowerShell 5.1 parsing

Severity: Medium

Status: Fixed

The six legacy installer scripts now carry an encoding marker compatible with
Windows PowerShell 5.1. Direct parser validation reports zero errors for all
six legacy scripts and all seven active package scripts.

## Environment findings that were intentionally not mutated

### QA-003 — Installed machine still runs the older build

Severity: High

Status: Deployment action pending

The installed service was not upgraded during QA because it owns an existing
legacy spool of approximately 48 MB. Installing over that state without first
proving the upgrade in a disposable elevated VM would create avoidable data
risk. Source, compiled-binary, live-manager, and MSI validation were performed
without modifying the installed service.

### QA-005 — Installed lifecycle settings are from the older build

Severity: High

Status: Deployment action pending

The new MSI contains both services, delayed automatic start configuration,
recovery configuration, the 180-second `PreshutdownTimeout` registry value,
and service configuration before service startup. Runtime SCM behavior still
requires elevated install, crash, shutdown, reboot, and sleep/resume testing.

## External release gates

### QA-008 — Release artifacts are unsigned

Severity: High for production distribution

Status: Open external gate

The MSI, agent executable, and watchdog executable report `NotSigned`. A
production code-signing certificate and release signing process are required.

### QA-009 — Elevated deployment matrix

Severity: High

Status: Open external gate

Run clean install, repair, older-to-2.0.1 upgrade, rollback, and uninstall on a
disposable elevated Windows VM. Confirm:

- one installed product entry;
- service SID, delayed start, recovery, shutdown, and pre-shutdown behavior;
- configuration, enrollment key, outbox, and legacy-spool preservation;
- crash/hang recovery and watchdog behavior;
- reboot and sleep/resume recovery;
- clean rollback on a forced upgrade failure.

## Passing evidence

### Automated tests

The suite contains 39 tests and passes with resource warnings treated as
errors. Coverage includes:

- invalid configuration classes and malformed normalizer input;
- Event Log normalization and secret-field filtering;
- manifest path, schema, hash, and atomic-write behavior;
- concurrent outbox writes, replay identity, dead letters, retries, and legacy
  spool migration;
- TLS trust, identity, pinning, protocol floor, proxy selection, and explicit
  development override;
- DNS/TCP early connectivity failures;
- SCA matchers, mutex, lifecycle markers, sender response classes, chunking,
  and watchdog health.

Test file: `tests/test_qa_matrix.py`

### Live manager delivery

Manager: `http://13.233.122.80:8080`

```text
Enrollment:               ok
Connection state:         healthy
Forwarded sections:       21
Acknowledged records:     22
Old replay record age:    600 seconds
Pending records:          0
Dead letters:             0
```

The additional acknowledged record is the deliberately old replay probe. It
proves a fresh wire envelope while preserving original collection time.

The rebuilt executable's `self-test` also completed successfully:

```text
DNS:      ok — 13.233.122.80
TCP:      ok — port 8080
HTTP:     ok — status 200
Overall:  ok
```

### MSI and artifact validation

- Artifact: `pkg/dist/attacklens-agent-2.0.1-x64.msi`
- Size: 19,200,250 bytes
- SHA-256:
  `12B4B52B31A2F4392D20FB0B00209257FC8E37D4B9B51FEBBFBB710BD50EC2D3`
- WiX ICE validation passes.
- MSI contains 106 file rows.
- Control Panel uses the embedded nine-resolution AttackLens product icon.
- Interactive setup contains branded banner/dialog artwork and the embedded
  AttackLens license; Next is gated by `LicenseAccepted = "1"`.
- TLS verification and state-preservation GUI choices use explicit radio
  values, and first-install configuration pages are excluded from maintenance.
- Both service executables match the generated install manifest by SHA-256 and
  size.
- Both LocalSystem services are automatic-start services.
- `MsiConfigureServices` is sequenced after `InstallServices` and before
  `StartServices`.
- The agent has a 180,000 ms pre-shutdown timeout.

## Release recommendation

Use 2.0.1 for the disposable elevated deployment matrix. Do not replace the
current service or publish the MSI to production until that matrix passes and
the three release artifacts are signed and signature-verified.

## 2.0.10 addendum

The current release target supersedes the older recommendation above for this
incident. Added coverage verifies public-status redaction, manager URL identity
normalization, loopback classification, old-credential archival, configuration
path completeness, status ACL read-only semantics, and MSI inclusion of the
runtime discovery and repair tools. Production release still requires signing
and a disposable elevated install/upgrade/uninstall matrix.

The complete Windows source suite passed 452 tests (7 skipped). The 2.0.10
canonical development pipeline passed its 325-test unit gate (2 skipped), rebuilt
both executables, produced a 152-row MSI File table covering 146 frozen payload
files plus six required operator/runtime assets, passed Microsoft Defender and
WiX validation, and passed compiled MSI contract verification. Artifact SHA-256:
`39C52FB58FCFE12AA2366C488AF9EEDC0A49336E1A12663C93D132E13D889B27`.

The 2.0.10 compiled MSI additionally verifies that GUI/silent properties are
prepared by a Binary-table JScript function, exposed as hidden
`CustomActionData`, and explicitly passed to the elevated PowerShell action.
WiX MSI validation completes without the ICE03 Target overflow warning.

The release gate also verifies the requested HTTP/8080 manager defaults and
the packaged editor's Administrator check, staging, installed-binary TOML
validation, protected backup, an exclusive durable existing-file write that
preserves the ACL, controlled service restart, and rollback path.

## 2.0.11 GUI handoff and config-recovery addendum

The 2.0.11 canonical pipeline rebuilt both agent and watchdog executables from
the changed sources, regenerated a 146-file integrity manifest, and created a
153-row x64 MSI File table. Its Windows gate passed 328 tests with 2 skipped.
Defender found no threats in either executable or the MSI; WiX validation and
compiled-MSI contract verification passed.

New compiled checks require the full-UI staging action, the
`ATTACKLENS_CONFIG_DATA` Secure+Hidden transfer property, explicit deferred
`CustomActionData` consumption, and no compiled localhost value. Focused
manager/recovery contracts passed 34 tests. Artifact:

- `pkg/dist/attacklens-agent-2.0.11-x64.msi`
- 22,582,265 bytes (21.54 MB)
- SHA-256 `FA0BD8D9BC50486BFD630F55F18CC03AAED48EB23765355BA30E6A7F1718B270`
- unsigned development build; production still requires signing and an
  elevated disposable-VM lifecycle matrix.

### 2.0.12 compiled sequence proof

The decompiled 2.0.11 MSI exposed the remaining defect: the capture action was
before `ResumeDlg`. Version 2.0.12 compiles it after `ProgressDlg` and before
`ExecuteAction`. The verifier now compares the actual numeric
`InstallUISequence` rows and fails any package outside that interval. The
2.0.12 gate passed 328 tests (2 skipped), Defender scans, WiX validation, and
compiled contracts. MSI size: 22,578,169 bytes; SHA-256:
`33492289C0DBC1A1FA1980F259A2A6086DFE3E30E88B49B8A1FF5FC4556EF59B`.

### 2.0.13 runtime configuration and payload-identity proof

An isolated integration test copied a real generated TOML, captured its exact
SDDL, ran `configure-manager.ps1 -ManagerUrl 72.61.228.62` without SCM mutation,
and verified all of the following:

- staged and live validation succeeded with the installed agent executable;
- the endpoint became `http://72.61.228.62:8080` with TLS verification false
  and insecure HTTP explicitly allowed;
- the before/after SDDL was byte-for-byte identical;
- a protected rollback copy was retained; and
- the older 2.0.12 MSI was rejected as stale by compiled-payload SHA comparison.

The final 2.0.13 gate passed 329 tests (2 skipped), 19 PowerShell parses,
Microsoft Defender scans of both executables and the MSI, WiX ICE validation,
compiled UI sequencing, and byte identity for critical packaged scripts. The
complete source suite passed 453 tests (7 skipped).

- Artifact: `pkg/dist/attacklens-agent-2.0.13-x64.msi`
- Size: 22,582,265 bytes (21.54 MB)
- SHA-256: `E670BE12CB5FCEA2CDA60E7299F14BCC94E07BD0B7817D87A71999CF622024DA`
- Signature: unsigned development build
