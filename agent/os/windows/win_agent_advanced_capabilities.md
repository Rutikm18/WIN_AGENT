# Windows Agent Advanced Capabilities

> Advanced startup diagnosis, conservative self-recovery, and isolated scenario testing are documented in [`advanced_support/`](advanced_support/README.md).

Verified: 2026-07-27

This is an evidence-based implementation matrix for the Windows agent. A
capability is marked complete only when source and automated verification exist.

Legend:

- COMPLETE: implemented and covered by source-level or package-level tests.
- PARTIAL: useful implementation exists, but an elevated VM, signed native
  component, external certificate, or manager change is still required.
- PLANNED: no production implementation is claimed.

## Manager communication

| Capability | State | Evidence |
|---|---|---|
| Enrollment and manager authentication | COMPLETE | DPAPI-backed key storage, controlled re-enrollment, live enrollment test |
| Encrypted ingest | COMPLETE | AES-GCM/HMAC envelope, live manager acceptance |
| Loss-resistant delivery | COMPLETE | Encrypted SQLite outbox, full sync, delete only after application ACK |
| Replay after long outage | COMPLETE | Stable delivery ID with fresh timestamp and nonce on every attempt |
| Retry classification | COMPLETE | DNS/TCP/TLS/timeouts, 408/425/429, 5xx, authentication and permanent 4xx paths tested |
| Retry-After | COMPLETE | Numeric manager delay is honored |
| Delivery identity | PARTIAL | Agent sends `Idempotency-Key`; exactly-once storage requires manager-side deduplication |
| TLS validation and hostname verification | COMPLETE | Local fixtures prove untrusted-certificate and hostname rejection plus custom-CA success; plain HTTP requires explicit development override |
| SPKI certificate pinning | COMPLETE | Local fixtures prove correct-pin success and incorrect-pin fail-closed behavior |
| Explicit enterprise proxy | COMPLETE | Authenticated HTTP/HTTPS proxy URL can be configured |
| Automatic system PAC/WinHTTP discovery | PLANNED | Requires a native WinHTTP resolver and enterprise proxy test matrix |

## Service lifecycle and reliability

| Capability | State | Evidence |
|---|---|---|
| SCM startup checkpoints | COMPLETE | Start-pending checkpoints and wait hints cover critical initialization |
| SCM recovery actions | COMPLETE | MSI configures restart actions for agent and watchdog |
| Service identities | PARTIAL | MSI configures unrestricted service SIDs for agent and watchdog; elevated install verification remains |
| Delayed auto-start | COMPLETE | MSI service registry configuration |
| Pre-shutdown flush window | COMPLETE | Pre-shutdown control, 180-second timeout, orderly outbox close |
| Shutdown handling | COMPLETE | SCM shutdown and stop controls use a shared clean-stop path |
| Sleep/resume handling | COMPLETE | Power events wake delivery and publish lifecycle telemetry |
| Single instance | COMPLETE | `Global\AttackLensAgent` kernel mutex |
| Worker supervision | COMPLETE | Sender/health thread death fails the service; watchdog monitors runtime heartbeat |
| Clean/unclean stop detection | COMPLETE | Atomic clean-stop marker and previous-runtime classification |
| Disk pressure | COMPLETE | Collection/cursor advancement pauses before unsafe free-space levels |
| Clock skew | COMPLETE | Manager date feedback and fresh transport timestamps |
| Bad configuration | COMPLETE | Typed validation before enrollment or collection |
| Outbox corruption | COMPLETE | SQLite quick-check and fail-closed startup |
| Cursor corruption | COMPLETE | Quarantine plus safe replay from available records |
| Fair live/replay scheduler | PARTIAL | Durable replay is bounded; explicit weighted fairness remains planned |

## Native telemetry

| Capability | State | Evidence |
|---|---|---|
| Windows Event Log API | COMPLETE | Native `win32evtlog` query path; no localized text parsing |
| Per-channel durable checkpoints | COMPLETE | `EventRecordID` cursor commits only after durable enqueue |
| Security audit events | COMPLETE | Logon, process, service, task, account/group, Kerberos and log-clear IDs |
| PowerShell Operational | COMPLETE | 4103-4106 |
| Defender Operational | COMPLETE | Detection, action and protection-state events |
| Sysmon Operational | COMPLETE | Process, network, image, injection, access, file, registry, pipe and DNS IDs |
| RDP session events | COMPLETE | Terminal Services Local Session Manager channel |
| WMI activity | COMPLETE | WMI Activity Operational provider events |
| Canonical process/network/DNS entities | COMPLETE | Security and Sysmon records normalize to source-independent entities |
| Real-time kernel ETW session | PLANNED | Requires a maintained native consumer and high-EPS loss testing |
| Threat-intelligence ETW provider | PLANNED | Requires protected-process/anti-malware signing eligibility |
| Boot autologger | PLANNED | Requires installer policy and elevated reboot testing |

## Process, network and persistence

| Capability | State | Evidence |
|---|---|---|
| Process command line and parent PID | COMPLETE | Native process snapshot plus 4688/Sysmon process events |
| Authenticode validation | COMPLETE | Cached WinVerifyTrust checks for emitted processes |
| Catalog signature validation | PARTIAL | Embedded trust is checked; catalog-specific verification remains |
| TCP/UDP ownership | COMPLETE | PID/process mapping for connections and listeners |
| DNS telemetry | COMPLETE when Sysmon is present | Sysmon DNS events; kernel DNS ETW remains planned |
| Run keys, tasks and services | COMPLETE | Existing inventory plus audit events |
| Deep persistence surface | PARTIAL | Additional IFEO, COM, WMI consumer, BITS, LSA and accessibility baselines remain |
| Kernel injection signals | PARTIAL | Sysmon remote-thread/process-access events; protected provider remains planned |

## Integrity and self-defense

| Capability | State | Evidence |
|---|---|---|
| Runtime ACL enforcement | COMPLETE | Central policies for config, key, data, spool, logs and executables |
| Install checksum manifest | COMPLETE | MSI-generated SHA-256 manifest verified before agent startup |
| Runtime config-change detection | COMPLETE | Initial config digest compared in health heartbeat |
| Service drift visibility | PARTIAL | Watchdog detects stop/stale state; full recovery-config self-repair remains |
| Signed executable and MSI | PARTIAL | Build supports packaging; release certificate is external and not present |
| Protected Process Light | PLANNED | Requires eligible signing and a native protected service |
| ELAM | PLANNED | Requires an approved anti-malware driver and signing program |

## Posture and compliance

| Capability | State | Evidence |
|---|---|---|
| Defender, firewall, BitLocker, UAC, Secure Boot and TPM | COMPLETE/PARTIAL | Existing posture collectors; unavailable values report unknown |
| ASR, WDAC/AppLocker, Credential Guard and LSA protection | PARTIAL | Registry/API coverage exists for selected states; full SKU matrix remains |
| Patch and pending reboot | COMPLETE | Inventory/posture collectors |
| Continuous CIS-aligned benchmark assessment | COMPLETE | 36 read-only endpoint controls run hourly; per-check pass/fail/unknown/not-applicable, bounded evidence, score, coverage, change deltas and collector health are delivered through the durable outbox |
| Version/SKU-specific full benchmark mapping | PARTIAL | The bundled Level 1 enterprise profile is CIS-aligned; separate exact policies for every Windows release, server role and licensed Level 2 profile remain future policy packs |

## Developer and AI security audit

| Capability | State | Evidence |
|---|---|---|
| VS Code, Cursor, Windsurf and browser extension inventory | COMPLETE | Bounded per-profile manifest parsing with activation/permission risk signals |
| MCP server discovery | COMPLETE for JSON/JSONC/TOML; PARTIAL for YAML | Claude, Cursor, VS Code, Windsurf, Codex and bounded workspace locations; arguments are redacted and environment values are never collected |
| Global Node and Python package inventory | COMPLETE for supported filesystem layouts | Manifest/metadata parsing avoids executing user-controlled package managers, interpreters or lifecycle code as LocalSystem |
| AI/agent CLI discovery and command shadowing | COMPLETE | PATH and common-location file resolution; discovered tools are never executed |
| PowerShell profile and PATH audit | COMPLETE | Hash/risk metadata, machine and loaded-user PATH coverage, relative/duplicate/user-profile detection |
| Task, service and startup execution risk | COMPLETE | Multiple task actions, CIM plus Run/RunOnce and Startup folders, unquoted/profile/script-host flags |
| AI process and listener exposure | COMPLETE | Secret-redacted filtered processes and TCP/UDP ownership with all-interface findings |
| Browser native-messaging hosts | COMPLETE for machine/currently loaded user hives | Chrome/Edge 32/64-bit registry views and manifest inspection |
| Git configuration, hooks and workspace execution files | COMPLETE for bounded common repository roots | No Git executable is launched; configs are redacted and execution files are hashed |
| Credential/secret location metadata | COMPLETE for known locations | `cmdkey` target metadata and file metadata only; credential/file contents are never emitted |
| Docker privilege and exposure audit | COMPLETE when a trusted machine Docker CLI and daemon are available | Privileged/socket/root/host-network/SYS_ADMIN/image/env-name checks; environment values are never emitted |
| Offline user registry hives | PARTIAL by design | The agent does not mount `NTUSER.DAT`; only already-loaded user hives are read to preserve a non-mutating audit |

## Troubleshooting and observability

| Capability | State | Evidence |
|---|---|---|
| Local runtime health file | COMPLETE | Atomic `agent.runtime.json` |
| Manager-visible health | COMPLETE | Outbox, delivery, clock, circuit and collector health |
| Windows Event Log service messages | COMPLETE | pywin32 service event source |
| `status` command | COMPLETE | Runtime, outbox and SCM summary |
| `capabilities` command | COMPLETE | Evidence-based runtime capability report |
| `self-test` command | COMPLETE | Rebuilt executable passed DNS, TCP and `/health` against the configured manager; TLS/pinning paths use local fixtures |
| `diagnose` command | COMPLETE | Status, service, integrity, outbox, channel and connectivity report |

## Packaging and enterprise deployment

| Capability | State | Evidence |
|---|---|---|
| Per-machine WiX MSI | COMPLETE | Silent and interactive properties, service registration, preservation and purge controls |
| Upgrade preserves state | COMPLETE in source | Requires elevated clean/upgrade/rollback VM matrix before release sign-off |
| MSI structural validation | COMPLETE | WiX ICE validation passes |
| GPO/Intune/SCCM guidance | PARTIAL | Silent properties exist; deployment guides and tenant tests remain |
| Signed update/rollback channel | PLANNED | Requires release service, signing keys and rollback policy |
| ARM64 package | PLANNED | Current artifact is x64 |

## Verification commands

Run from an elevated PowerShell:

```powershell
$env:ATTACKLENS_CONFIG = "C:\ProgramData\AttackLens\config\agent.toml"

& "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" validate-config
& "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" status
& "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" capabilities
& "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" self-test
& "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe" diagnose

Get-Service AttackLensAgent, AttackLensWatchdog
```

Source-level regression:

```powershell
py -3.13 -m unittest agent.os.windows.tests.test_reliability -v
py -3.13 -m unittest agent.tests.unit.test_windows_security_audit -v
```

Package validation:

```powershell
wix msi validate ".\pkg\dist\attacklens-agent-2.0.10-x64.msi"
```

## Release gates still requiring an elevated disposable VM

- Clean MSI install, repair, same/older/newer upgrade and uninstall.
- SCM crash, forced hang, pre-shutdown, reboot and sleep/resume.
- Disk exhaustion and high-event-rate Event Log/Sysmon rollover.
- Enterprise proxy/PAC/authentication combinations.
- Domain controller and terminal-server event volume.
- Windows 10, Windows 11, Server 2016-2025 and future ARM64 artifacts.
- Authenticode and MSI signing with production release certificates.
