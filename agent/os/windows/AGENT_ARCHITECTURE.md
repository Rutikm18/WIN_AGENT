# AttackLens Windows Agent Architecture

> Current implementation: [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md). As of 2026-08-12 the runtime has 26 scheduled sections, native ETW process/DNS streams, push Event Log bookmarks, transactional persistence baselines, 46 CIS checks, and periodic self-defense auditing.

> Startup recovery, root-cause evidence, failure cases, and one-command tooling are consolidated in [`advanced_support/`](advanced_support/README.md) (2026-08-09).

Scope: `PROJECT_CORE/agent/os/windows/`

Status: target architecture for the Windows endpoint agent and installer.

This document defines the Windows agent as a self-contained endpoint security
service. It is intentionally scoped to Windows runtime, Windows service
management, collection modules, local state, transport, installer behavior, and
operational validation.

## 1. Architecture Goals

The Windows agent must:

1. Run reliably as a Windows service with a separate watchdog service.
2. Auto-enroll on first start and store endpoint identity material with Windows
   protected storage.
3. Collect high-value endpoint telemetry with predictable CPU, memory, disk,
   network, and API usage.
4. Normalize every collection result into stable manager-facing schemas.
5. Encrypt and authenticate every payload before it leaves the endpoint.
6. Survive manager outages without losing accepted local telemetry.
7. Support policy, configuration, file, registry, inventory, event, and response
   workflows without mixing these concerns in one large module.
8. Install, upgrade, repair, and uninstall cleanly through MSI.
9. Protect config, keys, spool, logs, and response execution paths with explicit
   ACLs.
10. Provide enough local diagnostics for helpdesk, SOC, and engineering teams to
    identify service, enrollment, transport, and collection failures.

## 2. Installed Layout

Production install layout:

```text
C:\Program Files\AttackLens\
  bin\
    attacklens-agent\
      attacklens-agent.exe
      _internal\
    attacklens-watchdog\
      attacklens-watchdog.exe
      _internal\
  tools\
    attacklensctl.exe

C:\ProgramData\AttackLens\
  config\
    agent.toml
    policies\
    response.d\
  data\
    state\
    fim\
    inventory\
    eventlog\
    sca\
  logs\
    agent.log
    watchdog.log
    install.log
    response.log
  security\
    identity.json
    *.key.dpapi
  spool\
    win_agent.spool.ndjson
```

Rules:

- `Program Files` contains immutable binaries and bundled libraries.
- `ProgramData` contains mutable config, logs, security state, policy state, and
  offline payload spool.
- Sensitive files under `security`, `config`, `spool`, and `response.d` are
  restricted to `SYSTEM` and `Administrators`.
- Normal local users receive read and execute access only to safe binaries.

## 3. Service Topology

```text
Windows Service Control Manager
  |
  +-- AttackLensWatchdog
  |     |
  |     +-- polls AttackLensAgent through SCM
  |     +-- restarts the agent after crash or unexpected stop
  |     +-- rate-limits restart storms
  |     +-- writes Windows Event Log health and failure records
  |
  +-- AttackLensAgent
        |
        +-- resolves agent.toml
        +-- validates config and local paths
        +-- enrolls or loads existing key
        +-- starts collector workers
        +-- starts sender worker
        +-- starts heartbeat worker
        +-- flushes queue to spool on stop
```

`AttackLensAgent` is the main privileged process. `AttackLensWatchdog` is a
small independent service that supervises the main agent through SCM state.
The watchdog must not depend on the agent service, because it has to start even
when the agent is missing, stopped, or broken.

## 4. Runtime Modules

Current Windows module boundaries:

```text
agent/os/windows/
  agent_win_entry.py      PyInstaller entry point
  service.py              Windows SCM wrapper for AttackLensAgent
  watchdog_svc.py         Windows SCM wrapper for AttackLensWatchdog
  win_agent.py            Runtime orchestrator, queue, spool, encryption, sender
  tls_transport.py        HTTPS transport, TLS policy, optional SPKI pinning
  keystore.py             Credential Manager, DPAPI file, restricted-file fallback
  normalizer.py           Raw collector data to canonical schema
  sca/                    Security configuration assessment engine and policies
  collectors/             Windows collectors grouped by domain
  pkg/                    PyInstaller and WiX MSI build pipeline
  installer/              Legacy or alternate installer scripts
```

Target module additions:

```text
agent/os/windows/
  config_model.py         typed config loading, defaults, validation
  state_store.py          SQLite or JSON state for cursors, hashes, inventory
  acl.py                  centralized Windows ACL hardening helpers
  response.py             signed local response executor
  policy_loader.py        policy discovery, versioning, validation
  diagnostics.py          local health bundle and support snapshot
  collectors/
    fim.py                file integrity collector
    registry.py           registry integrity collector
```

The existing `win_agent.py` should remain the orchestrator, not the home for
every feature. New capabilities should land behind narrow modules and be called
from the orchestrator.

## 5. Startup Flow

```text
SCM starts AttackLensAgent
  |
  +-- service.py resolves config path
  |     1. MACINTEL_CONFIG environment override
  |     2. HKLM service Parameters config value
  |     3. C:\ProgramData\AttackLens\config\agent.toml
  |
  +-- WindowsAgent.from_config()
  |
  +-- validate:
  |     manager URL
  |     TLS settings
  |     collection sections
  |     writable state/log/spool paths
  |     protected security path
  |
  +-- load or enroll identity
  |
  +-- derive encryption and MAC keys
  |
  +-- initialize spool and recover orphan drain file
  |
  +-- load collectors and per-section circuit breakers
  |
  +-- start workers
```

Startup should fail closed for invalid config, missing write permissions, broken
identity material, and impossible TLS policy. Startup should degrade gracefully
for individual collectors that are unavailable on a specific Windows edition.

## 6. Enrollment and Identity

First start:

```text
agent.toml enrollment token
  |
  +-- POST /api/v1/enroll over HTTPS
  |
  +-- manager returns:
        agent number
        API key
        policy assignment
        optional transport pin
  |
  +-- key persisted through Windows keystore chain
  |
  +-- identity metadata written to protected identity.json
```

Key storage priority:

1. Windows Credential Manager through the WinVault backend.
2. DPAPI-encrypted file under `ProgramData\AttackLens\security`.
3. ACL-restricted plain file only as a last resort.

The enrollment token is an installer or provisioning input. It must not be
persisted after successful enrollment unless an operator explicitly enables a
re-enrollment workflow.

## 7. Collection Architecture

Collectors are independent, interval-driven workers. A collector returns raw
Windows data, the normalizer converts it to canonical schema, and the runtime
builds the encrypted envelope.

```text
Collector.collect()
  |
  +-- raw dict/list from Windows API, psutil, registry, PowerShell JSON, or CLI
  |
  +-- normalizer.normalize(section, raw)
  |
  +-- _build_envelope(section, data)
  |
  +-- in-memory send queue
  |
  +-- sender or disk spool
```

Collection groups:

| Group | Sections | Purpose |
| --- | --- | --- |
| Volatile | metrics, processes, connections | high-frequency runtime state |
| Network | ports, network, arp, mounts | exposure, routing, remote access |
| System | services, users, hardware, battery, openfiles, containers | host and account state |
| Inventory | apps, packages, binaries, storage, tasks, sbom | asset and software exposure |
| Posture | security, sysctl, configs | hardening, risky settings, control status |
| Event | eventlog | account, process, service, task, and security events |
| Assessment | sca | policy checks and compliance score |
| Integrity | fim, registry | target design for file and registry change detection |
| Response | response_result | target design for local action results |
| Health | agent_health | agent runtime state |

Config controls each section:

```toml
[collection.sections.eventlog]
enabled = true
interval_sec = 60

[collection.sections.binaries]
enabled = false
interval_sec = 86400
```

Heavy collectors must support staggered startup, cached state, bounded scan
scope, and incremental operation where Windows APIs allow it.

## 8. Event Collection

The event collector should prioritize records that materially improve security
detection:

- successful and failed logons
- explicit credential use
- privilege assignment at logon
- process creation where command-line auditing is enabled
- service creation and service configuration changes
- scheduled task creation, update, and deletion
- local account and group changes
- audit policy changes
- PowerShell operational events
- Defender and firewall state transitions

Target behavior:

- Maintain per-channel bookmarks or record cursors under `data\eventlog`.
- Read incrementally instead of repeatedly querying wide time windows.
- Track parser errors by channel and event ID.
- Emit normalized records with channel, event ID, timestamp, computer, subject,
  action category, and event-specific detail.
- Avoid collecting event message text when structured fields are available.

## 9. File and Registry Integrity

Target file integrity collector:

```text
policy target path
  |
  +-- baseline snapshot: path, size, mtime, owner, ACL hash, SHA-256
  |
  +-- incremental scan or watcher
  |
  +-- change event: created, modified, deleted, renamed, ACL changed
  |
  +-- normalized fim record
```

Default high-value paths:

- Windows startup folders
- service executable paths
- scheduled task files
- PowerShell profile paths
- common persistence locations
- selected `System32` executables and script interpreters
- installed agent config and response directories

Target registry integrity collector:

- service autorun locations
- Run and RunOnce keys
- Winlogon shell and userinit keys
- image file execution options
- AppInit DLLs
- LSA providers
- Defender exclusions
- firewall policy keys
- PowerShell logging policy keys

State must be persisted under `ProgramData\AttackLens\data` and protected from
normal users. Baseline rebuild must be an explicit operator action or policy
instruction, not an automatic response to drift.

## 10. Security Configuration Assessment

The assessment engine should evaluate OS-specific policy files and report:

- policy ID and version
- check ID and title
- result: pass, fail, not_applicable, error
- evidence summary
- remediation text
- compliance mapping
- roll-up score

Assessment scans should run on start and then on a long interval, with jitter to
avoid every endpoint scanning at the same time. The engine must distinguish
between "not applicable to this Windows edition" and "collector failed".

## 11. Local Response Architecture

Target response flow:

```text
manager response command
  |
  +-- verify command signature and policy allow-list
  |
  +-- check local safety gates
  |
  +-- execute signed response plugin with timeout
  |
  +-- capture stdout, stderr, exit code, duration
  |
  +-- write response.log
  |
  +-- send response_result envelope
```

Response safety rules:

- Responses are disabled unless explicitly enabled in `agent.toml`.
- Only allow-listed response IDs may run.
- Every response command must be signed or packaged with a signed policy.
- Arguments are structured data, not shell-concatenated strings.
- Each action has a timeout, max output size, and audit record.
- Response plugins run from a protected directory only writable by
  Administrators and `SYSTEM`.

This avoids turning the agent into a general remote shell.

## 12. Payload Security

Outbound telemetry is protected in two layers:

1. HTTPS with TLS 1.3 minimum where supported by the runtime and server.
2. Per-payload encryption and authentication derived from the enrolled API key.

Envelope construction:

```text
inner payload:
  section
  agent_id
  agent_name
  agent_number
  collected_at
  data

protect:
  gzip JSON
  AES-256-GCM with fresh 96-bit nonce
  HMAC-SHA256 over routing fields and ciphertext

wire payload:
  version
  agent_id
  timestamp
  nonce
  ciphertext
  hmac
  plaintext section for routing
```

Manager-side replay defense must enforce a bounded timestamp window and nonce
deduplication. The agent should treat key revocation as an operator-visible
state and stop retrying rejected payloads that cannot succeed without new
identity material.

## 13. Transport

`WindowsTLSTransport` owns the HTTP session. It should provide:

- `https://` only for production config.
- certificate validation by default.
- optional custom CA bundle.
- optional SPKI pinning.
- strict connect and read timeouts.
- no implicit library retries.
- caller-controlled backoff and spool behavior.

Development may allow disabled certificate verification, but it must still use
encrypted transport and must log that reduced validation is active.

## 14. Offline Resilience

Runtime queueing:

```text
collector workers
  |
  +-- bounded in-memory queue
        |
        +-- sender sends immediately when manager is reachable
        |
        +-- overflow or send failure writes to disk spool
```

Spool guarantees:

- append-only NDJSON containing base64-encoded wire envelopes
- hard size cap
- FIFO trim when cap is reached
- atomic drain through rename to `.draining`
- re-spool failed and remaining envelopes on mid-drain failure
- recover orphan `.draining` file on next start
- flush live queue to spool during service stop

The spool is not a database of record. It is a bounded reliability buffer for
manager outages. Operators should alert when spool bytes grow for too long.

## 15. Backpressure and Circuit Breakers

Each section has an independent circuit breaker:

```text
CLOSED
  |
  +-- 3 consecutive failures
  v
OPEN for 60 seconds
  |
  +-- cooldown elapsed
  v
HALF_OPEN probe
  |
  +-- success -> CLOSED
  +-- failure -> OPEN
```

This prevents a failing collector, broken PowerShell call, or unavailable
Windows feature from generating repeated failures at the normal collection
interval.

Additional target controls:

- per-collector timeout
- max records per cycle
- max payload size
- sampling for high-volume sections
- queue depth telemetry in `agent_health`
- policy-level disable for expensive collectors

## 16. Configuration Model

`agent.toml` is the single runtime configuration file.

Required blocks:

```toml
[agent]
id = "win-<machine-guid>"
name = "WORKSTATION-01"

[manager]
url = "https://manager.example.com:443"
tls_verify = true
timeout_sec = 30

[paths]
security_dir = "C:/ProgramData/AttackLens/security"
log_dir = "C:/ProgramData/AttackLens/logs"
spool_dir = "C:/ProgramData/AttackLens/spool"
data_dir = "C:/ProgramData/AttackLens/data"
```

Optional blocks:

- `[enrollment]`
- `[logging]`
- `[collection.sections.<name>]`
- `[policy]`
- `[response]`
- `[transport]`
- `[diagnostics]`

Target improvement: move config loading into `config_model.py` with typed
defaults, validation errors, and a `--validate-config` CLI path.

## 17. Installer Architecture

MSI responsibilities:

1. Install binaries under `Program Files`.
2. Create `ProgramData` directory tree.
3. Apply ACLs before writing config or keys.
4. Generate initial `agent.toml` from MSI properties.
5. Register both Windows services.
6. Configure delayed auto-start and network dependencies.
7. Write service registry parameters for config path.
8. Start services after successful install.
9. Preserve operator config and security state on upgrade.
10. Remove binaries on uninstall while preserving or purging state based on an
    explicit uninstall property.

Installer properties:

| Property | Purpose |
| --- | --- |
| `MANAGER_HOST` | manager host or DNS name |
| `MANAGER_PORT` | manager port; canonical host-only default is HTTP/8080 |
| `MANAGER_URL` | full override URL when host and port are insufficient |
| `TLS_VERIFY` | certificate validation policy |
| `CA_BUNDLE` | optional custom CA file path |
| `SPKI_PIN` | optional manager public key pin |
| `ENROLL_TOKEN` | first-start enrollment token |
| `AGENT_NAME` | display name for the endpoint |
| `COLLECTION_PROFILE` | baseline, standard, intensive, or custom |
| `PRESERVE_STATE` | preserve identity, config, logs, and spool on uninstall |

Custom actions should be minimal, idempotent, logged, and written in PowerShell
where possible. Text config generation should be centralized in one script with
clear escaping and validation.

## 18. Upgrade and Uninstall

Upgrade rules:

- Stop services before replacing binaries.
- Preserve `agent.toml`, identity material, state databases, logs, and spool.
- Migrate config schema forward with a versioned migration step.
- Re-apply ACLs after upgrade.
- Restart services only after config validation passes.
- Record previous and new versions in the install log.

Uninstall modes:

- default uninstall: remove services and binaries, preserve state for reinstall
- purge uninstall: remove services, binaries, config, identity, state, logs, and
  spool after explicit operator request

Repair mode:

- restore missing binaries
- re-register services
- re-apply ACLs
- preserve identity and config
- do not silently re-enroll if a valid key exists

## 19. Observability

Local outputs:

- rotating agent log
- rotating watchdog log
- Windows Event Log records for service lifecycle and fatal errors
- install log
- response audit log
- `agent_health` envelopes

Target diagnostics command:

```powershell
attacklensctl diagnostics --out C:\ProgramData\AttackLens\logs\diag.zip
```

Diagnostic bundle contents:

- redacted config
- service status
- recent logs
- Windows build and edition
- active collection sections
- queue depth and spool size
- circuit breaker states
- policy version
- last enrollment status
- last successful send timestamp

Secrets must be redacted before the bundle is written.

## 20. Tamper Resistance

Required controls:

- protected ACLs on config, security, policy, response, state, and spool paths
- service binaries installed under `Program Files`
- Authenticode signing for MSI and executables
- response plugin signature verification
- config schema validation before service start
- no writable plugin or response paths for normal users
- watchdog alerts when the agent service is unexpectedly stopped
- local health event when ACL repair is needed

Target controls:

- periodic self-check of service binary hashes
- protected policy version pinning
- optional event collection for changes to the agent service configuration
- manager alert when endpoint has not sent `agent_health` within SLA

## 21. Performance Budget

Baseline endpoint budget:

| Resource | Normal Target | Burst Ceiling |
| --- | ---: | ---: |
| CPU | under 2 percent average | under 15 percent during scans |
| Memory | under 200 MB RSS | under 350 MB RSS |
| Disk spool | under 50 MB default cap | configurable |
| Log files | 10 MB x 5 default | configurable |
| Network | compressed encrypted JSON | bounded by sender backoff |

Collector design requirements:

- no unbounded directory walks in default profile
- no unbounded PowerShell output
- no repeated full inventory scans at short intervals
- all expensive scans have long intervals and startup jitter
- all subprocess calls use timeouts and hidden windows

## 22. Profiles

Target collection profiles:

| Profile | Purpose | Default Behavior |
| --- | --- | --- |
| baseline | low overhead monitoring | metrics, services, users, security, eventlog, health |
| standard | recommended production | baseline plus inventory, network, tasks, apps, assessment |
| intensive | high coverage | standard plus binaries, packages, sbom, file and registry integrity |
| incident | temporary investigation | shorter intervals and expanded event scope |

Installer should default to `standard`. Operators can later tune individual
sections in `agent.toml`.

## 23. Build Pipeline

Primary Windows build:

```powershell
cd PROJECT_CORE\agent\os\windows\pkg
.\build_attacklens_msi.ps1 -Version "2.0.10"
```

Build steps:

1. PyInstaller builds the agent service bundle.
2. PyInstaller builds the watchdog service bundle.
3. Config generation script is embedded or staged for MSI use.
4. WiX fragments are generated for bundled files.
5. WiX builds the MSI.
6. Optional Authenticode signing signs binaries and MSI.
7. Smoke tests validate install, service start, collection once, repair,
   upgrade, and uninstall.

Use PyInstaller `onedir` for Windows services. A self-extracting single-file
service can confuse SCM process tracking during startup.

## 24. Test Strategy

Unit tests:

- config validation
- key storage fallback behavior
- normalizer schemas
- circuit breaker state machine
- spool write, trim, drain, recovery
- watchdog restart policy
- policy parser
- response command validation

Integration tests:

- collect once on Windows
- enrollment with a local test manager
- encrypted ingest and key revocation
- manager outage and spool drain
- service start and stop through SCM
- watchdog restart after forced service stop
- MSI clean install, upgrade, repair, uninstall, purge uninstall

Manual VM validation:

- Windows 10
- Windows 11
- Windows Server 2019
- Windows Server 2022
- non-admin local user tamper attempts
- offline boot followed by network recovery

## 25. Implementation Priorities

1. Clean up stale naming and encoding in Windows docs and service docstrings.
2. Extract config validation into `config_model.py`.
3. Centralize ACL logic in `acl.py` and call it from installer and runtime.
4. Add stateful event log cursors.
5. Add file integrity and registry integrity collectors.
6. Add diagnostics command and redacted support bundle.
7. Add signed response executor behind disabled-by-default config.
8. Add MSI install, upgrade, repair, uninstall, and purge validation scripts.
9. Add profile-based config generation.
10. Add performance budget tests for expensive collectors.

## 26. Non-Goals

- The Windows agent must not become a general-purpose remote shell.
- The runtime must not require interactive desktop access.
- The MSI must not depend on developer paths.
- Collection modules must not assume one specific Windows client edition.
- Secret material must not be logged, included in diagnostics, or stored in
  world-readable files.

## 27. Engineering Contract

Any new Windows agent feature should satisfy this contract:

1. It is controlled by config.
2. It has bounded resource use.
3. It has a normalized output schema.
4. It has unit tests for parsing and failure behavior.
5. It does not weaken local ACLs.
6. It degrades gracefully on unsupported Windows editions.
7. It emits enough local log detail for troubleshooting.
8. It can be packaged by the MSI without manual post-install steps.

## Operator-visible runtime state

Version 2.0.10 includes `paths.status_dir`. Detailed runtime state stays in the
protected data directory, while a separately constructed and allow-listed JSON
summary is atomically published to `status\agent-status.json` with read-only
local-user access. It includes endpoint (credentials/query removed), connection
state, delivery counters, timestamps, backoff, and outbox statistics. Manager
changes are identity-aware: credentials record their issuing manager and are
archived before re-enrollment when that manager identity changes.

### 2.0.11 installer-to-runtime configuration boundary

The full MSI UI serializes final dialog properties into the uppercase,
Secure+Hidden `ATTACKLENS_CONFIG_DATA` property before `ExecuteAction` crosses
to the elevated Windows Installer server. The execute sequence copies that
opaque Base64 JSON into deferred `CA_WriteConfig`; silent/basic-UI installs
serialize directly in the execute session. Runtime `agent.toml` stays under
ProgramData with SYSTEM full control and Administrators modify rights, while
installed safe-edit tools provide staged/live validation, an exclusive durable
write through the existing protected file object, backup, service coordination,
and rollback without requesting a DACL rewrite.
