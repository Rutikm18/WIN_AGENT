# Windows Agent Baseline Audit

> Startup failure findings and remediations from 2026-08-09 are recorded in [`advanced_support/ROOT_CAUSE.md`](advanced_support/ROOT_CAUSE.md).

Date: 2026-07-19

Scope: `PROJECT_CORE/agent/os/windows/`

Purpose: Milestone 0 baseline record before runtime, installer, GUI, CLI, or
collector behavior changes.

## Executive Summary

The Windows agent already has a usable foundation:

- main Windows service wrapper
- watchdog service wrapper
- PyInstaller packaging specs
- WiX MSI definition
- MSI config generation script
- encrypted HTTPS transport
- Windows key storage abstraction
- collector groups
- normalizer
- SCA module
- offline spool in the runtime
- install and troubleshooting docs

The main risks are consistency and productization rather than raw capability.
The tree currently has multiple installer tracks, generated artifacts committed
or present in the workspace, conflicting install documentation, stale naming in
some runtime comments/classes, and incomplete GUI installer behavior.

No runtime code was changed during this audit.

## Current Source Layout

Authoritative runtime files:

```text
agent/os/windows/
  agent_win_entry.py
  service.py
  watchdog_svc.py
  win_agent.py
  tls_transport.py
  keystore.py
  normalizer.py
  requirements.txt
```

Collectors:

```text
agent/os/windows/collectors/
  base.py
  volatile.py
  network.py
  system.py
  posture.py
  inventory.py
  eventlog.py
  sca.py
```

Assessment engine:

```text
agent/os/windows/sca/
  engine.py
  cis_windows.py
```

Primary packaging path:

```text
agent/os/windows/pkg/
  attacklens.wxs
  attacklens-agent.spec
  attacklens-watchdog.spec
  build_attacklens_msi.ps1
  build_msi.ps1
  build_exe.ps1
  gen_config.ps1
  generate_config.ps1
  manage_services.ps1
```

Secondary installer path:

```text
agent/os/windows/installer/
  product.wxs
  build_msi.ps1
  generate_config.ps1
  install.ps1
  setup_services.ps1
  uninstall.ps1
  attacklens-service.ps1
  attacklens-service.cmd
```

Decision: `pkg/` is the primary packaging path. `installer/` is legacy or
alternate packaging until explicitly reconciled.

## Generated or Workspace-Local Artifacts

These paths are generated or build-output-like and should not guide product
architecture decisions:

| Path group | Count observed | Action |
| --- | ---: | --- |
| `__pycache__` | 18 | ignore; should not be committed |
| `installer/build` | 86 | treat as stale generated copy until proven otherwise |
| `pkg/build` | 32 | build output |
| `pkg/dist` | 92 | build output and packaged artifacts |

Decision: future cleanup should keep source, packaging templates, and docs under
version control, while excluding build outputs through ignore rules.

## Current Runtime Services

Main service:

| Field | Current value |
| --- | --- |
| service name | `AttackLensAgent` |
| display name | `AttackLens Agent` |
| wrapper file | `service.py` |
| runtime file | `win_agent.py` |
| configured dependencies | `Tcpip`, `Dnscache` |
| default account in WiX | `LocalSystem` |

Watchdog service:

| Field | Current value |
| --- | --- |
| service name | `AttackLensWatchdog` |
| display name | `AttackLens Watchdog` |
| wrapper file | `watchdog_svc.py` |
| monitored service | `AttackLensAgent` |
| restart policy | max 5 restarts in 300 seconds, then backoff |
| default account in WiX | `LocalSystem` |

Decision: keep the two-service model. It is the right operational shape for a
Windows endpoint agent.

## Current Runtime Paths

Current runtime code resolves config in this order:

1. `MACINTEL_CONFIG` environment variable.
2. Registry value under the `AttackLensAgent` service parameters key.
3. `%PROGRAMDATA%\AttackLens\config\agent.toml`.

Current MSI writes the service registry config path to:

```text
HKLM\SYSTEM\CurrentControlSet\Services\AttackLensAgent\Parameters\MACINTEL_CONFIG
```

Current generated config path:

```text
C:\ProgramData\AttackLens\config\agent.toml
```

Current generated data paths:

```text
C:\ProgramData\AttackLens\config
C:\ProgramData\AttackLens\logs
C:\ProgramData\AttackLens\security
C:\ProgramData\AttackLens\spool
C:\ProgramData\AttackLens\data
```

Decision: retain the current `config\agent.toml` path. Do not move config to
the `ProgramData\AttackLens` root.

Decision: rename `MACINTEL_CONFIG` later to an `ATTACKLENS_CONFIG` style key,
but support the current key as a compatibility alias during transition.

## Current MSI Property Model

Primary WiX file currently exposes:

| Property | Current role |
| --- | --- |
| `MANAGER_IP` | manager host or IP without scheme |
| `MANAGER_PORT` | manager port |
| `TLS_VERIFY` | certificate validation switch |
| `ENROLL_TOKEN` | enrollment token |
| `AGENT_NAME` | endpoint display name |

Current config generator builds:

```text
https://<MANAGER_IP>:<MANAGER_PORT>
```

Current docs conflict:

- some docs use `MANAGER_IP` and `MANAGER_PORT`
- some docs use `MANAGER_URL`
- some docs show config at `C:\ProgramData\AttackLens\agent.toml`
- current service and MSI use `C:\ProgramData\AttackLens\config\agent.toml`

Decision: final property model should be:

| Property | Decision |
| --- | --- |
| `MANAGER_URL` | primary property |
| `MANAGER_IP` | compatibility alias |
| `MANAGER_PORT` | compatibility alias |
| `TLS_VERIFY` | keep |
| `CA_BUNDLE` | add |
| `SPKI_PIN` | add |
| `ENROLL_TOKEN` | keep as secure |
| `AGENT_NAME` | keep |
| `COLLECTION_PROFILE` | add |
| `PRESERVE_STATE` | add |
| `PURGE_ON_UNINSTALL` | add |

Decision: if both `MANAGER_URL` and `MANAGER_IP` are supplied,
`MANAGER_URL` wins.

Decision: HTTPS is the default and expected production transport. Any insecure
development mode must be explicit and validated.

## Current Build Pipeline

Primary build command:

```powershell
cd PROJECT_CORE\agent\os\windows\pkg
.\build_attacklens_msi.ps1 -Version "2.0.0"
```

Build steps currently implemented:

1. Build agent with PyInstaller `onedir`.
2. Build watchdog with PyInstaller `onedir`.
3. Encode `gen_config.ps1` as a WiX custom action payload.
4. Generate WiX fragments for `_internal` directories.
5. Build MSI with WiX v4.
6. Optionally Authenticode-sign the MSI.

Decision: keep PyInstaller `onedir` for services. A self-extracting single-file
service is not the best choice for SCM-managed service startup.

## Current Collector Coverage

Current section map from runtime and config generator:

| Section | Default interval | Default enabled |
| --- | ---: | --- |
| `metrics` | 10 sec | yes |
| `connections` | 10 sec | yes |
| `processes` | 10 sec | yes |
| `ports` | 30 sec | yes |
| `arp` | 60 sec | yes |
| `network` | 120 sec | yes |
| `mounts` | 120 sec | yes |
| `battery` | 120 sec | yes |
| `openfiles` | 120 sec | yes |
| `services` | 120 sec | yes |
| `users` | 120 sec | yes |
| `hardware` | 300 sec | yes |
| `containers` | 120 sec | yes |
| `storage` | 600 sec | yes |
| `tasks` | 600 sec | yes |
| `apps` | 900 sec | yes |
| `packages` | 900 sec | yes |
| `sbom` | 900 sec | yes |
| `security` | 3600 sec | yes |
| `sysctl` | 3600 sec | yes |
| `configs` | 3600 sec | yes |
| `sca` | 43200 sec | yes |
| `eventlog` | 300 sec | yes |
| `binaries` | 86400 sec | no |

Decision: keep `binaries` disabled by default. It is expensive and belongs in
an intensive profile.

Decision: add named collection profiles before enabling more heavy collectors.

## Current Security Model

Implemented or partially implemented:

- HTTPS transport wrapper.
- TLS verification option.
- optional SPKI pin support in transport.
- per-payload encryption and HMAC signing.
- key storage priority chain: Credential Manager, DPAPI file, restricted file.
- spool directory and protected security directory creation.
- service watchdog.

Gaps:

- ACL logic is split between WiX, config generator, and key storage.
- config and spool directory ACLs are not centrally defined.
- diagnostics and redaction are not implemented as one supported command.
- response execution framework is not implemented as a safe signed workflow.
- installer GUI is not yet a complete first-class path.

Decision: centralize ACL behavior before adding response actions or advanced
stateful collectors.

## Current Documentation State

Current docs:

```text
AGENT_ARCHITECTURE.md
WINDOWS_AGENT_ROADMAP.md
WINDOWS_AGENT_WORK_LOG.md
INSTALL.md
INSTALL_GUIDE.md
INSTALLATION.md
TROUBLESHOOTING.md
taskagent.md
agentpromptrequired.md
referance_architecture.md
```

Issues:

- multiple install guides disagree
- several files contain mojibake
- some docs still describe older command examples
- some docs describe a GUI that the primary WiX file does not fully implement
- some docs use different config paths
- reference-only material should stay separate from product docs

Decision: make `INSTALL.md` the authoritative install guide later. Fold useful
content from other install docs into it, then mark stale docs as historical or
remove them if requested.

## Current Test Status

Attempted targeted unit test command:

```powershell
python -m pytest .\PROJECT_CORE\agent\tests\unit\test_windows_normalizer.py .\PROJECT_CORE\agent\tests\unit\test_windows_keystore.py .\PROJECT_CORE\agent\tests\unit\test_windows_collectors.py .\PROJECT_CORE\agent\tests\unit\test_watchdog.py
```

Result:

```text
python: command not found
```

Attempted Windows launcher command:

```powershell
py -m pytest .\PROJECT_CORE\agent\tests\unit\test_windows_normalizer.py .\PROJECT_CORE\agent\tests\unit\test_windows_keystore.py .\PROJECT_CORE\agent\tests\unit\test_windows_collectors.py .\PROJECT_CORE\agent\tests\unit\test_watchdog.py
```

Result:

```text
Access is denied while launching Python 3.13 from WindowsApps.
```

Conclusion: no tests were executed in this sandbox. The next implementation
slice needs either a usable Python executable in PATH or an approved project
environment command.

## Milestone 0 Decisions

1. Scope stays only under `agent/os/windows`.
2. `pkg/` is the primary MSI packaging path.
3. `installer/` is legacy or alternate until reconciled.
4. Final config path is `C:\ProgramData\AttackLens\config\agent.toml`.
5. Current service names stay `AttackLensAgent` and `AttackLensWatchdog`.
6. Keep the two-service topology.
7. Keep PyInstaller `onedir` packaging.
8. Final MSI property model uses `MANAGER_URL` as primary.
9. `MANAGER_IP` and `MANAGER_PORT` remain compatibility aliases.
10. HTTPS remains default.
11. Insecure development transport, if supported, must be explicit.
12. Add typed config validation before deeper installer changes.
13. Add centralized ACL helpers before response or integrity collectors.
14. Keep `binaries` disabled in the default collection profile.
15. Build artifacts should be excluded from source tracking later.

## Immediate Next Step

Proceed to Milestone 1:

1. Clean stale naming in Windows service/watchdog comments and classes where safe.
2. Remove mojibake from Windows docs touched by the product workflow.
3. Make `INSTALL.md` the authoritative install guide.
4. Record `INSTALL_GUIDE.md` and `INSTALLATION.md` as stale until folded in.
5. Keep runtime behavior unchanged until config validation work begins.
