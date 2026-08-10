# Windows Developer and AI Security Audit Implementation Plan

> Service startup recovery preserves fail-closed ACL, identity, outbox, and TLS controls as documented in [`advanced_support/AUTOMATION.md`](advanced_support/AUTOMATION.md).

Source requirements: `windowsagent_additional_Capabilities.md`

Implementation section: `security_audit`

Default interval: 21,600 seconds (6 hours)

## 1. Objective

Add the developer-tool, AI-agent, MCP, browser, persistence, credential-surface,
and Docker checks from the source requirements to the production Windows agent.
The implementation must remain read-only, tolerate non-administrator execution,
work when the service runs as LocalSystem, avoid collecting secrets, and remain
bounded on multi-user or developer-heavy endpoints.

This is implemented as one cohesive `security_audit` payload. Existing
high-frequency sections continue to provide general process, connection,
listener, task, service, package, application, security-posture, and container
inventory. The new section supplies the missing provenance and risk context and
does not change those existing manager schemas.

## 2. Capability-to-implementation map

| Requirement domain | Implementation | Important edge handling |
|---|---|---|
| VS Code/Cursor extensions | Parse extension `package.json` files for all discovered profiles | Handles missing/malformed/oversized manifests, version directories, symlink/junction escape, startup/network/shell indicators |
| MCP configurations | Parse known Claude, Cursor, VS Code, Windsurf, Codex and workspace JSON/JSONC/TOML locations | JSONC comments/trailing commas, nested `mcpServers`, redacted arguments, environment names only, unpinned `npx`/`uvx` detection |
| Global Node packages | Read package manifests from npm, pnpm and Yarn global roots | Does not execute user-controlled `npm`, `pnpm`, `yarn`, or lifecycle scripts; scoped packages supported |
| Python packages | Read `*.dist-info/METADATA` in known system and per-user `site-packages` paths | Does not launch user Python interpreters or import packages; malformed metadata is skipped |
| Installed applications | Read 32-bit/64-bit machine uninstall keys and already-loaded user hives | Deduplicates registry views and filters developer/AI-relevant products |
| AI and agent CLIs | Resolve every matching file from machine, process, user and common tool paths | Does not execute tools; reports duplicate/shadowed commands and user-profile locations |
| PowerShell profiles/PATH | Hash and classify profile scripts; merge machine, current and loaded-user PATH data | Never emits profile contents; detects relative, duplicate, missing and user-profile entries |
| Scheduled tasks | Query every task action, principal and run level | Handles multiple actions, disabled tasks, script hosts, user-profile paths, downloads and encoded commands |
| Windows services | Query service path, account, state and start mode | Detects unquoted paths, profile binaries and script-host services; output is redacted |
| Startup entries | Combine `Win32_StartupCommand`, Run/RunOnce registry values and Startup folders | Includes loaded user hives and hashes Startup-folder files without reading their contents into the payload |
| Running processes | Filter process/command-line telemetry for AI/MCP/agent indicators | Handles process exit/access denial; token, authorization, URL-userinfo and environment-style secrets are redacted |
| Listening ports | Resolve TCP/UDP listeners to process names and paths | Identifies all-interface exposure (`0.0.0.0` and `::`) and AI-related public listeners |
| Browser extensions | Parse Chrome, Edge and Brave manifests across Default/Profile-* browser profiles | Reports permission/host-permission lists and flags native messaging, debugger, cookies, history, proxy and all-host access |
| Native messaging | Read Chrome/Edge native-host registry keys and manifests | Covers 32/64-bit views plus already-loaded user hives; flags user-profile executables |
| Git config/hooks/workspace execution | Parse system/global configs and inspect bounded common repository roots | Does not execute Git; reports hooks and hashes task/launch/container/build/workflow files without sending file contents |
| Credential and secret locations | Inventory credential-manager target metadata and known credential file metadata | Uses `cmdkey /list`, which cannot return secret material; sends names/paths/size/timestamps only, never file or credential values |
| Docker | Use only a Docker CLI installed under trusted machine locations | Inspects privilege, mounts, network mode, capabilities and image pinning; sends environment variable names only, never values |

## 3. Step-by-step implementation sequence

### Step 1: Preserve the privileged-service trust boundary

1. Resolve Windows PowerShell from `%SystemRoot%\System32` instead of PATH.
2. Never launch user-discovered Python, Node, npm, npx, Git, editor, or AI CLI
   executables.
3. Permit Docker inspection only through an executable under Program Files or
   System32.
4. Keep every invoked command read-only and apply the collector subprocess
   timeout.

Reason: the agent normally runs as LocalSystem. Executing a shim from a user's
profile would let a standard user gain SYSTEM execution.

### Step 2: Establish the data and privacy contract

1. Emit one versioned `security_audit` object with per-domain coverage.
2. Record only metadata needed for inventory or a finding.
3. Redact token/password/API-key flags, inline assignments, bearer values,
   URL userinfo, and sensitive URL query values.
4. For MCP and Docker environments, emit variable names only.
5. For profiles, Git execution files and credential folders, emit hashes and
   metadata rather than file contents.
6. Store only exception class names in coverage; never exception text that can
   include a secret path or value.

### Step 3: Discover real user profiles

1. Read `ProfileList` from HKLM.
2. Add existing profile directories under `C:\Users` as a fallback.
3. Exclude Default/Public/synthetic profiles.
4. Deduplicate paths case-insensitively and cap processing at 64 profiles.
5. Enumerate already-loaded `HKEY_USERS` SIDs for registry-only per-user data.
6. Do not load offline `NTUSER.DAT` hives because that mutates registry state.

### Step 4: Implement file-backed developer inventory

1. Parse editor and browser extension manifests.
2. Parse JSONC with a string-aware comment state machine so `https://` and
   comment-like string values are not corrupted.
3. Parse Codex and other TOML MCP configuration through `tomllib`.
4. Read Node and Python distribution metadata directly.
5. Inspect PowerShell profiles, Git hooks, workspace launch files and known
   credential directories with bounded traversal.
6. Reject files larger than 1 MiB and never follow directory symlinks.

### Step 5: Implement Windows API and registry inventory

1. Query tasks, services and startup commands through trusted PowerShell/CIM.
2. Read Run/RunOnce keys to cover entries CIM may omit.
3. Read 32-bit and 64-bit application/native-host registry views.
4. Read per-user application, PATH, startup and native-host data from loaded
   user hives.
5. Use `psutil` for process and listener ownership, tolerating access-denied
   and process-race failures.

### Step 6: Add risk classification

Generate structured findings for:

- AI extensions with startup, child-process, terminal/shell, workspace, or
  network capabilities.
- Unpinned MCP package launchers and user-profile MCP commands.
- Custom Node registries and enabled lifecycle scripts.
- Duplicate/shadowed developer commands and user-writable PATH entries.
- PowerShell profile downloads, dynamic execution, encoded commands and tool
  bootstrapping.
- Scheduled-task/startup/service script hosts, user-profile execution,
  obfuscated commands and unquoted service paths.
- AI listeners bound to all interfaces.
- Browser extensions with broad host or security-sensitive permissions.
- Native-messaging executables under user profiles.
- Git execution overrides and active repository hooks.
- Privileged Docker containers, Docker-socket/host-root mounts, host networking,
  `SYS_ADMIN`, sensitive environment names and unpinned images.

Findings are evidence, not automatic proof of compromise. The manager should
apply endpoint role, publisher allowlists and organizational policy before
alerting.

### Step 7: Bound resource consumption and failure impact

1. Run the section every six hours by default.
2. Use a 180-second overall soft deadline and 25-second subprocess timeouts.
3. Cap profiles at 64, records/findings at 500, Docker inspect at 64
   containers, and repositories at 50.
4. Cap individual filesystem walks by depth, directory count and result count.
5. Isolate every domain so access denial or malformed data produces partial
   coverage rather than losing the entire audit.
6. Publish the last coverage/findings summary through collector health.

### Step 8: Wire the production path

1. Add `security_audit` to typed configuration validation.
2. Register it in the shared collector registry.
3. Add it to the Windows runtime's explicit collector list and interval table.
4. Add an explicit normalizer entry.
5. Include it in generated standard/incident configurations.
6. Add it to the PyInstaller hidden-import list.
7. Rely on the source-harvesting MSI build to include the module.

### Step 9: Verify and release

1. Compile every changed Python module.
2. Run focused tests for parsing, redaction, traversal, risk classification,
   domain isolation and runtime wiring.
3. Run the existing Windows collector and reliability suites.
4. Run a live `--collect-once` on a disposable Windows VM as administrator and
   as a standard user.
5. Confirm the serialized payload contains no seeded secrets.
6. Verify service runtime, manager ingest size, six-hour scheduling and health
   reporting.
7. Rebuild the one-directory executable and MSI; validate the MSI and confirm
   the new module is present in the installed source/bundle.

## 4. Critical edge-case matrix

| Edge case | Expected result |
|---|---|
| Agent runs as LocalSystem | All real profile filesystem roots and loaded user hives are considered; LocalSystem HKCU is not treated as the only user |
| Standard user/no admin rights | Inaccessible domains return empty/partial evidence; the collector never raises |
| Hundreds of terminal-server profiles | First 64 valid profiles are audited and all traversal remains bounded |
| Junction/symlink leaves an approved root | Resolved containment check rejects the file |
| Manifest is malformed, locked, huge, deleted mid-read, or non-UTF-8 | File is skipped or marked unreadable; other records continue |
| JSONC contains URLs or comment tokens in strings | String-aware parser preserves them |
| MCP args/environment contain credentials | Values are redacted or omitted; environment names remain for risk classification |
| Process exits during collection | Record is skipped without failing the process domain |
| Service/task command contains token-like material | Redaction occurs before storage or finding generation |
| PATH contains an attacker-controlled shim | Shim is inventoried but never executed |
| Offline user registry hive | It is not loaded; filesystem evidence is still collected and coverage remains non-mutating |
| Docker is absent, stopped, or only user-installed | Docker domain reports unavailable/empty and no user CLI is launched |
| Container environment contains secrets | Only variable names and sensitive-name matches are emitted |
| Repository tree contains `node_modules`, build output, symlink loops, or huge depth | Exclusions/depth/directory/deadline limits stop traversal |
| One domain exceeds the overall deadline | Remaining domains are marked skipped with `collector_deadline` |
| Manager cannot ingest the new section yet | Existing sections are unchanged; `security_audit` can be disabled in configuration |

## 5. Verification evidence

Focused test command:

```powershell
py -3.13 -m unittest agent.tests.unit.test_windows_security_audit -v
```

Broader collector regression:

```powershell
py -3.13 -m pytest agent/tests/unit/test_windows_collectors.py `
  agent/tests/unit/test_windows_security_audit.py -q
```

Runtime configuration:

```toml
[collection.sections.security_audit]
enabled = true
interval_sec = 21600
```

Live payload review should seed recognizable fake tokens in MCP, npm, pip,
process, task and Docker configurations and assert that none appear in the
serialized output or manager storage.

## 6. Known operational limitations

- Offline per-user registry hives are deliberately not mounted. Per-user
  registry evidence is complete only for currently loaded hives.
- YAML MCP files are identified and hashed, but arbitrary YAML is not fully
  parsed without adding a YAML dependency. JSON/JSONC/TOML server definitions
  are parsed into records.
- Browser extension localized names may remain as `__MSG_*__`; permissions and
  extension IDs remain accurate.
- Docker inspection depends on a machine-installed trusted Docker CLI and
  daemon access. A user-profile Docker shim is never executed.
- Findings are local heuristics. Publisher reputation, organization allowlists,
  package vulnerability intelligence and manager-side correlation remain
  manager responsibilities.
- Final release sign-off still requires an elevated disposable-VM test and a
  rebuilt MSI/executable; source-level tests cannot prove every Windows SKU,
  domain policy, browser channel or Docker Desktop configuration.
