# AttackLens Windows Agent - Current Verified Implementation

Updated: 2026-08-14
Build: 2.0.26 (unsigned development artifact)
Installed endpoint: 2.0.24 (2.0.26 built and ready)

This is the authoritative summary for the Windows implementation. Older
version notes in surrounding documents are retained as history; where they
conflict with this file, this file wins.

## Outcome

The agent, watchdog, configuration tools, native telemetry, encrypted offline
delivery, diagnostics, self-repair, and MSI live under `agent/os/windows/`.
Mutable installed state is under `C:\ProgramData\AttackLens`; binaries and
operator tools are under `C:\Program Files\AttackLens`. Nothing intentionally
targets Program Files (x86).

The scheduler exposes 27 collection sections. `developer_security` reports 17
capability groups, including supported MCP configurations, editor extensions,
package ecosystems, local development servers, language runtimes, containers,
Git security posture, cloud credentials metadata, Windows scheduled tasks, and
network listeners. Every emitted record carries collection status/error
metadata so partial or unavailable evidence is not presented as a complete
inventory.

The build also includes ETW collection, push-based Windows Event Log
subscriptions with durable bookmarks, continuous SCA, persistence monitoring,
security posture collection, and `agent_health` / `agent_lifecycle`
control-plane evidence. The encrypted SQLite outbox commits evidence before
collector cursors or baselines advance, retries with a fresh wire nonce, and
deletes only after manager acknowledgement.

## Developer and DeepMesh accuracy

The 2026-08-13 live cross-check covered all 17 developer-security capability
groups with no partial group status. Independent Windows commands matched the
collector for the high-volume inventories:

- Scheduled tasks: 202 collector records and 202 native Task Scheduler records.
- Network listeners: 37 TCP plus 2 UDP records, for 39 collector records.
- Editor extension manifests: 8 filesystem manifests and 8 collector records.
- MCP inventory: zero is accurate on this host when none of the supported MCP
  configuration files are present; absence is reported separately from a
  collector failure.

The manager at `http://72.61.228.62:8080` accepts `developer_security`
telemetry, and its DeepMesh API/UI path recognizes that collection. The
2026-08-14 end-to-end 2.0.24 GUI upgrade completed with Windows Installer exit
code 0. A protected-file audit proved that the GUI rewrote `agent.toml` with
`http://72.61.228.62:8080`; its installer diagnostic reports
`manager_source=MANAGER_URL`, `manager_configured=True`, and
`gui_manager_required=True`. The manager reports endpoint `DESKTOP-34M18MB`
online and connected, with a complete post-upgrade `developer_security`
snapshot (`collection.partial=false`).

The latest runtime status reports healthy connectivity, zero pending outbox
rows, verified configuration and 156-file package integrity, and no delivery
stall. The manager API exposes 25 received sections for this endpoint. The
remote manager deployment still rejects `eventlog`, `persistence`, and
`security_audit` even though the current manager source in this repository
defines all three. Updating the remote manager deployment is required to accept
those sections; this does not affect accepted `developer_security` data.

## Startup, shutdown, and recovery

- `AttackLensAgent` and `AttackLensWatchdog` are dependency-free Windows
  services configured for automatic delayed startup.
- Both services have SCM recovery actions; the MSI enables the non-crash
  failure flag for each service, so clean error exits also trigger recovery.
- A global mutex prevents duplicate agent processes.
- Stop, pre-shutdown, power suspend, and power-resume controls are handled.
- The watchdog performs guarded self-repair and restarts a failed agent without
  creating an unbounded restart loop.
- Sleep/hibernate recovery wakes the delivery loop and resumes collection.
- After a full shutdown, code cannot run while the machine has no power.
  Windows starts the services automatically at the next boot. Starting a fully
  powered-off computer requires separately configured Wake-on-LAN or firmware
  scheduled-wake support and is outside the endpoint service.

## Verification evidence

- Authoritative Python syntax audit: 51 files, 0 errors.
- Canonical release PowerShell parser audit: 19 scripts, 0 errors.
- WiX XML audit: 8 tracked sources, 0 errors.
- Local Markdown-link audit: 47 links, 0 broken.
- Collection registry audit: scheduler intervals, collectors, and supported
  collection sets are identical at 27 entries.
- Windows agent/platform tests: 533 passed, 7 skipped.
- Manager unit tests: 25 passed.
- WiX ICE validation: passed.
- Compiled MSI database verification: passed; x64, version 2.0.25, 163 MSI
  file rows, 156 hashed manifest entries, embedded license, unattended EULA
  enforcement, dependency-free services, 64-bit configuration actions, and
  ordered recovery custom actions.
- Frozen packaged executable configuration validation: passed.
- Elevated full-GUI upgrade from 2.0.23: passed, Windows Installer exit 0.
- GUI manager handoff: passed client-to-server Secure-property transfer,
  protected TOML rewrite, fail-closed intent marker verification, and manager
  dialog validation-before-navigation.
- Installed manifest verification: 156 files checked, 0 mismatches.
- Installed service configuration and connectivity self-test: passed.
- Manager observation: endpoint online/connected, `developer_security`
  complete, 25 received sections, connection healthy, pending outbox 0.
- `git diff --check`: passed; line-ending conversion notices are informational.

Artifact:

```text
pkg\dist\attacklens-agent-2.0.25-x64.msi
Size:      23,813,038 bytes
SHA-256:   8A9028486588580EBF4780D76632AD4CFD7DD03C0C1A785C1ABC888CE04A2D3F
Signature: NotSigned (development build)
```

## Operator commands

Install or upgrade the development endpoint from an elevated PowerShell:

```powershell
msiexec.exe /i .\pkg\dist\attacklens-agent-2.0.25-x64.msi `
  MANAGER_URL="http://72.61.228.62:8080" `
  ALLOW_INSECURE_TRANSPORT="true" ACCEPT_EULA=1 `
  /l*v .\attacklens-agent-2.0.25-install.log
```

Validate and diagnose after installation:

```powershell
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' --validate-config
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' status
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' diagnose
& 'C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe' self-test
```

Production deployments must use HTTPS with certificate validation enabled.

## Remaining production gates

The development MSI is complete and verified, but it is not a signed
production release. Production promotion still requires an Authenticode
certificate and trusted timestamp, elevated fresh-install/upgrade/repair/
reboot/uninstall testing on the supported Windows matrix, and validation in
the intended Intune, GPO, or SCCM deployment path. ETW Threat Intelligence and
PPL additionally require the appropriate anti-malware signing status.
