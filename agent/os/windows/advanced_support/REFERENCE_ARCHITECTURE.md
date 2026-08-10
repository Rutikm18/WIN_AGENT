# Reference architecture decisions

The Windows layout follows Windows common-application-data conventions and
operational patterns documented by established endpoint-agent vendors.

## Decisions

- Immutable executables and tools live under `C:\Program Files\AttackLens`.
- Machine-wide mutable config, logs, credentials, spool, and status live under
  `C:\ProgramData\AttackLens`. Microsoft maps `CommonAppDataFolder` to this
  location for per-machine application data.
- Sensitive state is protected; routine status is a separate sanitized,
  read-only file. Wazuh similarly documents an agent state file and local
  connection inspection, while Elastic documents explicit install/data/log
  paths plus agent status and log troubleshooting.
- Enrollment is coupled to the configured manager. Changing managers triggers
  re-enrollment instead of reusing a credential scoped to the old endpoint.
- Delivery is durable: outages cause bounded retry/backoff and encrypted local
  queuing, not telemetry deletion or TLS weakening.

## Primary references

- Microsoft Known Folders (`FOLDERID_ProgramData`):
  https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
- Microsoft Windows Installer installation context and `CommonAppDataFolder`:
  https://learn.microsoft.com/en-us/windows/win32/msi/installation-context
- Elastic Agent installation layout:
  https://www.elastic.co/docs/reference/fleet/installation-layout
- Elastic Fleet-managed installation and enrollment:
  https://www.elastic.co/docs/reference/fleet/install-fleet-managed-elastic-agent
- Elastic Agent logging locations and rotation:
  https://www.elastic.co/docs/reference/fleet/elastic-agent-standalone-logging-config
- Elastic Fleet troubleshooting/status guidance:
  https://www.elastic.co/guide/en/fleet/8.19/fleet-troubleshooting.html
- Wazuh agent connection/state guidance:
  https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html
- Wazuh agent enrollment troubleshooting:
  https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html

These references inform layout and operability only; AttackLens retains its own
protocol, encrypted outbox, ACL policy, watchdog, and recovery implementation.
