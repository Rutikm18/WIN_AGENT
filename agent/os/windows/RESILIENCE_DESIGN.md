# Windows Agent Resilience Design

> The implemented startup recovery state machine and safety boundaries are documented in [`advanced_support/`](advanced_support/README.md).

Updated: 2026-07-27

This document records Windows endpoint failure patterns and the corresponding
AttackLens controls.

## Failure patterns and implemented controls

| Failure pattern | AttackLens control |
|---|---|
| Windows Event Log service is unavailable when the agent starts and collection does not reconnect | Every channel is queried independently on every interval. Service-unavailable errors are classified and retried; a channel failure does not disable the collector permanently. |
| Events may be missed while the Windows Event Log service is stopped or restarted | Per-channel `EventRecordID` cursors survive restarts. A cursor is committed only after the collected batch is durably enqueued. |
| `EvtSubscribe`/channel error 15007 or unavailable optional channels | Security, System, PowerShell, and Defender channels fail independently. Error 15007 is reported as `channel_unavailable`; enabled channels continue collecting. |
| Shutdown or file-permission race leaves a service running but disconnected | Fatal startup errors propagate to SCM, critical sender/health thread exits fail the service, runtime files are atomic, SQLite is transactional, and the watchdog detects stale heartbeats. |
| Upgrade succeeds but the agent does not reconnect or restart | SCM failure actions remain enabled, the watchdog checks process liveness and runtime heartbeat freshness, and the service reports `RUNNING` only after critical initialization. |
| Invalid manager credentials cause unnecessary or broken re-registration | Valid local credentials are reused. Re-enrollment after repeated 401/403 responses is disabled by default and requires both `auto_reenroll=true` and a non-empty enrollment token. Queued data uses an independent local key and survives manager-key rotation. |
| Full queues drop packages or events | The old bounded NDJSON spool and FIFO trimming are no longer used for runtime delivery. The SQLite outbox has no automatic data-drop policy; low disk stops cursor advancement instead of discarding telemetry. |

## Delivery contract

The Windows agent provides at-least-once delivery to the manager ingest API:

1. A collector creates a canonical message with a stable `delivery_id`,
   original `collected_at`, hostname, OS, and agent identity.
2. The complete batch is encrypted with a machine-local outbox key and committed
   to SQLite using WAL and `synchronous=FULL`.
3. A stateful collector, currently Windows Event Log, commits its source cursor
   only after the SQLite commit succeeds.
4. Every network attempt creates a fresh AES-GCM nonce and current transport
   timestamp. Long outages therefore do not make queued records fail the
   manager's replay-time window.
5. The row is deleted only after a valid 2xx application acknowledgement.
   Authentication, TLS, DNS, timeout, reset, 408, 425, 429, and 5xx failures
   retain the row and schedule bounded exponential backoff with jitter.
6. Other 4xx responses and locally unsplittable oversized payloads become
   retained dead letters. They are visible in health data and are not deleted.

Every POST includes `X-Delivery-ID` and `Idempotency-Key`. The current manager
does not yet enforce idempotency, so an accepted request whose response is lost
can be delivered more than once. This is intentional: duplication is preferred
to loss. End-to-end exactly-once storage requires the manager to persist
`delivery_id` and return a durable receipt.

The manager currently returns `{"status":"ok"}` as its application
acknowledgement. The agent can guarantee durable retention until that
acknowledgement; it cannot detect a manager-side storage failure hidden behind
a successful response.

## Outbox storage

- Database: `C:\ProgramData\AttackLens\spool\delivery-outbox.sqlite3`
- Local payload key:
  `C:\ProgramData\AttackLens\security\<agent-id>.delivery-outbox.key`
- Key protection: machine-scope DPAPI, with ACL-protected fallback
- States: `pending`, `dead`
- Automatic deletion: acknowledged `pending` rows only
- Legacy migration: decrypts old NDJSON wire records into canonical messages,
  assigns deterministic legacy delivery IDs, and preserves the migrated file
  with a timestamped suffix
- Database startup check: SQLite `PRAGMA quick_check`

The outbox is independent of the manager API key. Key rotation does not make
offline telemetry unreadable.

## Event Log continuity

Cursor file:
`C:\ProgramData\AttackLens\data\eventlog-cursors.json`

- Channels are queried oldest-first after the committed `EventRecordID`.
- Query and event handles are always closed.
- Errors are classified as `access_denied`,
  `eventlog_service_unavailable`, `channel_unavailable`, or
  `query_result_stale`.
- Channel disablement or service restart is retried automatically.
- A cleared/recreated channel is detected when its newest record ID is lower
  than the committed cursor. The cursor resets and collection resumes from the
  configured 24-hour bootstrap window.
- Cursor state is written with flush, fsync, and atomic replace.
- Corrupt cursor files are quarantined rather than silently trusted.

If Windows clears a channel before the agent reads it, those source records no
longer exist and no endpoint agent can recover them. Increase Windows log size
and retention policy for high-volume Security and PowerShell channels.

## Runtime and service recovery

`C:\ProgramData\AttackLens\data\agent.runtime.json` is updated atomically by the
health thread and includes connection state, delivery counters, outbox depth,
dead-letter count, manager clock skew, circuit states, and channel errors.

The service exits as failed when:

- configuration, ACL repair, enrollment, collector import, or outbox startup
  fails;
- the sender or health thread exits unexpectedly.

The watchdog restarts a stopped service and also detects:

- a runtime heartbeat older than 180 seconds;
- a crashed sender thread;
- a runtime that reports stopped while SCM reports running.

Restarts remain rate-limited. In harden mode the agent runs as
`NetworkService`; the watchdog remains `LocalSystem` so it retains permission
to stop and start the agent.

## Configuration

```toml
[transport]
initial_backoff_sec = 5
max_backoff_sec = 300
auth_failure_threshold = 3
auto_reenroll = true          # requires a non-empty enrollment token
min_free_mb = 128
outbox_busy_timeout_ms = 5000
```

`auto_reenroll=false` is the runtime default. New generated configurations set
it to true only when an enrollment token was explicitly supplied.

## Error automation matrix

| Error | Automatic action | Data disposition |
|---|---|---|
| DNS, refused connection, reset, timeout, proxy | Recreate transport; exponential backoff with jitter | Pending |
| TLS verification or SPKI pin failure | Fail closed; retry and expose `tls_error` | Pending |
| HTTP 401 timestamp window | Build a new envelope and retry; report estimated manager clock skew | Pending |
| HTTP 401/403 credential failure | Retain and back off; optionally rotate after threshold | Pending |
| Duplicate nonce response | Treat as acknowledgement because the manager has already seen the envelope | Acknowledged |
| HTTP 408/425/429 | Respect numeric `Retry-After`, then retry | Pending |
| HTTP 5xx | Retry with bounded exponential backoff | Pending |
| Other HTTP 4xx | Retain for diagnosis/manual replay | Dead letter |
| Payload over request limit | Split list payloads atomically; retain unsplittable payload | Pending or dead letter |
| Low disk | Stop accepting new cursor commits; report `disk_pressure` | Existing rows retained |
| Outbox/cursor corruption | Fail startup for outbox; quarantine cursor state | No silent deletion |
| Event Log service/channel unavailable | Retry each channel independently | Cursor unchanged |
| Event Log cleared | Detect lower record ID and reset cursor | Resume from available records |
| Sender/health thread crash | Fail service; SCM/watchdog restart | SQLite rows retained |

## Operator checks

Run in elevated PowerShell:

```powershell
$base = "C:\ProgramData\AttackLens"

Get-Service AttackLensAgent, AttackLensWatchdog |
    Select-Object Name, Status, StartType

Get-Content "$base\data\agent.runtime.json" -Raw |
    ConvertFrom-Json | ConvertTo-Json -Depth 8

Get-Item "$base\spool\delivery-outbox.sqlite3" |
    Select-Object FullName, Length, LastWriteTime

Get-Content "$base\logs\agent.log" -Tail 200 |
    Select-String "outbox|dead letter|eventlog|authentication|tls|disk_pressure"

Invoke-WebRequest -UseBasicParsing `
    -Uri "http://13.233.122.80:8080/health" -TimeoutSec 30
```

Do not delete the SQLite database to fix connectivity. Restore the manager,
certificate, credentials, ACL, or disk capacity and let the sender drain it.

## Manager migration invariant

Preserving state must not silently ignore explicit connection intent. On
upgrade, no manager argument preserves the whole file; an explicit manager
argument atomically changes only connection fields and keeps a protected
rollback file. A client credential is reused only when its normalized issuing
manager matches the configured manager (scheme, host, effective port, path,
and query). A mismatch archives the credential and enters re-enrollment while
the durable outbox remains intact.
