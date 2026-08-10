# AttackLens Windows Agent — Troubleshooting Guide

> The current root-cause matrix and one-command diagnosis/repair workflow are in [`advanced_support/`](advanced_support/README.md) (2026-08-09).

**Applies to:** AttackLens Windows Agent v2.0+  
**Last updated:** 2026-07-23

Delivery now uses the encrypted SQLite outbox described in
`RESILIENCE_DESIGN.md`. References below to the legacy NDJSON spool have
been replaced; do not delete `delivery-outbox.sqlite3` to fix connectivity.

---

## Quick Diagnostics (Run These First)

Open an **elevated PowerShell** (Run as Administrator) and run:

```powershell
# 1 — Service state
Get-Service AttackLensAgent, AttackLensWatchdog | Select Name, Status, StartType

# 2 — Last 50 log lines
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 50

# 3 — Durable outbox and runtime delivery status
Get-Item "C:\ProgramData\AttackLens\spool\delivery-outbox.sqlite3"
Get-Content "C:\ProgramData\AttackLens\data\agent.runtime.json" -Raw |
    ConvertFrom-Json | ConvertTo-Json -Depth 8

# 4 — Client key presence (should exist after first enrollment)
Test-Path "C:\ProgramData\AttackLens\security\client.key"

# 5 — Config file presence
Test-Path "C:\ProgramData\AttackLens\config\agent.toml"

# 6 — Manager reachability (replace with your manager IP/port)
$mgr = (Get-Content "C:\ProgramData\AttackLens\config\agent.toml" |
        Select-String "url\s*=").ToString() -replace '.*=\s*"(.*)".*','$1'
Invoke-WebRequest -Uri "$mgr/health" -UseBasicParsing -SkipCertificateCheck
```

---

## 1. Service Won't Start

### 1.1 Error: "Service did not respond to the start or control request"

**Cause:** The SCM start timeout elapsed before the agent reported SERVICE_RUNNING.
This usually means one of:
- Python import chain is taking too long (PyInstaller cold start)
- Enrollment is blocking on a slow/unreachable manager
- Log directory cannot be created (permissions)

**Diagnose:**
```powershell
# Check the Windows System event log for service errors
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 10 |
    Where-Object Message -Match "AttackLens" | Select -ExpandProperty Message

# Try running the agent in foreground debug mode to see startup output directly
Set-Location "C:\Program Files\AttackLens\bin\attacklens-agent"
$env:MACINTEL_CONFIG = "C:\ProgramData\AttackLens\config\agent.toml"
.\attacklens-agent.exe debug
```

**Fix:** If enrollment is the bottleneck, verify manager connectivity first (see §2).
If imports are slow, this is a PyInstaller warm-up issue — it should succeed on the
second start attempt.

---

### 1.2 Error: "Access is denied" (Event ID 7000)

**Cause:** The service binary path is inaccessible, or the service account lacks
execute rights on the binary directory.

**Diagnose:**
```powershell
# Confirm binary exists and is accessible to SYSTEM
$bin = "C:\Program Files\AttackLens\bin\attacklens-agent\attacklens-agent.exe"
Test-Path $bin
icacls $bin
```

**Fix:**
```powershell
# Grant SYSTEM read+execute on the install directory
icacls "C:\Program Files\AttackLens" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)(RX)" /T
```

---

### 1.3 Error: "Config not found" in agent.log

**Cause:** `agent.toml` is missing. The MSI custom action `CA_WriteConfig` failed
during install, or the file was manually deleted.

**Fix — repair or reinstall the protected configuration:**
```powershell
msiexec /fa "attacklens-agent-2.0.13-x64.msi" /l*v "$env:TEMP\attacklens-repair.log"
```

The installer-only generator runs as deferred LocalSystem because it creates
the protected file and establishes its ACL. Do not invoke that generator as an
Administrator runtime editing tool. If the file exists and only the manager is
wrong, use `configure-manager.ps1` as shown below.

---

### 1.4 Error: "Cannot parse agent.toml" / TOML syntax error

**Cause:** agent.toml contains invalid TOML — usually a path with unescaped
backslashes (use forward slashes or double backslashes in TOML strings).

**Valid:**
```toml
security_dir = "C:/ProgramData/AttackLens/security"   # forward slashes OK
security_dir = "C:\\ProgramData\\AttackLens\\security" # escaped backslash OK
```

**Invalid:**
```toml
security_dir = "C:\ProgramData\AttackLens\security"   # bare backslash = TOML error
```

**Fix:** Use the installed transactional editor. If no active file exists,
repair or reinstall 2.0.13 so the LocalSystem installer action can recreate it.

---

### 1.5 Error: "a required module is missing" / ImportError

**Cause:** The PyInstaller bundle is incomplete or corrupt.  
Common if the binary was copied without its `_internal/` directory.

**Diagnose:**
```powershell
# The exe and _internal folder must live together
Get-ChildItem "C:\Program Files\AttackLens\bin\attacklens-agent" | Select Name
# Must show: attacklens-agent.exe  and  _internal\  directory
```

**Fix:** Reinstall the MSI. If building from source, re-run
`build_attacklens_msi.ps1 -Version "2.0.7"` (see INSTALL_GUIDE.md §2).

---

## 2. Enrollment Failures

### 2.1 "Enrollment attempt N/5 failed (transient)"

The agent will retry automatically up to 5 times with backoff (10 s → 320 s).
You will see this in the log for **up to ~10 minutes** before giving up.

**While waiting, diagnose connectivity:**
```powershell
# Basic TCP connectivity
Test-NetConnection -ComputerName "34.224.174.38" -Port 8443

# HTTP-level health check (ignore cert error for self-signed)
Invoke-WebRequest -Uri "https://34.224.174.38:8443/health" `
    -UseBasicParsing -SkipCertificateCheck

# If the above hangs — check Windows Firewall outbound rule
Get-NetFirewallRule -Direction Outbound -Action Block | Select DisplayName
```

**Fix — common causes:**
| Symptom | Fix |
|---------|-----|
| TCP connection refused | Manager not running, or port wrong in agent.toml |
| Connection timeout | Firewall blocking outbound HTTPS |
| SSL error / cert invalid | Set `tls_verify = false` in agent.toml (dev/self-signed), or install manager CA cert |
| DNS resolution failure | Check DNS or use IP address directly in `[manager] url` |

---

### 2.2 TLS / Certificate Errors

**Error message:** `SSLCertVerificationError`, `CERTIFICATE_VERIFY_FAILED`, or
`hostname 'X' doesn't match 'Y'`

**Cause A:** Manager is using a self-signed certificate.  
**Fix:** Set `tls_verify = false` in `[manager]` section of agent.toml.  
For an `https://` URL, traffic remains encrypted and `tls_verify=false` only
skips the CA chain check. An `http://` URL is unencrypted by definition.

```toml
[manager]
url        = "https://34.224.174.38:8443"
tls_verify = false
```

**Cause B:** Manager cert is CA-signed but the CA is not in the Windows trust store.  
**Fix (enterprise):** Install the CA certificate into the Windows Certificate Store:
```powershell
Import-Certificate -FilePath "C:\path\to\ca.crt" `
    -CertStoreLocation "Cert:\LocalMachine\Root"
```

**Cause C:** SPKI pin mismatch — manager cert was rotated.  
**Error message:** `SPKI pin mismatch — possible MITM attack`  
**Fix:** Update `spki_pin` in agent.toml with the new certificate's SPKI hash.
Generate the new pin:
```powershell
python -c "
import base64, hashlib, ssl
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
pem = ssl.get_server_certificate(('manager-host', 8443))
cert = x509.load_pem_x509_certificate(pem.encode())
spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
print('sha256//' + base64.b64encode(hashlib.sha256(spki).digest()).decode())
"
```

---

### 2.3 Token Rejected (HTTP 401)

**Error message:** `Manager rejected enrollment token (HTTP 401)`

**Cause:** The `[enrollment] token` in agent.toml does not match any token
configured on the manager, or open enrollment is disabled.

**Fix:**
1. Verify the token on the manager:
   ```bash
   # On manager host
   grep -r "ENROLLMENT_TOKENS" /etc/attacklens/ /opt/attacklens/
   ```
2. Update agent.toml with the correct token:
   ```toml
   [enrollment]
   token = "sk-enroll-CORRECT-TOKEN-HERE"
   ```
3. Restart the service:
   ```powershell
   Restart-Service AttackLensAgent
   ```

---

### 2.4 Already Enrolled (HTTP 409)

**Error message:** `Agent already enrolled on manager (HTTP 409)`

**Cause:** This `agent_id` is already registered on the manager.
The local `client.key` was deleted or the agent was re-imaged.

**Fix — rotate the key on the manager:**
```bash
# On manager host (or via manager API)
curl -X POST https://manager:8443/api/v1/keys/<agent_id>/rotate \
     -H "Authorization: Bearer <admin-token>"
```

Then delete the local key and restart:
```powershell
Remove-Item "C:\ProgramData\AttackLens\security\client.key" -Force
Restart-Service AttackLensAgent
```

---

### 2.5 "Manager returned invalid api_key"

**Cause:** The manager returned an enrollment response but without a valid 64-hex
API key. Likely a manager version mismatch (old manager, new agent protocol).

**Fix:** Update the manager to a version that supports v2 enrollment responses, or
check the manager's enrollment handler logs for errors.

---

## 3. No Data Appearing in Dashboard

### 3.1 Agent is Running But Sending Nothing

**Diagnose — check whether the sender is actually posting:**
```powershell
# Watch the log for "sent" or "send error" lines
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 100 -Wait |
    Select-String "send|spool|circuit|ERROR|WARN"
```

**Check circuit breakers** — if all collectors are in OPEN state, nothing gets queued:
```powershell
# Look for "circuit OPEN" lines in the last 200 log lines
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 200 |
    Select-String "circuit OPEN"
```

A circuit breaker stays OPEN for 60 seconds, then sends one probe.  
**Fix:** If all collectors are OPEN, check whether psutil and win32 modules are importable:
```powershell
Set-Location "C:\Program Files\AttackLens\bin\attacklens-agent"
.\attacklens-agent.exe debug   # foreground mode — shows import errors immediately
```

---

### 3.2 Outbox Growing — Not Draining

**Cause:** Manager is unreachable or returning 5xx errors.

**Diagnose:**
```powershell
# Outbox file size and pending/dead-letter counts
Get-Item "C:\ProgramData\AttackLens\spool\delivery-outbox.sqlite3" |
    Select FullName, Length, LastWriteTime
Get-Content "C:\ProgramData\AttackLens\data\agent.runtime.json" -Raw |
    ConvertFrom-Json | Select -ExpandProperty outbox

# Manager health from the endpoint
Invoke-WebRequest -Uri "https://<manager>:<port>/health" -UseBasicParsing -SkipCertificateCheck
```

**The agent automatically drains the outbox once the manager is reachable again.**
No manual action needed — just restore manager connectivity.

There is no automatic FIFO trim. When free disk falls below `[transport]
min_free_mb`, collection cursor commits stop and the runtime reports
`disk_pressure`. Restore disk capacity; do not delete the outbox.

---

### 3.3 Dashboard Shows Stale Data

**Cause:** The agent is running but a specific collector section is failing.

**Diagnose:**
```powershell
# Collect all sections once and print JSON (no manager needed)
$env:MACINTEL_CONFIG = "C:\ProgramData\AttackLens\config\agent.toml"
Set-Location "E:\Project - AttacklensAgentwork\PROJECT_CORE"
python -m agent.os.windows.win_agent --config $env:MACINTEL_CONFIG --collect-once |
    Out-File "$env:TEMP\collect_once.json"
# Open the file to see which sections returned {"error": "..."}
notepad "$env:TEMP\collect_once.json"
```

---

## 4. Performance Issues

### 4.1 High CPU Usage

**Cause A:** The `binaries` collector is running — it walks `%ProgramFiles%` computing
SHA-256 hashes and takes 60–90 s.

**Fix:** Disable it (it is off by default):
```toml
[collection.sections.binaries]
enabled = false
```

**Cause B:** Multiple heavyweight collectors running simultaneously on first start.
The agent staggers slow collectors (>300 s interval) by up to 60 s to avoid this.
The spike should last less than 2 minutes.

**Cause C:** A collector PowerShell script is hung.

**Diagnose:**
```powershell
# Find hung powershell.exe children of the agent
Get-Process powershell | Where-Object {
    (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId -ne $PID
}
```

**Fix:** Identify which collector is spawning the hung process by checking the log
for the last collector that ran, then increase its timeout or disable it.

---

### 4.2 High Memory Usage

**Normal:** The agent holds up to 512 envelopes in the in-memory queue (~100 MB worst case if payloads are large).

**Abnormal:** If memory grows unboundedly, a collector is producing extremely large payloads (e.g., `processes` on a machine with thousands of processes).

**Fix:** Disable the offending section or increase its interval:
```toml
[collection.sections.processes]
interval_sec = 60   # was 10 s
```

---

### 4.3 Outbox Disk Growth

Growth is expected during an extended manager outage. The outbox does not
automatically delete old telemetry. Inspect manager connectivity, authentication,
dead-letter count, and disk capacity:

```powershell
Get-Content "C:\ProgramData\AttackLens\data\agent.runtime.json" -Raw |
    ConvertFrom-Json | ConvertTo-Json -Depth 8
Get-PSDrive -Name C | Select Used, Free
```

Deleting the outbox is a destructive data-loss action and is not a supported
connectivity repair.

---

## 5. Collector-Specific Issues

### 5.1 EventLog Collector: "Access Denied" / Empty Results

**Cause:** The agent service account does not have permission to read the Security
event log. Reading Security events requires `NT AUTHORITY\SYSTEM` or membership in
the `Event Log Readers` group.

**Check:** The MSI installs the service as `LocalSystem` which has full access.
If you changed the service account manually:
```powershell
# Check service logon account
(Get-WmiObject Win32_Service -Filter "Name='AttackLensAgent'").StartName

# If not LocalSystem, add the account to Event Log Readers
Add-LocalGroupMember -Group "Event Log Readers" -Member "DOMAIN\svc_attacklens"
```

**Also check:** The Security audit policy is enabled (otherwise Security log is empty):
```powershell
auditpol /get /category:* | Select-String "(Logon|Process)"
```

---

### 5.2 Security Collector: PowerShell Errors

**Cause:** PowerShell execution policy is blocking the collector scripts, or the
required modules (`BitLocker`, `Defender`) are not installed.

**Diagnose:**
```powershell
# Test that the Defender cmdlet works
Get-MpComputerStatus | Select AMServiceEnabled, RealTimeProtectionEnabled

# Test BitLocker (may fail on systems without BitLocker)
Get-BitLockerVolume -MountPoint "C:"
```

**Note:** Collector errors are silently swallowed — the section returns partial data.
If `Get-MpComputerStatus` fails, `defender` will show as `"unknown"` in the dashboard.
This is expected on Windows Server Core or Nano Server.

---

### 5.3 Inventory Collectors Timing Out

**Cause:** `apps`, `packages`, `tasks` use PowerShell/registry queries that can be
slow on machines with many installed applications.

**Fix — increase timeouts in agent.toml:**
```toml
# Nothing to set here; timeouts are hardcoded per-collector class.
# Instead, increase the interval so the slow collector runs less often:
[collection.sections.apps]
interval_sec = 3600   # was 900 s

[collection.sections.packages]
interval_sec = 3600
```

**Alternatively, disable slow collectors you don't need:**
```toml
[collection.sections.sbom]
enabled = false
```

---

## 6. Key and Authentication Issues

### 6.1 API Key Revoked or Expired (HTTP 401/403 on Ingest)

Queued telemetry is retained. If `[transport] auto_reenroll=true` and a
non-empty enrollment token is configured, the agent rotates credentials after
the configured authentication-failure threshold. Otherwise, confirm whether
the manager intentionally revoked this endpoint before re-enrolling it:

```powershell
& "C:\Program Files\AttackLens\bin\manage_services.ps1" enroll -Force
```

Do not delete credentials merely because one request returned 401: timestamp
window failures are retried with a fresh envelope and deliberate revocation
must remain effective.

---

### 6.2 DPAPI Key Load Failure

**Error message:** `DPAPI load failed: ...`

**Cause:** The DPAPI-encrypted key file exists but cannot be decrypted. This happens
if:
- The key was created under a different service account
- The machine was re-imaged and the DPAPI master key changed
- The key file is corrupt

**Fix:** Force re-enrollment (see §6.1 above).

**Verify DPAPI is working:**
```powershell
# Quick DPAPI round-trip test
Add-Type -AssemblyName System.Security
$plain = [System.Text.Encoding]::UTF8.GetBytes("test")
$enc = [System.Security.Cryptography.ProtectedData]::Protect(
    $plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
$dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $enc, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
[System.Text.Encoding]::UTF8.GetString($dec)   # should print "test"
```

---

### 6.3 "Credential Manager store failed"

**Cause:** `keyring` module cannot reach the Windows Credential Manager, usually
because the agent is running as `SYSTEM` in a non-interactive session on some
hardened configurations, or `keyring` wasn't installed.

**Effect:** The agent falls back to a DPAPI-encrypted file (priority 2), then to
an ACL-restricted plain file (priority 3). All three are functionally equivalent
for security purposes — only the storage mechanism differs.

**No action required** unless you specifically need Credential Manager storage.

---

## 7. Log Analysis Reference

### 7.1 Normal Startup Sequence

```
INFO  agent.windows          Windows agent starting  agent_id=win-XXXX  name=WORKSTATION-01
DEBUG agent.auto_enroll      client.key found — skipping enrollment ...
INFO  agent.windows          Enrollment OK  agent_name='WORKSTATION-01' agent_number=...
INFO  agent.windows          Agent running: 22 collector threads + sender + heartbeat (disabled=1)
INFO  agent.windows.tls_transport   (first POST to /api/v1/ingest succeeds)
```

If you see a gap between "agent starting" and "Enrollment OK" longer than 30 seconds,
the manager is slow or temporarily unreachable.

---

### 7.2 Warning-Level Messages (Expected in Normal Operation)

| Message | Meaning | Action |
|---------|---------|--------|
| `TLS certificate verification disabled` | `tls_verify=false` in config | OK for dev; use `true` in production |
| `icacls could not restrict key file ACL` | Non-SYSTEM service account | Check service account permissions |
| `outbox disk free space is ... below minimum` | Disk-pressure safety threshold | Restore capacity; existing telemetry is retained |
| `Key stored in ACL-restricted file (DPAPI unavailable)` | pywin32 not installed | Reinstall agent bundle; contains pywin32 |

---

### 7.3 Error-Level Messages (Action Required)

| Message | Root Cause | Fix |
|---------|-----------|-----|
| `Config not found: C:\ProgramData\...` | agent.toml missing | Re-run MSI or gen_config.ps1 |
| `Manager rejected enrollment (attempt N): HTTP 401` | Wrong token | Fix [enrollment] token in agent.toml |
| `Enrollment failed after 5 attempts` | Manager unreachable | Check network + manager status |
| `circuit OPEN: section=X after 3 consecutive failures` | Collector broken | Check §5 for section-specific help |
| `authentication_failed` | Key expired/revoked | Confirm manager state; allow configured rotation or run controlled re-enrollment |
| `SPKI pin mismatch — possible MITM attack` | Cert rotated or MITM | Update spki_pin or investigate |
| `critical runtime thread exited unexpectedly` | Sender/health runtime failure | SCM/watchdog restarts the service; inspect preceding log lines |

---

### 7.4 Circuit Breaker Messages

```
WARNING  circuit OPEN: section=eventlog after 3 consecutive failures
```
The `eventlog` collector failed 3 times in a row. The breaker will wait 60 seconds
before trying again. Look for the `collect[eventlog] ...` lines just before this
to see the actual error.

```
INFO  circuit OPEN → HALF probe allowed: section=eventlog
INFO  circuit CLOSED: section=eventlog recovered
```
The collector recovered. No action needed.

---

## 8. Recovery Procedures

### 8.1 Full Agent Reset (Re-enrollment from Scratch)

```powershell
# 1. Stop services
Stop-Service AttackLensAgent, AttackLensWatchdog

# 2. Clear enrollment state
Remove-Item "C:\ProgramData\AttackLens\security\*" -Force -ErrorAction SilentlyContinue

# 3. Clear spool (optional — keeps buffered data if you want to drain it later)
# Remove-Item "C:\ProgramData\AttackLens\spool\*" -Force

# 4. Clear logs (optional)
# Remove-Item "C:\ProgramData\AttackLens\logs\*" -Force

# 5. Restart
Start-Service AttackLensWatchdog
Start-Service AttackLensAgent

# 6. Watch enrollment
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 30 -Wait
```

---

### 8.2 Recovering a Corrupt Outbox

SQLite integrity is checked on startup. A failed check is fail-closed so rows
are not silently overwritten. Preserve the database and its WAL files for
recovery:

```powershell
Stop-Service AttackLensAgent

$support = Join-Path $env:TEMP ("attacklens-outbox-" + (Get-Date -Format yyyyMMdd-HHmmss))
New-Item -ItemType Directory -Path $support | Out-Null
Copy-Item "C:\ProgramData\AttackLens\spool\delivery-outbox.sqlite3*" $support
Copy-Item "C:\ProgramData\AttackLens\security\*.delivery-outbox.key" $support
Get-Content "C:\ProgramData\AttackLens\logs\agent.log" -Tail 500 |
    Set-Content (Join-Path $support "agent-tail.log")
```

The key contains protected security material; keep the support directory
restricted. Restore from a known-good backup or use a reviewed SQLite recovery
procedure. Deleting the files abandons buffered telemetry.

---

### 8.3 Repairing Service Registration

If the service entries are broken (e.g., after a failed upgrade):

```powershell
# Remove both services cleanly
Stop-Service AttackLensAgent, AttackLensWatchdog -ErrorAction SilentlyContinue
sc.exe delete AttackLensAgent
sc.exe delete AttackLensWatchdog

# Reinstall via MSI (preferred)
msiexec /i "attacklens-agent-2.0.7-x64.msi" /qn `
    MANAGER_IP="<ip>" MANAGER_PORT="<port>" ENROLL_TOKEN="<token>"

# Or register manually if MSI is unavailable
$bin = "C:\Program Files\AttackLens\bin"
& "$bin\attacklens-watchdog\attacklens-watchdog.exe" install
& "$bin\attacklens-agent\attacklens-agent.exe" install
Start-Service AttackLensWatchdog
Start-Service AttackLensAgent
```

---

### 8.4 Checking Watchdog Rate Limiting

The watchdog restarts the agent up to 5 times per 5-minute window. If the agent
keeps crashing, the watchdog logs an event and stops restarting:

```powershell
# Check Windows Application event log for watchdog messages
Get-EventLog -LogName Application -Source "AttackLensWatchdog" -Newest 10 |
    Select -ExpandProperty Message

# Check watchdog is running
Get-Service AttackLensWatchdog
```

If the watchdog hit the rate limit, fix the underlying agent error first, then:
```powershell
Restart-Service AttackLensWatchdog
Restart-Service AttackLensAgent
```

---

## 9. Common Error Messages Index

| Error Fragment | Section | Summary |
|----------------|---------|---------|
| `Service did not respond to start` | §1.1 | Startup timeout — run in debug mode |
| `Access is denied` (Event 7000) | §1.2 | Binary permissions — fix with icacls |
| `Config not found` | §1.3 | agent.toml missing — re-run gen_config.ps1 |
| `Cannot parse agent.toml` | §1.4 | TOML syntax error — backslashes |
| `required module is missing` | §1.5 | Corrupt PyInstaller bundle — reinstall MSI |
| `SSLCertVerificationError` | §2.2 | Self-signed cert — set tls_verify=false |
| `SPKI pin mismatch` | §2.2 | Cert rotated — update spki_pin |
| `HTTP 401` (enrollment) | §2.3 | Wrong enrollment token |
| `HTTP 409` (enrollment) | §2.4 | Agent ID already on manager — rotate key |
| `HTTP 401` (ingest) | §6.1 | Timestamp retry or controlled credential rotation; queued data is retained |
| `circuit OPEN` | §7.4 | Collector failed 3× — check section-specific §5 |
| `disk_pressure` | §4.3 | Outbox safety threshold reached — restore disk capacity |
| `DPAPI load failed` | §6.2 | Key file corrupt — force re-enrollment |
| `critical runtime thread exited` | §3.1 | SCM/watchdog restart — check preceding log lines |

---

## 10. Getting Support

Collect the following before opening a ticket:

```powershell
# Diagnostic bundle
$out = "$env:TEMP\attacklens-diag-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory $out | Out-Null

# Log file
Copy-Item "C:\ProgramData\AttackLens\logs\agent.log" $out -ErrorAction SilentlyContinue

# Config (REMOVE sensitive values like tokens before sharing)
Copy-Item "C:\ProgramData\AttackLens\config\agent.toml" $out -ErrorAction SilentlyContinue

# Service state
Get-Service AttackLensAgent, AttackLensWatchdog |
    Select Name, Status, StartType | Export-Csv "$out\services.csv"

# Windows version
[System.Environment]::OSVersion | Select * | Export-Csv "$out\os_version.csv"

# Event log (Service Control Manager + Application)
Get-EventLog -LogName System   -Source "Service Control Manager" -Newest 50 |
    Export-Csv "$out\eventlog_system.csv"
Get-EventLog -LogName Application -Source "AttackLens*" -Newest 50 -ErrorAction SilentlyContinue |
    Export-Csv "$out\eventlog_app.csv"

# Collect-once output
$env:MACINTEL_CONFIG = "C:\ProgramData\AttackLens\config\agent.toml"
python -m agent.os.windows.win_agent --config $env:MACINTEL_CONFIG --collect-once 2>&1 |
    Out-File "$out\collect_once.json" -ErrorAction SilentlyContinue

Write-Host "Diagnostic files saved to: $out"
Compress-Archive -Path $out -DestinationPath "$out.zip"
Write-Host "Zip: $out.zip"
```

Share the resulting `.zip` file (after redacting any tokens or IP addresses from the config copy).

## Installed but no files or no manager data

Do not look for mutable state under Program Files. Run:

```powershell
& 'C:\Program Files\AttackLens\tools\attacklens-status.ps1' -WaitForUpdate
Get-NetTCPConnection -OwningProcess (Get-Process attacklens-agent).Id
```

`Access Denied` for `config\agent.toml`, `security`, `spool`, detailed state,
or logs in a non-administrator terminal is the intended ACL, not evidence that
files are absent. If status shows a stale/loopback endpoint, use elevated
`configure-manager.ps1`. If host-level health/TCP checks also time out, restore
the manager listener, firewall, DNS, route, or proxy; the agent retains its
encrypted outbox and drains it automatically after recovery.

If an upgrade log shows Error 1730 under `RemoveExistingProducts`, the shell is
not elevated. Right-click PowerShell, select **Run as administrator**, then run
`advanced_support\install-or-repair.ps1`. Do not uninstall manually or purge
ProgramData; the elevated major upgrade preserves and migrates it.

## `agent.toml.invalid-*` appears after editing

This means the file **was writable and was saved**. Startup validation rejected
the edited TOML, copied it to `agent.toml.invalid-<timestamp>`, and restored
`agent.toml.last-known-good`. Version 2.0.11 writes the exact validation reason
and quarantine path to `agent.log` as an `Automatic startup recovery` warning.
Common causes are a bare IP in runtime `url`, missing quotes, unescaped Windows
backslashes, a non-boolean value, duplicate TOML keys, or HTTP while
`allow_insecure_transport=false`.

Use Administrator PowerShell instead of repeatedly editing the live file:

```powershell
& 'C:\Program Files\AttackLens\tools\edit-agent-config.ps1'
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' `
  -ManagerUrl 'MANAGER-IP-OR-DNS'
```

If installation still generates an empty manager, inspect the non-secret
capture summary and verbose MSI sequence:

```powershell
Get-Content 'C:\ProgramData\AttackLens\logs\installer-config.log' -Tail 30
Select-String -Path "$env:TEMP\attacklens-2.0.13-install.log" `
  -Pattern 'CA_StageWriteConfigUI|CA_PrepareWriteConfig|CA_WriteConfig'
```

## `configure-manager.ps1` reports `config: Access is denied`

This is the signature of a pre-2.0.13 installed tool calling the MSI-only
configuration generator. That generator hardens directory/file ACLs and must
run as deferred LocalSystem. An elevated Administrator commonly has Modify on
`agent.toml`, but Modify does not grant ownership/DACL-management rights.
Stopping the services therefore does not fix this particular error.

Upgrade to 2.0.13, then run from an Administrator PowerShell:

```powershell
& 'C:\Program Files\AttackLens\tools\configure-manager.ps1' `
  -ManagerUrl '72.61.228.62'

Select-String `
  -Path 'C:\ProgramData\AttackLens\config\agent.toml' `
  -Pattern '^\s*(url|tls_verify|allow_insecure_transport)\s*='
```

Expected values are `http://72.61.228.62:8080`, `false`, and `true`. The 2.0.13
tool validates both staged and live TOML, preserves the existing file security
descriptor, performs a durable write, restarts both services, and restores its
backup on validation/restart failure. If the command output does not include
`"acl_strategy": "existing file object preserved; no DACL rewrite requested"`,
the endpoint still has an older packaged script.

For MSI-side diagnosis, retain a verbose install log and the non-secret capture
log:

```powershell
msiexec /i "attacklens-agent-2.0.13-x64.msi" /l*v "$env:TEMP\attacklens-2.0.13-install.log"
Get-Content 'C:\ProgramData\AttackLens\logs\installer-config.log' -Tail 30
```
