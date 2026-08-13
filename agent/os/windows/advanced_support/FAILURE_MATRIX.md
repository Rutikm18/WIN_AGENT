# Startup and Recovery Failure Matrix

> Updated implementation status: [../CURRENT_IMPLEMENTATION.md](../CURRENT_IMPLEMENTATION.md). Runtime self-defense now adds install-integrity failure, config change/unreadable state, protected ACL drift, and Defender path exclusion evidence.

| Case | Typical evidence | Automatic behavior | Operator action |
|---|---|---|---|
| MSI configuration rollback | 1603/1722, `CA_WriteConfig`, Event 1001 with `icacls exit 6` | Corrected installer takes ownership only after normal ACL repair fails, bootstraps SYSTEM, reapplies final ACL, and preserves config | Run support `-Mode Repair`, then install 2.0.9+ with verbose logging |
| GUI manager remains localhost | GUI value was entered, but `agent.toml` retains localhost after install | 2.0.8 deferred EXE expected a non-guaranteed environment variable, so no explicit override reached the generator | Install 2.0.9+; its Binary-table bridge passes hidden `CustomActionData` explicitly |
| GUI manager becomes blank after 2.0.10 install | Service runs but logs `Manager URL is not configured` | 2.0.11 captures final dialog values before the UI-to-elevated-server transition in a Secure+Hidden staging property | Upgrade with 2.0.11 from Administrator PowerShell and retain the verbose MSI log |
| GUI manager remains blank in 2.0.11 | Decompiled MSI places staging before `ResumeDlg` | 2.0.12 forces and verifies `ProgressDlg -> staging -> ExecuteAction` | Upgrade to 2.0.12 or run installed `configure-manager.ps1` immediately |
| Installed `configure-manager.ps1` reports `config: Access is denied` | Administrator has Modify but packaged tool invokes installer ACL hardening | 2.0.13 uses staged/live validation and an exclusive durable write through the existing file object without requesting a DACL rewrite | Upgrade to 2.0.13; run the installed tool from Administrator PowerShell |
| Workspace script works but MSI script behaves differently | Compiled CAB contains an older script even though the source tree is fixed | 2.0.13 release gate extracts the completed MSI and SHA-256 compares critical payloads byte-for-byte | Reject the package and rebuild; do not copy scripts manually into Program Files |
| Edited TOML immediately reverts | New `agent.toml.invalid-*` plus unchanged active/last-known-good file | Invalid edit is quarantined and last-known-good restored; 2.0.11 logs the exact validation reason | Use elevated `edit-agent-config.ps1`, or `configure-manager.ps1 -ManagerUrl <IP-or-DNS>` |
| Major upgrade launched without elevation | 1603 with Error 1730 during `RemoveExistingProducts` | Roll back and leave 2.0.7 services/state intact | Run `install-or-repair.ps1` from Administrator PowerShell or approve UAC; silent MSI cannot prompt |
| Unsupported SCM status arguments | 1053/1067, `TypeError`, `checkPoint` | New binary uses supported call and journals checkpoints | Reinstall if an old binary remains |
| Missing or malformed config | `config_invalid`, TOML location | Restore validated `.last-known-good` when present; otherwise fail closed | Correct config, then run `-Mode Repair` |
| Config/data ACL denied | Win32 5, `ACL initialization failed` | Service writes diagnosis; no policy weakening | Elevated repair reapplies SID-based ACLs |
| Missing binary or DLL | Win32 2, import/DLL error | Classified fatal; watchdog avoids restart storm | Repair/reinstall; check endpoint protection quarantine |
| Legacy network dependency | Win32 1068 | None inside the blocked service | Elevated repair clears dependencies |
| Duplicate instance | mutex/another instance | Agent fails closed; SCM recovery remains active | Stop console/debug duplicate; use SCM instance |
| Agent/watchdog install race | 1056/already running | Treated as benign; startup grace prevents race | None after update |
| SCM start/stop pending too long | state pending over 120 seconds | Journal timeout without unsafe process termination | Bundle evidence; reboot if servicing is pending |
| Agent paused | `SERVICE_PAUSED` | Watchdog requests resume | Diagnose policy/tool that paused it |
| Worker thread dies | sender/health/watchdog worker exited | Parent service fails so SCM recovery can restart it | Inspect journal and outbox health |
| Missing heartbeat during initial start | no runtime JSON | 180-second heartbeat grace | None unless it remains missing |
| Corrupt heartbeat JSON | JSON parse error | Quarantined; agent recreates atomically | Inspect disk/filesystem health if repeated |
| Stale heartbeat | age over 180 seconds twice | Controlled stop/start with restart circuit breaker | Inspect CPU/disk stalls and agent log |
| Restart storm | five attempts in five minutes | Circuit opens for 120 seconds; exponential retry delay | Repair root cause instead of repeatedly starting |
| Corrupt/locked outbox | SQLite quick-check/error | Preserved; startup fails closed where durability is unsafe | Collect bundle; restore DB from supported process |
| Low disk space | disk pressure/min-free error | Collection/delivery protects durable evidence | Free space; never delete outbox blindly |
| Manager offline/DNS failure | DNS/TCP failed | Agent stays running and spools encrypted data | Repair network; no service restart required |
| Upgrade keeps old/localhost manager | Running service connects to `127.0.0.1:8443` or previous host | Explicit MSI/repair manager overrides only connection fields | Run installed `configure-manager.ps1` elevated |
| Credential belongs to previous manager | 401/403 after manager change | Archive old credential and re-enroll; preserve config/outbox | Supply enrollment token if manager requires one |
| Runtime files appear missing | Files absent under Program Files or Access Denied under ProgramData | Show `RUNTIME_LOCATION.txt` and sanitized public status | Run installed `attacklens-status.ps1` |
| Manager host itself unreachable | Host-level TCP/HTTP timeout | Keep services running, retain encrypted outbox, expose backoff | Restore manager/listener/firewall/routing, then allow automatic drain |
| TLS/CA/SPKI failure | certificate/pin error | Fail closed for delivery and retain data | Correct trust/pin; never auto-disable TLS |
| Invalid/revoked enrollment | 401/409 | Background re-enrollment only when explicitly configured | Supply valid token or repair manager enrollment |
| NETWORK SERVICE deployment | access denied on paths | Explicit SID rights are included | Re-run ACL repair after account change |
| Pending Windows reboot | servicing/reboot flag | Diagnosed, not forcibly rebooted | Schedule an approved reboot |

The watchdog's persistent runtime file records agent state, restart failures, recent restart count, and remaining cooldown so monitoring can distinguish “down” from “recovery intentionally paused.”
