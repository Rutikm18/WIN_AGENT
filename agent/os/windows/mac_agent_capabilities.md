# macOS Agent — Capabilities Manifest

**Module:** `agent/os/macos/` &nbsp;·&nbsp; **Target:** macOS 12+ (Apple Silicon / ARM64, x86_64 compatible)
**Status legend:** ✅ implemented & active · 🟡 implemented but not wired/active · 🔴 gap / to build
**Last updated:** 2026-07-23

> This remains the macOS reference. Windows parity/current implementation evidence is maintained separately in [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md).

> **Why this file exists.** Each OS needs a *different* agent — macOS uses `launchd`,
> Windows uses the SCM (`service.py`), Linux uses `systemd`. The collectors, persistence
> mechanism, and posture sources are OS-specific. This manifest is the single source of
> truth for **what the macOS agent must do**, **how it does it**, and **what is still
> missing**. Windows and Linux carry their own `CAPABILITIES.md` with the same structure.
> Scope of this document and all work it drives is strictly `agent/os/macos/`.


---

## 0. Capability matrix (at a glance)

| # | Capability | Status | Owner module |
|---|---|---|---|
| 1 | **Auto-launch on boot / restart** (survives reboot) | ✅ active — pkg bootstraps at install; `RunAtLoad`+`KeepAlive`; self-repairs a deleted/disabled/tampered plist | `launchd.py`, `boot_persistence.py` |
| 2 | **Always-on background operation** (binaries run behind, headless) | ✅ active — system LaunchDaemon, `Background`/`LowPriorityIO` | `launchd.py` |
| 3 | **Crash recovery / self-healing** (restart on death) | ✅ launchd `KeepAlive` + periodic `self_heal` (daemon-loaded + boot-persistence + delivery probe) | `launchd.py`, `self_heal.py`, `boot_persistence.py` |
| 4 | **Continuous data transfer** (never silently drop telemetry) | ✅ active & verified (zero-loss replay); disk-full-safe spool | `agent/sender.py` |
| 5 | **Connection checking** (probe before send, drain on reconnect) | ✅ active + surfaced in `agent_health` → dashboard; wake-from-sleep reprobe | `agent/sender.py`, `manager/api/assets.py` |
| 6 | **CIS benchmark data collection** | ✅ active — 23 checks, pipeline fixed + expanded | `os/macos/collectors/posture.py` (dispatched) |
| 7 | **Health heartbeat** (agent reports its own state) | ✅ active | `agent/core.py` |
| 8 | **Secure enrollment + payload encryption** | ✅ active — boot-safe file keystore (root daemon can't read login keychain at boot) | `agent/enrollment.py`, `crypto.py`, `keystore.py` |
| 9 | **Dynamic signed config** (signature-verified manager policies, fail-closed) | ✅ active — `ConfigEngine` + signed-policy verify/cache/reload; heartbeat carries `policy_versions` | `agent/policy.py`, `agent/config_engine.py`, `agent/core.py` |
| 10 | **Reboot / boot-transition telemetry** (detect unexpected reboots) | ✅ active — `system_boot` event with downtime + clean/unexpected verdict | `boot_persistence.py`, `agent/core.py` |
| 11 | **Single-instance guard** (no duplicate agents racing on the spool) | ✅ active — advisory `flock`, duplicate exits cleanly | `agent/single_instance.py` |
| 12 | **Edge-case resilience** (config / disk-full / clock-skew) | ✅ active — `ConfigError` fail-fast, non-raising spool, backward-clock re-seed | `agent/core.py`, `agent/sender.py` |

---

## 0a. Telemetry collection coverage (what the agent observes)

The agent ships **23 collection sections** plus the synthetic **Agent Health** heartbeat. Each
section is an independent collector in the macOS registry (`collectors/__init__.py`), scheduled
on its own cadence by the `Orchestrator`, guarded by a per-section circuit breaker + wall-clock
budget (§3, §4), normalised to a canonical schema (`normalizer.py`), then encrypted and shipped.
Intervals below are the fresh-install defaults (`installer/generate_config.sh`) and are
**config-tunable** and **policy-controllable** at runtime (§9).

| Section | Supplies | Producer (`collectors/…`) | Default cadence |
|---|---|---|---|
| **Agent Health** | agent's own state: circuit-breaker snapshot (CLOSED/OPEN/HALF-OPEN), queue depth, uptime, manager link state, `policy_versions`, `response_enabled` | `agent/core.py` `_emit_health` (synthetic) | 60 s |
| **Metrics** | CPU %, RAM, swap, disk I/O, network I/O, load average | `volatile.py` `MetricsCollector` | 10 s |
| **Connections** | established TCP/UDP connections with owning process + private/public flag | `volatile.py` `ConnectionsCollector` | 10 s |
| **Processes** | running processes (top by CPU) with code-signing / trust status | `volatile.py` `ProcessesCollector` | 10 s |
| **Ports** | listening ports with owning process | `network.py` `PortsCollector` | 30 s |
| **Network** | interfaces, IP addresses, routes, DNS config | `network.py` `NetworkCollector` | 120 s |
| **ARP** | ARP / neighbor table (L2 ↔ L3 mappings) | `network.py` `ArpCollector` | 120 s |
| **Mounts** | mounted filesystems + mount options | `network.py` `MountsCollector` | 120 s |
| **Battery** | power source, battery charge / health state | `system.py` `BatteryCollector` | 120 s |
| **Open Files** | open file handles / descriptors by process | `system.py` `OpenFilesCollector` | 120 s |
| **Services** | `launchd` services & daemons (LaunchDaemons/Agents) | `system.py` `ServicesCollector` | 120 s |
| **Users** | local accounts, group/admin membership, login/session state | `system.py` `UsersCollector` | 120 s |
| **Hardware** | model, CPU, memory, serial, hardware UUID | `system.py` `HardwareCollector` | 120 s |
| **Containers** | Docker / container runtime presence + running containers | `system.py` `ContainersCollector` | 120 s |
| **Storage** | physical disks, APFS volumes, capacity, FileVault state | `inventory.py` `StorageCollector` | 600 s |
| **Tasks** | scheduled tasks: cron, `launchd` periodic, `at` jobs | `inventory.py` `TasksCollector` | 600 s |
| **Security** | SIP, Gatekeeper, FileVault, Firewall, XProtect, remote login/sharing, screensaver lock … (drives 23 CIS checks — §6) | `posture.py` `SecurityCollector` | 3600 s |
| **Sysctl** | security-relevant kernel params (`kern.*`, `net.inet.*`, `security.*`) | `posture.py` `SysctlCollector` | 3600 s |
| **Configs** | shell rc, `~/.ssh/config`, `authorized_keys`, `/etc/hosts`, `sshd_config`, `sudoers` (4 KiB cap) | `posture.py` `ConfigsCollector` | 3600 s |
| **SBOM** | software bill of materials — components / dependencies for supply-chain risk | `inventory.py` `SbomCollector` | 3600 s |
| **Apps** | installed applications inventory | `inventory.py` `AppsCollector` | 3600 s |
| **Packages** | package-manager inventory (brew / pip / gem / npm / cargo …) | `inventory.py` `PackagesCollector` | 3600 s |
| **Binaries** | Mach-O binary inventory with signing / trust verdict | `inventory.py` `BinariesCollector` | 3600 s |
| **SCA** | CIS macOS Benchmark compliance scan (dedicated) | `sca.py` `ScaCollector` | 12 h *(in-code default only — see note)* |

> Resilience per section: a hung/erroring collector is converted to a circuit-breaker failure
> (skipped + probed on cooldown) and **never** overwrites the last good snapshot with an error
> blob; a slow collector degrades to *partial* data within its wall-clock budget rather than
> timing the whole section out (§3, `collectors/base.py`). Missing privileged fields score
> **unknown**, never a false FAIL (§6).

> ⚠️ **Config divergence (flag for reconciliation).** The two schedule sources disagree, so the
> effective cadence depends on which config a host runs:
> - the in-code fallback `agent/agent/core.py::_DEFAULT_SECTIONS` (used only when the config has
>   no `[collection.sections]`) — includes **sca @ 12 h**, runs metrics/connections/processes at
>   **60 s**, apps/packages/sbom at **24 h**, and has **binaries disabled**;
> - the fresh-install `installer/generate_config.sh` (what a pkg install actually runs) — **omits
>   `sca`**, runs metrics/connections/processes at **10 s**, and apps/packages/binaries/sbom at
>   **1 h** with binaries **enabled**.
>
> Net: a default pkg install currently does **not** schedule the SCA compliance scan (the CIS
> data still comes from the `security`/`sysctl`/`configs` sections — §6). Reconciling the two so
> they agree (and adding `sca` to the generated config) is an open item.

---

## 1. Auto-launch on boot / restart  ✅

**Requirement:** when the machine reboots, the agent must come back up on its own — no
human login, no manual start.

**Mechanism — two `launchd` daemons** (`launchd.py`):

```
launchd  (OS init, PID 1)
  └── com.attacklens.watchdog   KeepAlive=true, RunAtLoad=true   ← launchd restarts if it dies
        └── com.attacklens.agent   KeepAlive=true, RunAtLoad=true ← watchdog/launchd restart if it dies
```

- Plists live in `/Library/LaunchDaemons/` → **system** daemons, start at boot **before any user logs in**.
- `RunAtLoad=true` → start immediately when loaded / at boot.
- `KeepAlive=true` → `launchd` relaunches the process whenever it exits for any reason.
- `ThrottleInterval=10` → 10 s floor between relaunches (prevents crash-loop spin).
- Runs as `UserName=root` so collectors that need privilege (csrutil, fdesetup, sysctl) work.

**Activation:** the pkg postinstall bootstraps both daemons at install
(`pkg/build_pkg.sh` → `launchctl enable`/`bootstrap` with legacy `load -w` fallback) and
now **verifies the agent reached `running`**, dumping `agent-stderr.log` if it didn't — so
a crash-loop surfaces at install time, not after a reboot.

**Boot-persistence self-repair (`boot_persistence.py`, 2026-07-23).** `RunAtLoad` alone
does NOT survive a reboot if the plist is deleted or `launchctl disable`d (a tamper /
botched-uninstall / persistence-defeat vector — KeepAlive can't save a job that no longer
exists at boot). `ensure_boot_persistence()` runs at agent startup **and** on every
`self_heal` cycle to verify + repair:

- plist present and structurally correct (`RunAtLoad` + `KeepAlive` + right binary + label),
- owned `root:wheel`, mode `0644`,
- **enabled** in launchd (`is_enabled`/`enable` added to `launchd.py`, parses both
  `print-disabled` formats),
- loaded — re-bootstraps if not (throttled so the 5-min self_heal cadence can't thrash launchctl).

Repair requires root and is verify-only otherwise; it never raises into startup. Ops entry:
`python -m agent.os.macos.boot_persistence [--verify|--repair]`.

**Helpers available:** `install_plist()`, `uninstall_plist()`, `start()`, `stop()`,
`restart()`, `reload_config()` (SIGHUP), `is_enabled()`, `enable()`.

**Tests:** `agent/tests/unit/test_boot_persistence.py` (plist-drift analysis, launchctl
`print-disabled` parsing, enable/verify logic).

---

## 2. Always-on background operation  ✅

**Requirement:** the binaries run silently behind the system, with no UI, no Dock icon,
low resource footprint, surviving user logout.

**Mechanism (plist keys in `launchd.py`):**
- `ProcessType=Background` → scheduler treats it as non-interactive; deprioritised vs UI apps.
- `LowPriorityIO=true` → disk I/O yields to foreground work.
- System-domain LaunchDaemon (not a LaunchAgent) → **not tied to a GUI session**, runs with
  no user logged in.
- `StandardOutPath` / `StandardErrorPath` → `/Library/AttackLens/logs/{agent,watchdog}-std*.log`.
- `WorkingDirectory=/Library/AttackLens`.

**Background PATH fix already in place** (`collectors/base.py:_get_env`): LaunchDaemons start
with a minimal `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin`). The agent injects
`/usr/local/bin:/opt/homebrew/bin` so brew/docker/pip-based collectors still resolve.

**Status:** ✅ active — runs as a headless system LaunchDaemon (activates with #1).

---

## 3. Crash recovery / self-healing  ✅ (launchd) / 🟡 (watchdog layer)

**Requirement:** if the agent crashes, it restarts automatically; if it crash-loops, it backs
off instead of pinning the CPU.

**Primary mechanism — launchd `KeepAlive`:** the agent plist has `KeepAlive=true` +
`ThrottleInterval=10`, so `launchd` itself relaunches the agent on any exit, with a 10 s floor
to prevent crash-loop spin. This alone satisfies the requirement and activates with #1.

**Optional second layer — `agent/watchdog.py`** (standalone supervisor with rate-limited
restarts, `max_restarts`/`restart_window_sec` back-off). **Code fixed (2026-06-09):** the
watchdog now detects a `.py` agent target (the deployed `[binaries].agent =
/Library/AttackLens/bin/run_agent.py`) and launches it via a Python interpreter
(`[binaries].python`, defaulting to the framework `python3` running the watchdog) instead of
exec'ing a non-executable script — the historical FATAL-loop. Native PyInstaller binaries still
launch directly (strict `X_OK`). Verified by `agent/tests/unit/test_watchdog.py::TestInterpreterMode`.
The installed watchdog plist already runs `python3 run_watchdog.py --config …`, so enabling the
layer is now just a launchd switch in `activate.sh` (load `com.attacklens.watchdog` instead of
the bare agent). Left **opt-in** 🟡 because launchd `KeepAlive` already satisfies crash recovery;
the watchdog adds rate-limited back-off on top.

**Third layer — periodic `self_heal` (`self_heal.py`).** A one-shot LaunchDaemon
(`StartInterval` 300 s) that closes the gaps `KeepAlive` cannot see:
- `ensure_daemon_loaded()` re-bootstraps the agent if launchd dropped the job,
- `ensure_boot_persistence()` re-asserts the plist/enable/ownership so the NEXT reboot
  still auto-starts even after tampering (see §1),
- a manager **delivery probe** catches *silent non-delivery* (agent alive + launchd-happy
  but shipping zero telemetry: manager down, rogue server on the port, persistent 401) and
  escalates by cause — never a blind restart that would trigger a spool-replay storm.

> ⚠️ **Topology note (2026-07-23):** both `com.attacklens.agent` (runs the agent directly)
> and `com.attacklens.watchdog` (spawns the agent via `subprocess.Popen`) ship with
> `RunAtLoad`/`KeepAlive`, so two agent processes can run at once. The single-instance
> guard (§11) now prevents the resulting spool race, but the clean fix is to pick ONE
> supervision model (drop the direct agent daemon, or the watchdog). Tracked in `friction.md`.

---

## 4. Continuous data transfer  ✅

**Requirement:** telemetry flows to the manager continuously and is **never silently lost**,
even across manager outages, network drops, or reboots.

**Mechanism — `agent/sender.py` (`Sender` + `DiskSpool`):**
- Dedicated daemon thread drains an in-memory queue and POSTs encrypted envelopes to
  `…/api/v1/ingest`.
- **Disk spool** (`/Library/AttackLens/spool/unsent.ndjson`, append-only NDJSON):
  - On any send failure the envelope is written to disk, not dropped.
  - **Replayed on startup** (`Sender.start()` drains the spool from the previous run) → survives reboot.
  - **Auto-drained** back into the queue the moment the manager is reachable again.
  - 50 MB cap; on overflow drops the **oldest** 10 % (newest data preferred) and logs it.
  - **Disk-full safe (2026-07-23):** `DiskSpool.write` never raises — ENOSPC / read-only FS /
    non-serialisable envelope are counted as dropped (not silently lost) and an ENOSPC write
    trims the spool to free room. The sender send-path is fully try-wrapped so no surprise can
    kill the delivery thread. Tests: `agent/tests/unit/test_spool_disk_full.py`.
- **Exponential backoff + jitter** (`retry_delay` × 2ⁿ, capped 60 s) on transient errors.
- **HTTP status awareness:** `200` ok · `401` → spool + re-enroll after 3 strikes ·
  `429` honoured as transient · `503` (manager couldn't persist) → spool · other `4xx` → dropped
  as unrecoverable (a bad payload is not retried forever).
- **TLS 1.3 minimum** when manager URL is `https://`; plain `http://` supported for local dev
  (warns).

> Historical bug (fixed): payloads used to be dropped on a 503 instead of spooled — that was
> the "silent data-loss" defect. The 503-spools-and-retries path above is the fix.

**Status:** active and **verified**. Zero-loss replay is proven by an automated offline→online
cycle over a real loopback socket — `agent/tests/integration/test_offline_online_replay.py`
(200 envelopes emitted while offline → all delivered after reconnect, in order, no duplicates,
spool drained to zero; plus a restart-replays-prior-spool case). The `DiskSpool` integrity
primitive is pinned by `agent/tests/unit/test_spool.py`. No change required for the base
capability; see §10 for hardening.

---

## 5. Connection checking  ✅

**Requirement:** know whether the manager is reachable; don't waste the retry budget when it
obviously isn't; resume the instant it returns.

**Mechanism (`agent/sender.py`):**
- `_probe()` → lightweight `GET /health` with a 5 s timeout (endpoint confirmed at
  `manager/server.py:360`).
- While offline, the loop **skips the full 3× retry cycle** and spools directly, re-probing
  every 30 s.
- On a successful probe the spool is drained and normal sending resumes; `"Manager connection
  restored"` is logged on the first 200 after an outage.
- **Wake-from-sleep resume (2026-07-23):** the drain loop measures `time.monotonic()` between
  its ~1 s iterations; a jump past `_WAKE_GAP_SEC` (30 s) means the Mac slept/hibernated, so
  cached sockets are dead — it forces an immediate reprobe + spool drain rather than waiting
  out the offline backoff (up to 30 s).

**Dashboard surfacing (2026-06-08):** `Sender.link_state()` snapshots manager connectivity
(`manager_online`, `spool_bytes`, `auth_failures`, `last_contact_ts`, `seconds_since_contact`)
and is embedded in the `agent_health` heartbeat (`Orchestrator._emit_health` → `link`). The
manager's assets API (`manager/api/assets.py`, list + detail) condenses it via `_link_summary`
into a per-agent `link.status` of **healthy / degraded / auth_failed**. The dashboard renders
it as a `LinkBadge` in the asset detail header (`AssetRegistry.tsx`), with a tooltip showing
seconds-since-contact, offline spool size, and auth-failure count; rebuilt into
`dashboard/static/` via `make build-dashboard`.
Tests: `agent/tests/unit/test_link_state.py`, `manager/tests/unit/test_link_status_api.py`.

**Status:** active — link state probed, heartbeated, and exposed to the dashboard.

---

## 6. CIS benchmark data collection  ✅

**Requirement:** collect every field the manager needs to score the **CIS macOS Benchmark**.

> **Pipeline fix (2026-06-08):** the live `COLLECTORS` registry now
> platform-dispatches the posture collectors (`security`/`sysctl`/`configs`) to
> the macOS-specific `agent/os/macos/collectors/posture.py` on darwin (see
> `agent/agent/collectors/__init__.py`). Previously the registry always used the
> generic `agent/agent/collectors/posture.py`, which emitted **raw CLI strings**
> (`sip="System Integrity Protection status: enabled."`) that never matched the
> canonical values the scorer compares against — so SIP/FileVault/Gatekeeper/
> Firewall reported FAIL and the rest "unknown" on every Mac. `_norm_security`
> was also corrected to forward the full field set and the `xprotect_version` /
> `dev_tools` keys. Net: a hardened Mac now scores correctly (verified end-to-end).

**Producers (macOS-specific, `collectors/posture.py`, 1 hr cadence):**

| Collector | Section | Supplies |
|---|---|---|
| `SecurityCollector` | `security` | SIP, Gatekeeper, FileVault, Firewall, XProtect, Secure Boot, auto-update, dev-tools, Lockdown Mode, SSH (remote login / password auth / root login), Screen Sharing (VNC), Remote Management (ARD), screensaver lock + idle timeout |
| `ConfigsCollector` | `configs` | shell rc, `~/.ssh/config`, `authorized_keys`, `/etc/hosts`, `sshd_config`, `sudoers` (4 KiB cap each) + download-cradle "suspicious" flag |
| `SysctlCollector` | `sysctl` | security-relevant kernel params (`kern.*`, `net.inet.*`, `security.*`) |

**Consumer:** `manager/api/posture.py` maps these fields → **23 CIS checks** across CIS
Controls **3, 4, 5, 7, 8, 10, 12**. Every check below already has a producing field:

| CIS check | Source field (`security` unless noted) |
|---|---|
| SIP / System Integrity Protection | `sip` |
| FileVault FDE | `filevault` |
| Gatekeeper | `gatekeeper` |
| Application Firewall | `firewall` |
| Secure Boot — Full Security | `secure_boot` |
| Automatic Security Updates | `auto_update` |
| Screensaver requires password | `screensaver_lock` |
| Screensaver idle ≤ 5 min | `screensaver_idle_sec` |
| SSH password auth disabled | `remote_login` + `ssh_password_auth` |
| SSH root login prohibited | `ssh_permit_root_login` |
| Screen Sharing (VNC) off | `screen_sharing` |
| Apple Remote Desktop off | `remote_management` |
| XProtect definitions present | `xprotect_version` |
| No suspicious shell configs | `configs[].suspicious` |
| Developer Tools security | `dev_tools` |
| Lockdown Mode | `lockdown_mode` |

**CIS expansion (✅ implemented 2026-06-08 — 7 new checks):**

| New check (id) | Source field(s) | CIS Control |
|---|---|---|
| Audit Subsystem Enabled (`AUD`) | `audit_enabled` + `audit_flags` (auditd / `/etc/security/audit_control`) | 8 Audit Log Management |
| Password Policy ≥8 (`PWP`) | `pw_policy_configured` + `pw_min_length` (`pwpolicy -getaccountpolicies`) | 5 Account Management |
| Guest Account Disabled (`GST`) | `guest_account` (`com.apple.loginwindow GuestEnabled`) | 5 |
| Automatic Login Disabled (`ALI`) | `auto_login_user` (`com.apple.loginwindow autoLoginUser`) | 5 |
| Automatic Update Install (`AUI`) | `auto_update_install` + `critical_update_install` | 7 Vulnerability Management |
| Network Time Sync (`NTP`) | `network_time` + `time_server` (`systemsetup -getusingnetworktime`) | 8 |
| File / Printer Sharing Off (`SHR`) | `file_sharing` + `printer_sharing` (smbd / `cupsctl`) | 4 Secure Configuration |

A missing field (root-only tools when not yet collected) scores **unknown**, never a
false FAIL — unknowns are excluded from the score denominator.

**Tests:** `manager/tests/unit/test_posture_cis.py` (scorer: regression that canonical
fields PASS + the 7 new checks) and `agent/tests/unit/test_posture_collector_cis.py`
(collector parsing + normalizer passthrough/key-fix).

**Remaining gaps (🔴 — future):** per-user screensaver policy via MDM, Bluetooth sharing,
EFI integrity, and password *age/lockout* (only min-length is scored today).

---

## 7. Health heartbeat  ✅

`agent/core.py` pushes a synthetic `agent_health` section every 60 s containing the
circuit-breaker snapshot (which collectors are CLOSED / OPEN / HALF-OPEN). This is how the
manager distinguishes "agent online but a collector is failing" from "agent gone".

---

## 8. Secure enrollment + payload encryption  ✅

- `agent/enrollment.py` — first-run enrollment against the manager, obtains agent identity.
- `agent/crypto.py` + `keystore.py` (macOS keystore at `os/macos/keystore.py`) — per-agent key
  (`security/agent-001.key`), envelopes encrypted before they ever hit the queue/spool.
- Re-enrollment is triggered automatically after 3 consecutive `401`s (stale key) — see §4.
- **Boot-safe key storage (2026-07-23).** A root LaunchDaemon starts at boot with **no user
  login session**, so the macOS *login* keychain is locked and `keyring` can't read the key
  back — a `keystore = "keychain"` config lost the key on every reboot and churned on
  enrollment. Fixes: fresh installs generate `keystore = "file"` (ACL-restricted
  `/Library/AttackLens/security/<id>.key`, `0600` root-only — the only storage a root daemon
  can read at boot); `store_key()` always **mirrors** the key to that file even for the
  `keychain` backend; and a keychain-loaded key is mirrored on startup so older keychain-only
  installs self-heal. Tests: `agent/tests/unit/test_keystore.py::TestKeychainBootSafeMirror`.
  See TROUBLESHOOT.md Issue 5c.

---

## 9. Dynamic signed config (ConfigEngine & signed-policy control plane)  ✅

**Requirement:** the manager must be able to *tighten or relax* agent behaviour
(security thresholds, active-response actions, telemetry cadence, compliance
baselines) at runtime — but the agent must only ever obey configuration it can
prove came from the manager, unmodified, current, and meant for it. Active
response, in particular, must **fail closed**: absent a perfect proof it stays off.

**Mechanism — one immutable `RuntimeConfig` from three layers** (`config_engine.py`):

```
baseline (agent.toml)  ◅  verified manager policies  ◅  tighten-only runtime overrides
```

- **Baseline** — the existing `agent.toml`, unchanged for non-policy config.
- **Verified policies** — fetched from `GET /api/v1/policies/<type>` for each of
  `security | response | telemetry | compliance`, signature-verified and merged
  over the matching baseline section (policy wins on key conflict).
- **Tighten-only overrides** — env `ATTACKLENS_*` may *disable* response or
  *shrink* `allowed_actions`; they can **never** enable response or add an action
  (explicit allow-list; anything else is logged and ignored).

`response_enabled` is `True` **iff** a `response` policy is present, signature-
valid, audience-valid, unexpired, and version-monotonic — and the wall clock is
sane. Every other state ⇒ `False`. It is **never** derived from baseline or env.

**Snapshots swap atomically** under a lock (`current()`); readers never see a
torn config. Startup `load()` is **cache-first and non-blocking** — the agent
runs from the last verified policies even with the manager offline, and
`refresh()` re-fetches on a monotonic cadence and on reconnect. Durations use
`time.monotonic()`; expiry uses the wall clock; a backward wall jump beyond
`MAX_SKEW_SEC` (300 s) forces `response_enabled=False` (`clock_skew`) until the
next good refresh.

### Signing contract (byte-exact — for the manager team)

The wire object from `GET /api/v1/policies/<type>`:

```json
{ "payload_b64": "<base64 of the exact signed bytes>",
  "signature_b64": "<base64>",
  "sig_alg": "ed25519" | "rsa-pss-sha256",
  "key_id": "<pinned key id>" }
```

`payload_b64` base64-decodes to UTF-8 JSON = the **signed payload**:

```json
{ "schema": 1, "type": "security|response|telemetry|compliance",
  "version": <int>, "issued_at": <int unix s>, "expires_at": <int unix s>,
  "audience": "<agent_id|group_id|fleet>", "content": { } }
```

- **The manager signs the exact bytes it base64-encodes into `payload_b64`.**
  The agent verifies the signature over the **raw decoded bytes** and parses the
  JSON **only after** verification succeeds — it never re-serialises the payload.
  There is no canonical-JSON negotiation: the transmitted bytes are the signed
  bytes. `sig_alg` selects the verify routine (ed25519 preferred, else RSA-PSS
  with MGF1-SHA256 and salt = digest length); `key_id` selects the pinned key.

### Verify order → reject code (`policy.py:load_verified`)

Checks run in this fixed order; each failure raises a `PolicyError` with a stable
`.reason`:

| Step | Check | Reject code |
|---|---|---|
| 1 | `payload_b64` / `signature_b64` decode | `corrupt` |
| 2 | `key_id` resolves to a pinned key | `key_unavailable` |
| 3 | signature verifies over raw bytes (**before any parse**) | `signature_invalid` |
| 4 | payload parses as JSON | `corrupt` |
| 5 | `schema == 1` | `schema_invalid` |
| 6 | `audience ∈ {agent_id, fleet} ∪ group_ids` | `audience_mismatch` |
| 7 | `issued_at ≤ now + MAX_SKEW_SEC` (not future-dated) | `corrupt` |
| 8 | `expires_at > now` | `expired` |
| 9 | `version > high_water[type]` (monotonic) | `downgrade` |
| 10 | per-type `content` schema | `schema_invalid` |

Because the signature covers the raw bytes, flipping **any** signed field
(version / issued_at / expires_at / audience / content) is caught at step 3 as
`signature_invalid` — the later codes fire only for *validly signed* policies
that are genuinely expired / mis-addressed / rolled back.

### Cache, high-water, reload

- Under `policies_dir` (`0o700`): `<type>.policy` (raw verified wire object),
  `<type>.prev` (previous good), `.versions.json` (monotonic high-water, `0o600`).
- High-water advances **only** on a fully successful accept, and **persists
  across restarts** — a replayed older version is rejected `downgrade` even after
  a reboot. Cache files are re-verified on load; a corrupt/tampered cache is
  treated as absent (no crash).
- `SIGHUP` / `reload_config()` triggers `ConfigEngine.refresh()`; the heartbeat
  (`agent/core.py:_emit_health`) carries `policy_versions` + `response_enabled`
  so the manager can confirm fleet-wide policy convergence.

### Rotation & revocation

- **Key rotation:** publish the new public key as `<new_key_id>.pub` under
  `keystore_dir` and start signing with it; policies carry the `key_id` they were
  signed under, so old and new keys can coexist during a rollover. Retire a key
  by deleting its `.pub` — any policy still referencing it then fails closed with
  `key_unavailable` (response off, alert), rather than being silently trusted.
- **Policy revocation:** there is no "unsign" — revoke by **superseding**. Issue a
  higher-`version` policy (monotonic high-water guarantees the old one can never
  be replayed) and/or let the bad policy **expire** (`expires_at`); keep TTLs
  short so a compromised-but-unexpired document self-heals. To kill active
  response fleet-wide immediately, push a `response` policy with
  `enabled=false` / empty `allowed_actions`, or expire it — the gate fails closed.
- **No secrets in policies:** `content` is config, not credentials; values flagged
  sensitive are redacted in logs and reject reasons log only the `.reason` code.

**Tests:** `agent/tests/unit/test_policy.py` (verify-then-parse, every reject
code, parser-never-runs-on-unverified-bytes) and
`agent/tests/unit/test_config_engine.py` (merge, fail-closed matrix, tighten-only
env, downgrade + high-water persistence across restart, offline→reconnect,
atomic hot-reload under concurrent readers, clock-skew). Hermetic via
`agent/tests/fixtures/signing.py` (throwaway keypair; real pinned key never used).

---

## 10. Reboot / boot-transition telemetry  ✅

**Requirement:** an EDR agent should record and report reboots — an unexpected reboot is a
security signal (attackers reboot to clear volatile state or apply persistence).

**Mechanism (`boot_persistence.py`, 2026-07-23):** a marker
(`/Library/AttackLens/boot_state.json`: kernel `boot_time`, `last_seen`, `clean_stop`) is
compared against the live kernel boot time on startup (psutil `boot_time()`, falling back to
`sysctl -n kern.boottime`). A change ⇒ the box rebooted since the agent last ran, so it emits
a `system_boot` telemetry event (`Orchestrator.emit_event()`) with:

- `downtime_sec` — new boot minus the last heartbeat,
- `clean_shutdown` — `True` only if the agent got a graceful `SIGTERM` (`mark_clean_stop()` in
  `core._shutdown`); a power loss / panic / `SIGKILL` leaves it `False` → reported **unexpected**.

A 60 s daemon thread (`touch_heartbeat()`) keeps `last_seen` fresh for an accurate downtime
estimate. Best-effort throughout — never raises into startup.
**Tests:** `agent/tests/unit/test_boot_persistence.py` (first-run / reboot / clean-vs-unexpected
state machine, downtime math).

---

## 11. Single-instance guard  ✅

**Requirement:** exactly one agent process delivers telemetry — two would race on the shared
`unsent.ndjson` spool (duplicate sends, and `DiskSpool.drain()`'s read-then-remove corrupts
across processes).

**Mechanism (`agent/single_instance.py`, 2026-07-23):** `core.main` acquires an exclusive
advisory lock (`fcntl.flock`) on `attacklens-agent.lock`. A 5 s wait covers the normal
old→new overlap during a launchd restart; a persistent duplicate logs and exits `0`. The
holder PID is written for diagnostics. POSIX-only (no-op elsewhere — Windows has service-level
single-instance). Motivated by the two-daemon topology in §3.
**Tests:** `agent/tests/unit/test_single_instance.py`.

---

## 12. Edge-case resilience (config / disk-full / clock-skew)  ✅

Hardening for the failure modes that silently take a long-running agent down (2026-07-23):

- **Config (`core.load_config`):** was a raw `tomllib.load` with no handling — a missing file /
  malformed TOML / missing `[manager].url` crashed the daemon into a launchd restart-loop. Now
  raises `ConfigError` with an operator-actionable message and `main` exits `78` (EX_CONFIG)
  once instead of looping; `--status` uses a raw parse so it still works on a broken config.
  Tests: `agent/tests/unit/test_config_robustness.py`.
- **Disk-full:** see §4 — non-raising spool write, trim-on-ENOSPC, guarded send loop.
- **Clock-skew:** the collector scheduler runs on `time.time()`, so a backward NTP correction
  after boot would stall all collection. `Orchestrator._maybe_reseed_on_skew` re-seeds the
  schedule on a backward jump > `_CLOCK_SKEW_BACKWARD_SEC` (60 s); forward jumps and jitter are
  ignored. Tests: `agent/tests/unit/test_clock_skew.py`.

---

## 13. Build / packaging anchors

- `pkg/build_pkg.sh` + `pkg/entitlements.plist` — signed ARM64 `.pkg` that installs to
  `/Library/AttackLens/`, drops both plists, and bootstraps the daemons. Postinstall now
  verifies the binary runs (`--help`), polls launchd for the agent PID, and dumps
  `agent-stderr.log` if it didn't reach `running` — install-time failure surfacing.
- `installer/install.sh` / `uninstall.sh` — script-based install path.
- `requirements.txt` — runtime deps (PyInstaller target).
- Repo `Makefile`: `make build-binaries` (agent + watchdog), `make build-pkg`.

---

## 14. Work queue (gaps → tasks)

Derived from the status flags above; all scoped to `agent/os/macos/`:

1. **[#1/#2/#3] Activate persistence.** ✅ loader modernised + `installer/activate.sh`
   added. **Run:** `sudo bash agent/os/macos/installer/activate.sh`, then confirm
   RunAtLoad/KeepAlive survive a real reboot (last verification step).
2. **[#3] Self-heal guard.** Optional: re-enable the watchdog layer (fix its exec target,
   see §3) or add a periodic re-bootstrap check.
3. **[#4] Continuous-transfer verification.** ✅ Done — automated offline→online cycle proves
   zero-loss spool replay (`agent/tests/integration/test_offline_online_replay.py`,
   `agent/tests/unit/test_spool.py`). Run: `python3 -m pytest agent/tests/unit/test_spool.py
   agent/tests/integration/test_offline_online_replay.py`.
4. **[#6] CIS coverage expansion.** ✅ Done — fixed the broken pipeline (rich macOS posture
   collectors now dispatched into the registry + `_norm_security` forwards the canonical
   schema) and added 7 checks (audit, password policy, guest, auto-login, update-install,
   network time, sharing) → **23 checks** total. Tests: `manager/tests/unit/test_posture_cis.py`,
   `agent/tests/unit/test_posture_collector_cis.py`.
5. **[#5] Connection-check surfacing.** ✅ Done — `Sender.link_state()` → `agent_health.link`
   heartbeat → `manager/api/assets.py` (`_link_summary`, list + detail) exposes per-agent
   `link.status` (healthy/degraded/auth_failed). Tests: `agent/tests/unit/test_link_state.py`,
   `manager/tests/unit/test_link_status_api.py`.

> Remaining open items: the optional **#3 watchdog** re-enable and resolving the **two-daemon
> topology** (§3 note) so only one supervisor starts the agent. **#1/#2 auto-launch are now
> active** (pkg bootstraps + boot-persistence self-repair). Everything else in this manifest is
> implemented + tested.
