# taskagent.md — Windows Agent Implementation Tracker

> Historical task tracker. Completed state and remaining external release gates are consolidated in [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md); support automation remains in [`advanced_support/`](advanced_support/README.md).

Scope: **`agent/os/windows/` only.** This tracker records the real, verified state
of the Windows agent (which differs from the stale `agentpromptrequired.md`) and
breaks the remaining work into small, independently-verifiable tasks.

Legend: `[x]` done & verified · `[~]` in progress · `[ ]` todo · `[-]` out of scope (shared code)

---

## 0. Ground truth — audit of current state (2026-07-14)

`agentpromptrequired.md` marks many collectors "NEEDS IMPL". A file-by-file audit
shows they are already implemented and production-grade. Corrected status:

| Section     | File                     | Real status                          |
|-------------|--------------------------|--------------------------------------|
| metrics     | collectors/volatile.py   | DONE (cpu/mem/swap/io, freq in _raw) |
| connections | collectors/volatile.py   | DONE (TCP established)               |
| processes   | collectors/volatile.py   | DONE (top-80 by CPU)                 |
| ports       | collectors/network.py    | DONE (TCP LISTEN + UDP bound)        |
| network     | collectors/network.py    | DONE (ifaces/dns/wifi/gw/domain)     |
| arp         | collectors/network.py    | **DONE** (doc said NEEDS IMPL)       |
| mounts      | collectors/network.py    | **DONE** (doc said NEEDS IMPL)       |
| battery/openfiles/services/users/hardware/containers | collectors/system.py | DONE |
| storage     | collectors/inventory.py  | DONE                                 |
| tasks       | collectors/inventory.py  | **DONE** (Get-ScheduledTask + CSV)   |
| apps        | collectors/inventory.py  | **DONE** (3 uninstall hives)         |
| packages    | collectors/inventory.py  | **DONE** (pip/npm/choco/winget/scoop)|
| binaries    | collectors/inventory.py  | **DONE** (PE walk + SHA-256 cap)     |
| sbom        | collectors/inventory.py  | **DONE** (purl records)              |
| security/sysctl/configs | collectors/posture.py | DONE                          |
| eventlog    | collectors/eventlog.py   | DONE (Windows-only, not in macOS)    |
| **sca**     | collectors/sca.py        | **MISSING — the only real gap**      |

Supporting modules (`normalizer.py`, `service.py`, `keystore.py`, `watchdog_svc.py`,
`tls_transport.py`, `win_agent.py`, `agent_win_entry.py`) exist and are implemented.
Packaging (`pkg/*.spec`, `pkg/*.wxs`, `pkg/build_*.ps1`, `installer/*.ps1`) exists.

**Conclusion:** the agent is feature-complete except for **SCA** — the declarative
CIS-benchmark configuration-audit engine that gives the agent parity with mature
endpoint agents. Everything below builds that, wires it in, and verifies it.

---

## 1. SCA engine (self-contained under windows/)

- [x] **1a** `sca/engine.py` — `ScaEngine`: loads policies, evaluates each check's
  rules through a caller-supplied runner, returns canonical result doc. Tri-state
  rule eval (match / no-match / error); `all|any|none` conditions; never raises.
- [x] **1b** `sca/engine.py` — rule grammar: `c:<cmd> [-> <matcher>]`, `f:<path>`,
  `not ` prefix; matchers `r:<regex>`, `n:<regex> compare <op> <n>`, `!<matcher>`,
  literal substring.
- [x] **1c** `sca/engine.py` — policy loader `load_policies(dirs, platform)`:
  bundled Python policy always available (zero parse deps); operator drop-ins from
  `C:\ProgramData\AttackLens\sca\*.json` (stdlib) and `*.yaml` (only if PyYAML present).
- [x] **1d** `sca/cis_windows.py` — bundled `POLICY` dict, **19** CIS Windows checks
  (Secure Boot, BitLocker, UAC, Defender RTP, Firewall, SMBv1, SMB signing, LLMNR,
  NetBIOS, LSASS PPL, Credential Guard, Guest/Admin accounts, auto-update, patch age,
  audit policy, RDP NLA, Remote Registry, Telnet) with title/rationale/remediation/compliance.
- [x] **1e** `sca/__init__.py` — export `ScaEngine`, `load_policies`, `BUNDLED_POLICIES`.

## 2. Windows SCA collector

- [x] **2a** `collectors/sca.py` — `ScaCollector(WinBaseCollector)`, `name="sca"`,
  `timeout=600`; `_route_command` routes console-native tools (reg/sc/netsh/auditpol/
  manage-bde) as tokenized argv (no cmd.exe → no quote-mangling, no `sc`→Set-Content
  alias), everything else via powershell.exe. `_tokenize` is quote-aware and
  backslash-preserving.
- [x] **2b** Register `ScaCollector` in `collectors/__init__.py` COLLECTORS map.

## 3. Normalizer

- [x] **3a** `normalizer.py` — added `_sca` + `_sca_summary` (light coercion; engine
  already canonical) and registered `"sca": _sca` in `_NORMALIZERS`.

## 4. Scheduling / config wiring (windows-only)

- [x] **4a** `pkg/generate_config.ps1` — added `sca` to emitted `[collection.sections]`
  (enabled, interval 43200 s = 12 hr).
- [x] **4b** `installer/generate_config.ps1` — same (section count comment updated 23→24).
- [x] **4c** `requirements.txt` — PyYAML noted as optional (YAML SCA drop-ins only).

## 5. Tests & verification

- [x] **5a** 19 unit tests added to `agent/tests/unit/test_windows_collectors.py`
  (`TestScaEngine`, `TestScaCollector`) — mock-runner grammar/condition matrix,
  tokenizer, never-raise contract, registration, normalizer round-trip. All pass.
- [x] **5b** Local smoke run on this Windows box: `ScaCollector().collect()` →
  19 checks, **16 pass / 3 fail / 0 error**, score 84.2 %, ~50 s, canonical shape
  valid. The 3 fails are genuine (no BitLocker, no LLMNR GPO, no Credential Guard).
- [x] **5c** Import-safety: `agent.os.windows.collectors` imports cleanly;
  `COLLECTORS` now has 24 sections incl. `sca`; `_NORMALIZERS` has `sca`.

### Verification note — one PRE-EXISTING, unrelated test failure

`TestArpCollector::test_broadcast_mac_filtered` fails, but it is **not** caused by
this work: `network.py:197` deliberately drops broadcast MAC entries while the test
expects them kept with `mac=None`. `network.py` and the arp test were never touched
here. It was subsequently fixed (see §6). Final windows suite:
`test_windows_collectors.py` + `test_windows_normalizer.py` → **141 passed, 0 failed**
(includes 19 SCA tests + 7 volatile-enhancement tests). Note: the broader agent
suite has 12 pre-existing failures in `test_keystore.py`/`test_macos_keystore.py`
that are environmental on Windows (Unix `0o600` file-mode assertions → `0o666`) and
unrelated to this work — no keystore logic was touched.

## 6. Roadmap / follow-ups

- [x] Added `sca` to `_DEFAULT_SECTIONS` in `agent/agent/core.py` (12 hr) so the
  section also schedules when a config omits `[collection.sections]`. Shared file,
  done at the user's explicit request; a single additive dict entry.
- [x] **Fixed the pre-existing arp test/code mismatch** (found during verification).
  `network.py` ArpCollector was *dropping* broadcast/multicast rows; the macOS arp
  collector (`os/macos/collectors/network.py:235`) and the `_arp` normalizer both
  keep the row with `mac=None`. Aligned Windows to that cross-platform contract:
  broadcast/multicast entries are kept (they still record a live IP) with the MAC
  nulled. Full windows suite now **134 passed, 0 failed**.
- [x] `volatile.py` enhancements from the original prompt, implemented + normalized +
  tested on this box:
  - `metrics.cpu_per_core` — per-logical-core list (verified: 4 cores).
  - `connections` — now includes TCP LISTEN + UDP alongside ESTABLISHED, each with
    `direction` (inbound/outbound/listen via the live listening-port set) and
    `service` (well-known port→name map). Verified: 129 rows, services resolved.
  - `processes.signed` — Authenticode trust via WinVerifyTrust (ctypes), bounded
    cache keyed by (path, mtime, size); never raises. Verified: 71 signed / 4
    unsigned / 5 unknown across the top-80 on this box.
- [x] **End-to-end data-path verification on this box** (mirrors `debug` minus the
  network). All **24 sections** collect→normalize→strict-JSON with 0 raises and 0
  non-serializable fields; the real `Orchestrator._run_section` was driven for
  metrics/connections/processes/sca → encrypt → enqueue (correct section tag) →
  wire-JSON → **decrypt round-trip restores the payload**; circuit-breaker health
  heartbeat emits. Sample real counts: apps 104, binaries 500(cap), packages 205,
  services 1012, tasks 389, sca 2, connections 139. **RESULT: ALL PHASES PASSED.**
- [x] **Built the real EXE and ran it — which exposed a critical integration bug.**
  This box has PyInstaller 6.19 + pywin32 + WiX v3.11, so it qualifies as a build box.
  `pyinstaller pkg/attacklens-agent.spec` → `dist/attacklens-agent/attacklens-agent.exe`
  (5.8 MB). Running `attacklens-agent.exe debug` with a seeded `client.key` (skips
  enrollment) and an unreachable manager (forces disk spooling) revealed:

  **BUG (found + fixed):** the shipped Windows agent runs via `win_agent.py`, which
  keeps its **own** collector list (`_load_collectors`) and interval table
  (`_INTERVALS`) — *separate* from `collectors/__init__.py`'s `COLLECTORS`. Neither
  included `sca`, and `_build_active_intervals` only iterates `_INTERVALS`, so a
  config-only section is dropped. **Net effect: SCA was registered everywhere else
  but never ran in the actual agent binary.** Fixed by adding `sca` to `_INTERVALS`
  (43200 s) and `ScaCollector()` to `_load_collectors`. Added 3 regression tests
  (`TestWinAgentScaWiring`) incl. a guard that every `COLLECTORS` section is loadable
  by `win_agent`, so this class of gap can't recur silently.

  **Re-built + re-verified from the frozen binary:** `attacklens-agent.exe debug`
  with an SCA-only config → "1 collector threads (disabled=23)" → the SCA scan ran,
  encrypted, and spooled. Decrypted from disk (AES-256-GCM + HMAC verified): the full
  **CIS Microsoft Windows Security Baseline, 19 checks, 16 pass / 3 fail / 0 error,
  84.2 %** — identical to the Python-level result. **The frozen EXE produces valid,
  encrypted, decryptable NDJSON SCA payloads.**
- [x] **Built the MSI.** Built the watchdog EXE too, then `pkg/build_msi.ps1 -SkipBuild`
  with WiX v4.0.5 (dotnet tool): harvested 66 agent + 20 watchdog `_internal` files,
  compiled → **`pkg/dist/attacklens-agent-2.0.0-x64.msi` (15.8 MB)**, validated as a
  well-formed MSI (OLE compound-doc header `d0cf11e0`). It packages the SCA-wired
  agent EXE (timestamp confirms the post-fix rebuild).
  Install: `msiexec /i attacklens-agent-2.0.0-x64.msi /qn MANAGER_IP="..." ENROLL_TOKEN="..."`.
  Note: `pkg/build_exe.ps1` trips a Windows PowerShell 5.1 parser quirk (braces are
  balanced; pre-existing, unrelated); invoke PyInstaller directly or use
  `build_msi.ps1` (which uses `Set-StrictMode -Off` and builds cleanly).
- [ ] Only truly-remaining piece: a send to a *live* manager (needs a reachable
  endpoint). Everything up to the wire — collect → normalize → encrypt → HMAC → NDJSON
  spool → decrypt, from the frozen EXE, packaged in the MSI — is verified.

---

## 7. Rebrand jarvis → attacklens + one-command MSI build

- [x] **Purged leftover `jarvis` branding.** Windows source/scripts now have ZERO
  jarvis references. Changes:
  - `win_agent.py`: `_JARVIS_DATA` → `_ATTACKLENS_DATA` (all uses).
  - `collectors/eventlog.py`: "Jarvis analyzers" → "AttackLens analyzers".
  - `pkg/generate_config.ps1`: **functional fix** — `jarvis-agent.exe`/`jarvis-watchdog.exe`
    → `attacklens-*.exe`; `JARVIS_ENROLL_TOKEN` → `ATTACKLENS_ENROLL_TOKEN`; doc URL.
  - `pkg/manage_services.ps1`: `Get-JarvisRegValue` → `Get-AttackLensRegValue`;
    "Jarvis services" → "AttackLens services".
  - Shared win32 default paths (used only if the agent ran via `core.py`): `core.py`
    and `sender.py` win32 branches `…\Jarvis\…` → AttackLens ProgramData/Program Files
    paths. Linux/macOS default paths left untouched (other platforms' branding).
  - Deleted dead legacy files (attacklens-* equivalents exist and are what the build
    uses): `pkg/jarvis-agent.spec`, `pkg/jarvis-agent.wxs`, `pkg/jarvis-watchdog.spec`,
    and stale `dist/jarvis-*` / `build/*/jarvis-*` artifacts.
  - Left `AGENT_ARCHITECTURE.md` / `WINDOWS_AGENT_WORK_LOG.md` untouched — they are
    historical migration logs that quote the old jarvis values ("Was: jarvis…"), so
    rewriting them would corrupt the record.
- [x] **`pkg/build_msi.sh`** — single command to build the MSI end-to-end (bash / Git
  Bash): checks prereqs (python, PyInstaller, pywin32, WiX v4), builds both onedir EXEs
  with PyInstaller, then harvests `_internal` + compiles the MSI via `build_msi.ps1`
  (WiX v4). **Verified: `./build_msi.sh` → `dist/attacklens-agent-2.0.0-x64.msi`
  (15.8 MB), valid OLE header, no jarvis artifacts.** Usage: `./build_msi.sh [version]`.

## Design notes

- **Zero new hard dependency.** The bundled CIS policy is a Python module, so SCA
  works in the frozen PyInstaller EXE with no parser. PyYAML is optional and only
  enables operator YAML drop-ins; its absence degrades gracefully (logged, skipped).
- **Never raises.** Engine and collector catch everything and return partial results
  or `{}`, honoring the collector contract in `AGENT_ARCHITECTURE.md`.
- **Read-only checks.** Every rule is a non-destructive query (reg query, sc query,
  netsh show, Get-* cmdlets). No state is modified.
- **Bounded runtime.** Per-rule timeout (15 s) under the collector's 600 s budget.
