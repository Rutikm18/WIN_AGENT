"""
agent/os/windows/win_agent.py — Self-contained Windows endpoint agent.

Architecture
────────────
  WindowsAgent.run()
    ├─ _enroll_if_needed()   — DPAPI-backed key via agent.os.windows.keystore
    ├─ _load_collectors()    — all standard + Windows-specific collectors
    ├─ per-section threads   — _collect_loop() × N, circuit-breaker guarded
    ├─ sender thread         — _sender_loop() with disk spool + backoff
    └─ heartbeat thread      — _health_loop() every 60 s

Security model
──────────────
  Transport:       TLS 1.3 minimum; optional SPKI certificate pinning
  Confidentiality: AES-256-GCM (96-bit random nonce per payload)
  Integrity:       GCM authentication tag + HMAC-SHA256 over wire envelope
  Key derivation:  HKDF-SHA256 → enc_key + mac_key
  Key storage:     DPAPI Credential Manager → DPAPI file → ACL-restricted file
  Enrollment:      TLS-protected; enrollment token never stored on disk
  Replay defence:  ±300 s timestamp window + per-nonce dedup (server-side)

Offline resilience
──────────────────
  Outbox: encrypted SQLite WAL with FULL synchronous durability.
  Retry: fresh timestamp and nonce per attempt; bounded exponential backoff.
  ACK: rows are deleted only after manager application acknowledgement.
  Rejection: non-retryable rows are retained as dead letters.
  Migration: legacy NDJSON envelopes are converted to canonical outbox rows.

Configuration (agent.toml)
──────────────────────────
  [agent]
  id   = "workstation-001"
  name = "Alice's Workstation"

  [manager]
  url        = "https://manager.example.com"
  tls_verify = true
  spki_pin   = "sha256//..."  # optional

  [enrollment]
  token = "sk-enroll-..."

  [paths]
  security_dir = 'C:\\ProgramData\\AttackLens\\security'
  spool_dir    = 'C:\\ProgramData\\AttackLens\\spool'

  [logging]
  level = "INFO"
  file  = 'C:\\ProgramData\\AttackLens\\logs\\agent.log'

CLI (foreground / debug)
────────────────────────
  python -m agent.os.windows.win_agent --config path\\to\\agent.toml
  python -m agent.os.windows.win_agent --config path\\to\\agent.toml --collect-once
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import logging.handlers
import os
import queue
import random
import shutil
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("agent.windows")

# ── Collection intervals (seconds) ───────────────────────────────────────────

_INTERVALS: dict[str, int] = {
    "metrics":     10,   "connections": 10,   "processes":  10,
    "ports":       30,   "network":    120,   "arp":        60,
    "mounts":      120,
    "battery":     120,  "openfiles":  120,   "services":  120,
    "users":       120,  "hardware":   300,   "containers": 120,
    "storage":     600,  "tasks":      600,   "apps":       900,
    "packages":    900,  "binaries": 86400,   "sbom":     86400,
    "security":   3600,  "sysctl":   3600,   "configs":   3600,
    "sca":        3600,
    "eventlog":    300,
    "security_audit": 21600,
}

_HEALTH_INTERVAL = 60    # seconds between agent_health heartbeats
_QUEUE_MAXSIZE   = 512   # drop-oldest-to-spool above this depth
_SEND_TIMEOUT    = 30    # seconds per POST to manager
_SPOOL_PROBE_SEC = 30    # seconds between /health probes when queue is quiet
# Keep a margin below the manager's 10 MiB request limit for JSON/envelope
# overhead and future reverse-proxy limits.
_MAX_ENVELOPE_BYTES = 9 * 1024 * 1024

# ── Defaults ──────────────────────────────────────────────────────────────────

_PROGRAMDATA = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
_ATTACKLENS_DATA = os.path.join(_PROGRAMDATA, "AttackLens")

_DEFAULTS = {
    "security_dir": os.path.join(_ATTACKLENS_DATA, "security"),
    "spool_dir":    os.path.join(_ATTACKLENS_DATA, "spool"),
    "data_dir":     os.path.join(_ATTACKLENS_DATA, "data"),
    "status_dir":   os.path.join(_ATTACKLENS_DATA, "status"),
    "log_file":     os.path.join(_ATTACKLENS_DATA, "logs", "agent.log"),
    "log_level":    "INFO",
}


# ── Circuit breaker ───────────────────────────────────────────────────────────

def _normalise_manager_url(url: str) -> tuple[str, str, int | None, str, str]:
    """Return a comparison-safe manager identity without credentials."""
    try:
        parsed = urlsplit(str(url).strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80 if scheme == "http" else None
        return scheme, host, port, parsed.path.rstrip("/"), parsed.query
    except (TypeError, ValueError):
        return "", "", None, "", ""


def _public_manager_endpoint(url: str) -> str:
    """Return scheme/host/port/path only; never expose URL credentials/query."""
    try:
        parsed = urlsplit(str(url).strip())
        if not parsed.scheme or not parsed.hostname:
            return ""
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme.lower()}://{host.lower()}{port}{parsed.path.rstrip('/')}"
    except (TypeError, ValueError):
        return ""


def _manager_is_loopback(url: str) -> bool:
    try:
        host = (urlsplit(str(url).strip()).hostname or "").lower().rstrip(".")
    except (TypeError, ValueError):
        return False
    return host in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")


class AgentStartupError(RuntimeError):
    """Fatal startup failure that SCM should report as a service failure."""


class _CircuitBreaker:
    """
    Three-state per-section circuit breaker.
    CLOSED → OPEN (3 consecutive failures, 60 s cooldown) → HALF-OPEN → CLOSED.
    Prevents a broken collector from flooding the send queue with errors.
    """
    _THRESHOLD = 3   # consecutive failures to trip
    _BACKOFF   = 60  # seconds cooldown (OPEN → HALF-OPEN); per architecture spec

    def __init__(self, section: str) -> None:
        self._section   = section
        self._failures  = 0
        self._opened_at = 0.0
        self._state     = "CLOSED"

    def allow(self) -> bool:
        if self._state == "CLOSED":
            return True
        if self._state == "OPEN":
            if time.monotonic() - self._opened_at >= self._BACKOFF:
                self._state = "HALF"
                return True
            return False
        return True   # HALF — single probe allowed

    def success(self) -> None:
        self._failures = 0
        self._state    = "CLOSED"

    def failure(self) -> None:
        self._failures += 1
        if self._failures >= self._THRESHOLD:
            self._state     = "OPEN"
            self._opened_at = time.monotonic()
            log.warning("circuit OPEN: section=%s after %d consecutive failures",
                        self._section, self._failures)


# ── Disk spool ────────────────────────────────────────────────────────────────

_SPOOL_MAX_BYTES = 50 * 1024 * 1024   # 50 MB hard cap
_SPOOL_TRIM_PCT  = 0.10               # trim oldest 10% when cap is reached


class _DiskSpool:
    """
    Append-only NDJSON spool for resilient payload delivery.

    Guarantees:
    • Payloads are stored as base64 wire envelopes (identical to what the
      sender POSTs) so drain → re-POST is trivially safe.
    • All file operations are protected by a threading.Lock.
    • On overflow: oldest 10% of entries are dropped (FIFO trim), not new ones.
    • On process crash during drain: the orphaned .draining file is merged back
      on the next start so no data is silently lost.
    """

    def __init__(self, spool_dir: str) -> None:
        self._dir  = Path(spool_dir)
        self._path = self._dir / "win_agent.spool.ndjson"
        self._lock = threading.Lock()
        self._trimmed_entries = 0
        self._corrupt_entries = 0
        self._write_errors = 0
        self._dir.mkdir(parents=True, exist_ok=True)
        self._recover_orphan_drain()

    # ── Public API ────────────────────────────────────────────────────────────

    def write(self, envelope_json: bytes) -> bool:
        """Append one wire envelope (thread-safe). Trims oldest 10% when full."""
        import base64
        line = base64.b64encode(envelope_json).decode() + "\n"
        with self._lock:
            try:
                if self._path.exists() and self._path.stat().st_size >= _SPOOL_MAX_BYTES:
                    self._trim_oldest()
                with open(self._path, "a", encoding="ascii") as f:
                    f.write(line)
                return True
            except OSError as exc:
                self._write_errors += 1
                log.debug("spool write error: %s", exc)
                return False

    def drain(self) -> list[bytes]:
        """
        Atomically consume and return all spooled envelopes.
        The spool file is renamed before reading, so concurrent writers
        create a fresh file without affecting the drain batch.
        Returns [] if the spool is empty or inaccessible.
        """
        import base64
        if not self._path.exists():
            return []
        tmp = self._path.with_suffix(".draining")
        with self._lock:
            try:
                self._path.rename(tmp)
            except OSError:
                return []
        envelopes: list[bytes] = []
        try:
            with open(tmp, "r", encoding="ascii") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        envelopes.append(base64.b64decode(line, validate=True))
                    except Exception:
                        self._corrupt_entries += 1
                        log.debug("spool: skipped corrupted entry (bad base64)")
        except OSError as exc:
            log.debug("spool drain read error: %s", exc)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        return envelopes

    def size(self) -> int:
        """Return current spool file size in bytes (0 if absent)."""
        try:
            return self._path.stat().st_size
        except OSError:
            return 0

    def stats(self) -> dict[str, int]:
        """Return bounded spool counters for the health heartbeat."""
        with self._lock:
            return {
                "trimmed_entries": self._trimmed_entries,
                "corrupt_entries": self._corrupt_entries,
                "write_errors": self._write_errors,
            }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _trim_oldest(self) -> None:
        """
        Drop the oldest 10% of spool entries to make room.
        Called under self._lock. Uses an atomic write to avoid partial state.
        """
        try:
            with open(self._path, "r", encoding="ascii") as f:
                lines = f.readlines()
            drop    = max(1, int(len(lines) * _SPOOL_TRIM_PCT))
            kept    = lines[drop:]
            tmp     = self._path.with_suffix(".trimming")
            with open(tmp, "w", encoding="ascii") as f:
                f.writelines(kept)
            os.replace(str(tmp), str(self._path))
            self._trimmed_entries += drop
            log.info("spool trimmed: dropped %d oldest entries, kept %d",
                     drop, len(kept))
        except OSError as exc:
            self._write_errors += 1
            log.debug("spool trim error: %s", exc)

    def _recover_orphan_drain(self) -> None:
        """
        If a previous process crashed during drain(), a .draining file is left.
        Merge it back into the spool so those payloads are not silently lost.
        Called from __init__ before any threads are started (no lock needed).
        """
        orphan = self._path.with_suffix(".draining")
        if not orphan.exists():
            return
        try:
            if self._path.exists():
                with open(orphan, "rb") as src, open(self._path, "ab") as dst:
                    dst.write(src.read())
                orphan.unlink(missing_ok=True)
            else:
                orphan.rename(self._path)
            log.info("spool: recovered orphaned .draining file from previous crash")
        except OSError as exc:
            log.debug("spool orphan recovery failed: %s", exc)


# ── WindowsAgent ──────────────────────────────────────────────────────────────

class WindowsAgent:
    """
    Self-contained Windows endpoint agent.

      WindowsAgent.from_config(path) → agent
      agent.run()                    → blocks until stop()
      agent.stop()                   → signals the run() loop to exit
      agent.collect_once()           → returns all sections as a dict (for testing)
    """

    def __init__(self, cfg: dict) -> None:
        self._cfg          = cfg
        self._agent_id     = cfg["agent"]["id"]
        self._agent_name   = cfg["agent"].get("name", socket.gethostname())
        self._agent_number = ""
        self._stop_ev      = threading.Event()
        self._started_monotonic = time.monotonic()
        self._send_q: queue.Queue[bytes] = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._breakers:   dict[str, _CircuitBreaker] = {}
        self._collectors: dict[str, Any]             = {}
        self._enc_key: bytes = b""
        self._mac_key: bytes = b""
        self._spool:   _DiskSpool | None = None
        self._outbox: Any = None
        self._send_wake = threading.Event()
        self._conn_ok: bool = True
        self._connection_state = "starting"
        self._consecutive_auth_failures = 0
        self._last_reenroll_at = 0.0
        self._manager_clock_skew_sec: int | None = None
        self._key_lock = threading.RLock()
        self._fatal_runtime_error: str | None = None
        self._config_path: str | None = None
        self._config_digest: str | None = None
        self._instance_guard: Any = None
        self._stop_reason = "service_stop"
        self._power_events: list[dict[str, int]] = []
        self._integrity_status: dict[str, Any] = {
            "status": "not_checked",
            "checked_files": 0,
        }
        self._previous_lifecycle: dict[str, Any] = {}
        self._stats_lock = threading.Lock()
        self._delivery_stats: dict[str, Any] = {
            "sent": 0,
            "failed": 0,
            "discarded": 0,
            "last_success_at": None,
            "last_failure_at": None,
            "last_failure_reason": None,
            "current_backoff_sec": 0,
            "queue_full": 0,
            "oversize_dropped": 0,
            "spool_drain_attempts": 0,
            "spool_drain_failures": 0,
            "spool_drained": 0,
            "durably_queued": 0,
            "acknowledged": 0,
            "retry_scheduled": 0,
            "dead_lettered": 0,
            "auth_failures": 0,
            "duplicate_acks": 0,
            "oversize_preserved": 0,
        }
        # Active sections: section_name → interval_sec (built from config + defaults)
        self._active_intervals: dict[str, int] = self._build_active_intervals()

    @classmethod
    def from_config(cls, config_path: str) -> "WindowsAgent":
        from agent.os.windows.config_model import load_config
        from agent.os.windows.integrity import sha256_file

        agent = cls(load_config(config_path).to_dict())
        agent._config_path = config_path
        try:
            agent._config_digest = sha256_file(config_path)
        except OSError:
            agent._config_digest = None
        return agent

    # ── Public interface ──────────────────────────────────────────────────────

    def run(
        self,
        win32_stop_event: Any = None,
        ready_callback: Any = None,
        progress_callback: Any = None,
    ) -> None:
        """
        Main agent loop. Blocks until stop() is called or SCM stop event fires.
        win32_stop_event: win32event handle (int) or None for foreground mode.
        ready_callback: optional callback invoked after config, enrollment,
            collectors, and spool initialization succeed.
        progress_callback: optional callback invoked after each critical
            startup phase with a monotonically increasing checkpoint number.
        """
        # Phase 1 — validate before logging setup, network, enrollment, or
        # collector work.  A malformed config must fail closed and explain the
        # operator action without ever printing a token or API key.
        try:
            self._validate_config()
        except ValueError as exc:
            print(f"ERROR: Agent cannot start — {exc}", file=sys.stderr)
            raise AgentStartupError("configuration validation failed") from exc

        try:
            from agent.os.windows.single_instance import (
                AlreadyRunningError,
                SingleInstanceGuard,
            )

            self._instance_guard = SingleInstanceGuard().acquire()
        except AlreadyRunningError as exc:
            raise AgentStartupError("another agent instance is already running") from exc
        except Exception as exc:
            raise AgentStartupError("single-instance guard failed") from exc

        self._notify_progress(progress_callback, 1)
        self._setup_logging()
        for recovery in getattr(self, "_startup_recovery_actions", []):
            if recovery.get("status") != "repaired":
                continue
            log.warning(
                "Automatic startup recovery action=%s target=%s detail=%s",
                recovery.get("action", "unknown"),
                recovery.get("target", ""),
                recovery.get("detail", ""),
            )
        log.info("Windows agent starting  agent_id=%s  name=%s",
                 self._agent_id, self._agent_name)

        try:
            from agent.os.windows.integrity import verify_current_install

            self._integrity_status = verify_current_install()
            log.info(
                "Install integrity status=%s checked_files=%s",
                self._integrity_status.get("status"),
                self._integrity_status.get("checked_files"),
            )
        except Exception as exc:
            log.critical("Agent cannot start — install integrity failed: %s", exc)
            raise AgentStartupError("install integrity verification failed") from exc

        # Phase 2 — repair protected runtime paths before enrollment or
        # collector startup. A key/config/spool ACL failure is fail-closed;
        # otherwise a local normal user could tamper with privileged inputs.
        try:
            from agent.os.windows.acl import ensure_runtime_acls, report_is_compliant
            acl_paths = dict(self._cfg.get("paths", {}))
            if self._config_path:
                acl_paths["config_file"] = self._config_path
            acl_paths.update(self._cfg.get("acl", {}))
            acl_results = ensure_runtime_acls(acl_paths, repair=True)
            failures = [result for result in acl_results if not result.compliant and not result.skipped]
            enforced_results = [result for result in acl_results if not result.skipped]
            if failures or (enforced_results and not report_is_compliant(enforced_results)):
                details = "; ".join(
                    f"{result.path}: {result.error or 'not compliant'}"
                    for result in failures
                )
                if failures:
                    log.critical("Agent cannot start — ACL policy failed: %s", details)
                    raise AgentStartupError(f"ACL policy failed: {details}")
        except Exception as exc:
            log.critical("Agent cannot start — ACL initialization failed: %s", exc)
            if isinstance(exc, AgentStartupError):
                raise
            raise AgentStartupError("ACL initialization failed") from exc

        # Phase 3 — opportunistic enrollment. Manager configuration and
        # availability are optional: failures leave the agent in encrypted
        # offline-spool mode and the sender retries enrollment in background.
        self._notify_progress(progress_callback, 2)
        try:
            self._enroll_if_needed(max_attempts=1)
        except Exception as exc:
            log.error("Initial enrollment attempt failed; continuing offline: %s", exc)
            self._connection_state = "enrollment_pending"
            self._conn_ok = False

        # Phase 4 — load collector modules (Python imports only; no I/O)
        self._notify_progress(progress_callback, 3)
        try:
            self._load_collectors()
        except ImportError as exc:
            log.critical(
                "Agent cannot start — a required module is missing: %s\n"
                "Reinstall the agent or run: pip install pywin32 psutil cryptography requests",
                exc,
            )
            raise AgentStartupError("required collector module is missing") from exc
        except Exception as exc:
            log.critical("Agent cannot start — collector load failed: %s", exc)
            raise AgentStartupError("collector load failed") from exc

        # Phase 5 — spool directory (disk I/O)
        self._notify_progress(progress_callback, 4)
        try:
            from agent.os.windows.reliable_outbox import ReliableOutbox

            transport_cfg = self._cfg.get("transport", {})
            self._outbox = ReliableOutbox(
                self._path("spool_dir"),
                self._path("security_dir"),
                self._agent_id,
                busy_timeout_ms=int(
                    transport_cfg.get("outbox_busy_timeout_ms", 5000)
                ),
            )
            self._migrate_legacy_spool()
            self._previous_lifecycle = self._consume_previous_lifecycle()
            if self._previous_lifecycle.get("unexpected_stop"):
                self._queue_collected_data(
                    "agent_lifecycle",
                    {
                        "event": "unexpected_previous_stop",
                        **self._previous_lifecycle,
                    },
                )
        except Exception as exc:
            log.critical(
                "Agent cannot start — spool init failed at %s: %s\n"
                "Check that NT AUTHORITY\\SYSTEM has write access to that directory.",
                self._path("spool_dir"), exc,
            )
            raise AgentStartupError("delivery outbox initialization failed") from exc

        self._notify_progress(progress_callback, 5)
        self._publish_runtime_state("running")
        if ready_callback is not None:
            try:
                ready_callback()
            except Exception as exc:
                log.critical("Service readiness callback failed: %s", exc)
                raise AgentStartupError("service readiness callback failed") from exc

        threads: list[threading.Thread] = []

        for section in self._active_intervals:
            t = threading.Thread(
                target=self._collect_loop, args=(section,),
                daemon=True, name=f"col-{section}",
            )
            threads.append(t)
            t.start()

        sender_t = threading.Thread(
            target=self._reliable_sender_loop, daemon=True, name="win-sender"
        )
        threads.append(sender_t)
        sender_t.start()

        hb_t = threading.Thread(
            target=self._reliable_health_loop, daemon=True, name="win-health"
        )
        threads.append(hb_t)
        hb_t.start()

        log.info("Agent running: %d collector threads + sender + heartbeat  (disabled=%d)",
                 len(self._active_intervals),
                 len(_INTERVALS) - len(self._active_intervals))

        self._wait_for_stop(
            win32_stop_event,
            critical_threads=(sender_t, hb_t),
        )
        log.info("Agent stopping")
        self._stop_ev.set()
        self._send_wake.set()

        # Let in-flight collectors finish their enqueue/cursor transaction.
        collector_deadline = time.monotonic() + 15.0
        for thread in threads:
            if thread in {sender_t, hb_t}:
                continue
            remaining = collector_deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)

        # The sender never owns the only copy; pending rows remain in SQLite.
        sender_t.join(timeout=15)
        hb_t.join(timeout=2)
        self._publish_runtime_state("stopped")
        live_collectors = [
            thread.name
            for thread in threads
            if thread not in {sender_t, hb_t} and thread.is_alive()
        ]
        if self._outbox is not None and not live_collectors:
            try:
                self._outbox.close()
            except Exception as exc:
                log.warning("delivery outbox close failed: %s", exc)
        elif live_collectors:
            log.warning(
                "outbox left open until process exit; collectors still stopping: %s",
                ", ".join(live_collectors),
            )
        if not self._fatal_runtime_error:
            self._write_clean_stop_marker()
        if self._instance_guard is not None:
            try:
                self._instance_guard.release()
            except Exception as exc:
                log.warning("single-instance mutex release failed: %s", exc)
        log.info("Agent stopped")
        if self._fatal_runtime_error:
            raise RuntimeError(self._fatal_runtime_error)

    def stop(self, reason: str = "service_stop") -> None:
        self._stop_reason = reason
        self._stop_ev.set()
        self._send_wake.set()

    def handle_power_event(self, event_type: int) -> None:
        """Wake delivery immediately after resume and expose power transitions."""
        now = int(time.time())
        self._power_events.append({"event_type": int(event_type), "at": now})
        self._power_events = self._power_events[-16:]
        # PBT_APMRESUMESUSPEND=7, PBT_APMRESUMEAUTOMATIC=18.
        if int(event_type) in {7, 18}:
            self._connection_state = "resuming"
            self._send_wake.set()
            if self._outbox is not None:
                try:
                    self._queue_collected_data(
                        "agent_lifecycle",
                        {"event": "power_resume", "event_type": int(event_type), "at": now},
                    )
                except Exception as exc:
                    log.warning("power resume event enqueue failed: %s", exc)

    @staticmethod
    def _notify_progress(callback: Any, checkpoint: int) -> None:
        """Report startup progress without breaking the agent on SCM errors."""
        if callback is None:
            return
        try:
            callback(checkpoint)
        except Exception as exc:
            log.warning(
                "Service startup progress callback failed at checkpoint %d: %s",
                checkpoint,
                exc,
            )

    def collect_once(self) -> dict[str, Any]:
        """Run every active collector synchronously. Useful for testing and diagnostics."""
        self._load_collectors()
        results: dict[str, Any] = {}
        from agent.os.windows.normalizer import normalize
        for section, collector in self._collectors.items():
            if section not in self._active_intervals:
                continue  # respect enabled=false from config
            try:
                raw    = collector()
                results[section] = normalize(section, raw)
            except Exception as exc:
                results[section] = {"error": str(exc)}
        return results

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        from agent.os.windows.config_model import load_config_dict
        model = load_config_dict(self._cfg)
        self._cfg = model.to_dict()
        self._agent_id = model.agent.id
        self._agent_name = model.agent.name
        self._active_intervals = self._build_active_intervals()
        log.debug("Config validated OK  agent_id=%s  manager=%s",
                  model.agent.id, model.manager.url)

    # ── Key management ────────────────────────────────────────────────────────

    def _enroll_if_needed(self, *, max_attempts: int = 1) -> bool:
        """
        Enroll with the manager and derive encryption keys.

        If a valid client.key exists, loading is immediate. Otherwise this
        performs a bounded attempt; failure is reported as an offline state,
        not a service-start failure.
        """
        from agent.agent.crypto import derive_keys
        from agent.agent.enrollment import EnrollmentError

        manager_url = str(self._cfg.get("manager", {}).get("url") or "").strip()
        if not manager_url:
            self._connection_state = "manager_unconfigured"
            self._conn_ok = False
            log.warning(
                "Manager URL is not configured; collecting to encrypted local spool"
            )
            return False

        max_attempts = max(1, int(max_attempts))
        backoff = 10.0
        last_exc: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                client_key = self._get_or_enroll_windows()
                break
            except EnrollmentError as exc:
                last_exc = exc
                # 401/409 are operator-action errors; retrying won't help.
                msg = str(exc)
                if "HTTP 401" in msg or "HTTP 409" in msg or "invalid enrollment token" in msg.lower():
                    log.critical(
                        "Enrollment rejected by manager (attempt %d): %s\n"
                        "This requires operator action — check manager logs and "
                        "[enrollment] token in agent.toml.",
                        attempt, exc,
                    )
                    self._connection_state = "enrollment_rejected"
                    self._conn_ok = False
                    return False
                log.warning(
                    "Enrollment attempt %d/%d failed (transient): %s",
                    attempt, max_attempts, exc,
                )
            except Exception as exc:
                last_exc = exc
                log.warning(
                    "Enrollment attempt %d/%d unexpected error: %s: %s",
                    attempt, max_attempts, type(exc).__name__, exc,
                )

            if attempt < max_attempts:
                log.info(
                    "Retrying enrollment in %.0f s (attempt %d/%d) — "
                    "check manager URL and network connectivity",
                    backoff, attempt + 1, max_attempts,
                )
                if self._stop_ev.wait(backoff):
                    return False
                backoff = min(backoff * 2.0, 300.0)
            else:
                log.error(
                    "Enrollment unavailable after %d attempt(s); collecting offline.\n"
                    "  Last error: %s\n"
                    "  Checks:\n"
                    "    1. Manager reachable? curl https://<manager_ip>:<port>/health\n"
                    "    2. TLS cert valid? (or set tls_verify=false for self-signed)\n"
                    "    3. Enrollment token correct? Check [enrollment] token in agent.toml\n"
                    "  The background sender will retry without discarding telemetry.",
                    max_attempts, last_exc,
                )
                self._connection_state = "enrollment_pending"
                self._conn_ok = False
                return False

        self._enc_key, self._mac_key = derive_keys(client_key.token)
        self._agent_name   = client_key.agent_name
        self._agent_number = client_key.agent_number

        log.info("Enrollment OK  agent_name=%r agent_number=%s",
                 self._agent_name, self._agent_number)
        return True

    def _post_enrollment_windows(
        self,
        payload: dict[str, Any],
        token: str,
    ) -> dict[str, Any]:
        """Enroll through the same TLS/pinning/proxy policy as ingest."""
        from agent.agent.enrollment import EnrollmentError
        from agent.os.windows.tls_transport import WindowsTLSTransport

        manager = self._cfg["manager"]
        timeout = max(1, int(manager.get("timeout_sec", 30)))
        transport = WindowsTLSTransport(
            base_url=manager["url"],
            spki_pin=manager.get("spki_pin") or None,
            tls_verify=manager.get("ca_bundle") or manager.get("tls_verify", True),
            timeout=(min(15, timeout), timeout),
            proxy_url=manager.get("proxy_url") or None,
        )
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Enrollment-Token"] = token
        try:
            response = transport.post(
                "/api/v1/enroll",
                data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                extra_headers=headers,
            )
            status = int(response.status_code)
            try:
                body = response.json()
            except Exception as exc:
                raise EnrollmentError(
                    f"Enrollment HTTP {status}: manager returned invalid JSON"
                ) from exc
            if not 200 <= status < 300:
                detail = (
                    str(body.get("detail") or body.get("error") or "request rejected")
                    if isinstance(body, dict)
                    else "request rejected"
                )
                raise EnrollmentError(f"Enrollment HTTP {status}: {detail[:256]}")
            if not isinstance(body, dict):
                raise EnrollmentError("Enrollment response must be a JSON object")
            return body
        finally:
            transport.close()

    def _get_or_enroll_windows(self) -> Any:
        """Load the existing client key or enroll with Windows transport policy."""
        import platform
        from agent.agent.auto_enroll import client_key_path
        from agent.agent.client_key import (
            ClientKey,
            generate_agent_number,
            load,
            save,
        )
        from agent.agent.enrollment import EnrollmentError

        key_path = client_key_path(self._cfg)
        existing = load(key_path)
        if existing:
            configured_url = str(self._cfg["manager"]["url"]).strip()
            if _normalise_manager_url(existing.manager_url) == _normalise_manager_url(configured_url):
                return existing

            # An enrollment credential is scoped to the manager that issued
            # it. Reusing it after an operator changes the endpoint causes an
            # endless authentication failure. Preserve it for rollback, then
            # enroll against the newly configured manager.
            archive_path = key_path + ".previous-manager"
            try:
                os.replace(key_path, archive_path)
            except OSError as exc:
                raise EnrollmentError(
                    "Manager URL changed but the previous enrollment credential "
                    f"could not be archived: {exc}"
                ) from exc
            log.warning(
                "Manager URL changed; archived the previous credential and "
                "starting re-enrollment (old=%s new=%s)",
                _public_manager_endpoint(existing.manager_url),
                _public_manager_endpoint(configured_url),
            )

        agent_number = generate_agent_number()
        response = self._post_enrollment_windows(
            {
                "agent_id": self._agent_id,
                "agent_name": self._agent_name,
                "hostname": socket.gethostname(),
                "os": "windows",
                "arch": platform.machine(),
                "timestamp": int(time.time()),
            },
            str(self._cfg.get("enrollment", {}).get("token") or "").strip(),
        )
        api_key = str(response.get("api_key") or "").strip()
        if len(api_key) != 64 or not all(
            character in "0123456789abcdefABCDEF" for character in api_key
        ):
            raise EnrollmentError("Manager returned an invalid enrollment API key")
        client_key = ClientKey(
            agent_name=self._agent_name,
            agent_number=str(response.get("agent_number") or agent_number),
            token=api_key,
            issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            manager_url=str(self._cfg["manager"]["url"]).rstrip("/"),
        )
        save(key_path, client_key)
        return client_key

    # ── Collector setup ───────────────────────────────────────────────────────

    def _load_collectors(self) -> None:
        from agent.os.windows.collectors.volatile  import (
            MetricsCollector, ConnectionsCollector, ProcessesCollector)
        from agent.os.windows.collectors.network   import (
            PortsCollector, NetworkCollector, ArpCollector, MountsCollector)
        from agent.os.windows.collectors.system    import (
            BatteryCollector, OpenFilesCollector, ServicesCollector,
            UsersCollector, HardwareCollector, ContainersCollector)
        from agent.os.windows.collectors.posture   import (
            SecurityCollector, SysctlCollector, ConfigsCollector)
        from agent.os.windows.collectors.inventory import (
            StorageCollector, TasksCollector, AppsCollector,
            PackagesCollector, BinariesCollector, SbomCollector)
        from agent.os.windows.collectors.sca       import ScaCollector
        from agent.os.windows.collectors.eventlog  import EventLogCollector
        from agent.os.windows.collectors.security_audit import WindowsSecurityAuditCollector

        all_collectors = [
            MetricsCollector(),     ConnectionsCollector(),  ProcessesCollector(),
            PortsCollector(),       NetworkCollector(),      ArpCollector(),
            MountsCollector(),      BatteryCollector(),      OpenFilesCollector(),
            ServicesCollector(),    UsersCollector(),        HardwareCollector(),
            ContainersCollector(),  SecurityCollector(),     SysctlCollector(),
            ConfigsCollector(),     StorageCollector(),      TasksCollector(),
            AppsCollector(),        PackagesCollector(),     BinariesCollector(),
            SbomCollector(),        ScaCollector(state_dir=self._path("data_dir")),
            EventLogCollector(state_dir=self._path("data_dir")),
            WindowsSecurityAuditCollector(),
        ]
        for c in all_collectors:
            self._collectors[c.name] = c
            self._breakers[c.name]   = _CircuitBreaker(c.name)

    # ── Collection loop ───────────────────────────────────────────────────────

    def _collect_loop(self, section: str) -> None:
        from agent.os.windows.normalizer import normalize

        interval  = self._active_intervals.get(section, _INTERVALS.get(section, 300))
        breaker   = self._breakers[section]
        collector = self._collectors.get(section)
        if not collector:
            return

        # Stagger first run for slow collectors (>300 s) to avoid a startup
        # spike where every heavy collector (storage, apps, packages…) hits
        # psutil / PowerShell simultaneously at T=0.
        stagger  = random.uniform(0, 60) if interval > 300 else 0
        next_run = time.monotonic() + stagger

        while not self._stop_ev.is_set():
            now = time.monotonic()
            if now < next_run:
                self._stop_ev.wait(min(1.0, next_run - now))
                continue

            if not breaker.allow():
                next_run = time.monotonic() + interval
                continue

            try:
                raw      = collector()
                data     = normalize(section, raw)
                self._queue_collected_data(section, data)
                try:
                    commit = getattr(collector, "commit", None)
                    if callable(commit):
                        commit()
                    breaker.success()
                except queue.Full:
                    log.debug("queue full — spooling %s", section)
                    self._record_delivery("queue_full")
                    self._rollback_collector(collector)
                    raise
            except RuntimeError as exc:
                # RuntimeError from _build_envelope means keys are missing —
                # no point continuing; log at error so it's visible in the log file.
                self._rollback_collector(collector)
                log.error("collect[%s] fatal: %s", section, exc)
                breaker.failure()
            except Exception as exc:
                self._rollback_collector(collector)
                log.debug("collect[%s] %s: %s", section, type(exc).__name__, exc)
                breaker.failure()

            next_run = time.monotonic() + interval

    # ── Health heartbeat ──────────────────────────────────────────────────────

    def _health_loop(self) -> None:
        while not self._stop_ev.wait(_HEALTH_INTERVAL):
            try:
                health = {
                    "uptime_sec":     self._uptime_seconds(),
                    "queue_depth":    self._send_q.qsize(),
                    "spool_bytes":    self._spool.size() if self._spool else 0,
                    "circuit_states": {
                        s: b._state for s, b in self._breakers.items()
                        if s in self._active_intervals
                    },
                    "active_sections": len(self._active_intervals),
                    "conn_ok":        self._conn_ok,
                    "platform":       "windows",
                    "delivery":       self._delivery_snapshot(),
                }
                if self._spool:
                    health["spool"] = self._spool.stats()
                envelope = self._build_envelope("agent_health", health)
                try:
                    self._send_q.put_nowait(envelope)
                except queue.Full:
                    pass
            except Exception as exc:
                log.debug("health heartbeat error: %s", exc)

    # ── Sender loop ───────────────────────────────────────────────────────────

    def _new_message(
        self,
        section: str,
        data: Any,
        *,
        collected_at: int | None = None,
    ) -> dict[str, Any]:
        """Build the canonical message stored in the durable outbox."""
        from agent.os.windows.reliable_outbox import new_delivery_id

        return {
            "schema_version": 1,
            "delivery_id": new_delivery_id(),
            "section": section,
            "agent_id": self._agent_id,
            "agent_name": self._agent_name,
            "agent_number": self._agent_number,
            "hostname": socket.gethostname(),
            "os": "windows",
            "collected_at": int(collected_at or time.time()),
            "data": data,
        }

    def _wire_for_message(self, message: dict[str, Any]) -> bytes:
        """Create a fresh replay-safe wire envelope for one send attempt."""
        from agent.agent.crypto import encrypt

        with self._key_lock:
            enc_key = self._enc_key
            mac_key = self._mac_key
        if not enc_key or not mac_key:
            raise RuntimeError(
                "Cannot encrypt payload: enrollment keys are unavailable"
            )

        wire_message = dict(message)
        # Messages collected before enrollment have no manager agent number.
        # Enrich them when they are eventually transmitted after enrollment.
        if not wire_message.get("agent_number"):
            wire_message["agent_number"] = self._agent_number
        timestamp = int(time.time())
        envelope = encrypt(
            wire_message,
            enc_key,
            mac_key,
            self._agent_id,
            timestamp,
        )
        envelope["section"] = str(message.get("section") or "unknown")
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _split_message(
        message: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Split the largest list in a message without dropping an element."""
        from agent.os.windows.reliable_outbox import new_delivery_id

        data = message.get("data")
        if isinstance(data, list) and len(data) > 1:
            midpoint = len(data) // 2
            left_data: Any = data[:midpoint]
            right_data: Any = data[midpoint:]
        elif isinstance(data, dict):
            candidates = [
                (key, value)
                for key, value in data.items()
                if isinstance(value, list) and len(value) > 1
            ]
            if not candidates:
                return None
            key, values = max(candidates, key=lambda entry: len(entry[1]))
            midpoint = len(values) // 2
            left_data = dict(data)
            right_data = dict(data)
            left_data[key] = values[:midpoint]
            right_data[key] = values[midpoint:]
        else:
            return None

        group_id = str(
            message.get("chunk_group_id")
            or message.get("delivery_id")
            or new_delivery_id()
        )
        left = dict(message)
        right = dict(message)
        left["delivery_id"] = new_delivery_id()
        right["delivery_id"] = new_delivery_id()
        left["chunk_group_id"] = group_id
        right["chunk_group_id"] = group_id
        left["data"] = left_data
        right["data"] = right_data
        return left, right

    def _prepare_messages(
        self,
        message: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fit a collection into bounded envelopes, retaining unsplittable data."""
        pending = [message]
        ready: list[dict[str, Any]] = []
        safety_limit = _MAX_ENVELOPE_BYTES - (64 * 1024)

        while pending:
            candidate = pending.pop()
            with self._key_lock:
                keys_ready = bool(self._enc_key and self._mac_key)
            if keys_ready:
                candidate_size = len(self._wire_for_message(candidate))
            else:
                # The outbox encrypts canonical messages with its own
                # machine-local key. Reserve space for the future transport
                # envelope without requiring manager keys at collection time.
                candidate_size = len(json.dumps(
                    candidate, separators=(",", ":"), default=str
                ).encode("utf-8")) + (128 * 1024)
            if candidate_size <= safety_limit:
                ready.append(candidate)
                continue
            split = self._split_message(candidate)
            if split is None:
                return [candidate], (
                    f"payload_too_large:{candidate_size}>{_MAX_ENVELOPE_BYTES}"
                )
            pending.extend(split)

        if len(ready) > 1:
            ready.sort(key=lambda entry: str(entry["delivery_id"]))
            for index, candidate in enumerate(ready, start=1):
                candidate["chunk_index"] = index
                candidate["chunk_count"] = len(ready)
        return ready, None

    def _queue_collected_data(self, section: str, data: Any) -> None:
        """Durably persist data before a collector cursor is committed."""
        if self._outbox is None:
            raise RuntimeError("delivery outbox is not initialized")

        transport_cfg = self._cfg.get("transport", {})
        min_free_mb = int(transport_cfg.get("min_free_mb", 128))
        free_mb = shutil.disk_usage(self._path("spool_dir")).free // (1024 * 1024)
        if free_mb < min_free_mb:
            self._connection_state = "disk_pressure"
            raise RuntimeError(
                f"outbox disk free space is {free_mb} MiB; "
                f"minimum is {min_free_mb} MiB"
            )

        messages, retained_error = self._prepare_messages(
            self._new_message(section, data)
        )
        if retained_error:
            self._outbox.enqueue_many(
                messages,
                state="dead",
                error=retained_error,
            )
            self._record_delivery("dead_lettered", len(messages))
            self._record_delivery("oversize_preserved", len(messages))
            log.error(
                "collection retained as dead letter section=%s reason=%s",
                section,
                retained_error,
            )
        else:
            self._outbox.enqueue_many(messages)
            self._record_delivery("durably_queued", len(messages))
        self._send_wake.set()

    @staticmethod
    def _rollback_collector(collector: Any) -> None:
        rollback = getattr(collector, "rollback", None)
        if callable(rollback):
            try:
                rollback()
            except Exception as exc:
                log.warning(
                    "collector cursor rollback failed collector=%s error=%s",
                    getattr(collector, "name", type(collector).__name__),
                    exc,
                )

    def _reliable_health_loop(self) -> None:
        """Publish local diagnostics and queue manager-visible health records."""
        while not self._stop_ev.is_set():
            try:
                collector_health: dict[str, Any] = {}
                for section, collector in self._collectors.items():
                    snapshot = getattr(collector, "health_snapshot", None)
                    if callable(snapshot):
                        section_health = snapshot()
                        if isinstance(section_health, dict):
                            section_health["enabled"] = (
                                section in self._active_intervals
                            )
                        collector_health[section] = section_health
                outbox_stats = self._outbox.stats() if self._outbox else {}
                health = {
                    "agent_uptime_sec": self._uptime_seconds(),
                    "connection_state": self._connection_state,
                    "conn_ok": self._conn_ok,
                    "platform": "windows",
                    "active_sections": len(self._active_intervals),
                    "disabled_sections": sorted(
                        set(_INTERVALS) - set(self._active_intervals)
                    ),
                    "circuit_states": {
                        section: breaker._state
                        for section, breaker in self._breakers.items()
                        if section in self._active_intervals
                    },
                    "outbox": outbox_stats,
                    "delivery": self._delivery_snapshot(),
                    "manager_clock_skew_sec": self._manager_clock_skew_sec,
                    "collectors": collector_health,
                    "integrity": dict(self._integrity_status),
                    "config_integrity": self._config_integrity_snapshot(),
                    "previous_lifecycle": dict(self._previous_lifecycle),
                    "power_events": list(self._power_events[-8:]),
                }
                self._publish_runtime_state("running", health)
                self._queue_collected_data("agent_health", health)
            except Exception as exc:
                log.warning("health heartbeat failed: %s", exc)
                self._publish_runtime_state(
                    "degraded",
                    {"health_error": f"{type(exc).__name__}: {exc}"},
                )
            if self._stop_ev.wait(_HEALTH_INTERVAL):
                break

    def _uptime_seconds(self) -> int:
        """Return process uptime using a clock unaffected by wall-clock jumps."""
        return max(0, int(time.monotonic() - self._started_monotonic))

    def _publish_runtime_state(
        self,
        status: str,
        health: dict[str, Any] | None = None,
    ) -> None:
        """Atomically publish a local heartbeat for watchdog diagnostics."""
        try:
            data_dir = Path(self._path("data_dir"))
            data_dir.mkdir(parents=True, exist_ok=True)
            state_path = data_dir / "agent.runtime.json"
            temp_path = data_dir / "agent.runtime.json.tmp"
            state = {
                "status": status,
                "pid": os.getpid(),
                "agent_id": self._agent_id,
                "updated_at": int(time.time()),
                "connection_state": self._connection_state,
                "outbox": self._outbox.stats() if self._outbox else {},
            }
            if health:
                state["health"] = health
            with temp_path.open("w", encoding="utf-8") as handle:
                json.dump(state, handle, separators=(",", ":"), default=str)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, state_path)

            # Publish a separate, non-sensitive operator surface. The status
            # directory has a read-only Users grant; secrets, raw responses,
            # collector output, config and credential material never enter it.
            status_dir = Path(self._path("status_dir"))
            status_dir.mkdir(parents=True, exist_ok=True)
            public_path = status_dir / "agent-status.json"
            public_temp = status_dir / "agent-status.json.tmp"
            manager_url = str(self._cfg.get("manager", {}).get("url") or "")
            delivery = self._delivery_snapshot()
            public_state = {
                "schema": 1,
                "product": "AttackLens Agent",
                "status": status,
                "pid": os.getpid(),
                "updated_at": int(time.time()),
                "connection_state": self._connection_state,
                "manager": {
                    "configured": bool(manager_url),
                    "endpoint": _public_manager_endpoint(manager_url),
                    "loopback": _manager_is_loopback(manager_url),
                },
                "delivery": {
                    key: delivery.get(key)
                    for key in (
                        "sent", "failed", "last_success_at", "last_failure_at",
                        "current_backoff_sec", "auth_failures",
                    )
                },
                "outbox": self._outbox.stats() if self._outbox else {},
            }
            with public_temp.open("w", encoding="utf-8") as handle:
                json.dump(public_state, handle, separators=(",", ":"), default=str)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(public_temp, public_path)
        except Exception as exc:
            log.debug("runtime state publish failed: %s", exc)

    def _config_integrity_snapshot(self) -> dict[str, Any]:
        if not self._config_path or not self._config_digest:
            return {"status": "unknown", "changed": None}
        try:
            from agent.os.windows.integrity import sha256_file

            current = sha256_file(self._config_path)
            return {
                "status": "changed" if current != self._config_digest else "verified",
                "changed": current != self._config_digest,
            }
        except OSError as exc:
            return {
                "status": "unreadable",
                "changed": None,
                "error": f"{type(exc).__name__}: {exc}",
            }

    def _consume_previous_lifecycle(self) -> dict[str, Any]:
        """Consume the prior clean-stop marker and classify the last exit."""
        data_dir = Path(self._path("data_dir"))
        marker = data_dir / "clean-stop.json"
        runtime_path = data_dir / "agent.runtime.json"
        result: dict[str, Any] = {
            "unexpected_stop": False,
            "classification": "first_start",
        }
        if marker.is_file():
            try:
                raw = json.loads(marker.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    result.update({
                        "classification": "clean",
                        "previous_stop_at": raw.get("stopped_at"),
                        "previous_stop_reason": raw.get("reason"),
                    })
            except Exception as exc:
                result.update({
                    "classification": "marker_corrupt",
                    "unexpected_stop": True,
                    "error": f"{type(exc).__name__}: {exc}",
                })
            finally:
                try:
                    marker.unlink(missing_ok=True)
                except OSError:
                    pass
            return result

        try:
            previous = json.loads(runtime_path.read_text(encoding="utf-8"))
            previous_status = str(previous.get("status", "unknown"))
            result.update({
                "classification": (
                    "unclean" if previous_status not in {"stopped"} else "legacy_clean"
                ),
                "unexpected_stop": previous_status not in {"stopped"},
                "previous_status": previous_status,
                "previous_updated_at": previous.get("updated_at"),
            })
        except FileNotFoundError:
            pass
        except Exception as exc:
            result.update({
                "classification": "runtime_state_corrupt",
                "unexpected_stop": True,
                "error": f"{type(exc).__name__}: {exc}",
            })
        return result

    def _write_clean_stop_marker(self) -> None:
        data_dir = Path(self._path("data_dir"))
        marker = data_dir / "clean-stop.json"
        temp = data_dir / "clean-stop.json.tmp"
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema": 1,
                "stopped_at": int(time.time()),
                "reason": self._stop_reason,
                "pid": os.getpid(),
            }
            with temp.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, marker)
        except Exception as exc:
            log.warning("clean-stop marker write failed: %s", exc)
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass

    def _migrate_legacy_spool(self) -> None:
        """Convert replay-expiring NDJSON envelopes into canonical outbox rows."""
        if self._outbox is None:
            return
        from agent.agent.crypto import decrypt

        spool_dir = Path(self._path("spool_dir"))
        legacy_paths = [
            spool_dir / "win_agent.spool.ndjson",
            spool_dir / "win_agent.spool.ndjson.draining",
        ]
        for legacy_path in legacy_paths:
            if not legacy_path.exists():
                continue
            messages: list[dict[str, Any]] = []
            try:
                with legacy_path.open("r", encoding="ascii") as handle:
                    for line_number, line in enumerate(handle, start=1):
                        if not line.strip():
                            continue
                        wire = base64.b64decode(line.strip(), validate=True)
                        envelope = json.loads(wire.decode("utf-8"))
                        inner = decrypt(envelope, self._enc_key, self._mac_key)
                        if not isinstance(inner, dict):
                            raise ValueError("decrypted legacy payload is not an object")
                        inner = dict(inner)
                        inner.setdefault("section", envelope.get("section", "unknown"))
                        inner.setdefault("agent_id", self._agent_id)
                        inner.setdefault("agent_name", self._agent_name)
                        inner.setdefault("agent_number", self._agent_number)
                        inner.setdefault("hostname", socket.gethostname())
                        inner.setdefault("os", "windows")
                        inner["delivery_id"] = (
                            "legacy-" + hashlib.sha256(wire).hexdigest()[:32]
                        )
                        messages.append(inner)
                if messages:
                    self._outbox.enqueue_many(messages)
                    self._record_delivery("durably_queued", len(messages))
                migrated = legacy_path.with_name(
                    legacy_path.name + f".migrated-{int(time.time())}"
                )
                os.replace(legacy_path, migrated)
                log.info(
                    "legacy spool migrated path=%s rows=%d preserved=%s",
                    legacy_path,
                    len(messages),
                    migrated,
                )
            except Exception as exc:
                log.error(
                    "legacy spool migration stopped path=%s error=%s; "
                    "original file retained",
                    legacy_path,
                    f"{type(exc).__name__}: {exc}",
                )

    @staticmethod
    def _response_detail(response: Any) -> str:
        try:
            body = response.json()
            if isinstance(body, dict):
                return str(
                    body.get("detail")
                    or body.get("error")
                    or body.get("status")
                    or body
                )[:512]
            return str(body)[:512]
        except Exception:
            return str(getattr(response, "text", "") or "")[:512]

    @staticmethod
    def _retry_after(response: Any) -> float:
        try:
            value = response.headers.get("Retry-After", "")
            return max(0.0, min(3600.0, float(value)))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _classify_send_exception(exc: Exception) -> str:
        try:
            import requests

            if isinstance(exc, requests.exceptions.SSLError):
                return "tls_error"
            if isinstance(exc, requests.exceptions.ConnectTimeout):
                return "connect_timeout"
            if isinstance(exc, requests.exceptions.ReadTimeout):
                return "read_timeout"
            if isinstance(exc, requests.exceptions.ProxyError):
                return "proxy_error"
            if isinstance(exc, requests.exceptions.ConnectionError):
                text = str(exc).lower()
                if "name or service not known" in text or "getaddrinfo" in text:
                    return "dns_error"
                if "reset" in text:
                    return "connection_reset"
                return "connection_error"
        except ImportError:
            pass
        return type(exc).__name__

    def _send_reliable(
        self,
        transport: Any,
        wire: bytes,
        delivery_id: str,
    ) -> dict[str, Any]:
        """Classify one manager response without deleting queued telemetry."""
        try:
            response = transport.post(
                "/api/v1/ingest",
                data=wire,
                extra_headers={
                    "X-Agent-ID": self._agent_id,
                    "X-Delivery-ID": delivery_id,
                    "Idempotency-Key": delivery_id,
                },
            )
        except Exception as exc:
            return {
                "action": "retry",
                "reason": self._classify_send_exception(exc),
                "status": None,
                "retry_after": 0.0,
            }

        status = int(response.status_code)
        detail = self._response_detail(response)
        detail_lower = detail.lower()
        try:
            from email.utils import parsedate_to_datetime

            date_value = response.headers.get("Date")
            if date_value:
                server_time = parsedate_to_datetime(date_value).timestamp()
                self._manager_clock_skew_sec = int(server_time - time.time())
        except Exception:
            pass

        if 200 <= status < 300:
            if status == 200:
                try:
                    body = response.json()
                    positive_status = (
                        str(body.get("status") or "").lower()
                        if isinstance(body, dict)
                        else ""
                    )
                    queued = (
                        body.get("queued") is True
                        if isinstance(body, dict)
                        else False
                    )
                    if positive_status not in {
                        "ok",
                        "accepted",
                        "queued",
                        "stored",
                        "success",
                    } and not queued:
                        return {
                            "action": "retry",
                            "reason": f"invalid_ack:{detail}",
                            "status": status,
                            "retry_after": 0.0,
                        }
                except Exception:
                    return {
                        "action": "retry",
                        "reason": f"invalid_ack:{detail}",
                        "status": status,
                        "retry_after": 0.0,
                    }
            return {"action": "ack", "reason": "accepted", "status": status}

        if status == 401 and "duplicate" in detail_lower and "nonce" in detail_lower:
            return {
                "action": "ack",
                "reason": "duplicate_nonce_ack",
                "status": status,
            }
        if status == 401 and "timestamp" in detail_lower:
            return {
                "action": "retry",
                "reason": "manager_timestamp_window",
                "status": status,
                "retry_after": 5.0,
            }
        if status in {401, 403}:
            return {
                "action": "auth",
                "reason": f"http_{status}:{detail}",
                "status": status,
                "retry_after": 60.0,
            }
        if status in {408, 425, 429} or status >= 500:
            return {
                "action": "retry",
                "reason": f"http_{status}:{detail}",
                "status": status,
                "retry_after": self._retry_after(response),
            }
        return {
            "action": "dead",
            "reason": f"http_{status}:{detail}",
            "status": status,
        }

    def _attempt_credential_refresh(self) -> bool:
        """Rotate credentials only when explicitly enabled with a token."""
        transport_cfg = self._cfg.get("transport", {})
        token = str(self._cfg.get("enrollment", {}).get("token") or "").strip()
        if not transport_cfg.get("auto_reenroll", False) or not token:
            return False
        if time.monotonic() - self._last_reenroll_at < 300:
            return False
        self._last_reenroll_at = time.monotonic()

        try:
            import platform
            from agent.agent.auto_enroll import client_key_path
            from agent.agent.client_key import (
                ClientKey,
                generate_agent_number,
                save,
            )
            from agent.agent.crypto import derive_keys

            manager_cfg = self._cfg["manager"]
            manager_url = str(manager_cfg["url"]).rstrip("/")
            response = self._post_enrollment_windows(
                payload={
                    "agent_id": self._agent_id,
                    "agent_name": self._agent_name,
                    "hostname": socket.gethostname(),
                    "os": "windows",
                    "arch": platform.machine(),
                    "timestamp": int(time.time()),
                },
                token=token,
            )
            api_key = str(response.get("api_key") or "").strip()
            if len(api_key) != 64:
                raise ValueError("manager returned an invalid replacement API key")
            agent_number = self._agent_number or generate_agent_number()
            replacement = ClientKey(
                agent_name=self._agent_name,
                agent_number=agent_number,
                token=api_key,
                issued_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                manager_url=manager_url,
            )
            new_enc_key, new_mac_key = derive_keys(api_key)
            save(client_key_path(self._cfg), replacement)
            with self._key_lock:
                self._enc_key = new_enc_key
                self._mac_key = new_mac_key
                self._agent_number = agent_number
            self._consecutive_auth_failures = 0
            self._connection_state = "credential_refreshed"
            log.warning("manager credentials refreshed after repeated auth failures")
            return True
        except Exception as exc:
            log.error(
                "automatic credential refresh failed: %s: %s",
                type(exc).__name__,
                exc,
            )
            return False

    def _reliable_sender_loop(self) -> None:
        """Drain the durable outbox with bounded retry and explicit ACK rules."""
        from agent.os.windows.tls_transport import WindowsTLSTransport

        manager_cfg = self._cfg["manager"]
        transport_cfg = self._cfg.get("transport", {})
        initial_backoff = float(transport_cfg.get("initial_backoff_sec", 5))
        max_backoff = float(transport_cfg.get("max_backoff_sec", 300))
        auth_threshold = int(transport_cfg.get("auth_failure_threshold", 3))
        transport: WindowsTLSTransport | None = None
        transport_backoff = initial_backoff

        try:
            while not self._stop_ev.is_set():
                manager_url = str(manager_cfg.get("url") or "").strip()
                if not manager_url:
                    self._connection_state = "manager_unconfigured"
                    self._conn_ok = False
                    self._send_wake.wait(30.0)
                    self._send_wake.clear()
                    continue

                with self._key_lock:
                    keys_ready = bool(self._enc_key and self._mac_key)
                if not keys_ready:
                    if self._enroll_if_needed(max_attempts=1):
                        transport_backoff = initial_backoff
                        continue
                    self._send_wake.wait(transport_backoff)
                    self._send_wake.clear()
                    transport_backoff = min(
                        max_backoff,
                        transport_backoff * 2.0,
                    )
                    continue

                if transport is None:
                    try:
                        transport = WindowsTLSTransport(
                            base_url=manager_cfg["url"],
                            spki_pin=manager_cfg.get("spki_pin") or None,
                            tls_verify=(
                                manager_cfg.get("ca_bundle")
                                or manager_cfg.get("tls_verify", True)
                            ),
                            timeout=(
                                min(
                                    30,
                                    max(1, int(manager_cfg.get("timeout_sec", 30))),
                                ),
                                max(
                                    1,
                                    int(manager_cfg.get("timeout_sec", _SEND_TIMEOUT)),
                                ),
                            ),
                            proxy_url=manager_cfg.get("proxy_url") or None,
                        )
                        transport_backoff = initial_backoff
                    except Exception as exc:
                        reason = self._classify_send_exception(exc)
                        self._connection_state = reason
                        self._conn_ok = False
                        self._set_delivery("last_failure_reason", reason)
                        self._set_delivery("last_failure_at", int(time.time()))
                        self._send_wake.wait(transport_backoff)
                        self._send_wake.clear()
                        transport_backoff = min(
                            max_backoff,
                            transport_backoff * 2.0,
                        )
                        continue

                item = self._outbox.next_due() if self._outbox else None
                if item is None:
                    delay = (
                        self._outbox.seconds_until_next(30.0)
                        if self._outbox
                        else 30.0
                    )
                    self._send_wake.wait(delay)
                    self._send_wake.clear()
                    continue

                try:
                    wire = self._wire_for_message(item.message)
                except Exception as exc:
                    self._outbox.retain_dead_letter(
                        item,
                        error=f"local_envelope_error:{type(exc).__name__}:{exc}",
                    )
                    self._record_delivery("dead_lettered")
                    continue
                if len(wire) > _MAX_ENVELOPE_BYTES:
                    self._outbox.retain_dead_letter(
                        item,
                        error=(
                            f"payload_too_large_after_queue:{len(wire)}>"
                            f"{_MAX_ENVELOPE_BYTES}"
                        ),
                    )
                    self._record_delivery("dead_lettered")
                    self._record_delivery("oversize_preserved")
                    continue

                result = self._send_reliable(
                    transport,
                    wire,
                    item.delivery_id,
                )
                action = result["action"]
                reason = str(result.get("reason") or action)
                status = result.get("status")

                if action == "ack":
                    self._outbox.acknowledge(item)
                    self._record_delivery("acknowledged")
                    self._record_delivery("sent")
                    if reason == "duplicate_nonce_ack":
                        self._record_delivery("duplicate_acks")
                    self._set_delivery("last_success_at", int(time.time()))
                    self._set_delivery("current_backoff_sec", 0)
                    self._consecutive_auth_failures = 0
                    self._connection_state = "healthy"
                    self._conn_ok = True
                    continue

                self._record_delivery("failed")
                self._set_delivery("last_failure_at", int(time.time()))
                self._set_delivery("last_failure_reason", reason)
                self._conn_ok = False

                if action == "dead":
                    self._outbox.retain_dead_letter(
                        item,
                        error=reason,
                        status_code=status,
                    )
                    self._record_delivery("dead_lettered")
                    self._connection_state = "manager_rejected_payload"
                    continue

                if action == "auth":
                    self._consecutive_auth_failures += 1
                    self._record_delivery("auth_failures")
                    self._connection_state = "authentication_failed"
                    refreshed = False
                    if self._consecutive_auth_failures >= auth_threshold:
                        refreshed = self._attempt_credential_refresh()
                    delay = 0.0 if refreshed else float(
                        result.get("retry_after") or max_backoff
                    )
                else:
                    self._connection_state = reason
                    server_delay = float(result.get("retry_after") or 0.0)
                    exponential = min(
                        max_backoff,
                        initial_backoff * (2 ** min(item.attempts, 10)),
                    )
                    delay = max(
                        server_delay,
                        random.uniform(exponential * 0.8, exponential * 1.2),
                    )
                    if reason in {
                        "tls_error",
                        "connect_timeout",
                        "connection_error",
                        "connection_reset",
                        "dns_error",
                        "proxy_error",
                    }:
                        try:
                            transport.close()
                        except Exception:
                            pass
                        transport = None

                self._outbox.retry(
                    item,
                    delay_sec=delay,
                    error=reason,
                    status_code=status,
                )
                self._record_delivery("retry_scheduled")
                self._set_delivery("current_backoff_sec", int(delay))
        except Exception as exc:
            self._connection_state = "sender_crashed"
            self._conn_ok = False
            log.exception(
                "reliable sender stopped unexpectedly; queued data remains on disk: %s",
                exc,
            )
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass

    def _sender_loop(self) -> None:
        mgr_cfg    = self._cfg["manager"]
        tls_verify = mgr_cfg.get("ca_bundle") or mgr_cfg.get("tls_verify", True)
        spki_pin   = mgr_cfg.get("spki_pin") or None

        from agent.os.windows.tls_transport import WindowsTLSTransport

        transport: WindowsTLSTransport | None = None
        try:
            transport = WindowsTLSTransport(
                base_url   = mgr_cfg["url"],
                spki_pin   = spki_pin,
                tls_verify = tls_verify,
                timeout    = (
                    min(30, max(1, int(mgr_cfg.get("timeout_sec", 30)))),
                    max(1, int(mgr_cfg.get("timeout_sec", _SEND_TIMEOUT))),
                ),
                proxy_url  = mgr_cfg.get("proxy_url") or None,
            )
        except Exception as exc:
            log.critical(
                "Sender cannot create TLS transport to %s: %s\n"
                "Payloads will be spooled to disk until the transport is fixed.",
                mgr_cfg.get("url"), exc,
            )
            self._conn_ok = False
            self._flush_queue_to_spool()
            return

        backoff          = 5.0
        spool_retry_after = 0.0  # monotonic timestamp; drain only when past this

        try:
            while not self._stop_ev.is_set():
                now = time.monotonic()

                # ── Spool drain ───────────────────────────────────────────────
                # Drain only when we believe the manager is reachable AND the
                # retry hold-off has expired (set on send/drain failure).
                if (self._spool and self._spool.size() > 0
                        and self._conn_ok and now >= spool_retry_after):
                    ok = self._drain_spool(transport)
                    if not ok:
                        # Mid-drain failure: hold off before next drain attempt
                        spool_retry_after = time.monotonic() + min(backoff * 2, 300.0)
                        self._conn_ok = False

                # ── Live queue ────────────────────────────────────────────────
                try:
                    envelope = self._send_q.get(timeout=1.0)
                except queue.Empty:
                    # When idle and spool is pending, probe /health periodically
                    # so we know when to start draining after an outage.
                    if (self._spool and self._spool.size() > 0
                            and not self._conn_ok
                            and time.monotonic() >= spool_retry_after):
                        if self._probe_health(transport):
                            log.info("manager reachable again — will drain spool")
                            self._conn_ok     = True
                            spool_retry_after = 0.0
                        else:
                            spool_retry_after = time.monotonic() + _SPOOL_PROBE_SEC
                    continue

                if self._send_one(transport, envelope):
                    # Successful live send → manager is reachable
                    self._conn_ok     = True
                    spool_retry_after = 0.0
                    backoff           = 5.0
                    self._set_delivery("current_backoff_sec", 0)
                else:
                    self._conn_ok = False
                    if self._spool:
                        self._spool.write(envelope)
                    log.debug("send failed — backing off %.0f s", backoff)
                    self._set_delivery("current_backoff_sec", int(backoff))
                    self._stop_ev.wait(backoff)
                    backoff           = min(backoff * 2.0, 300.0)
                    spool_retry_after = time.monotonic() + backoff

        except Exception as exc:
            log.error(
                "Sender loop crashed unexpectedly: %s: %s — "
                "flushing queue to spool for recovery on next restart",
                type(exc).__name__, exc,
            )
        finally:
            # Flush any remaining live-queue items to spool so they survive restart.
            self._flush_queue_to_spool()
            try:
                if transport is not None:
                    transport.close()
            except Exception:
                pass

    def _probe_health(self, transport: Any) -> bool:
        """Lightweight GET /health to confirm manager reachability before draining spool."""
        try:
            resp = transport.get("/health")
            return resp.status_code < 500
        except Exception:
            return False

    def _drain_spool(self, transport: Any) -> bool:
        """
        Atomically drain the spool and send all envelopes.

        On mid-batch failure: the failed envelope AND all remaining ones in the
        batch are written back to the spool so no data is lost. Returns True
        only if every envelope in the batch was sent successfully.
        """
        envelopes = self._spool.drain()
        if not envelopes:
            return True

        self._record_delivery("spool_drain_attempts")
        log.info("spool drain started: %d payloads", len(envelopes))

        for i, env in enumerate(envelopes):
            if self._stop_ev.is_set():
                # Agent is stopping — re-spool everything from current onwards
                for remaining in envelopes[i:]:
                    self._spool.write(remaining)
                log.info("spool drain interrupted at %d/%d — re-spooled %d",
                         i, len(envelopes), len(envelopes) - i)
                self._record_delivery("spool_drain_failures")
                return False

            if not self._send_one(transport, env):
                # Re-spool the failed envelope and ALL that follow it
                for remaining in envelopes[i:]:
                    self._spool.write(remaining)
                log.warning("spool drain failed at %d/%d — re-spooled %d payloads",
                            i + 1, len(envelopes), len(envelopes) - i)
                self._record_delivery("spool_drain_failures")
                return False

        self._record_delivery("spool_drained", len(envelopes))
        log.info("spool drain complete: sent %d payloads", len(envelopes))
        return True

    def _flush_queue_to_spool(self) -> None:
        """
        On shutdown: drain the in-memory queue into the spool so that payloads
        collected during the current run are not silently lost on process exit.
        """
        if self._spool is None:
            return
        count = 0
        while True:
            try:
                self._spool.write(self._send_q.get_nowait())
                count += 1
            except queue.Empty:
                break
        if count:
            log.info("shutdown flush: spooled %d unsent payloads", count)

    def _send_one(self, transport: Any, envelope: bytes) -> bool:
        """
        POST one wire envelope to the manager.
        Returns True if the payload was accepted or should be discarded (4xx).
        Returns False if the manager is unreachable or returned a 5xx.
        """
        try:
            resp = transport.post(
                "/api/v1/ingest",
                data=envelope,
                extra_headers={"X-Agent-ID": self._agent_id},
            )
            if resp.status_code == 200:
                self._record_delivery("sent")
                self._set_delivery("last_success_at", int(time.time()))
                return True
            if resp.status_code in (401, 403):
                # Key revoked or expired — operator must re-enroll.
                # Discard the payload (retrying won't help without a new key).
                log.error(
                    "manager returned HTTP %d — API key may be revoked or expired. "
                    "Delete security/client.key and restart to trigger re-enrollment.",
                    resp.status_code,
                )
                self._record_delivery("discarded")
                self._set_delivery("last_failure_at", int(time.time()))
                self._set_delivery("last_failure_reason", f"http_{resp.status_code}")
                return True  # discard; not a transport error
            if 400 <= resp.status_code < 500:
                log.warning("manager rejected payload HTTP %d — discarding",
                            resp.status_code)
                self._record_delivery("discarded")
                self._set_delivery("last_failure_at", int(time.time()))
                self._set_delivery("last_failure_reason", f"http_{resp.status_code}")
                return True  # bad payload — won't get better on retry
            log.debug("manager HTTP %d", resp.status_code)
            self._record_delivery("failed")
            self._set_delivery("last_failure_at", int(time.time()))
            self._set_delivery("last_failure_reason", f"http_{resp.status_code}")
            return False
        except Exception as exc:
            log.debug("send error: %s", exc)
            self._record_delivery("failed")
            self._set_delivery("last_failure_at", int(time.time()))
            self._set_delivery("last_failure_reason", type(exc).__name__)
            return False

    # ── Envelope construction ─────────────────────────────────────────────────

    def _build_envelope(self, section: str, data: Any) -> bytes:
        """Compress, encrypt, and HMAC-sign a section payload."""
        return self._wire_for_message(self._new_message(section, data))

        # Legacy implementation retained below for source compatibility with
        # older tests; runtime delivery uses canonical outbox messages above.
        from agent.agent.crypto import encrypt

        if not self._enc_key or not self._mac_key:
            # Should never happen after run() completes enrollment successfully.
            raise RuntimeError(
                "Cannot encrypt payload — keys are not set. "
                "Enrollment did not complete before collection started."
            )

        ts    = int(time.time())
        inner = {
            "section":      section,
            "agent_id":     self._agent_id,
            "agent_name":   self._agent_name,
            "agent_number": self._agent_number,
            "collected_at": ts,
            "data":         data,
        }
        envelope             = encrypt(inner, self._enc_key, self._mac_key,
                                       self._agent_id, ts)
        envelope["section"]  = section   # plaintext field for manager routing
        wire = json.dumps(envelope, separators=(",", ":")).encode()
        if len(wire) > _MAX_ENVELOPE_BYTES:
            self._record_delivery("oversize_dropped")
            raise ValueError(
                f"encrypted {section} payload is {len(wire)} bytes; "
                f"maximum is {_MAX_ENVELOPE_BYTES} bytes"
            )
        return wire

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _path(self, key: str) -> str:
        return (self._cfg.get("paths", {}).get(key) or _DEFAULTS[key])

    def _record_delivery(self, key: str, amount: int = 1) -> None:
        with self._stats_lock:
            self._delivery_stats[key] = self._delivery_stats.get(key, 0) + amount

    def _set_delivery(self, key: str, value: Any) -> None:
        with self._stats_lock:
            self._delivery_stats[key] = value

    def _delivery_snapshot(self) -> dict[str, Any]:
        with self._stats_lock:
            return dict(self._delivery_stats)

    def _build_active_intervals(self) -> dict[str, int]:
        """
        Build the section → interval_sec map from:
          1. [collection.sections.<name>] in agent.toml  (operator overrides)
          2. _INTERVALS module-level defaults
        Sections with enabled = false are excluded entirely.
        """
        cfg_secs = self._cfg.get("collection", {}).get("sections", {})
        active: dict[str, int] = {}
        for section, default_interval in _INTERVALS.items():
            sec = cfg_secs.get(section, {})
            if not sec.get("enabled", True):
                continue
            interval = sec.get("interval_sec", default_interval)
            try:
                active[section] = max(1, int(interval))
            except (TypeError, ValueError):
                active[section] = default_interval
        return active

    def _setup_logging(self) -> None:
        log_cfg      = self._cfg.get("logging", {})
        level        = getattr(logging,
                               log_cfg.get("level", _DEFAULTS["log_level"]).upper(),
                               logging.INFO)
        log_file     = log_cfg.get("file", _DEFAULTS["log_file"])
        max_bytes    = int(log_cfg.get("max_mb",  10)) * 1024 * 1024
        backup_count = int(log_cfg.get("backups", 5))

        handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                handlers.append(logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding="utf-8",
                ))
            except OSError as exc:
                print(f"WARNING: cannot open log file {log_file}: {exc}",
                      file=sys.stderr)

        logging.basicConfig(
            level=level,
            format="%(asctime)s %(name)-32s %(levelname)s %(message)s",
            handlers=handlers,
        )

    def _wait_for_stop(
        self,
        win32_stop_event: Any,
        *,
        critical_threads: tuple[threading.Thread, ...] = (),
    ) -> None:
        """Block until stop() is called or win32_stop_event is signalled by SCM."""
        win32event = None
        if win32_stop_event is not None:
            try:
                import win32event as _win32event

                win32event = _win32event
            except ImportError:
                win32event = None

        while not self._stop_ev.is_set():
            dead = [thread.name for thread in critical_threads if not thread.is_alive()]
            if dead:
                self._fatal_runtime_error = (
                    "critical runtime thread exited unexpectedly: "
                    + ", ".join(dead)
                )
                log.critical(self._fatal_runtime_error)
                return
            if win32event is not None:
                rc = win32event.WaitForSingleObject(win32_stop_event, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    return
            else:
                self._stop_ev.wait(1.0)


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    import signal
    from agent.os.windows.config_model import ConfigValidationError

    parser = argparse.ArgumentParser(description="AttackLens Windows Agent")
    parser.add_argument(
        "--config",
        default=os.path.join(_ATTACKLENS_DATA, "config", "agent.toml"),
        help="Path to agent.toml",
    )
    parser.add_argument(
        "--collect-once",
        action="store_true",
        help="Collect all sections once, print JSON, and exit (no manager needed)",
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate agent.toml and exit without network, enrollment, or collection",
    )
    args = parser.parse_args()

    try:
        agent = WindowsAgent.from_config(args.config)
    except ConfigValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

    if args.validate_config:
        print(f"OK: valid Windows agent config: {args.config}")
        return

    if args.collect_once:
        import json as _json
        print(_json.dumps(agent.collect_once(), indent=2, default=str))
        return

    def _on_signal(sig: int, _frame: Any) -> None:
        log.info("Signal %d received — stopping agent", sig)
        agent.stop()

    signal.signal(signal.SIGINT,  _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    agent.run()


if __name__ == "__main__":
    main()
