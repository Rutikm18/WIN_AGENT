"""
agent/os/windows/win_agent.py — Self-contained Windows endpoint agent.

This is the primary "function" for Windows.  Call WindowsAgent.run() to start
the full collection-encrypt-send loop.  macOS serves as the data-point schema
reference — every section output is normalised to the same canonical schema
used by the macOS agent (handled by agent/os/windows/normalizer.py).

Architecture
────────────
  WindowsAgent.run()
    ├─ _enroll_if_needed()   — DPAPI-backed key via agent.os.windows.keystore
    ├─ _load_collectors()    — all 22 standard + eventlog (Windows-only)
    ├─ per-section threads   — _collect_loop() × N, circuit-breaker guarded
    ├─ sender thread         — _sender_loop() with disk spool + backoff
    └─ heartbeat thread      — _health_loop() every 60 s

Security model
──────────────
  Transport:       TLS 1.3 minimum; optional SPKI certificate pinning
  Confidentiality: AES-256-GCM (96-bit random nonce per payload)
  Integrity:       GCM authentication tag + HMAC-SHA256 over wire envelope
  Key derivation:  HKDF-SHA256 → enc_key + mac_key (domain-separated)
  Key storage:     DPAPI Credential Manager → DPAPI file → ACL-restricted file
  Enrollment:      TLS-protected; enrollment token never stored on disk
  Replay defence:  ±300 s timestamp window + per-nonce dedup (server-side)

Configuration (agent.toml)
──────────────────────────
  [agent]
  id   = "workstation-001"
  name = "Alice's Workstation"

  [manager]
  url        = "https://manager.example.com"
  tls_verify = true          # or path to CA cert
  spki_pin   = "sha256//..."  # optional — leave blank to skip pinning

  [enrollment]
  token = "sk-enroll-..."

  [paths]
  security_dir = 'C:\\Program Files (x86)\\Jarvis\\security'
  spool_dir    = 'C:\\Program Files (x86)\\Jarvis\\spool'

  [logging]
  level = "INFO"
  file  = 'C:\\Program Files (x86)\\Jarvis\\logs\\win_agent.log'

Windows Service integration
───────────────────────────
  service.py calls:
    agent = WindowsAgent.from_config(config_path)
    agent.run(win32_stop_event=self._stop_event)

CLI (foreground / debug)
────────────────────────
  python -m agent.os.windows.win_agent --config path\\to\\agent.toml
  python -m agent.os.windows.win_agent --config path\\to\\agent.toml --collect-once
"""
from __future__ import annotations

import json
import logging
import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-reuse-import]

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
    "eventlog":    300,   # Windows-only: security events, last 24 hrs
}

_HEALTH_INTERVAL = 60    # seconds between agent_health heartbeats
_QUEUE_MAXSIZE   = 512   # drop-oldest-to-spool above this depth
_SEND_TIMEOUT    = 30    # seconds per POST to manager

# ── Defaults ──────────────────────────────────────────────────────────────────

_PROGRAMDATA = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
_JARVIS_DATA = os.path.join(_PROGRAMDATA, "Jarvis")

_DEFAULTS = {
    "security_dir": os.path.join(_JARVIS_DATA, "security"),
    "spool_dir":    os.path.join(_JARVIS_DATA, "spool"),
    "log_file":     os.path.join(_JARVIS_DATA, "logs", "agent.log"),
    "log_level":    "INFO",
}


# ── Circuit breaker ───────────────────────────────────────────────────────────

class _CircuitBreaker:
    """
    Three-state per-section circuit breaker: CLOSED → OPEN (on N failures)
    → HALF (after backoff) → CLOSED (on success).

    Prevents a broken collector from saturating the send queue with errors.
    """
    _THRESHOLD = 3      # consecutive failures to trip
    _BACKOFF   = 300    # seconds before trying again (OPEN → HALF)

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
            log.warning("circuit OPEN: section=%s after %d failures",
                        self._section, self._failures)


# ── Disk spool ────────────────────────────────────────────────────────────────

_SPOOL_MAX_BYTES = 50 * 1024 * 1024   # 50 MB hard cap


class _DiskSpool:
    """
    Append-only NDJSON spool for resilient payload delivery.
    Payloads are stored as base64-encoded wire envelopes — identical format
    to what the sender would POST.  The spool is drained atomically (rename
    then read) so the writer never reads a partial drain.
    """

    def __init__(self, spool_dir: str) -> None:
        self._dir  = Path(spool_dir)
        self._path = self._dir / "win_agent.spool.ndjson"
        self._lock = threading.Lock()
        self._dir.mkdir(parents=True, exist_ok=True)

    def write(self, envelope_json: bytes) -> None:
        """Append one wire envelope to the spool (thread-safe)."""
        import base64
        line = base64.b64encode(envelope_json).decode() + "\n"
        with self._lock:
            try:
                if self._path.exists() and self._path.stat().st_size >= _SPOOL_MAX_BYTES:
                    log.warning("spool at %d MB cap — dropping payload",
                                _SPOOL_MAX_BYTES // (1024 * 1024))
                    return
                with open(self._path, "a", encoding="ascii") as f:
                    f.write(line)
            except OSError as exc:
                log.debug("spool write error: %s", exc)

    def drain(self) -> list[bytes]:
        """
        Atomically consume and return all spooled envelopes.
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
                    if line:
                        try:
                            envelopes.append(base64.b64decode(line))
                        except Exception:
                            pass
        finally:
            tmp.unlink(missing_ok=True)
        return envelopes

    def size(self) -> int:
        try:
            return self._path.stat().st_size
        except OSError:
            return 0


# ── WindowsAgent ──────────────────────────────────────────────────────────────

class WindowsAgent:
    """
    Self-contained Windows endpoint agent.

    The public interface is intentionally narrow:
      WindowsAgent.from_config(path) → agent
      agent.run()                    → blocks until stop()
      agent.stop()                   → signals the run() loop to exit
      agent.collect_once()           → returns all sections as a dict (for testing)
    """

    def __init__(self, cfg: dict) -> None:
        self._cfg          = cfg
        self._agent_id     = cfg["agent"]["id"]
        self._agent_name   = cfg["agent"].get("name", socket.gethostname())
        self._agent_number = ""   # filled in by _enroll_if_needed from client.key
        self._stop_ev      = threading.Event()
        self._send_q: queue.Queue[bytes] = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._breakers:   dict[str, _CircuitBreaker] = {}
        self._collectors: dict[str, Any]             = {}
        self._enc_key: bytes = b""
        self._mac_key: bytes = b""
        self._spool:   _DiskSpool | None = None

    @classmethod
    def from_config(cls, config_path: str) -> "WindowsAgent":
        with open(config_path, "rb") as fh:
            cfg = tomllib.load(fh)
        return cls(cfg)

    # ── Public interface ──────────────────────────────────────────────────────

    def run(self, win32_stop_event: Any = None) -> None:
        """
        Main agent loop.  Blocks until stop() is called.

        win32_stop_event: an integer win32event handle returned by
        win32event.CreateEvent() — when set by SCM, the loop exits gracefully.
        Pass None for foreground (CLI) mode.
        """
        self._setup_logging()
        log.info("Windows agent starting  agent_id=%s  name=%s",
                 self._agent_id, self._agent_name)

        self._enroll_if_needed()
        self._load_collectors()
        self._spool = _DiskSpool(self._path("spool_dir"))

        threads: list[threading.Thread] = []

        # One collection thread per section
        for section in _INTERVALS:
            t = threading.Thread(
                target=self._collect_loop, args=(section,),
                daemon=True, name=f"col-{section}",
            )
            threads.append(t)
            t.start()

        # Sender thread
        sender_t = threading.Thread(
            target=self._sender_loop, daemon=True, name="win-sender"
        )
        threads.append(sender_t)
        sender_t.start()

        # Health heartbeat thread
        hb_t = threading.Thread(
            target=self._health_loop, daemon=True, name="win-health"
        )
        threads.append(hb_t)
        hb_t.start()

        log.info("Agent running: %d collector threads + sender + heartbeat",
                 len(_INTERVALS))

        # Block main thread until stop is requested
        self._wait_for_stop(win32_stop_event)
        log.info("Agent stopping")
        self._stop_ev.set()

        # Give sender a moment to flush the queue
        sender_t.join(timeout=10)
        log.info("Agent stopped")

    def stop(self) -> None:
        self._stop_ev.set()

    def collect_once(self) -> dict[str, Any]:
        """
        Run every collector synchronously and return the raw output.
        Useful for testing and one-shot inventory snapshots.
        Does NOT require keys or a manager connection.
        """
        self._load_collectors()
        results: dict[str, Any] = {}
        from agent.os.windows.normalizer import normalize
        for section, collector in self._collectors.items():
            try:
                raw    = collector()
                results[section] = normalize(section, raw)
            except Exception as exc:
                results[section] = {"error": str(exc)}
        return results

    # ── Key management ────────────────────────────────────────────────────────

    def _enroll_if_needed(self) -> None:
        """
        Auto-enrollment via client.key.

        On first run: contacts the manager, gets a token, writes client.key.
        On subsequent runs: reads client.key directly - no network call needed.

        client.key location: <security_dir>/client.key
        """
        from agent.agent.auto_enroll import get_or_enroll
        from agent.agent.crypto import derive_keys

        client_key = get_or_enroll(self._cfg)

        # Use the token from client.key as the symmetric key for crypto
        self._enc_key, self._mac_key = derive_keys(client_key.token)

        # Sync agent identity from client.key (authoritative after enrollment)
        self._agent_name   = client_key.agent_name
        self._agent_number = client_key.agent_number

        log.info(
            "Ready: agent_name=%r agent_number=%s",
            self._agent_name, self._agent_number,
        )

    # ── Collector setup ───────────────────────────────────────────────────────

    def _load_collectors(self) -> None:
        from agent.os.windows.collectors.volatile  import MetricsCollector, ConnectionsCollector, ProcessesCollector
        from agent.os.windows.collectors.network   import PortsCollector, NetworkCollector, ArpCollector, MountsCollector
        from agent.os.windows.collectors.system    import (BatteryCollector, OpenFilesCollector,
                                                            ServicesCollector, UsersCollector,
                                                            HardwareCollector, ContainersCollector)
        from agent.os.windows.collectors.posture   import SecurityCollector, SysctlCollector, ConfigsCollector
        from agent.os.windows.collectors.inventory import (StorageCollector, TasksCollector,
                                                            AppsCollector, PackagesCollector,
                                                            BinariesCollector, SbomCollector)
        from agent.os.windows.collectors.eventlog  import EventLogCollector

        all_collectors = [
            MetricsCollector(),     ConnectionsCollector(),  ProcessesCollector(),
            PortsCollector(),       NetworkCollector(),      ArpCollector(),
            MountsCollector(),      BatteryCollector(),      OpenFilesCollector(),
            ServicesCollector(),    UsersCollector(),        HardwareCollector(),
            ContainersCollector(),  SecurityCollector(),     SysctlCollector(),
            ConfigsCollector(),     StorageCollector(),      TasksCollector(),
            AppsCollector(),        PackagesCollector(),     BinariesCollector(),
            SbomCollector(),        EventLogCollector(),
        ]

        for c in all_collectors:
            self._collectors[c.name] = c
            self._breakers[c.name]   = _CircuitBreaker(c.name)

    # ── Collection loop ───────────────────────────────────────────────────────

    def _collect_loop(self, section: str) -> None:
        from agent.os.windows.normalizer import normalize

        interval  = _INTERVALS.get(section, 300)
        breaker   = self._breakers[section]
        collector = self._collectors.get(section)
        if not collector:
            return

        next_run = time.monotonic()   # run immediately on first pass

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
                envelope = self._build_envelope(section, data)
                breaker.success()
                try:
                    self._send_q.put_nowait(envelope)
                except queue.Full:
                    log.debug("queue full — spooling %s", section)
                    if self._spool:
                        self._spool.write(envelope)
            except Exception as exc:
                log.debug("collect[%s] error: %s", section, exc)
                breaker.failure()

            next_run = time.monotonic() + interval

    # ── Health heartbeat ──────────────────────────────────────────────────────

    def _health_loop(self) -> None:
        import psutil
        while not self._stop_ev.wait(_HEALTH_INTERVAL):
            try:
                health = {
                    "uptime_sec":    int(time.time() - psutil.boot_time()),
                    "queue_depth":   self._send_q.qsize(),
                    "spool_bytes":   self._spool.size() if self._spool else 0,
                    "circuit_states": {s: b._state for s, b in self._breakers.items()},
                    "platform":      "windows",
                }
                envelope = self._build_envelope("agent_health", health)
                try:
                    self._send_q.put_nowait(envelope)
                except queue.Full:
                    pass
            except Exception as exc:
                log.debug("health heartbeat error: %s", exc)

    # ── Sender loop ───────────────────────────────────────────────────────────

    def _sender_loop(self) -> None:
        mgr_cfg    = self._cfg["manager"]
        tls_verify = mgr_cfg.get("tls_verify", True)
        spki_pin   = mgr_cfg.get("spki_pin") or None

        from agent.os.windows.tls_transport import WindowsTLSTransport
        transport = WindowsTLSTransport(
            base_url   = mgr_cfg["url"],
            spki_pin   = spki_pin,
            tls_verify = tls_verify,
            timeout    = (15, _SEND_TIMEOUT),
        )

        backoff = 5.0

        try:
            while not self._stop_ev.is_set():
                # Drain disk spool first whenever it has data
                if self._spool and self._spool.size() > 0:
                    for env in self._spool.drain():
                        if not self._send_one(transport, env):
                            self._spool.write(env)
                            break   # stop draining; wait for reconnect

                # Consume one envelope from the live queue
                try:
                    envelope = self._send_q.get(timeout=1.0)
                except queue.Empty:
                    continue

                if self._send_one(transport, envelope):
                    backoff = 5.0
                else:
                    if self._spool:
                        self._spool.write(envelope)
                    log.debug("send failed — backing off %.0f s", backoff)
                    self._stop_ev.wait(backoff)
                    backoff = min(backoff * 2.0, 300.0)

        finally:
            transport.close()

    def _send_one(self, transport: Any, envelope: bytes) -> bool:
        try:
            resp = transport.post(
                "/api/v1/ingest",
                data=envelope,
                extra_headers={
                    "X-Agent-ID": self._agent_id,
                },
            )
            if resp.status_code == 200:
                return True
            if 400 <= resp.status_code < 500:
                # 4xx = bad payload — log and discard (do not spool)
                log.warning("manager rejected payload HTTP %d — discarding",
                            resp.status_code)
                return True
            log.debug("manager HTTP %d", resp.status_code)
            return False
        except Exception as exc:
            log.debug("send error: %s", exc)
            return False

    # ── Envelope construction ─────────────────────────────────────────────────

    def _build_envelope(self, section: str, data: Any) -> bytes:
        """
        Compress, encrypt, and sign a section payload.
        Returns the JSON wire envelope as UTF-8 bytes.
        """
        from agent.agent.crypto import encrypt

        ts       = int(time.time())
        inner    = {
            "section":      section,
            "agent_id":     self._agent_id,
            "agent_name":   self._agent_name,
            "agent_number": self._agent_number,
            "collected_at": ts,
            "data":         data,
        }
        envelope = encrypt(inner, self._enc_key, self._mac_key,
                           self._agent_id, ts)
        envelope["section"] = section   # plaintext field for manager routing
        return json.dumps(envelope, separators=(",", ":")).encode()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _path(self, key: str) -> str:
        return (
            self._cfg.get("paths", {}).get(key)
            or _DEFAULTS[key]
        )

    def _setup_logging(self) -> None:
        log_cfg  = self._cfg.get("logging", {})
        level    = getattr(logging, log_cfg.get("level", _DEFAULTS["log_level"]).upper(),
                           logging.INFO)
        log_file = log_cfg.get("file", _DEFAULTS["log_file"])

        handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
            except OSError as exc:
                print(f"WARNING: cannot open log file {log_file}: {exc}", file=sys.stderr)

        logging.basicConfig(
            level=level,
            format="%(asctime)s %(name)-32s %(levelname)s %(message)s",
            handlers=handlers,
        )

    def _wait_for_stop(self, win32_stop_event: Any) -> None:
        """
        Block until stop() is called or win32_stop_event is signalled by SCM.
        win32_stop_event may be:
          None  → block on self._stop_ev (foreground / threading mode)
          int   → a win32event handle returned by win32event.CreateEvent()
        """
        if win32_stop_event is None:
            self._stop_ev.wait()
            return

        # Windows Service: poll both the SCM event and our threading.Event
        try:
            import win32event
            while not self._stop_ev.is_set():
                rc = win32event.WaitForSingleObject(win32_stop_event, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
        except ImportError:
            # pywin32 not available — fall back to threading.Event
            self._stop_ev.wait()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    import signal

    parser = argparse.ArgumentParser(description="Jarvis Windows Agent")
    parser.add_argument(
        "--config",
        default=r"C:\Program Files (x86)\Jarvis\config\agent.toml",
        help="Path to agent.toml",
    )
    parser.add_argument(
        "--collect-once",
        action="store_true",
        help="Collect all sections once, print JSON, and exit (no manager needed)",
    )
    args = parser.parse_args()

    agent = WindowsAgent.from_config(args.config)

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
