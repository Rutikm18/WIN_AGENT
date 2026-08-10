"""
agent/agent.py — Main orchestrator
Reads agent.toml, schedules collectors, encrypts, sends to manager.

Usage:
    python3 agent/agent.py [--config path/to/agent.toml]

Signal handling:
    SIGTERM / SIGINT  → graceful shutdown
    SIGHUP            → reload config (change intervals without restart)
"""

import argparse
import logging
import logging.handlers
import os
import queue
import signal
import sys
import threading
import time

# ── Config ────────────────────────────────────────────────────────────────────
try:
    import tomllib                          # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib             # backport: pip install tomli
    except ImportError:
        print("ERROR: Python 3.11+ required, or: pip install tomli", file=sys.stderr)
        sys.exit(1)

import platform
import socket

from .crypto          import derive_keys, encrypt
from .enrollment      import enroll, EnrollmentError
from .keystore        import load_key, store_key
from .circuit_breaker import CircuitBreakerRegistry

# ── OS-aware path defaults ────────────────────────────────────────────────────
if sys.platform == "darwin":
    _DEFAULT_LOG_FILE  = "/Library/Jarvis/logs/agent.log"
    _DEFAULT_SPOOL_DIR = "/Library/Jarvis/spool"
    _DEFAULT_SECURITY  = "/Library/Jarvis/security"
    _DEFAULT_CONFIG    = "/Library/Jarvis/agent.toml"
elif sys.platform == "win32":
    _DEFAULT_LOG_FILE  = r"C:\Program Files (x86)\Jarvis\logs\agent.log"
    _DEFAULT_SPOOL_DIR = r"C:\Program Files (x86)\Jarvis\spool"
    _DEFAULT_SECURITY  = r"C:\Program Files (x86)\Jarvis\security"
    _DEFAULT_CONFIG    = r"C:\Program Files (x86)\Jarvis\config\agent.toml"
else:
    _DEFAULT_LOG_FILE  = "/var/log/jarvis/agent.log"
    _DEFAULT_SPOOL_DIR = "/var/lib/jarvis/spool"
    _DEFAULT_SECURITY  = "/var/lib/jarvis/security"
    _DEFAULT_CONFIG    = "/etc/jarvis/agent.toml"

# ── Built-in default collection schedule (used when [collection.sections] absent) ──
_DEFAULT_SECTIONS: dict = {
    "metrics":     {"enabled": True,  "interval_sec": 60,    "send": True},
    "connections": {"enabled": True,  "interval_sec": 60,    "send": True},
    "processes":   {"enabled": True,  "interval_sec": 60,    "send": True},
    "ports":       {"enabled": True,  "interval_sec": 30,    "send": True},
    "network":     {"enabled": True,  "interval_sec": 120,   "send": True},
    "arp":         {"enabled": True,  "interval_sec": 120,   "send": True},
    "mounts":      {"enabled": True,  "interval_sec": 120,   "send": True},
    "battery":     {"enabled": True,  "interval_sec": 120,   "send": True},
    "openfiles":   {"enabled": True,  "interval_sec": 120,   "send": True},
    "services":    {"enabled": True,  "interval_sec": 120,   "send": True},
    "users":       {"enabled": True,  "interval_sec": 120,   "send": True},
    "hardware":    {"enabled": True,  "interval_sec": 120,   "send": True},
    "containers":  {"enabled": True,  "interval_sec": 120,   "send": True},
    "storage":     {"enabled": True,  "interval_sec": 600,   "send": True},
    "tasks":       {"enabled": True,  "interval_sec": 600,   "send": True},
    "security":    {"enabled": True,  "interval_sec": 3600,  "send": True},
    "sysctl":      {"enabled": True,  "interval_sec": 3600,  "send": True},
    "configs":     {"enabled": True,  "interval_sec": 3600,  "send": True},
    "apps":        {"enabled": True,  "interval_sec": 86400, "send": True},
    "packages":    {"enabled": True,  "interval_sec": 86400, "send": True},
    "binaries":    {"enabled": False, "interval_sec": 86400, "send": False},
    "sbom":        {"enabled": True,  "interval_sec": 86400, "send": True},
}

# ── OS-aware collector + normalizer loading ───────────────────────────────────
if sys.platform == "win32":
    try:
        from agent.os.windows.collectors import COLLECTORS
        from agent.os.windows.normalizer import normalize as _normalize
        _HAS_NORMALIZER = True
    except Exception as _e:
        log_init = logging.getLogger("agent")
        log_init.warning("Windows collectors unavailable (%s) — using empty registry", _e)
        COLLECTORS: dict = {}
        _HAS_NORMALIZER = False
elif sys.platform == "darwin":
    try:
        from agent.os.macos.collectors import COLLECTORS
        from agent.os.macos.normalizer import normalize as _normalize
        _HAS_NORMALIZER = True
    except Exception as _e:
        log_init = logging.getLogger("agent")
        log_init.warning("macOS collectors unavailable (%s) — falling back to generic", _e)
        from .collectors import COLLECTORS
        try:
            from .normalizer import normalize as _normalize
            _HAS_NORMALIZER = True
        except Exception:
            _HAS_NORMALIZER = False
else:
    from .collectors import COLLECTORS   # Linux / generic collector registry
    try:
        from .normalizer import normalize as _normalize
        _HAS_NORMALIZER = True
    except Exception:
        _HAS_NORMALIZER = False

# Cached at startup — never changes during the process lifetime
_OS_NAME   = "macos" if sys.platform == "darwin" else ("linux" if sys.platform.startswith("linux") else "windows")
_OS_VER    = platform.mac_ver()[0] if sys.platform == "darwin" else platform.version()
_ARCH      = platform.machine()
_HOSTNAME  = socket.gethostname()

# How often to push a synthetic agent_health section (circuit-breaker snapshot)
_HEALTH_INTERVAL_SEC = 60
_START_TIME          = time.time()


# ─────────────────────────────────────────────────────────────────────────────
#  Orchestrator  (with circuit breakers + health heartbeat)
# ─────────────────────────────────────────────────────────────────────────────

class Orchestrator:
    """
    Schedules all collection sections, encrypts payloads, enqueues for sender.

    Features
    ────────
    • Per-section circuit breakers: CLOSED → OPEN → HALF-OPEN state machine.
      Failing sections are skipped and probed again after cooldown (60 s default).
    • Health heartbeat: synthetic agent_health payload every 60 s containing
      circuit-breaker snapshot, queue depth, and uptime.
    • Thread-pool execution: collectors run concurrently (one slot each).
    • Graceful shutdown via _stop event.
    """

    def __init__(self, config: dict, enc_key: bytes, mac_key: bytes,
                 send_queue: "queue.Queue"):
        self.config     = config
        self.enc_key    = enc_key
        self.mac_key    = mac_key
        self.send_queue = send_queue
        self.agent_id   = config["agent"]["id"]
        self.tick       = config.get("collection", {}).get("tick_sec", 5)
        self._stop      = threading.Event()
        self._last_run: dict[str, float] = {}
        self._last_health = 0.0
        self._executor  = None
        self._cbr       = CircuitBreakerRegistry(fail_threshold=3, cooldown_sec=60)

    def start(self):
        import concurrent.futures
        self._stop.clear()
        self._last_run    = {}
        self._last_health = 0.0
        self._executor    = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(4, len(COLLECTORS)),
            thread_name_prefix="collector",
        )
        t = threading.Thread(target=self._tick_loop, daemon=True,
                             name="orchestrator")
        t.start()
        log.info("Orchestrator started — %d sections, circuit breakers active",
                 len(self._sections()))
        return t

    def stop(self):
        self._stop.set()
        if self._executor:
            self._executor.shutdown(wait=False)

    def _sections(self) -> dict:
        cfg_sections = self.config.get("collection", {}).get("sections", {})
        if cfg_sections:
            return cfg_sections
        # No [collection.sections] in config — use built-in defaults
        return _DEFAULT_SECTIONS

    def _tick_loop(self):
        while not self._stop.is_set():
            now = time.time()

            # ── Health heartbeat ──────────────────────────────────────────────
            if now - self._last_health >= _HEALTH_INTERVAL_SEC:
                self._last_health = now
                self._executor.submit(self._emit_health)  # type: ignore

            # ── Section scheduling ────────────────────────────────────────────
            for name, cfg in self._sections().items():
                if not cfg.get("enabled", True):
                    continue
                interval = cfg.get("interval_sec", 60)
                if now - self._last_run.get(name, 0) >= interval:
                    self._last_run[name] = now
                    if self._cbr.allow(name):
                        self._executor.submit(self._run_section, name, cfg)  # type: ignore
                    else:
                        log.debug("[%s] circuit open — skipping", name)

            self._stop.wait(timeout=self.tick)

    def _run_section(self, name: str, cfg: dict):
        fn = COLLECTORS.get(name)
        if not fn:
            return
        try:
            raw = fn()
            # Normalize raw output to canonical schema
            data = raw
            if _HAS_NORMALIZER:
                try:
                    data = _normalize(name, raw)
                except Exception as exc:
                    log.debug("Normalizer skipped for %s: %s", name, exc)
            self._cbr.success(name)
            log.debug("Collected %s: %s items", name,
                      len(data) if isinstance(data, (list, dict)) else "—")
        except Exception as exc:
            self._cbr.failure(name, str(exc))
            log.warning("Collector %s failed: %s", name, exc)
            data = {"error": str(exc)}

        if not cfg.get("send", True):
            return

        self._enqueue(name, data)

    def _enqueue(self, section: str, data) -> None:
        payload = {
            "section":      section,
            "agent_id":     self.agent_id,
            "agent_name":   self.config["agent"].get("name", ""),
            "os":           _OS_NAME,
            "os_version":   _OS_VER,
            "arch":         _ARCH,
            "hostname":     _HOSTNAME,
            "collected_at": int(time.time()),
            "data":         data,
        }
        try:
            envelope = encrypt(payload, self.enc_key, self.mac_key,
                               self.agent_id, int(time.time()))
            envelope["section"] = section   # plaintext routing hint for manager
            maxq = self.config["manager"].get("max_queue_size", 500)
            if self.send_queue.qsize() >= maxq:
                try:
                    self.send_queue.get_nowait()   # drop oldest
                    log.warning("Send queue full — dropped oldest item")
                except queue.Empty:
                    pass
            self.send_queue.put_nowait(envelope)
        except Exception as exc:
            log.error("Encrypt/enqueue failed for %s: %s", section, exc)

    def _emit_health(self) -> None:
        """Emit a synthetic agent_health section with diagnostics."""
        health_data = {
            "agent_id":    self.agent_id,
            "hostname":    _HOSTNAME,
            "os":          _OS_NAME,
            "arch":        _ARCH,
            "uptime_sec":  int(time.time() - _START_TIME),
            "queue_depth": self.send_queue.qsize(),
            "sections":    self._cbr.snapshot(),
        }
        self._enqueue("agent_health", health_data)


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

log = logging.getLogger("agent")


def setup_logging(cfg: dict):
    lcfg    = cfg.get("logging", {})
    level   = getattr(logging, lcfg.get("level", "INFO").upper(), logging.INFO)
    logfile = lcfg.get("file", _DEFAULT_LOG_FILE)
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        logfile,
        maxBytes=lcfg.get("max_mb", 10) * 1024 * 1024,
        backupCount=lcfg.get("backups", 3),
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[handler, logging.StreamHandler()],
    )


def _auto_agent_id() -> str:
    """
    Derive a stable hardware-bound agent ID.
    macOS  → Hardware UUID from system_profiler  → mac-<uuid>
    Windows→ MachineGuid from registry           → win-<guid>
    Linux  → /etc/machine-id                     → linux-<id>
    Fallback → hostname-based deterministic ID
    """
    try:
        if sys.platform == "darwin":
            import subprocess
            out = subprocess.check_output(
                ["system_profiler", "SPHardwareDataType"],
                text=True, timeout=10,
            )
            for line in out.splitlines():
                if "Hardware UUID" in line:
                    uuid = line.split(":")[-1].strip().lower()
                    return f"mac-{uuid}"
        elif sys.platform == "win32":
            import subprocess
            out = subprocess.check_output(
                ["reg", "query",
                 r"HKLM\SOFTWARE\Microsoft\Cryptography",
                 "/v", "MachineGuid"],
                text=True, timeout=10,
            )
            for line in out.splitlines():
                if "MachineGuid" in line:
                    guid = line.split()[-1].strip().lower()
                    return f"win-{guid}"
        else:
            try:
                with open("/etc/machine-id") as f:
                    mid = f.read().strip()
                if mid:
                    return f"linux-{mid[:32]}"
            except OSError:
                pass
    except Exception:
        pass
    # Fallback: hostname-based
    h = socket.gethostname().lower()
    import re
    h = re.sub(r"[^a-z0-9-]", "-", h)[:48]
    return f"host-{h}"


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _resolve_security_dir(cfg: dict, config_path: str) -> str:
    """Absolute path as-is; relative paths resolve next to the config file."""
    raw = cfg.get("paths", {}).get("security_dir", _DEFAULT_SECURITY)
    if os.path.isabs(raw):
        return raw
    base = os.path.dirname(os.path.abspath(config_path))
    return os.path.normpath(os.path.join(base, raw))


def _hex64(s: str) -> bool:
    s = s.strip().lower()
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _obtain_api_key(cfg: dict, config_path: str) -> str:
    """
    Resolution order:
      1) [manager] api_key in agent.toml if set to a valid 64-hex key (dev / explicit)
         — wins over keystore so bootstrap + make keygen stay in sync with manager
      2) Keystore (keychain or file under security_dir)
      3) enroll() using [enrollment] token
    """
    agent_id     = cfg["agent"]["id"]
    backend      = cfg.get("enrollment", {}).get("keystore", "keychain")
    security_dir = _resolve_security_dir(cfg, config_path)
    cfg.setdefault("paths", {})["security_dir"] = security_dir

    raw = (cfg.get("manager") or {}).get("api_key")
    if isinstance(raw, str):
        k = raw.strip()
        if k and k != "REPLACE_ME" and _hex64(k):
            try:
                store_key(agent_id, k, backend=backend, security_dir=security_dir)
                log.info(
                    "Using [manager] api_key from %s; synced to keystore (%s)",
                    os.path.basename(config_path),
                    backend,
                )
            except Exception as exc:
                log.warning(
                    "Could not persist key to keystore (%s); using config key this run",
                    exc,
                )
            return k

    k = load_key(agent_id, backend=backend, security_dir=security_dir)
    if k:
        return k

    if isinstance(raw, str):
        k = raw.strip()
        if k and k != "REPLACE_ME":
            try:
                store_key(agent_id, k, backend=backend, security_dir=security_dir)
                log.info(
                    "Loaded API key from [manager] api_key in %s; saved to keystore (%s)",
                    os.path.basename(config_path),
                    backend,
                )
            except Exception as exc:
                log.warning(
                    "Could not persist key to keystore (%s); using [manager] api_key this run",
                    exc,
                )
            return k

    log.info("No API key in keystore or config — starting first-run enrollment...")
    return enroll(cfg)


def main():
    parser = argparse.ArgumentParser(description="mac_intel agent")
    parser.add_argument("--config", default=_DEFAULT_CONFIG)
    args = parser.parse_args()

    cfg = load_config(args.config)
    setup_logging(cfg)

    # ── Auto-populate agent ID from hardware if not set in config ─────────────
    cfg.setdefault("agent", {})
    if not cfg["agent"].get("id"):
        cfg["agent"]["id"] = _auto_agent_id()
        log.info("Agent ID auto-derived: %s", cfg["agent"]["id"])

    log.info("mac_intel agent starting — id=%s name=%r",
             cfg["agent"]["id"], cfg["agent"].get("name", ""))

    agent_id = cfg["agent"]["id"]
    backend  = cfg.get("enrollment", {}).get("keystore", "keychain")

    try:
        api_key = _obtain_api_key(cfg, args.config)
    except EnrollmentError as exc:
        log.critical("Enrollment failed: %s", exc)
        log.critical(
            "Set [manager] api_key in %s (same 64-hex as manager DB / make keygen), "
            "or set [enrollment] token and run again. Stale key?  make reset-agent-key",
            os.path.basename(args.config),
        )
        sys.exit(1)

    if not api_key:
        log.critical("No API key for agent_id=%s", agent_id)
        sys.exit(1)

    log.info("API key ready (keystore backend=%s, agent_id=%s)", backend, agent_id)

    enc_key, mac_key = derive_keys(api_key)
    log.info("Crypto keys derived (tail=...%s)", api_key[-4:])

    send_queue: queue.Queue = queue.Queue()

    # Import sender here (avoids circular import)
    from .sender import Sender
    sender = Sender(cfg, send_queue)
    sender_thread = sender.start()

    orch = Orchestrator(cfg, enc_key, mac_key, send_queue)
    orch_thread  = orch.start()

    def _shutdown(signum, frame):
        log.info("Shutting down (signal %d)", signum)
        orch.stop()
        sender.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    # SIGHUP — POSIX only (reload config); not available on Windows
    if sys.platform != "win32":
        def _reload(signum, frame):
            nonlocal cfg
            try:
                cfg = load_config(args.config)
                log.info("Config reloaded on SIGHUP")
                orch.stop()
                orch.__init__(cfg, enc_key, mac_key, send_queue)
                orch.start()
            except Exception as exc:
                log.error("Config reload failed: %s", exc)
        signal.signal(signal.SIGHUP, _reload)

    log.info("Agent running. tick=%ss. SIGHUP to reload, SIGTERM to stop.",
             cfg.get("collection", {}).get("tick_sec", 5))
    orch_thread.join()


if __name__ == "__main__":
    main()
