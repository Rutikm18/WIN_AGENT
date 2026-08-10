"""
agent/agent/watchdog.py — Standalone process watchdog binary.

Reads [watchdog], [binaries], and [paths] from agent.conf.
Starts the main agent binary and restarts it on crash.
Rate-limits restarts: if the agent crashes more than max_restarts times
in restart_window_sec, the watchdog backs off and logs a critical alert
instead of looping endlessly.

Managed by the com.jarvis.watchdog LaunchDaemon plist.
The LaunchDaemon launches *this process*, which in turn manages the agent:

  launchd
    └── jarvis-watchdog (KeepAlive=true — launchd restarts watchdog if it dies)
          └── jarvis-agent  (watchdog restarts agent if it crashes)

Usage
─────
  /Library/Jarvis/bin/macintel-watchdog \\
      --config "/Library/Jarvis/agent.toml"
"""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print("ERROR: Python 3.11+ required, or: pip install tomli", file=sys.stderr)
        sys.exit(1)

log = logging.getLogger("watchdog")


class Watchdog:
    """
    Monitors and auto-restarts the agent binary.

    Rate-limiting: > max_restarts crashes within restart_window_sec → back-off.
    The back-off is intentional: a crash loop likely means a bug or config
    problem that requires operator attention, not an infinite restart spiral.
    """

    def __init__(self, cfg: dict) -> None:
        wdcfg  = cfg.get("watchdog", {})
        bins   = cfg.get("binaries", {})
        paths  = cfg.get("paths",    {})

        self.agent_bin       = bins.get("agent", "/Library/Jarvis/bin/macintel-agent")
        self.config_path     = cfg.get("_config_path", "")
        self.pid_file        = paths.get("pid_file", "/Library/Jarvis/jarvis-agent.pid")
        self.check_interval  = int(wdcfg.get("check_interval_sec", 30))
        self.max_restarts    = int(wdcfg.get("max_restarts", 5))
        self.restart_window  = int(wdcfg.get("restart_window_sec", 300))

        self._proc: subprocess.Popen | None = None
        self._restart_times: list[float]    = []
        self._stop = threading.Event()

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info("Watchdog started. agent_bin=%s check_interval=%ds",
                 self.agent_bin, self.check_interval)
        self._verify_binary()
        self._start_agent()

        while not self._stop.is_set():
            self._stop.wait(timeout=self.check_interval)
            if self._stop.is_set():
                break
            self._check_and_maybe_restart()

        log.info("Watchdog main loop exited.")

    def stop(self) -> None:
        self._stop.set()
        proc = self._proc
        if proc and proc.poll() is None:
            log.info("Watchdog: sending SIGTERM to agent PID=%d", proc.pid)
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                log.warning("Agent did not exit cleanly — sending SIGKILL")
                proc.kill()
        self._clear_pid()

    # ── Binary verification ───────────────────────────────────────────────────

    def _verify_binary(self) -> bool:
        """Check binary exists, is executable, and has expected permissions."""
        if not os.path.isfile(self.agent_bin):
            log.critical(
                "FATAL: agent binary not found at %s. "
                "Re-install or update [binaries] agent = ... in agent.conf.",
                self.agent_bin,
            )
            return False
        if not os.access(self.agent_bin, os.X_OK):
            log.critical("FATAL: agent binary %s is not executable.", self.agent_bin)
            return False
        # Warn if binary is world-writable (tampering risk)
        mode = os.stat(self.agent_bin).st_mode & 0o777
        if mode & 0o002:
            log.error(
                "SECURITY WARNING: agent binary %s is world-writable (%o). "
                "This is a tampering risk. Fix: chmod 755 %s",
                self.agent_bin, mode, self.agent_bin,
            )
        return True

    # ── Process management ────────────────────────────────────────────────────

    def _start_agent(self) -> None:
        if not self._verify_binary():
            return

        cmd = [self.agent_bin]
        if self.config_path:
            cmd += ["--config", self.config_path]

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                # stdout/stderr inherit from this process → captured by launchd
            )
            self._write_pid(self._proc.pid)
            log.info("Agent started: PID=%d  cmd=%s", self._proc.pid, " ".join(cmd))
        except Exception as exc:
            log.error("Failed to start agent: %s", exc)
            self._proc = None

    def _check_and_maybe_restart(self) -> None:
        if self._proc is None:
            log.warning("Agent is not running — attempting start")
            self._rate_limited_restart()
            return

        rc = self._proc.poll()
        if rc is None:
            return   # still running — all good

        log.warning("Agent exited with code %d (PID=%d)", rc, self._proc.pid)
        self._proc = None
        self._clear_pid()
        self._rate_limited_restart()

    def _rate_limited_restart(self) -> None:
        now = time.monotonic()
        # Remove timestamps that have aged out of the window
        self._restart_times = [
            t for t in self._restart_times if now - t < self.restart_window
        ]

        if len(self._restart_times) >= self.max_restarts:
            log.critical(
                "Agent crashed %d times in %ds (limit=%d). "
                "Watchdog is backing off — manual intervention required. "
                "Check logs at agent.log for root cause.",
                len(self._restart_times), self.restart_window, self.max_restarts,
            )
            return

        self._restart_times.append(now)
        log.info("Restarting agent (crash #%d / %d allowed in %ds window)",
                 len(self._restart_times), self.max_restarts, self.restart_window)
        self._start_agent()

    # ── PID file ──────────────────────────────────────────────────────────────

    def _write_pid(self, pid: int) -> None:
        try:
            pid_dir = os.path.dirname(self.pid_file)
            if pid_dir:
                os.makedirs(pid_dir, exist_ok=True)
            with open(self.pid_file, "w") as f:
                f.write(str(pid))
        except Exception as exc:
            log.warning("Could not write PID file %s: %s", self.pid_file, exc)

    def _clear_pid(self) -> None:
        try:
            if os.path.exists(self.pid_file):
                os.unlink(self.pid_file)
        except Exception:
            pass


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(cfg: dict) -> None:
    lcfg    = cfg.get("logging", {})
    level   = getattr(logging, lcfg.get("level", "INFO").upper(), logging.INFO)
    log_dir = cfg.get("paths", {}).get("log_dir", "/Library/Jarvis/logs")
    logfile = os.path.join(log_dir, "watchdog.log")
    os.makedirs(log_dir, exist_ok=True)
    fmt     = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")

    fh = logging.handlers.RotatingFileHandler(
        logfile,
        maxBytes=lcfg.get("max_mb", 10) * 1024 * 1024,
        backupCount=lcfg.get("backups", 3),
    )
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(fh)
    root.addHandler(sh)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="mac_intel process watchdog")
    parser.add_argument(
        "--config",
        default="/Library/Jarvis/agent.toml",
        help="Path to agent.toml",
    )
    args = parser.parse_args()

    try:
        with open(args.config, "rb") as f:
            cfg = tomllib.load(f)
    except FileNotFoundError:
        print(f"ERROR: Config not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to parse config: {exc}", file=sys.stderr)
        sys.exit(1)

    cfg["_config_path"] = args.config
    setup_logging(cfg)
    log.info("mac_intel watchdog initialising. config=%s", args.config)

    watchdog = Watchdog(cfg)

    def _shutdown(signum, frame):
        log.info("Received signal %d — initiating graceful shutdown", signum)
        watchdog.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    watchdog.run()


if __name__ == "__main__":
    main()
