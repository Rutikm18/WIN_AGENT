"""
agent/os/windows/watchdog_svc.py — Windows Watchdog Service for mac_intel agent.

Architecture
────────────
  SCM
   └─ MacIntelWatchdog service  (this file)
       └─ MacIntelAgent service  ← monitors via SCM + optional process health-check

The watchdog is a separate Windows Service that:
  1. Ensures MacIntelAgent is running (restarts it if stopped/crashed)
  2. Rate-limits restarts: max MAX_RESTARTS in RESTART_WINDOW_SEC seconds
  3. On rate-limit hit: opens a non-blocking BACKOFF_SEC circuit and logs a
     Windows Event so operators are alerted.
  4. Exposes status via Windows Event Log entries.

Why a separate service instead of SC failure actions?
──────────────────────────────────────────────────────
• SC failure actions are limited (3 actions, no sliding-window rate limit).
• We need custom backoff logic and Windows Event Log integration.
• The watchdog can be monitored independently — if both services are stopped
  something is very wrong (tamper indicator).

CLI
───
  macintel-watchdog.exe install   — register watchdog service
  macintel-watchdog.exe start     — start watchdog
  macintel-watchdog.exe stop      — stop watchdog
  macintel-watchdog.exe remove    — unregister watchdog
  macintel-watchdog.exe debug     — run in foreground

Dependencies
────────────
  pip install pywin32
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import time
from collections import deque

log = logging.getLogger("agent.windows.watchdog")

# ── Restart policy ────────────────────────────────────────────────────────────
MAX_RESTARTS        = 5     # max restarts within the window
RESTART_WINDOW_SEC  = 300   # 5-minute sliding window
CHECK_INTERVAL_SEC  = 30    # how often to poll agent service state
BACKOFF_SEC         = 120   # wait after rate-limit hit before final attempt
HEARTBEAT_STALE_SEC = 180   # running service must update local state within 3 min
UNHEALTHY_CHECKS    = 2     # avoid restarting on one partial state-file write
STARTUP_GRACE_SEC   = 45    # avoid racing MSI/SCM while both services are installed
START_TIMEOUT_SEC   = 120   # SCM start request must settle within this time

AGENT_SERVICE_NAME  = "AttackLensAgent"


def _add_root_to_path() -> None:
    root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    if root not in sys.path:
        sys.path.insert(0, root)


def _resolve_runtime_state_path() -> str | None:
    """Follow the agent's configured data_dir instead of assuming ProgramData."""
    try:
        _add_root_to_path()
        from agent.os.windows.config_model import load_config
        from agent.os.windows.service import _resolve_config_path

        cfg = load_config(_resolve_config_path()).to_dict()
        return os.path.join(cfg["paths"]["data_dir"], "agent.runtime.json")
    except Exception:
        return None


def _startup_journal():
    try:
        _add_root_to_path()
        from agent.os.windows.startup_recovery import StartupJournal
        return StartupJournal("watchdog")
    except Exception:
        return None


def _classify_error(exc: BaseException | str) -> dict[str, str]:
    try:
        _add_root_to_path()
        from agent.os.windows.startup_recovery import classify_startup_error
        return classify_startup_error(exc)
    except Exception:
        return {"code": "unexpected_startup_error", "severity": "fatal"}


def _setup_bootstrap_logging() -> None:
    try:
        root = os.path.join(
            os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "AttackLens", "logs"
        )
        os.makedirs(root, exist_ok=True)
        path = os.path.join(root, "watchdog.log")
        logger = log
        if not any(
            isinstance(handler, logging.FileHandler)
            and os.path.normcase(getattr(handler, "baseFilename", "")) == os.path.normcase(path)
            for handler in logger.handlers
        ):
            handler = logging.handlers.RotatingFileHandler(
                path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(name)s %(levelname)s %(message)s"
            ))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
    except Exception:
        pass

# ── pywin32 guard ─────────────────────────────────────────────────────────────
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    import pywintypes
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False


# ── Watchdog logic (OS-agnostic core) ────────────────────────────────────────

class WatchdogCore:
    """
    Pure-Python watchdog state machine — works whether wrapped in a Windows
    Service or run in foreground debug mode.
    """

    def __init__(
        self,
        stop_event: "threading.Event | None" = None,
        runtime_state_path: str | None = None,
    ):
        self._stop_event  = stop_event
        self._restarts: deque[float] = deque()   # timestamps of recent restarts
        programdata = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        self._runtime_state_path = runtime_state_path or _resolve_runtime_state_path()
        if not self._runtime_state_path:
            self._runtime_state_path = os.path.join(
                programdata, "AttackLens", "data", "agent.runtime.json"
            )
        self._runtime_missing_since: float | None = None
        self._started_at = time.monotonic()
        self._cooldown_until = 0.0
        self._restart_failures = 0
        self._pending_since: float | None = None
        self._journal = _startup_journal()
        self._state_path = os.path.join(
            os.path.dirname(self._runtime_state_path), "watchdog.runtime.json"
        )

    def run(self) -> None:
        log.info("Watchdog started — monitoring %s every %ds",
                 AGENT_SERVICE_NAME, CHECK_INTERVAL_SEC)
        consecutive_failures = 0

        while not self._should_stop():
            try:
                state, reason = self._query_agent_state()
                self._publish_state(state, reason)
                if state == "stopped":
                    if time.monotonic() - self._started_at < STARTUP_GRACE_SEC:
                        log.info("Agent is stopped during watchdog startup grace")
                        self._sleep(CHECK_INTERVAL_SEC)
                        continue
                    log.warning("Agent service %s is not running", AGENT_SERVICE_NAME)
                    self._attempt_restart()
                    consecutive_failures += 1
                elif state == "running":
                    self._pending_since = None
                    runtime_ok, reason = self._runtime_is_healthy()
                    if runtime_ok:
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                        log.warning(
                            "Agent service is running but runtime is unhealthy "
                            "check=%d/%d reason=%s",
                            consecutive_failures,
                            UNHEALTHY_CHECKS,
                            reason,
                        )
                        if consecutive_failures >= UNHEALTHY_CHECKS:
                            self._attempt_restart(force_stop=True)
                            consecutive_failures = 0
                elif state == "paused":
                    self._resume_agent_service()
                elif state in {"start_pending", "stop_pending", "continue_pending"}:
                    if self._pending_since is None:
                        self._pending_since = time.monotonic()
                    pending_for = time.monotonic() - self._pending_since
                    if pending_for > START_TIMEOUT_SEC:
                        self._record_problem(
                            "service_pending_timeout",
                            f"{state} for {int(pending_for)} seconds",
                        )
                else:
                    # Missing service, access denied, and SCM query failures are
                    # not equivalent to a stopped service. Retrying StartService
                    # would create a restart storm and hide the root cause.
                    self._record_problem("service_query_failed", reason or state)
            except Exception as exc:
                log.error("Watchdog check error: %s", exc)
                self._record_problem("watchdog_check_error", str(exc))

            self._sleep(CHECK_INTERVAL_SEC)

        log.info("Watchdog stopped")

    def _query_agent_state(self) -> tuple[str, str]:
        if not _HAS_WIN32:
            return "running", "win32_unavailable"
        try:
            status = win32serviceutil.QueryServiceStatus(AGENT_SERVICE_NAME)
            names = {
                win32service.SERVICE_STOPPED: "stopped",
                win32service.SERVICE_START_PENDING: "start_pending",
                win32service.SERVICE_STOP_PENDING: "stop_pending",
                win32service.SERVICE_RUNNING: "running",
                win32service.SERVICE_PAUSED: "paused",
                getattr(win32service, "SERVICE_CONTINUE_PENDING", 5): "continue_pending",
                getattr(win32service, "SERVICE_PAUSE_PENDING", 6): "pause_pending",
            }
            return names.get(status[1], f"state_{status[1]}"), ""
        except Exception as exc:
            diagnosis = _classify_error(exc)
            return diagnosis.get("code", "query_failed"), str(exc)

    def _is_agent_running(self) -> bool:
        """Compatibility helper used by existing callers and tests."""
        return self._query_agent_state()[0] == "running"

    def _runtime_is_healthy(self) -> tuple[bool, str]:
        """Detect running-but-dead agents using the atomic runtime heartbeat."""
        now = time.time()
        try:
            with open(self._runtime_state_path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            self._runtime_missing_since = None
        except FileNotFoundError:
            if self._runtime_missing_since is None:
                self._runtime_missing_since = now
            missing_for = now - self._runtime_missing_since
            if missing_for <= HEARTBEAT_STALE_SEC:
                return True, "runtime_state_startup_grace"
            return False, f"runtime_state_missing_for_{int(missing_for)}s"
        except (OSError, ValueError, TypeError) as exc:
            return False, f"runtime_state_unreadable:{type(exc).__name__}"

        try:
            updated_at = int(state.get("updated_at") or 0)
            age = max(0, int(now - updated_at))
        except (TypeError, ValueError):
            return False, "runtime_state_timestamp_invalid"
        if updated_at > now + 300:
            return False, "runtime_state_timestamp_in_future"
        if age > HEARTBEAT_STALE_SEC:
            return False, f"runtime_state_stale_{age}s"
        if state.get("connection_state") == "sender_crashed":
            return False, "sender_thread_crashed"
        if state.get("status") == "stopped":
            return False, "runtime_reports_stopped"
        return True, "healthy"

    def _attempt_restart(self, *, force_stop: bool = False) -> None:
        now = time.time()
        if time.monotonic() < self._cooldown_until:
            return
        # Evict timestamps outside the sliding window
        while self._restarts and now - self._restarts[0] > RESTART_WINDOW_SEC:
            self._restarts.popleft()

        if len(self._restarts) >= MAX_RESTARTS:
            log.error(
                "Rate limit: %d restarts in %ds — waiting %ds before final attempt",
                MAX_RESTARTS, RESTART_WINDOW_SEC, BACKOFF_SEC,
            )
            self._event_log_error(
                f"Restart rate limit hit ({MAX_RESTARTS}/{RESTART_WINDOW_SEC}s). "
                f"Waiting {BACKOFF_SEC}s before retrying."
            )
            self._cooldown_until = time.monotonic() + BACKOFF_SEC
            self._restarts.clear()
            self._record_problem(
                "restart_circuit_open",
                f"cooldown={BACKOFF_SEC}s restarts={MAX_RESTARTS}",
            )
            return

        log.info("Restarting %s...", AGENT_SERVICE_NAME)
        self._restarts.append(time.time())
        if force_stop and not self._stop_agent_service():
            return
        if self._start_agent_service():
            self._restart_failures = 0
        else:
            self._restart_failures += 1
            delay = min(BACKOFF_SEC, 2 ** min(self._restart_failures, 7))
            self._cooldown_until = time.monotonic() + delay

    def _stop_agent_service(self) -> bool:
        if not _HAS_WIN32:
            return True
        try:
            win32serviceutil.StopService(AGENT_SERVICE_NAME)
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline and not self._should_stop():
                status = win32serviceutil.QueryServiceStatus(AGENT_SERVICE_NAME)
                if status[1] == win32service.SERVICE_STOPPED:
                    return True
                self._sleep(1.0)
            raise RuntimeError("service did not stop within 30 seconds")
        except Exception as exc:
            log.error("Failed to stop unhealthy %s: %s", AGENT_SERVICE_NAME, exc)
            self._event_log_error(
                f"Failed to stop unhealthy {AGENT_SERVICE_NAME}: {exc}"
            )
            return False

    def _start_agent_service(self) -> bool:
        if not _HAS_WIN32:
            return True
        try:
            win32serviceutil.StartService(AGENT_SERVICE_NAME)
            deadline = time.monotonic() + START_TIMEOUT_SEC
            while time.monotonic() < deadline and not self._should_stop():
                state, reason = self._query_agent_state()
                if state == "running":
                    log.info("Service %s reached RUNNING", AGENT_SERVICE_NAME)
                    self._event_log_info(f"Watchdog restarted {AGENT_SERVICE_NAME}")
                    return True
                if state == "stopped":
                    raise RuntimeError("service returned to STOPPED during startup")
                if state in {"service_missing", "access_denied"}:
                    raise RuntimeError(f"{state}: {reason}")
                self._sleep(1.0)
            raise RuntimeError(f"service did not reach RUNNING within {START_TIMEOUT_SEC}s")
        except Exception as exc:
            diagnosis = _classify_error(exc)
            if diagnosis.get("code") == "already_running":
                return True
            log.error("Failed to start %s: %s", AGENT_SERVICE_NAME, exc)
            self._event_log_error(
                f"Failed to restart {AGENT_SERVICE_NAME} [{diagnosis.get('code')}]: {exc}"
            )
            self._record_problem("agent_restart_failed", str(exc), diagnosis=diagnosis)
            return False

    def _resume_agent_service(self) -> None:
        if not _HAS_WIN32:
            return
        try:
            win32serviceutil.ResumeService(AGENT_SERVICE_NAME)
            self._event_log_info(f"Watchdog resumed {AGENT_SERVICE_NAME}")
        except Exception as exc:
            self._record_problem("agent_resume_failed", str(exc), diagnosis=_classify_error(exc))

    def _record_problem(self, event: str, detail: str, **fields: object) -> None:
        if self._journal is not None:
            self._journal.record(event, detail=detail, **fields)

    def _publish_state(self, agent_state: str, reason: str) -> None:
        value = {
            "updated_at": int(time.time()),
            "status": "running",
            "agent_service_state": agent_state,
            "reason": reason,
            "recent_restarts": len(self._restarts),
            "restart_failures": self._restart_failures,
            "cooldown_remaining_sec": max(0, int(self._cooldown_until - time.monotonic())),
        }
        try:
            os.makedirs(os.path.dirname(self._state_path), exist_ok=True)
            temp = self._state_path + ".tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True)
            os.replace(temp, self._state_path)
        except Exception:
            pass

    def _should_stop(self) -> bool:
        if self._stop_event is None:
            return False
        return self._stop_event.is_set()

    def _sleep(self, seconds: float) -> None:
        """Sleep in small increments so we can react to stop events quickly."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self._should_stop():
                return
            time.sleep(min(5.0, deadline - time.monotonic()))

    @staticmethod
    def _event_log_info(msg: str) -> None:
        if not _HAS_WIN32:
            return
        try:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE, 0xF000, (msg, "")
            )
        except Exception:
            pass

    @staticmethod
    def _event_log_error(msg: str) -> None:
        if not _HAS_WIN32:
            return
        try:
            servicemanager.LogErrorMsg(msg)
        except Exception:
            pass


# ── Windows Service wrapper ───────────────────────────────────────────────────

if _HAS_WIN32:
    class AttackLensWatchdogService(win32serviceutil.ServiceFramework):
        _svc_name_         = "AttackLensWatchdog"
        _svc_display_name_ = "AttackLens Watchdog"
        _svc_description_  = (
            "Monitors the AttackLens Agent service and restarts it if it stops. "
            "Rate-limited to prevent restart storms."
        )
        # No dependency on MacIntelAgent — the watchdog must start even when
        # the agent is down (that is precisely when it does its job).
        _svc_deps_: list[str] = []

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event_win32 = win32event.CreateEvent(None, 0, 0, None)
            import threading
            self._py_stop          = threading.Event()
            self._core             = WatchdogCore(stop_event=self._py_stop)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event_win32)
            self._py_stop.set()

        def SvcDoRun(self):
            _setup_bootstrap_logging()
            journal = _startup_journal()
            if journal is not None:
                journal.record("scm_start_requested", executable=sys.executable)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            # ServiceFramework.ReportServiceStatus accepts waitHint but does
            # not expose a checkPoint keyword. Passing that keyword crashes
            # the service before the watchdog thread is started.
            self.ReportServiceStatus(
                win32service.SERVICE_START_PENDING,
                30000,
            )
            import threading
            t = threading.Thread(target=self._core.run, daemon=True, name="watchdog")
            t.start()
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            while True:
                result = win32event.WaitForSingleObject(
                    self._stop_event_win32,
                    1000,
                )
                if result == win32event.WAIT_OBJECT_0:
                    break
                if not t.is_alive():
                    message = (
                        "Watchdog worker exited unexpectedly; stopping the "
                        "service so SCM recovery can restart it"
                    )
                    log.critical(message)
                    self._core._event_log_error(message)
                    if journal is not None:
                        journal.record("worker_exited_unexpectedly", detail=message)
                    raise RuntimeError(message)
            self._py_stop.set()
            t.join(timeout=30)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ""),
            )


# ── Foreground debug ──────────────────────────────────────────────────────────

def _run_debug() -> None:
    import threading
    stop = threading.Event()
    try:
        WatchdogCore(stop_event=stop).run()
    except KeyboardInterrupt:
        stop.set()


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1].lower() in (
        "diagnose", "--diagnose", "repair", "--repair"
    ):
        _run_support_cli(sys.argv[1].lower().lstrip("-"))
        return
    if not _HAS_WIN32:
        print("ERROR: pywin32 required. pip install pywin32", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AttackLensWatchdogService)
        servicemanager.StartServiceCtrlDispatcher()
    elif len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
        _run_debug()
    else:
        win32serviceutil.HandleCommandLine(AttackLensWatchdogService)


def _run_support_cli(command: str) -> None:
    _add_root_to_path()
    from agent.os.windows.service import _resolve_config_path
    from agent.os.windows.startup_recovery import (
        actions_as_dict,
        diagnose_startup,
        safe_repair,
    )

    config_path = _resolve_config_path()
    result: dict[str, object] = {
        "component": "watchdog",
        "diagnosis": diagnose_startup(config_path),
    }
    if command == "repair":
        result["scope"] = "safe_file_state_only"
        result["actions"] = actions_as_dict(safe_repair(config_path))
    print(json.dumps(result, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
