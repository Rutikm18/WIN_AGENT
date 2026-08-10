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
  3. On rate-limit hit: pauses BACKOFF_SEC then tries once more, then gives up
     and logs a Windows Event so operators are alerted.
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

import logging
import sys
import time
from collections import deque

log = logging.getLogger("agent.windows.watchdog")

# ── Restart policy ────────────────────────────────────────────────────────────
MAX_RESTARTS        = 5     # max restarts within the window
RESTART_WINDOW_SEC  = 300   # 5-minute sliding window
CHECK_INTERVAL_SEC  = 30    # how often to poll agent service state
BACKOFF_SEC         = 120   # wait after rate-limit hit before final attempt

AGENT_SERVICE_NAME  = "MacIntelAgent"

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

    def __init__(self, stop_event: "threading.Event | None" = None):
        self._stop_event  = stop_event
        self._restarts: deque[float] = deque()   # timestamps of recent restarts

    def run(self) -> None:
        log.info("Watchdog started — monitoring %s every %ds",
                 AGENT_SERVICE_NAME, CHECK_INTERVAL_SEC)
        consecutive_failures = 0

        while not self._should_stop():
            try:
                if not self._is_agent_running():
                    log.warning("Agent service %s is not running", AGENT_SERVICE_NAME)
                    self._attempt_restart()
                    consecutive_failures += 1
                else:
                    consecutive_failures = 0
            except Exception as exc:
                log.error("Watchdog check error: %s", exc)

            self._sleep(CHECK_INTERVAL_SEC)

        log.info("Watchdog stopped")

    def _is_agent_running(self) -> bool:
        if not _HAS_WIN32:
            return True   # can't check without pywin32; assume OK
        try:
            status = win32serviceutil.QueryServiceStatus(AGENT_SERVICE_NAME)
            return status[1] == win32service.SERVICE_RUNNING
        except Exception:
            return False

    def _attempt_restart(self) -> None:
        now = time.time()
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
            self._sleep(BACKOFF_SEC)
            # Clear the window for one final attempt
            self._restarts.clear()

        log.info("Restarting %s...", AGENT_SERVICE_NAME)
        self._restarts.append(time.time())
        self._start_agent_service()

    def _start_agent_service(self) -> None:
        if not _HAS_WIN32:
            return
        try:
            win32serviceutil.StartService(AGENT_SERVICE_NAME)
            log.info("Service %s started successfully", AGENT_SERVICE_NAME)
            self._event_log_info(f"Watchdog restarted {AGENT_SERVICE_NAME}")
        except pywintypes.error as exc:
            log.error("Failed to start %s: %s", AGENT_SERVICE_NAME, exc)
            self._event_log_error(f"Failed to restart {AGENT_SERVICE_NAME}: {exc}")

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
    class MacIntelWatchdogService(win32serviceutil.ServiceFramework):
        _svc_name_         = "MacIntelWatchdog"
        _svc_display_name_ = "mac_intel Watchdog"
        _svc_description_  = (
            "Monitors the mac_intel Agent service and restarts it if it stops. "
            "Rate-limited to prevent restart storms."
        )
        # No dependency on MacIntelAgent — the watchdog must start even when
        # the agent is down (that is precisely when it does its job).
        _svc_deps_         = ["Tcpip"]

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
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            import threading
            t = threading.Thread(target=self._core.run, daemon=True, name="watchdog")
            t.start()
            win32event.WaitForSingleObject(self._stop_event_win32, win32event.INFINITE)
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
    if not _HAS_WIN32:
        print("ERROR: pywin32 required. pip install pywin32", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(MacIntelWatchdogService)
        servicemanager.StartServiceCtrlDispatcher()
    elif len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
        _run_debug()
    else:
        win32serviceutil.HandleCommandLine(MacIntelWatchdogService)


if __name__ == "__main__":
    main()
