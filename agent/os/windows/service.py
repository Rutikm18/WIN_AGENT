"""
agent/os/windows/service.py — Windows Service wrapper for mac_intel agent.

The agent binary is built as a console application by PyInstaller. This module
wraps the agent core inside a Windows Service so it starts at boot, runs as
NETWORK SERVICE (or a dedicated service account), and integrates with the
Windows Service Control Manager (SCM).

Architecture
────────────
  SCM
   └─ MacIntelAgent service  (this module)
       └─ agent.agent.core   (runs in a daemon thread)

Service lifecycle
─────────────────
  install   → sc create / win32serviceutil.InstallService
  start     → SvcDoRun → _run_agent_thread
  stop      → SvcStop → sets _stop_event → thread exits → service stops
  remove    → sc delete / win32serviceutil.RemoveService

CLI (when run as a PyInstaller binary)
──────────────────────────────────────
  macintel-agent.exe install   — register service
  macintel-agent.exe start     — start service
  macintel-agent.exe stop      — stop service
  macintel-agent.exe remove    — unregister service
  macintel-agent.exe debug     — run in foreground (no service; useful for testing)
  macintel-agent.exe           — (no args) hand control to SCM (used when SCM starts it)

Dependencies (Windows only)
───────────────────────────
  pip install pywin32
  python Scripts/pywin32_postinstall.py -install  (only needed once after pip install)

Default config path: C:\\ProgramData\\AttackLens\\config\\agent.toml
Override:            set MACINTEL_CONFIG env var, or write it to the service
                     registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\
                     AttackLensAgent\\Parameters\\MACINTEL_CONFIG (the WiX MSI
                     installer does this automatically).
"""
from __future__ import annotations

import logging
import json
import os
import sys
import threading

log = logging.getLogger("agent.windows.service")

# ── Config ────────────────────────────────────────────────────────────────────
_PROGRAMDATA  = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
DEFAULT_CONFIG = os.path.join(_PROGRAMDATA, "AttackLens", "config", "agent.toml")


# ── pywin32 availability guard ────────────────────────────────────────────────
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False


# ── Service class ─────────────────────────────────────────────────────────────

if _HAS_WIN32:
    class AttackLensAgentService(win32serviceutil.ServiceFramework):
        _svc_name_         = "AttackLensAgent"
        _svc_display_name_ = "AttackLens Agent"
        _svc_description_  = (
            "Endpoint telemetry agent — collects system metrics, security posture, "
            "and software inventory. Sends encrypted data to the AttackLens manager."
        )
        # Network is deliberately not a service dependency: collection and
        # encrypted spooling must start even when TCP/IP or DNS is unavailable.
        _svc_deps_: list[str] = []
        # Service account: LocalSystem gives full access; NetworkService is
        # more restrictive (recommended for production).
        # Set via sc config AttackLensAgent obj= "NT AUTHORITY\NetworkService" password= ""
        _exe_name_         = sys.executable   # PyInstaller sets this to the .exe path

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._win_agent  = None
            self._stop_reason = "service_stop"
            self._startup_journal = None

        def GetAcceptedControls(self):
            controls = win32serviceutil.ServiceFramework.GetAcceptedControls(self)
            controls |= getattr(win32service, "SERVICE_ACCEPT_PRESHUTDOWN", 0x100)
            controls |= getattr(win32service, "SERVICE_ACCEPT_POWEREVENT", 0x40)
            controls |= getattr(win32service, "SERVICE_ACCEPT_SHUTDOWN", 0x4)
            return controls

        # ── SCM callbacks ─────────────────────────────────────────────────────

        def SvcStop(self):
            self._request_stop("service_stop")

        def SvcShutdown(self):
            self._request_stop("shutdown")

        def SvcOtherEx(self, control, event_type, data):
            if control == getattr(win32service, "SERVICE_CONTROL_PRESHUTDOWN", 15):
                self._request_stop("preshutdown", wait_hint=180000)
                return 0
            if control == getattr(win32service, "SERVICE_CONTROL_POWEREVENT", 13):
                if self._win_agent:
                    try:
                        self._win_agent.handle_power_event(int(event_type))
                    except Exception:
                        log.exception("Power-event handling failed event=%s", event_type)
                return 0
            return win32serviceutil.ServiceFramework.SvcOtherEx(
                self, control, event_type, data
            )

        def _request_stop(self, reason: str, wait_hint: int = 30000) -> None:
            self._stop_reason = reason
            try:
                self.ReportServiceStatus(
                    win32service.SERVICE_STOP_PENDING, waitHint=wait_hint
                )
            except TypeError:
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            log.info("Service stop requested by SCM reason=%s", reason)
            win32event.SetEvent(self._stop_event)
            if self._win_agent:
                try:
                    self._win_agent.stop(reason=reason)
                except Exception:
                    log.exception("Agent stop request failed reason=%s", reason)

        def SvcDoRun(self):
            _add_root_to_path()
            from agent.os.windows.startup_recovery import (
                StartupJournal,
                write_diagnosis,
            )

            _setup_bootstrap_logging("agent")
            self._startup_journal = StartupJournal("agent")
            self._startup_journal.record("scm_start_requested", executable=sys.executable)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            # Keep SCM in start-pending until config, enrollment, collectors,
            # and spool initialization have passed. The runtime invokes the
            # callback only after those critical checks succeed.
            self._report_start_pending(1)
            try:
                self._run_agent()
            except Exception as exc:
                diagnosis = self._startup_journal.failure("service_runtime", exc)
                try:
                    report = write_diagnosis(_resolve_config_path())
                    self._startup_journal.record(
                        "diagnosis_written", path=str(report), diagnosis=diagnosis
                    )
                except Exception as report_exc:
                    self._startup_journal.record(
                        "diagnosis_write_failed", error=str(report_exc)
                    )
                raise
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ""),
            )

        # ── Agent bootstrap ───────────────────────────────────────────────────

        def _run_agent(self):
            config_path = _resolve_config_path()
            from agent.os.windows.startup_recovery import actions_as_dict, safe_repair

            recovery_actions = safe_repair(config_path)
            if self._startup_journal is not None:
                self._startup_journal.record(
                    "safe_recovery_complete",
                    actions=actions_as_dict(recovery_actions),
                )
            if not os.path.isfile(config_path):
                msg = (
                    f"Config not found: {config_path} — "
                    "re-run the MSI installer or generate agent.toml manually using gen_config.ps1"
                )
                servicemanager.LogErrorMsg(msg)
                log.critical(msg)
                raise RuntimeError(msg)

            _add_root_to_path()

            try:
                from agent.os.windows.win_agent import WindowsAgent
            except ImportError as exc:
                msg = (
                    f"Cannot import agent module: {exc} — "
                    "the PyInstaller bundle may be corrupt. Reinstall the MSI."
                )
                servicemanager.LogErrorMsg(msg)
                log.critical(msg)
                raise RuntimeError(msg) from exc

            try:
                self._win_agent = WindowsAgent.from_config(config_path)
            except Exception as exc:
                msg = (
                    f"Cannot parse agent.toml ({config_path}): {exc} — "
                    "check the file for TOML syntax errors"
                )
                servicemanager.LogErrorMsg(msg)
                log.critical(msg)
                raise RuntimeError(msg) from exc

            # Main file logging is initialized inside WindowsAgent.run(). Pass
            # recovery evidence forward so a rejected operator edit is visible
            # in agent.log, not only in the bootstrap JSONL journal.
            self._win_agent._startup_recovery_actions = actions_as_dict(
                recovery_actions
            )

            log.info("Windows agent starting via SCM  config=%s", config_path)
            if self._startup_journal is not None:
                self._startup_journal.record("configuration_loaded", config_path=config_path)

            try:
                # run() blocks until the SCM stop event fires.
                # It handles enrollment failures and collector errors internally;
                # only truly unexpected exceptions propagate here.
                self._win_agent.run(
                    win32_stop_event=self._stop_event,
                    progress_callback=self._report_start_pending,
                    ready_callback=lambda: self.ReportServiceStatus(
                        win32service.SERVICE_RUNNING
                    ),
                )
                log.info("Windows agent exited cleanly")
                if self._startup_journal is not None:
                    self._startup_journal.record("service_runtime_exited_cleanly")
            except Exception as exc:
                msg = f"Agent service fatal error: {type(exc).__name__}: {exc}"
                servicemanager.LogErrorMsg(msg)
                log.exception("Agent service fatal error")
                raise

        def _report_start_pending(self, checkpoint: int) -> None:
            """Keep SCM informed while validation/enrollment may take time."""
            # pywin32 advances its internal checkpoint for pending states.
            # Its public wrapper accepts waitHint but not checkPoint.
            if self._startup_journal is not None:
                self._startup_journal.record("startup_checkpoint", checkpoint=checkpoint)
            self.ReportServiceStatus(
                win32service.SERVICE_START_PENDING,
                120000,
            )


# ── Foreground debug mode (no SCM) ───────────────────────────────────────────

def _run_debug() -> None:
    """Run agent in foreground — useful for testing the service logic without SCM."""
    config_path = _resolve_config_path()
    if not os.path.isfile(config_path):
        print(f"ERROR: config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    _add_root_to_path()
    from agent.os.windows.win_agent import main as agent_main
    sys.argv = ["attacklens-agent", "--config", config_path]
    agent_main()


def _validate_config_cli() -> None:
    """Validate the installed TOML without requiring SCM or network access."""
    config_path = _resolve_config_path()
    try:
        from agent.os.windows.config_model import validate_config_file
        validate_config_file(config_path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    print(f"OK: valid Windows agent config: {config_path}")


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1].lower() in (
        "status", "--status", "diagnose", "--diagnose",
        "self-test", "--self-test", "capabilities", "--capabilities",
        "repair", "--repair",
    ):
        _add_root_to_path()
        _run_diagnostics_cli(sys.argv[1].lower().lstrip("-"))
        return
    if len(sys.argv) >= 2 and sys.argv[1].lower() in (
        "--validate-config", "validate-config"
    ):
        _add_root_to_path()
        _validate_config_cli()
        return

    if not _HAS_WIN32:
        print(
            "ERROR: pywin32 is required for Windows service mode.\n"
            "  pip install pywin32\n"
            "  python Scripts/pywin32_postinstall.py -install",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(sys.argv) == 1:
        # No arguments → SCM is starting us as a service
        from agent.os.windows.eventlog_source import (
            SOURCE_NAME,
            register_event_source,
        )

        event_source = register_event_source()
        if not event_source.get("registered"):
            log.warning("Windows Event Log source registration failed: %s", event_source)
        try:
            import win32evtlog

            servicemanager.Initialize(SOURCE_NAME, win32evtlog.__file__)
        except TypeError:
            servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AttackLensAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    elif len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
        _run_debug()
    else:
        win32serviceutil.HandleCommandLine(AttackLensAgentService)


def _run_diagnostics_cli(command: str) -> None:
    """Run operator diagnostics without starting or mutating the service."""
    from agent.os.windows.config_model import load_config
    from agent.os.windows.diagnostics import (
        capability_report,
        connectivity_test,
        status_report,
    )
    from agent.os.windows.startup_recovery import (
        actions_as_dict,
        diagnose_startup,
        safe_repair,
    )

    config_path = _resolve_config_path()
    try:
        if command == "repair":
            actions = actions_as_dict(safe_repair(config_path))
            result = {
                "ok": not any(action["status"] == "failed" for action in actions),
                "scope": "safe_file_state_only",
                "actions": actions,
                "diagnosis": diagnose_startup(config_path),
            }
        elif command == "diagnose":
            result = diagnose_startup(config_path)
            try:
                cfg = load_config(config_path).to_dict()
                result["connectivity"] = connectivity_test(cfg)
            except Exception:
                # The startup report already contains the config error.  A
                # malformed config must not prevent all other diagnosis.
                pass
        else:
            cfg = load_config(config_path).to_dict()
        if command == "status":
            result = status_report(cfg)
        elif command == "capabilities":
            result = capability_report(cfg)
        elif command == "self-test":
            result = connectivity_test(cfg)
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "command": command,
            "error": f"{type(exc).__name__}: {exc}",
        }, indent=2), file=sys.stderr)
        raise SystemExit(2) from None
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    if command == "self-test" and not result.get("ok"):
        raise SystemExit(3)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_config_path() -> str:
    """
    Return the agent config path.  Resolution order:
      1. MACINTEL_CONFIG environment variable (manual override / test)
      2. Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\
                   AttackLensAgent\\Parameters\\MACINTEL_CONFIG
         (written by the WiX MSI custom action at install time)
      3. Compile-time default: %PROGRAMDATA%\\AttackLens\\config\\agent.toml
    """
    path = os.environ.get("ATTACKLENS_CONFIG") or os.environ.get("MACINTEL_CONFIG")
    if path:
        return path
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\AttackLensAgent\Parameters",
        ) as k:
            for value_name in ("ATTACKLENS_CONFIG", "MACINTEL_CONFIG"):
                try:
                    val, _ = winreg.QueryValueEx(k, value_name)
                    if val:
                        return str(val)
                except FileNotFoundError:
                    continue
    except Exception:
        pass
    return DEFAULT_CONFIG


def _add_root_to_path() -> None:
    """Ensure project root (grandparent of this file's package) is on sys.path."""
    root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    if root not in sys.path:
        sys.path.insert(0, root)


def _setup_bootstrap_logging(component: str) -> None:
    """Create a best-effort log before config parsing and main logging exist."""
    try:
        root = os.path.join(
            os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "AttackLens", "logs"
        )
        os.makedirs(root, exist_ok=True)
        path = os.path.join(root, f"{component}-bootstrap.log")
        # Attach only to the service bootstrap logger. A root handler would
        # make WindowsAgent._setup_logging()'s later basicConfig a no-op.
        logger = log
        if not any(
            isinstance(handler, logging.FileHandler)
            and os.path.normcase(getattr(handler, "baseFilename", "")) == os.path.normcase(path)
            for handler in logger.handlers
        ):
            handler = logging.FileHandler(path, encoding="utf-8")
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(name)s %(levelname)s %(message)s"
            ))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
    except Exception:
        pass


if __name__ == "__main__":
    main()
