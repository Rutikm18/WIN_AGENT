import os, sys
_INSTALL = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SRC = os.path.join(_INSTALL, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
try:
    import win32serviceutil, servicemanager
    import agent.os.windows.watchdog_svc as _wd_mod
    _wd_mod.AGENT_SERVICE_NAME = "AttackLensAgent"
    from agent.os.windows.watchdog_svc import MacIntelWatchdogService, WatchdogCore
    class AttackLensWatchdogService(MacIntelWatchdogService):
        _svc_name_         = "AttackLensWatchdog"
        _svc_display_name_ = "AttackLens Watchdog"
        _svc_description_  = "Monitors and restarts the AttackLens Agent service."
        _svc_deps_         = ["Tcpip"]
    def main():
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AttackLensWatchdogService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(AttackLensWatchdogService)
    main()
except ImportError as _e:
    print(f"pywin32 unavailable ({_e})")
    sys.exit(1)