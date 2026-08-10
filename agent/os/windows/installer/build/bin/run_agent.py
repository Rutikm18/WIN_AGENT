import os, sys
_INSTALL = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SRC = os.path.join(_INSTALL, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
_DATA_DIR = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
_CONFIG   = os.path.join(_DATA_DIR, "AttackLens", "agent.toml")
os.environ.setdefault("MACINTEL_CONFIG", _CONFIG)
try:
    import win32serviceutil, servicemanager
    from agent.os.windows.service import MacIntelAgentService, _add_root_to_path
    class AttackLensAgentService(MacIntelAgentService):
        _svc_name_         = "AttackLensAgent"
        _svc_display_name_ = "AttackLens Agent"
        _svc_description_  = "AttackLens endpoint telemetry agent."
    def main():
        _add_root_to_path()
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AttackLensAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        elif len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
            sys.argv = ["agent", "--config", _CONFIG]
            from agent.agent.core import main as _main
            _main()
        else:
            win32serviceutil.HandleCommandLine(AttackLensAgentService)
    main()
except ImportError as _e:
    print(f"pywin32 unavailable ({_e}) - running foreground")
    sys.argv = ["agent", "--config", _CONFIG]
    from agent.agent.core import main as _main
    _main()