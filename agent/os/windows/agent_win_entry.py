"""
agent/os/windows/agent_win_entry.py — PyInstaller entry point for Windows agent.

PyInstaller runs the entry script as __main__, which breaks relative imports.
This wrapper uses absolute imports so the full package resolves correctly.

All subcommands (install, start, stop, remove, debug, no-args) are handled by
service.main():

  attacklens-agent.exe             -> SCM dispatcher (started by Service Control Manager)
  attacklens-agent.exe install     -> register AttackLensAgent with SCM
  attacklens-agent.exe start       -> start the service
  attacklens-agent.exe stop        -> stop the service
  attacklens-agent.exe remove      -> unregister the service
  attacklens-agent.exe debug       -> run agent in foreground (no SCM; Ctrl+C to stop)

Build:
  pyinstaller --noconfirm pkg/attacklens-agent.spec
"""
import sys


def main() -> None:
    from agent.os.windows.service import main as service_main
    service_main()


if __name__ == "__main__":
    main()
