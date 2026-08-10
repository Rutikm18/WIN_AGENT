"""
agent/os/windows/agent_win_entry.py — PyInstaller entry point for Windows.

PyInstaller runs the entry script as __main__, which breaks relative imports.
This wrapper uses absolute imports so the full package resolves correctly.

Supports two modes:
  1. Windows Service (default) — called by SCM at boot
  2. Console debug mode       — called with "debug" argument

Build with:
  pyinstaller --onefile --name jarvis-agent
              --hidden-import agent.agent.circuit_breaker
              --hidden-import agent.os.windows.collectors
              ...
              agent/os/windows/agent_win_entry.py
"""
import sys


def main():
    # If called with "debug" → run in foreground (no service)
    if len(sys.argv) >= 2 and sys.argv[1].lower() == "debug":
        from agent.agent.core import main as agent_main
        agent_main()
    else:
        # Hand control to the Windows Service wrapper
        from agent.os.windows.service import main as service_main
        service_main()


if __name__ == "__main__":
    main()
