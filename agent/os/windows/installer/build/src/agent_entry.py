"""
agent/agent_entry.py — PyInstaller entry point for macintel-agent.

PyInstaller runs the entry script as __main__, which breaks relative imports
in agent/agent/core.py (from .crypto import ..., etc.).
This wrapper uses absolute imports so PyInstaller can resolve the full package.
"""
from agent.agent.core import main

if __name__ == "__main__":
    main()
