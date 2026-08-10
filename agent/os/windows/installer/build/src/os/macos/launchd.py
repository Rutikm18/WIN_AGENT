"""
agent/os/macos/launchd.py — macOS LaunchDaemon management.

Equivalent to agent/os/windows/service.py for macOS.

Provides:
  • MacIntelLaunchd — context manager that registers/unregisters the agent
    with launchd; not normally called directly (the .pkg installer handles this).
  • agent_main() — run the full agent inside launchd context (bootstraps
    config, enrollment, crypto, Orchestrator, Sender).
  • install_plist() / uninstall_plist() — helpers for installer scripts.
  • is_running() / start() / stop() / restart() — launchctl wrappers.

LaunchDaemon hierarchy:
  launchd (KeepAlive = true) → jarvis-watchdog → jarvis-agent

The watchdog binary is the launchd child. launchd restarts it if it exits.
The watchdog starts/monitors the agent process (rate-limited restarts).
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile

log = logging.getLogger("agent.os.macos.launchd")

# ── Constants ─────────────────────────────────────────────────────────────────

_AGENT_LABEL    = "com.jarvis.agent"
_WATCHDOG_LABEL = "com.jarvis.watchdog"
_PLIST_DIR      = "/Library/LaunchDaemons"
_AGENT_PLIST    = f"{_PLIST_DIR}/{_AGENT_LABEL}.plist"
_WATCHDOG_PLIST = f"{_PLIST_DIR}/{_WATCHDOG_LABEL}.plist"

_INSTALL_DIR    = "/Library/Jarvis/bin"
_AGENT_BIN      = f"{_INSTALL_DIR}/jarvis-agent"
_WATCHDOG_BIN   = f"{_INSTALL_DIR}/jarvis-watchdog"
_CONFIG_DEFAULT = "/Library/Jarvis/config/agent.toml"
_LOG_DIR        = "/Library/Jarvis/logs"


# ── launchctl helpers ─────────────────────────────────────────────────────────

def _lctl(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    cmd = ["launchctl"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=15)


def is_running(label: str = _AGENT_LABEL) -> bool:
    r = _lctl("list", label)
    return r.returncode == 0 and '"PID"' in r.stdout


def start(label: str = _AGENT_LABEL) -> bool:
    r = _lctl("kickstart", f"system/{label}")
    if r.returncode != 0:
        # macOS 10.x compatibility
        r = _lctl("load", "-w", _AGENT_PLIST)
    return r.returncode == 0


def stop(label: str = _AGENT_LABEL) -> bool:
    r = _lctl("kill", "TERM", f"system/{label}")
    if r.returncode != 0:
        r = _lctl("stop", label)
    return r.returncode == 0


def restart(label: str = _AGENT_LABEL) -> bool:
    stop(label)
    return start(label)


def reload_config(label: str = _AGENT_LABEL) -> bool:
    """Send SIGHUP to trigger config reload without full restart."""
    r = _lctl("kill", "HUP", f"system/{label}")
    return r.returncode == 0


# ── Plist templates ───────────────────────────────────────────────────────────

def _agent_plist_xml(
    config_path: str = _CONFIG_DEFAULT,
    agent_bin: str = _AGENT_BIN,
    log_dir: str = _LOG_DIR,
) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_AGENT_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{agent_bin}</string>
        <string>--config</string>
        <string>{config_path}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>UserName</key>
    <string>root</string>

    <key>StandardOutPath</key>
    <string>{log_dir}/agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/agent-stderr.log</string>

    <!-- Throttle rapid restarts: launchd waits 10 s before restarting -->
    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>ProcessType</key>
    <string>Background</string>

    <key>WorkingDirectory</key>
    <string>/Library/Jarvis</string>

    <!-- Low I/O priority — we're a background agent -->
    <key>LowPriorityIO</key>
    <true/>
</dict>
</plist>
"""


def _watchdog_plist_xml(
    config_path: str = _CONFIG_DEFAULT,
    watchdog_bin: str = _WATCHDOG_BIN,
    log_dir: str = _LOG_DIR,
) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_WATCHDOG_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{watchdog_bin}</string>
        <string>--config</string>
        <string>{config_path}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>UserName</key>
    <string>root</string>

    <key>StandardOutPath</key>
    <string>{log_dir}/watchdog-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/watchdog-stderr.log</string>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>ProcessType</key>
    <string>Background</string>

    <key>WorkingDirectory</key>
    <string>/Library/Jarvis</string>

    <key>LowPriorityIO</key>
    <true/>
</dict>
</plist>
"""


# ── Plist install / uninstall ─────────────────────────────────────────────────

def install_plist(
    which: str = "both",
    config_path: str = _CONFIG_DEFAULT,
    agent_bin: str = _AGENT_BIN,
    watchdog_bin: str = _WATCHDOG_BIN,
    log_dir: str = _LOG_DIR,
) -> None:
    """
    Write LaunchDaemon plist(s) and load them.
    which: "agent" | "watchdog" | "both"
    """
    os.makedirs(_PLIST_DIR, exist_ok=True)

    if which in ("agent", "both"):
        xml = _agent_plist_xml(config_path, agent_bin, log_dir)
        _write_plist(_AGENT_PLIST, xml)
        _lctl("load", "-w", _AGENT_PLIST)
        log.info("LaunchDaemon loaded: %s", _AGENT_LABEL)

    if which in ("watchdog", "both"):
        xml = _watchdog_plist_xml(config_path, watchdog_bin, log_dir)
        _write_plist(_WATCHDOG_PLIST, xml)
        _lctl("load", "-w", _WATCHDOG_PLIST)
        log.info("LaunchDaemon loaded: %s", _WATCHDOG_LABEL)


def uninstall_plist(which: str = "both") -> None:
    """Unload and remove LaunchDaemon plist(s)."""
    pairs = []
    if which in ("watchdog", "both"):
        pairs.append((_WATCHDOG_LABEL, _WATCHDOG_PLIST))
    if which in ("agent", "both"):
        pairs.append((_AGENT_LABEL, _AGENT_PLIST))

    for label, path in pairs:
        _lctl("unload", "-w", path)
        if os.path.exists(path):
            os.unlink(path)
            log.info("Removed plist: %s", path)


def _write_plist(path: str, xml: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(xml)
    os.chmod(tmp, 0o644)
    try:
        import shutil
        shutil.chown(tmp, user="root", group="wheel")
    except Exception:
        pass
    os.replace(tmp, path)


# ── agent_main — entry point when running under launchd ──────────────────────

def agent_main(config_path: str | None = None) -> None:
    """
    Full agent bootstrap for launchd context.
    Equivalent to agent.agent.core.main() but resolves config from
    the standard macOS install path if not specified.
    """
    import argparse
    parser = argparse.ArgumentParser(description="mac_intel agent (macOS)")
    parser.add_argument("--config", default=config_path or _CONFIG_DEFAULT)
    args, _ = parser.parse_known_args()

    # Delegate to core.main() with the resolved config path
    sys.argv = ["macintel-agent", "--config", args.config]
    from agent.agent.core import main as _core_main
    _core_main()


if __name__ == "__main__":
    agent_main()
