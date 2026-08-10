#!/usr/bin/env bash
# =============================================================================
#  agent/os/macos/installer/uninstall.sh — mac_intel Agent macOS Uninstaller
#
#  Removes the agent completely: stops services, removes binaries,
#  removes LaunchDaemons, optionally removes data/keys/logs.
#
#  Usage:
#    sudo bash uninstall.sh [--keep-config] [--keep-logs] [--keep-keys]
#
#  Flags:
#    --keep-config   Do NOT remove agent.toml
#    --keep-logs     Do NOT remove log files
#    --keep-keys     Do NOT delete Keychain entry or key files
# =============================================================================
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/Library/Jarvis}"
DATA_DIR="${DATA_DIR:-/Library/Jarvis}"
LOG_DIR="${LOG_DIR:-/Library/Jarvis/logs}"
SECURITY_DIR="${DATA_DIR}/security"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"

KEEP_CONFIG=false
KEEP_LOGS=false
KEEP_KEYS=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --keep-config) KEEP_CONFIG=true; shift ;;
    --keep-logs)   KEEP_LOGS=true;   shift ;;
    --keep-keys)   KEEP_KEYS=true;   shift ;;
    *)             echo "Unknown flag: $1"; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "  ERROR: must run as root. Use: sudo bash uninstall.sh" >&2
  exit 1
fi

echo ""
echo "  mac_intel Agent — Uninstalling..."
echo ""

# ── Stop and unload services ──────────────────────────────────────────────────
for LABEL in com.macintel.watchdog com.macintel.agent; do
  PLIST="${LAUNCHDAEMON_DIR}/${LABEL}.plist"
  if [[ -f "$PLIST" ]]; then
    echo "  Stopping ${LABEL}..."
    launchctl unload -w "$PLIST" 2>/dev/null || true
    sleep 1
    rm -f "$PLIST"
    echo "    Removed: $PLIST"
  fi
done

# ── Remove binaries ───────────────────────────────────────────────────────────
echo "  Removing binaries..."
for BIN in macintel-agent macintel-watchdog; do
  BIN_PATH="${INSTALL_DIR}/bin/${BIN}"
  if [[ -f "$BIN_PATH" ]]; then
    rm -f "$BIN_PATH"
    echo "    Removed: $BIN_PATH"
  fi
done

# Remove install dir if empty
rmdir "${INSTALL_DIR}/bin" 2>/dev/null || true
rmdir "${INSTALL_DIR}"     2>/dev/null || true

# ── Remove Keychain entries ───────────────────────────────────────────────────
if [[ "$KEEP_KEYS" == "false" ]]; then
  echo "  Removing Keychain entries..."
  # Remove all entries for com.macintel.agent service
  security delete-generic-password \
    -s "com.macintel.agent" \
    /Library/Keychains/System.keychain 2>/dev/null || true

  # Remove key files from security dir
  if [[ -d "$SECURITY_DIR" ]]; then
    rm -rf "$SECURITY_DIR"
    echo "    Removed: $SECURITY_DIR"
  fi
fi

# ── Remove config ─────────────────────────────────────────────────────────────
if [[ "$KEEP_CONFIG" == "false" ]]; then
  CONFIG_PATH="${DATA_DIR}/agent.toml"
  if [[ -f "$CONFIG_PATH" ]]; then
    rm -f "$CONFIG_PATH"
    echo "  Removed: $CONFIG_PATH"
  fi
fi

# ── Remove logs ───────────────────────────────────────────────────────────────
if [[ "$KEEP_LOGS" == "false" ]]; then
  if [[ -d "$LOG_DIR" ]]; then
    rm -rf "$LOG_DIR"
    echo "  Removed: $LOG_DIR"
  fi
fi

# Remove data dir if now empty
rmdir "${DATA_DIR}/data"    2>/dev/null || true
rmdir "${DATA_DIR}"         2>/dev/null || true

# ── Remove pid file ───────────────────────────────────────────────────────────
rm -f /Library/Jarvis/jarvis-agent.pid 2>/dev/null || true

echo ""
echo "  Uninstall complete."
if [[ "$KEEP_CONFIG" == "true" ]]; then
  echo "  Config retained: ${DATA_DIR}/agent.toml"
fi
if [[ "$KEEP_LOGS" == "true" ]]; then
  echo "  Logs retained:   ${LOG_DIR}/"
fi
if [[ "$KEEP_KEYS" == "true" ]]; then
  echo "  Keys retained:   Keychain + ${SECURITY_DIR}/"
fi
echo ""
