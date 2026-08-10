#!/usr/bin/env bash
# =============================================================================
#  agent/scripts/install.sh — Install mac_intel agent on macOS
#
#  Run from the agent/ package directory:
#    cd macbook_data/agent
#    bash scripts/install.sh
# =============================================================================
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYN='\033[0;36m'; N='\033[0m'
info() { printf "${CYN}[info]${N}  %s\n" "$*"; }
ok()   { printf "${GRN}[ok]${N}    %s\n" "$*"; }
warn() { printf "${YEL}[warn]${N}  %s\n" "$*"; }
err()  { printf "${RED}[err]${N}   %s\n" "$*"; exit 1; }

# ── 1. Python check ───────────────────────────────────────────────────────────
command -v python3 &>/dev/null || err "python3 not found. Install via: brew install python"
VER=$(python3 -c "import sys; print(sys.version_info[:2] >= (3,9))")
[[ "$VER" == "True" ]] || err "Python 3.9+ required"
ok "Python $(python3 --version)"

# ── 2. Install deps ───────────────────────────────────────────────────────────
info "Installing agent dependencies..."
python3 -m pip install -q --upgrade pip
python3 -m pip install -q -r "${AGENT_DIR}/requirements.txt"
ok "Dependencies installed"

# ── 3. Config ─────────────────────────────────────────────────────────────────
if [[ ! -f "${AGENT_DIR}/config/agent.toml" ]]; then
    warn "config/agent.toml not found — creating from example"
    cp "${AGENT_DIR}/config/agent.toml.example" "${AGENT_DIR}/config/agent.toml"
    warn "Edit config/agent.toml: set [manager] url and api_key, then re-run."
    exit 0
fi

if grep -q "REPLACE_ME" "${AGENT_DIR}/config/agent.toml"; then
    warn "agent.toml still has placeholder values."
    info "Run: cd manager && python3 scripts/keygen.py"
    info "Then paste the key into agent/config/agent.toml [manager] api_key"
    exit 0
fi

# ── 4. Log directory ──────────────────────────────────────────────────────────
mkdir -p "${AGENT_DIR}/logs"

# ── 5. macOS launchd service ──────────────────────────────────────────────────
if [[ "$(uname)" != "Darwin" ]]; then
    warn "Non-macOS detected. Run manually:"
    echo "  cd ${AGENT_DIR} && python3 -m agent.core --config config/agent.toml"
    exit 0
fi

PLIST="${HOME}/Library/LaunchAgents/com.mac-intel.agent.plist"
mkdir -p "${HOME}/Library/LaunchAgents"

cat > "${PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key>           <string>com.mac-intel.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(command -v python3)</string>
    <string>-m</string>
    <string>agent.core</string>
    <string>--config</string>
    <string>${AGENT_DIR}/config/agent.toml</string>
  </array>
  <key>WorkingDirectory</key> <string>${AGENT_DIR}</string>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>${AGENT_DIR}/logs/agent.log</string>
  <key>StandardErrorPath</key><string>${AGENT_DIR}/logs/agent-err.log</string>
</dict></plist>
PLIST

launchctl unload "${PLIST}" 2>/dev/null || true
launchctl load   "${PLIST}"

ok "Agent installed as launchd service: com.mac-intel.agent"
echo ""
info "Logs:    tail -f ${AGENT_DIR}/logs/agent.log"
info "Stop:    launchctl unload ${PLIST}"
info "Restart: launchctl unload ${PLIST} && launchctl load ${PLIST}"
info "Reload config (no restart): kill -HUP \$(pgrep -f agent.core)"
