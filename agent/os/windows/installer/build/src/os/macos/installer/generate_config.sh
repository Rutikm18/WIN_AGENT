#!/usr/bin/env bash
# =============================================================================
#  agent/os/macos/installer/generate_config.sh
#
#  Write a complete agent.toml to DATA_DIR/agent.toml.
#  Called by install.sh and the .pkg postinstall script.
#  Can also be run standalone to regenerate config after edits.
#
#  All parameters come from environment variables so that the
#  .pkg postinstall script can set them before calling this.
#
#  Required:
#    MANAGER_URL      — https://manager-host:8443
#    AGENT_ID         — unique UUID-style identifier
#    AGENT_NAME       — human-readable label (default: ComputerName)
#
#  Optional:
#    ENROLL_TOKEN     — sk-enroll-<hex>  (first-run enrollment)
#    MANAGER_API_KEY  — 64-hex key (skip enrollment)
#    TLS_VERIFY       — true/false (default: true)
#    INSTALL_DIR      — default: /Library/Jarvis
#    DATA_DIR         — default: /Library/Jarvis
#    LOG_DIR          — default: /Library/Jarvis/logs
#    SECURITY_DIR     — default: $DATA_DIR/security
# =============================================================================
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/Library/Jarvis}"
DATA_DIR="${DATA_DIR:-/Library/Jarvis}"
LOG_DIR="${LOG_DIR:-/Library/Jarvis/logs}"
SECURITY_DIR="${SECURITY_DIR:-${DATA_DIR}/security}"
MANAGER_URL="${MANAGER_URL:-https://localhost:8443}"
ENROLL_TOKEN="${ENROLL_TOKEN:-}"
MANAGER_API_KEY="${MANAGER_API_KEY:-}"
AGENT_ID="${AGENT_ID:-}"
AGENT_NAME="${AGENT_NAME:-$(scutil --get ComputerName 2>/dev/null || hostname)}"
TLS_VERIFY="${TLS_VERIFY:-true}"

CONFIG_PATH="${DATA_DIR}/agent.toml"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Resolve agent ID — prefer hardware UUID for stability across reinstalls
if [[ -z "$AGENT_ID" ]]; then
  HW_UUID=$(system_profiler SPHardwareDataType 2>/dev/null \
    | awk '/Hardware UUID/{print tolower($NF)}')
  if [[ -n "$HW_UUID" ]]; then
    AGENT_ID="mac-${HW_UUID}"
  else
    AGENT_ID="mac-$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')"
  fi
fi

# Ensure data dir exists
mkdir -p "${DATA_DIR}" "${SECURITY_DIR}" "${LOG_DIR}" "${DATA_DIR}/data"

# ── Write agent.toml (minimal — binary auto-applies all other defaults) ───────
{
cat <<EOF
# mac_intel Agent Configuration
# Generated: ${TIMESTAMP}
#
# Only these two fields are required:
#   [manager] url  — your manager's HTTPS address
#   [agent]   name — friendly name shown on dashboard (optional)
#
# The agent binary auto-detects its ID from the Mac's hardware UUID.
# All collection schedules, paths, and logging use built-in defaults.
# Edit and send SIGHUP (or restart) to apply changes.

[agent]
name = "${AGENT_NAME}"

[manager]
url        = "${MANAGER_URL}"
tls_verify = ${TLS_VERIFY}
EOF

# Only write api_key if a valid 64-hex key was provided
if [[ ${#MANAGER_API_KEY} -eq 64 && "$MANAGER_API_KEY" =~ ^[0-9a-fA-F]+$ ]]; then
  echo "api_key = \"${MANAGER_API_KEY}\""
fi

# Only write enrollment token if provided
if [[ -n "${ENROLL_TOKEN}" ]]; then
cat <<EOF

[enrollment]
token = "${ENROLL_TOKEN}"
EOF
fi

} > "${CONFIG_PATH}"

chown root:wheel "${CONFIG_PATH}" 2>/dev/null || true
chmod 640 "${CONFIG_PATH}"

echo "  agent.toml written to: ${CONFIG_PATH}"
echo "  Agent ID  : ${AGENT_ID}"
echo "  Agent Name: ${AGENT_NAME}"
echo "  Manager   : ${MANAGER_URL}"
