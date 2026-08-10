#!/usr/bin/env bash
# =============================================================================
#  agent/pkg/build_pkg.sh — Build mac_intel agent .pkg installer (ARM64)
#
#  Usage:
#    cd /path/to/macbook_data
#    VERSION=1.0.0 bash agent/pkg/build_pkg.sh
#
#  Optional environment variables:
#    VERSION         Package version string (default: 1.0.0)
#    SIGN_IDENTITY   Apple "Developer ID Installer: ..." identity for signing
#    ARCH            Target architecture: arm64 | x86_64 | universal (default: arm64)
#
#  Prerequisites:
#    pip install pyinstaller
#    Xcode command-line tools  (for pkgbuild, productbuild, codesign)
#    Apple Developer ID (for signing + notarisation — optional for dev builds)
#
#  Output:
#    agent/pkg/build/macintel-agent-<VERSION>-<ARCH>.pkg
# =============================================================================
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
VERSION="${VERSION:-1.0.0}"
ARCH="${ARCH:-arm64}"
PKG_ID="com.macintel.agent"

INSTALL_DIR="/opt/macintel"
CONFIG_DIR="/Library/Application Support/MacIntel"
LOG_DIR="/Library/Logs/MacIntel"
LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
SECURITY_DIR="${CONFIG_DIR}/security"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
PKG_ROOT="${BUILD_DIR}/pkgroot"
PKG_NAME="macintel-agent-${VERSION}-${ARCH}.pkg"

echo "============================================="
echo " mac_intel Agent PKG Builder"
echo " Version : ${VERSION}"
echo " Arch    : ${ARCH}"
echo " Output  : ${BUILD_DIR}/${PKG_NAME}"
echo "============================================="
echo ""

# ── Clean build dir ───────────────────────────────────────────────────────────
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

cd "${REPO_ROOT}"

# ── Step 1: Build agent binary ────────────────────────────────────────────────
echo "[1/5] Building macintel-agent binary (PyInstaller)..."
python3 -m PyInstaller \
    --onefile \
    --clean \
    --name "macintel-agent" \
    --target-architecture "${ARCH}" \
    --hidden-import "agent.agent.collectors" \
    --hidden-import "agent.agent.normalizer" \
    --hidden-import "agent.agent.enrollment" \
    --hidden-import "agent.agent.keystore" \
    --hidden-import "tomllib" \
    --distpath "${BUILD_DIR}/bin" \
    agent/agent/core.py

# ── Step 2: Build watchdog binary ─────────────────────────────────────────────
echo "[2/5] Building macintel-watchdog binary (PyInstaller)..."
python3 -m PyInstaller \
    --onefile \
    --clean \
    --name "macintel-watchdog" \
    --target-architecture "${ARCH}" \
    --hidden-import "tomllib" \
    --distpath "${BUILD_DIR}/bin" \
    agent/agent/watchdog.py

# ── Step 3: Assemble package root ─────────────────────────────────────────────
echo "[3/5] Assembling package root..."
mkdir -p "${PKG_ROOT}${INSTALL_DIR}/bin"
mkdir -p "${PKG_ROOT}${CONFIG_DIR}"
mkdir -p "${PKG_ROOT}${SECURITY_DIR}"
mkdir -p "${PKG_ROOT}${LOG_DIR}"
mkdir -p "${PKG_ROOT}${LAUNCHDAEMON_DIR}"
mkdir -p "${PKG_ROOT}/var/run"

# Binaries
cp "${BUILD_DIR}/bin/macintel-agent"    "${PKG_ROOT}${INSTALL_DIR}/bin/"
cp "${BUILD_DIR}/bin/macintel-watchdog" "${PKG_ROOT}${INSTALL_DIR}/bin/"
chmod 755 "${PKG_ROOT}${INSTALL_DIR}/bin/macintel-agent"
chmod 755 "${PKG_ROOT}${INSTALL_DIR}/bin/macintel-watchdog"

# Config template (postinstall script copies to agent.conf only if not present)
cp "agent/config/agent.conf.example" "${PKG_ROOT}${CONFIG_DIR}/agent.conf.example"
chmod 644 "${PKG_ROOT}${CONFIG_DIR}/agent.conf.example"

# LaunchDaemon
cp "agent/launchd/com.macintel.agent.plist" "${PKG_ROOT}${LAUNCHDAEMON_DIR}/"
chmod 644 "${PKG_ROOT}${LAUNCHDAEMON_DIR}/com.macintel.agent.plist"

# ── Step 4: Build .pkg ────────────────────────────────────────────────────────
echo "[4/5] Building .pkg with pkgbuild..."
pkgbuild \
    --root "${PKG_ROOT}" \
    --scripts "${SCRIPT_DIR}/scripts" \
    --identifier "${PKG_ID}" \
    --version "${VERSION}" \
    --install-location "/" \
    "${BUILD_DIR}/${PKG_NAME}"

# ── Step 5: Optional code signing ─────────────────────────────────────────────
echo "[5/5] Code signing..."
if [ -n "${SIGN_IDENTITY:-}" ]; then
    SIGNED="${BUILD_DIR}/macintel-agent-${VERSION}-${ARCH}-signed.pkg"
    productsign \
        --sign "${SIGN_IDENTITY}" \
        "${BUILD_DIR}/${PKG_NAME}" \
        "${SIGNED}"
    echo "  Signed: ${SIGNED}"
    echo ""
    echo "  To notarise:"
    echo "    xcrun notarytool submit ${SIGNED} \\"
    echo "      --apple-id YOUR_APPLE_ID \\"
    echo "      --team-id YOUR_TEAM_ID \\"
    echo "      --password APP_SPECIFIC_PASSWORD \\"
    echo "      --wait"
else
    echo "  Skipped (set SIGN_IDENTITY to sign)"
    echo "  Example: SIGN_IDENTITY='Developer ID Installer: Acme Corp (TEAMID)'"
fi

echo ""
echo "============================================="
echo " Build complete!"
echo " Package: ${BUILD_DIR}/${PKG_NAME}"
echo "============================================="
echo ""
echo "To install (on target machine):"
echo "  sudo installer -pkg ${BUILD_DIR}/${PKG_NAME} -target /"
echo ""
echo "Post-install steps:"
echo "  1. Edit /Library/Application\\ Support/MacIntel/agent.conf"
echo "  2. Set [manager] url and [enrollment] token"
echo "  3. sudo launchctl kickstart system/com.macintel.agent"
