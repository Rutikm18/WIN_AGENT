#!/usr/bin/env bash
#
# build_msi.sh — Build the AttackLens Windows agent MSI end-to-end, in one command.
#
# Produces:  pkg/dist/attacklens-agent-<VERSION>-x64.msi
#
# Steps:
#   1. Build attacklens-agent + attacklens-watchdog onedir EXEs (PyInstaller).
#   2. Harvest the _internal trees and compile the MSI (WiX v4, via build_msi.ps1).
#
# Requirements (all present on a configured build box):
#   - Python 3.11+ with:  pip install -r ../requirements.txt  pyinstaller
#   - WiX v4 CLI:          dotnet tool install --global wix
#   - Runs under Git Bash on Windows (invokes powershell.exe for the WiX step).
#
# Usage:
#   ./build_msi.sh                # version 2.0.0
#   ./build_msi.sh 2.1.0          # explicit version
#
set -euo pipefail

VERSION="${1:-2.0.0}"

# ── Resolve paths (this script lives in pkg/) ─────────────────────────────────
PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$PKG/../../../.." && pwd)"     # -> PROJECT_CORE (so `agent` package imports)
DIST="$PKG/dist"

AGENT_SPEC="$PKG/attacklens-agent.spec"
WATCHDOG_SPEC="$PKG/attacklens-watchdog.spec"
MSI_PS1="$PKG/build_msi.ps1"
MSI_OUT="$DIST/attacklens-agent-$VERSION-x64.msi"

say()  { printf '\n\033[36m==> %s\033[0m\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ── Prerequisite checks ───────────────────────────────────────────────────────
say "Checking prerequisites"
command -v python        >/dev/null 2>&1 || die "python not found on PATH"
python -c "import PyInstaller" 2>/dev/null || die "PyInstaller not installed (pip install pyinstaller)"
python -c "import win32api"    2>/dev/null || die "pywin32 not installed (pip install pywin32)"
[ -f "$AGENT_SPEC" ]    || die "missing spec: $AGENT_SPEC"
[ -f "$WATCHDOG_SPEC" ] || die "missing spec: $WATCHDOG_SPEC"
[ -f "$MSI_PS1" ]       || die "missing WiX build script: $MSI_PS1"

# WiX v4 CLI is a dotnet global tool; make sure its dir is on PATH for the child.
if [ -d "$HOME/.dotnet/tools" ]; then
    export PATH="$HOME/.dotnet/tools:$PATH"
fi
command -v wix >/dev/null 2>&1 || command -v wix.exe >/dev/null 2>&1 \
    || die "WiX v4 CLI ('wix') not found. Install: dotnet tool install --global wix"
echo "  python + PyInstaller + pywin32 + WiX OK"

# ── Step 1: PyInstaller onedir EXEs (run from ROOT so imports resolve) ─────────
say "Building EXEs (PyInstaller onedir)"
cd "$ROOT"
pyinstaller --noconfirm --distpath "$DIST" --workpath "$PKG/build/agent"    "$AGENT_SPEC"
pyinstaller --noconfirm --distpath "$DIST" --workpath "$PKG/build/watchdog" "$WATCHDOG_SPEC"
[ -f "$DIST/attacklens-agent/attacklens-agent.exe" ]       || die "agent EXE not produced"
[ -f "$DIST/attacklens-watchdog/attacklens-watchdog.exe" ] || die "watchdog EXE not produced"
echo "  EXEs built"

# ── Step 2: Harvest _internal + compile MSI (WiX v4, reuse the EXEs above) ─────
say "Building MSI (WiX v4)"
# powershell.exe needs a Windows-style path for -File (paths contain spaces).
MSI_PS1_WIN="$(cygpath -w "$MSI_PS1" 2>/dev/null || echo "$MSI_PS1")"
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
    -File "$MSI_PS1_WIN" -SkipBuild -Version "$VERSION"

# ── Verify ────────────────────────────────────────────────────────────────────
[ -f "$MSI_OUT" ] || die "MSI not produced at $MSI_OUT"
SIZE=$(du -h "$MSI_OUT" | cut -f1)
say "Done"
echo "  MSI: $MSI_OUT  (${SIZE})"
echo
echo "  Install:"
echo "    msiexec /i \"$MSI_OUT\" /qn MANAGER_IP=\"<ip>\" ENROLL_TOKEN=\"<token>\" /l*v install.log"
echo "  Uninstall:"
echo "    msiexec /x \"$MSI_OUT\" /qn"
