#!/usr/bin/env bash
# Build NetWatchM Linux executables with PyInstaller.
# Run from anywhere — script resolves the repo root automatically.
#
# Produces dist/netwatchm/ (inside repo root) containing:
#   netwatchm        — CLI monitor
#   netwatchm-server — HTTPS web server
#
# Usage:
#   bash netwachmInstall/build-linux.sh [--zip] [--clean]
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }
step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

ZIP=false
CLEAN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --zip)   ZIP=true ;;
        --clean) CLEAN=true ;;
        -h|--help)
            echo "Usage: bash netwachmInstall/build-linux.sh [--zip] [--clean]"
            echo "  --zip    Tar-gz output to dist/netwatchm-linux.tar.gz"
            echo "  --clean  Remove dist/ and build/ before building"
            exit 0
            ;;
        *) error "Unknown option: $1" ;;
    esac
    shift
done

INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$INSTALLER_DIR/.." && pwd)"
SPEC="$INSTALLER_DIR/netwatchm.spec"

cd "$REPO_ROOT"
info "Repository root: $REPO_ROOT"

# ── Python check ──────────────────────────────────────────────────────────────
step "Checking Python..."
if ! command -v python3 &>/dev/null; then
    error "python3 not found. Install Python 3.12+."
fi
PY_VER=$(python3 --version 2>&1 | sed 's/Python //')
info "Python $PY_VER"

# ── Build dependencies ────────────────────────────────────────────────────────
step "Installing build dependencies..."
pip install --quiet --upgrade pip
pip install --quiet "pyinstaller>=6.0"

if command -v uv &>/dev/null; then
    info "uv found — syncing deps..."
    uv sync
else
    warn "uv not found — skipping uv sync"
fi

# ── Clean (optional) ──────────────────────────────────────────────────────────
if [[ "$CLEAN" == true ]]; then
    step "Cleaning previous build artifacts..."
    for d in dist build; do
        if [[ -d "$d" ]]; then
            rm -rf "$d"
            info "  Removed $d/"
        fi
    done
fi

# ── Build ─────────────────────────────────────────────────────────────────────
step "Running PyInstaller..."
pyinstaller "$SPEC" --clean --noconfirm

# ── Verify ────────────────────────────────────────────────────────────────────
step "Verifying outputs..."
for bin in "dist/netwatchm/netwatchm" "dist/netwatchm/netwatchm-server"; do
    if [[ -f "$bin" ]]; then
        size=$(du -sh "$bin" | cut -f1)
        info "  $bin  ($size)"
    else
        warn "  MISSING: $bin"
    fi
done

step "Smoke-testing netwatchm --help..."
if dist/netwatchm/netwatchm --help >/dev/null 2>&1; then
    info "  --help OK"
else
    warn "  netwatchm --help exited with non-zero status"
fi

# ── Archive (optional) ────────────────────────────────────────────────────────
if [[ "$ZIP" == true ]]; then
    step "Creating distribution archive..."
    tar -czf dist/netwatchm-linux.tar.gz -C dist netwatchm
    size=$(du -sh dist/netwatchm-linux.tar.gz | cut -f1)
    info "  Created dist/netwatchm-linux.tar.gz  ($size)"
fi

echo ""
info "Build complete!"
info "  Output folder:     dist/netwatchm/"
info "  CLI binary:        dist/netwatchm/netwatchm"
info "  Web server binary: dist/netwatchm/netwatchm-server"
[[ "$ZIP" == true ]] && info "  Archive:           dist/netwatchm-linux.tar.gz"
info ""
info "Quick test:"
info "  ./dist/netwatchm/netwatchm --help"
