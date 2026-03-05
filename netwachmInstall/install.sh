#!/usr/bin/env bash
# NetWatchM Linux installer
# Usage: bash netwachmInstall/install.sh [--yes] [--uninstall] [--no-service] [--no-web]
#                                        [--config PATH] [--experimental-macos]
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR ]${NC} $*" >&2; exit 1; }
step()    { echo -e "${BLUE}[STEP]${NC} $*"; }

INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$INSTALLER_DIR/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
YES=false
UNINSTALL=false
NO_SERVICE=false
NO_WEB=false
EXPERIMENTAL_MACOS=false
CONFIG_PATH="/etc/netwatchm/netwatchm.yaml"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|--unattend)     YES=true ;;
        --uninstall)          UNINSTALL=true ;;
        --no-service)         NO_SERVICE=true ;;
        --no-web)             NO_WEB=true ;;
        --experimental-macos) EXPERIMENTAL_MACOS=true ;;
        --config)
            shift
            CONFIG_PATH="${1:?--config requires a path argument}"
            ;;
        -h|--help)
            echo "Usage: bash netwachmInstall/install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --yes              Non-interactive (skip prompts, use defaults)"
            echo "  --uninstall        Remove NetWatchM from this system"
            echo "  --no-service       Install package only, skip systemd service setup"
            echo "  --no-web           Skip web server setup"
            echo "  --config PATH      Use custom config path (default: /etc/netwatchm/netwatchm.yaml)"
            echo "  --experimental-macos  Enable macOS (Homebrew) support"
            echo "  -h, --help         Show this help"
            exit 0
            ;;
        *) error "Unknown option: $1  (use --help for usage)" ;;
    esac
    shift
done

CONFIG_DIR="$(dirname "$CONFIG_PATH")"

# ── Detect OS / package manager ───────────────────────────────────────────────
IS_MACOS=false
PKG_MGR=""
if [[ "$(uname)" == "Darwin" ]]; then
    IS_MACOS=true
    if [[ "$EXPERIMENTAL_MACOS" != true ]]; then
        error "macOS detected. Re-run with --experimental-macos to proceed (unsupported, use at your own risk)."
    fi
    PKG_MGR="brew"
elif command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v zypper &>/dev/null; then
    PKG_MGR="zypper"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
fi

# ── Helper: run sudo command with clear error message ─────────────────────────
sudo_run() {
    local desc="$1"; shift
    if ! sudo "$@"; then
        error "Failed: $desc (command: sudo $*)"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  UNINSTALL
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$UNINSTALL" == true ]]; then
    step "Uninstalling NetWatchM..."

    for svc in netwatchm netwatchm-web netwatchm-notify@; do
        if systemctl is-active --quiet "${svc%.@}" 2>/dev/null || \
           systemctl is-enabled --quiet "${svc%.@}" 2>/dev/null; then
            sudo_run "Stop service $svc" systemctl stop "$svc" 2>/dev/null || true
            sudo_run "Disable service $svc" systemctl disable "$svc" 2>/dev/null || true
        fi
    done

    for f in /etc/systemd/system/netwatchm.service \
              /etc/systemd/system/netwatchm-web.service \
              /etc/systemd/system/netwatchm-notify@.service; do
        [[ -f "$f" ]] && sudo_run "Remove $f" rm -f "$f"
    done

    for b in /usr/local/bin/netwatchm-server /usr/local/bin/netwatchm-notify; do
        [[ -f "$b" ]] && sudo_run "Remove $b" rm -f "$b"
    done

    if command -v uv &>/dev/null; then
        uv tool uninstall netwatchm 2>/dev/null || true
    fi

    sudo_run "Reload systemd" systemctl daemon-reload

    info "NetWatchM removed."
    info "Config and data left in place:"
    info "  $CONFIG_DIR  (config)"
    info "  /var/lib/netwatchm  (data/certs/db)"
    info "  /var/log/netwatchm  (logs)"
    info "Remove them manually if desired."
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
#  PREFLIGHT CHECKS
# ══════════════════════════════════════════════════════════════════════════════
step "Running preflight checks..."

# Python 3.12+
if ! command -v python3 &>/dev/null; then
    error "python3 not found. Install Python 3.12+ first."
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 12 ]]; }; then
    error "Python 3.12+ required (found $PY_VER). Please upgrade Python."
fi
info "Python $PY_VER OK"

# 200 MB free disk
FREE_KB=$(df -k "$HOME" | awk 'NR==2 {print $4}')
FREE_MB=$(( FREE_KB / 1024 ))
if [[ "$FREE_MB" -lt 200 ]]; then
    error "Less than 200 MB free disk space (found ${FREE_MB} MB). Free up space and retry."
fi
info "Disk space: ${FREE_MB} MB free — OK"

# Network reachability
if ! curl -sf --max-time 10 https://pypi.org/simple/ >/dev/null 2>&1; then
    warning "Cannot reach pypi.org — check your network connection."
    warning "Continuing anyway (may fail at dependency install)."
else
    info "Network: pypi.org reachable — OK"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEM DEPENDENCIES
# ══════════════════════════════════════════════════════════════════════════════
install_pkg() {
    local apt_name="$1"
    local dnf_name="${2:-$1}"
    local zypper_name="${3:-$1}"
    local pacman_name="${4:-$1}"
    local brew_name="${5:-$1}"

    case "$PKG_MGR" in
        apt)    sudo_run "Install $apt_name" apt-get install -y "$apt_name" ;;
        dnf)    sudo_run "Install $dnf_name" dnf install -y "$dnf_name" ;;
        zypper) sudo_run "Install $zypper_name" zypper install -n "$zypper_name" ;;
        pacman) sudo_run "Install $pacman_name" pacman -S --noconfirm "$pacman_name" ;;
        brew)   brew install "$brew_name" ;;
        "")     error "No supported package manager found (apt/dnf/zypper/pacman/brew). Install $apt_name manually." ;;
    esac
}

# arp-scan
step "Checking arp-scan..."
if ! command -v arp-scan &>/dev/null; then
    warning "arp-scan not found — installing..."
    install_pkg "arp-scan" "arp-scan" "arp-scan" "arp-scan" "arp-scan"
fi
if command -v arp-scan &>/dev/null; then
    sudo setcap cap_net_raw+ep "$(command -v arp-scan)" 2>/dev/null || true
    info "arp-scan ready: $(command -v arp-scan)"
fi

# tshark
step "Checking tshark..."
if ! command -v tshark &>/dev/null; then
    warning "tshark not found — installing..."
    install_pkg "tshark" "wireshark-cli" "wireshark" "wireshark-cli" "wireshark"
fi
if ! command -v tshark &>/dev/null; then
    error "tshark still not found after install attempt. Install wireshark/tshark manually."
fi
info "tshark found: $(command -v tshark)"

# ══════════════════════════════════════════════════════════════════════════════
#  uv
# ══════════════════════════════════════════════════════════════════════════════
step "Checking uv..."
if ! command -v uv &>/dev/null; then
    info "Installing uv..."
    if ! curl -LsSf https://astral.sh/uv/install.sh | sh; then
        error "Failed to install uv. Check your network and try again."
    fi
    export PATH="$HOME/.local/bin:$PATH"
fi
UV_BIN="$(command -v uv)"
info "uv found: $UV_BIN"

# ══════════════════════════════════════════════════════════════════════════════
#  PYTHON PACKAGE
# ══════════════════════════════════════════════════════════════════════════════
step "Installing Python dependencies..."
cd "$REPO_ROOT"
if ! "$UV_BIN" sync; then
    error "uv sync failed. Check your network or pyproject.toml for errors."
fi

step "Installing netwatchm CLI..."
if ! "$UV_BIN" tool install --no-cache . --force; then
    error "uv tool install failed."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════
step "Setting up configuration..."
if [[ ! -f "$CONFIG_PATH" ]]; then
    info "Creating $CONFIG_PATH..."
    sudo_run "Create config dir $CONFIG_DIR" mkdir -p "$CONFIG_DIR"
    sudo_run "Copy example config" cp "$REPO_ROOT/netwatchm.yaml.example" "$CONFIG_PATH"
    info "Edit $CONFIG_PATH to customise settings."
else
    info "Config already exists at $CONFIG_PATH — not overwriting."
fi

sudo_run "Create log dir" mkdir -p /var/log/netwatchm
sudo_run "Create data dir" mkdir -p /var/lib/netwatchm

# ══════════════════════════════════════════════════════════════════════════════
#  EMAIL PASSWORD
# ══════════════════════════════════════════════════════════════════════════════
ENV_FILE="$CONFIG_DIR/env"
if [[ ! -f "$ENV_FILE" ]]; then
    if [[ "$YES" == true ]]; then
        info "Skipping email password prompt (--yes mode)."
    else
        echo ""
        read -r -p "Enter Gmail App Password for alert emails (leave empty to skip): " EMAIL_PASS || EMAIL_PASS=""
        if [[ -n "${EMAIL_PASS:-}" ]]; then
            printf 'NETWATCHM_EMAIL_PASSWORD=%s\n' "$EMAIL_PASS" | sudo_run "Save env file" tee "$ENV_FILE" >/dev/null
            sudo_run "Secure env file" chmod 600 "$ENV_FILE"
            info "App password saved to $ENV_FILE"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
#  MONITOR SERVICE
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$NO_SERVICE" == false ]]; then
    step "Installing monitor service..."
    if [[ -f "$ENV_FILE" ]]; then
        # shellcheck source=/dev/null
        set -a; source "$ENV_FILE"; set +a
    fi
    if ! sudo env NETWATCHM_EMAIL_PASSWORD="${NETWATCHM_EMAIL_PASSWORD:-}" \
            "$UV_BIN" run netwatchm --config "$CONFIG_PATH" --install-service; then
        warning "Monitor service install reported an error (may already be installed). Continuing..."
    fi
else
    info "Skipping monitor service setup (--no-service)."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  WEB SERVER
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$NO_WEB" == false ]]; then
    step "Installing web dashboard..."

    # GeoIP database
    GEOIP_TAR=$(find "$REPO_ROOT/geolite2-city-gzip" -name "GeoLite2-City*.tar.gz" 2>/dev/null | head -1 || true)
    GEOIP_MMDB="$REPO_ROOT/geolite2-city-gzip/GeoLite2-City.mmdb"
    if [[ -f "$GEOIP_MMDB" ]]; then
        info "Installing GeoLite2-City database..."
        sudo_run "Install GeoIP DB" cp "$GEOIP_MMDB" /var/lib/netwatchm/GeoLite2-City.mmdb
        info "  GeoIP installed at /var/lib/netwatchm/GeoLite2-City.mmdb"
    elif [[ -n "${GEOIP_TAR:-}" && -f "$GEOIP_TAR" ]]; then
        info "Extracting GeoLite2-City database..."
        sudo tar -xzf "$GEOIP_TAR" -C /tmp/ --wildcards "*/GeoLite2-City.mmdb" 2>/dev/null || true
        sudo find /tmp -name "GeoLite2-City.mmdb" -exec mv {} /var/lib/netwatchm/GeoLite2-City.mmdb \; 2>/dev/null || true
        info "  GeoIP installed at /var/lib/netwatchm/GeoLite2-City.mmdb"
    else
        warning "GeoLite2-City database not found — GeoIP lookups will be skipped."
        warning "Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    fi

    for f in report.html; do
        [[ -f "$REPO_ROOT/$f" ]] && sudo_run "Install $f" cp "$REPO_ROOT/$f" /var/lib/netwatchm/"$f"
    done

    sudo_run "Install server script" cp "$REPO_ROOT/netwatchm_server.py" /usr/local/bin/netwatchm-server
    sudo_run "Mark server executable" chmod +x /usr/local/bin/netwatchm-server

    for svc in netwatchm-web.service "netwatchm-notify@.service"; do
        if [[ -f "$REPO_ROOT/$svc" ]]; then
            sudo_run "Install $svc" cp "$REPO_ROOT/$svc" /etc/systemd/system/"$svc"
        fi
    done

    # TLS certificate
    step "Setting up HTTPS certificate..."
    if command -v mkcert &>/dev/null; then
        mkcert -install 2>/dev/null || true
        mkcert -key-file /tmp/nwm-server.key -cert-file /tmp/nwm-server.crt localhost 127.0.0.1
        sudo_run "Install TLS key" mv /tmp/nwm-server.key /var/lib/netwatchm/server.key
        sudo_run "Install TLS cert" mv /tmp/nwm-server.crt /var/lib/netwatchm/server.crt
        sudo_run "Secure TLS key" chmod 600 /var/lib/netwatchm/server.key
        info "  TLS: mkcert certificate installed (browser-trusted)"
    elif [[ ! -f /var/lib/netwatchm/server.crt ]]; then
        if ! sudo openssl req -x509 -newkey rsa:2048 \
                -keyout /var/lib/netwatchm/server.key \
                -out /var/lib/netwatchm/server.crt \
                -days 3650 -nodes \
                -subj "/CN=localhost/O=NetWatchM" \
                -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null; then
            error "openssl failed to generate TLS certificate. Install openssl and retry."
        fi
        sudo_run "Secure TLS key" chmod 600 /var/lib/netwatchm/server.key
        info "  TLS: self-signed certificate installed (browser will warn — install mkcert for trusted HTTPS)"
    else
        info "  TLS: certificate already exists — not regenerating."
    fi

    if [[ -f "$REPO_ROOT/scripts/notify-down.py" ]]; then
        sudo_run "Install notify script" cp "$REPO_ROOT/scripts/notify-down.py" /usr/local/bin/netwatchm-notify
        sudo_run "Mark notify executable" chmod +x /usr/local/bin/netwatchm-notify
    fi

    sudo_run "Reload systemd" systemctl daemon-reload
    if ! sudo systemctl enable --now netwatchm-web; then
        warning "Could not enable/start netwatchm-web. Check: systemctl status netwatchm-web"
    fi
else
    info "Skipping web server setup (--no-web)."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
echo ""
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "NetWatchM installed successfully!"
info ""
info "  Monitor status:   systemctl status netwatchm"
info "  Web dashboard:    https://localhost:8765/events.html"
info "  Web status:       systemctl status netwatchm-web"
info "  Logs:             journalctl -u netwatchm -f"
info "  Config:           $CONFIG_PATH"
[[ "$NO_WEB" == false ]] && info "  Down alerts:      email sent when netwatchm or netwatchm-web stops"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
