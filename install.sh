#!/usr/bin/env bash
# NetWatchM Linux installer
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR ]${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Check Python >= 3.12
info "Checking Python..."
if ! command -v python3 &>/dev/null; then
    error "python3 not found. Install Python 3.12+."
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 12 ]]; }; then
    error "Python 3.12+ required (found $PY_VER)"
fi
info "Python $PY_VER OK"

# 2. Check tshark
info "Checking tshark..."
if ! command -v tshark &>/dev/null; then
    warning "tshark not found. Attempting install..."
    if command -v apt-get &>/dev/null; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y wireshark-cli
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm wireshark-cli
    else
        error "Cannot install tshark automatically. Please install wireshark-cli/tshark."
    fi
fi
info "tshark found: $(command -v tshark)"

# 3. Install uv if missing
info "Checking uv..."
if ! command -v uv &>/dev/null; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi
UV_BIN="$(command -v uv)"
info "uv found: $UV_BIN"

# 4. Sync dependencies
info "Installing Python dependencies..."
cd "$SCRIPT_DIR"
"$UV_BIN" sync

# 5. Copy example config
CONFIG_DIR="/etc/netwatchm"
CONFIG_FILE="$CONFIG_DIR/netwatchm.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    info "Creating $CONFIG_FILE..."
    sudo mkdir -p "$CONFIG_DIR"
    sudo cp "$SCRIPT_DIR/netwatchm.yaml.example" "$CONFIG_FILE"
    info "Edit $CONFIG_FILE to customise settings."
else
    info "Config already exists at $CONFIG_FILE"
fi

# 6. Create log directory
sudo mkdir -p /var/log/netwatchm
sudo mkdir -p /var/lib/netwatchm

# 7. Prompt for Gmail App Password
ENV_FILE="/etc/netwatchm/env"
if [[ ! -f "$ENV_FILE" ]]; then
    echo ""
    read -r -p "Enter Gmail App Password for alert emails (leave empty to skip): " EMAIL_PASS
    if [[ -n "$EMAIL_PASS" ]]; then
        echo "NETWATCHM_EMAIL_PASSWORD=$EMAIL_PASS" | sudo tee "$ENV_FILE" > /dev/null
        sudo chmod 600 "$ENV_FILE"
        info "App password saved to $ENV_FILE"
    fi
fi

# 8. Install monitor service
info "Installing systemd service..."
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    set -a; source "$ENV_FILE"; set +a
fi
sudo env NETWATCHM_EMAIL_PASSWORD="${NETWATCHM_EMAIL_PASSWORD:-}" \
    "$UV_BIN" run netwatchm --config "$CONFIG_FILE" --install-service || true

# 9. Install web dashboard service
info "Installing web dashboard service..."
sudo cp "$SCRIPT_DIR/report.html" /var/lib/netwatchm/report.html
sudo cp "$SCRIPT_DIR/netwatchm-web.service" /etc/systemd/system/netwatchm-web.service

# 10. Install down-alert notification script and service template
info "Installing service-down email alert..."
sudo cp "$SCRIPT_DIR/scripts/notify-down.py" /usr/local/bin/netwatchm-notify
sudo chmod +x /usr/local/bin/netwatchm-notify
sudo cp "$SCRIPT_DIR/netwatchm-notify@.service" /etc/systemd/system/netwatchm-notify@.service

sudo systemctl daemon-reload
sudo systemctl enable --now netwatchm-web

info ""
info "NetWatchM installed successfully!"
info "  Monitor status:   systemctl status netwatchm"
info "  Web dashboard:    http://localhost:8765/report.html"
info "  Web status:       systemctl status netwatchm-web"
info "  Logs:             journalctl -u netwatchm -f"
info "  Config:           $CONFIG_FILE"
info "  Down alerts:      email sent when netwatchm or netwatchm-web stops"
