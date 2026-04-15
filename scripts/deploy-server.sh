#!/usr/bin/env bash
# =============================================================================
# scripts/deploy-server.sh
#
# PURPOSE
#   Full deploy of the NetWatchM web server (netwatchm_server.py) to the
#   system, then restart the netwatchm-web systemd service.
#
# WHAT THIS SCRIPT DOES
#   1. Creates a system-owned venv at /usr/local/lib/netwatchm/venv
#      (independent of the developer's home directory — required so the
#       netwatchm system user can execute Python without home dir access)
#   2. Installs the netwatchm package + all deps into that system venv
#   3. Copies netwatchm_server.py to /usr/local/lib/netwatchm/
#   4. Writes /usr/local/bin/netwatchm-server wrapper pointing at system venv
#   5. Patches NETWATCHM_CMD in the service file to point at the system venv
#      CLI (required when running as non-root netwatchm user — home dir blocked)
#   6. Reinstalls the CLI binary to ~/.local/bin/netwatchm (for manual use)
#   7. Reloads systemd and restarts netwatchm-web
#
# WHEN TO RUN
#   - After any change to netwatchm_server.py
#   - After adding/changing Python dependencies (pyproject.toml)
#   - After running harden-service-user.sh (fixes venv permission issue)
#
# NOTE: hotdeploy.sh is faster for server-only changes (skips venv rebuild).
# =============================================================================
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SYSTEM_VENV="/usr/local/lib/netwatchm/venv"
SYSTEM_PYTHON="$SYSTEM_VENV/bin/python3"

echo "=== NetWatchM full deploy ==="

# --- Step 1: Create/update system venv ---
echo "[1/5] Setting up system venv at $SYSTEM_VENV…"
sudo mkdir -p /usr/local/lib/netwatchm
if [ ! -x "$SYSTEM_PYTHON" ]; then
    sudo python3 -m venv "$SYSTEM_VENV"
    echo "      Venv created."
else
    echo "      Venv already exists."
fi

# --- Step 2: Install package into system venv ---
echo "[2/5] Installing netwatchm package into system venv…"
sudo "$SYSTEM_VENV/bin/pip" install -e "$REPO" --quiet

# --- Step 3: Copy server source ---
echo "[3/5] Copying netwatchm_server.py…"
sudo cp "$REPO/netwatchm_server.py" /usr/local/lib/netwatchm/netwatchm_server.py

# --- Step 4: Write wrapper pointing at system venv ---
echo "[4/5] Writing /usr/local/bin/netwatchm-server wrapper…"
sudo tee /usr/local/bin/netwatchm-server > /dev/null <<WRAPPER
#!/bin/bash
exec "$SYSTEM_PYTHON" /usr/local/lib/netwatchm/netwatchm_server.py "\$@"
WRAPPER
sudo chmod +x /usr/local/bin/netwatchm-server

# --- Step 5: Patch NETWATCHM_CMD in service file to use system venv ---
# The netwatchm user cannot access the developer's home directory, so
# NETWATCHM_CMD must point to the system venv CLI, not ~/.local/bin/netwatchm.
echo "[5/6] Patching NETWATCHM_CMD in service file to use system venv CLI…"
SYSTEM_CLI="$SYSTEM_VENV/bin/netwatchm"
SERVICE_FILE="/etc/systemd/system/netwatchm-web.service"
if grep -q "^Environment=NETWATCHM_CMD=" "$SERVICE_FILE"; then
    sudo sed -i "s|^Environment=NETWATCHM_CMD=.*|Environment=NETWATCHM_CMD=$SYSTEM_CLI|" "$SERVICE_FILE"
    echo "      Updated NETWATCHM_CMD → $SYSTEM_CLI"
else
    sudo sed -i "/^\[Service\]/a Environment=NETWATCHM_CMD=$SYSTEM_CLI" "$SERVICE_FILE"
    echo "      Inserted NETWATCHM_CMD=$SYSTEM_CLI"
fi

# --- Step 6: Refresh user-local CLI binary (for manual use only) ---
echo "[6/6] Refreshing ~/.local/bin/netwatchm CLI binary…"
"$REPO/.venv/bin/pip" install -e "$REPO" --quiet 2>/dev/null || true
cp "$REPO/.venv/bin/netwatchm" "$HOME/.local/bin/netwatchm" 2>/dev/null || true

echo ""
echo "Reloading systemd and restarting netwatchm-web…"
sudo systemctl daemon-reload
sudo systemctl restart netwatchm-web
echo "=== Done. ==="
echo ""
systemctl status netwatchm-web --no-pager -l 2>/dev/null || true
