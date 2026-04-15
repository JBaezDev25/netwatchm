#!/usr/bin/env bash
# =============================================================================
# scripts/harden-service-user.sh
#
# PURPOSE
#   Harden the netwatchm-web service by running it as a dedicated, low-privilege
#   system user ("netwatchm") instead of root.
#
# WHY THIS EXISTS
#   The web server (netwatchm-web.service) only reads data files and serves
#   HTTP/HTTPS — it has no need for root privileges. Running it as root is a
#   security risk: a bug or exploit in the server code could give an attacker
#   full system access. A dedicated system user limits that blast radius.
#
# WHAT THIS SCRIPT DOES
#   1. Creates the "netwatchm" system user (no login shell, no home dir)
#   2. Transfers ownership of all data/log/config directories to that user
#   3. Secures the OpenAI API key drop-in so only root+systemd can read it
#   4. Updates the service file to run as User=netwatchm
#   5. Reloads systemd and restarts the web service
#
# WHAT IS NOT CHANGED
#   - The main netwatchm monitor (packet capture) still runs as root because
#     tshark requires raw packet access (CAP_NET_RAW). Only the web server
#     is affected by this script.
#
# SAFE TO RE-RUN
#   All steps are idempotent — running this script more than once will not
#   break anything.
#
# UNDO
#   To revert: change User=netwatchm back to User=root in the service file,
#   run `sudo systemctl daemon-reload && sudo systemctl restart netwatchm-web`.
#   You do not need to re-chown the files — root can always read them.
# =============================================================================
set -euo pipefail

SERVICE_USER="netwatchm"
DATA_DIR="/var/lib/netwatchm"
LOG_DIR="/var/log/netwatchm"
CONF_DIR="/etc/netwatchm"
SERVICE_FILE="/etc/systemd/system/netwatchm-web.service"
DROPIN_DIR="/etc/systemd/system/netwatchm-web.service.d"

echo "=== NetWatchM web service hardening ==="
echo "Switching netwatchm-web from root → dedicated user: $SERVICE_USER"
echo ""

# --- Step 1: Create the system user if it does not already exist ---
if id "$SERVICE_USER" &>/dev/null; then
    echo "[1/5] System user '$SERVICE_USER' already exists — skipping creation."
else
    echo "[1/5] Creating system user '$SERVICE_USER' (no login shell, no home dir)…"
    useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "NetWatchM web service account" \
        "$SERVICE_USER"
    echo "      User created."
fi

# --- Step 2: Transfer ownership of data/log/config directories ---
echo "[2/5] Transferring ownership of runtime directories to $SERVICE_USER…"
for dir in "$DATA_DIR" "$LOG_DIR" "$CONF_DIR"; do
    if [ -d "$dir" ]; then
        chown -R "$SERVICE_USER":"$SERVICE_USER" "$dir"
        echo "      chown $SERVICE_USER: $dir"
    else
        echo "      WARN: $dir does not exist — skipping."
    fi
done

# --- Step 3: Lock down the OpenAI API key drop-in (root-only read) ---
echo "[3/5] Securing API key drop-in files in $DROPIN_DIR…"
if [ -d "$DROPIN_DIR" ]; then
    # Drop-ins are read by systemd (root), not by the service process itself.
    # Set to 600 so only root can read the raw key file.
    chmod 600 "$DROPIN_DIR"/*.conf 2>/dev/null && \
        echo "      Drop-in files secured (chmod 600)." || \
        echo "      No .conf files found in drop-in dir — skipping."
else
    echo "      Drop-in dir $DROPIN_DIR not found — skipping."
fi

# --- Step 4: Update the service file User= directive ---
echo "[4/5] Updating $SERVICE_FILE to run as User=$SERVICE_USER…"
if grep -q "^User=root" "$SERVICE_FILE"; then
    sed -i "s/^User=root/User=$SERVICE_USER/" "$SERVICE_FILE"
    echo "      Updated: User=root → User=$SERVICE_USER"
elif grep -q "^User=$SERVICE_USER" "$SERVICE_FILE"; then
    echo "      Already set to User=$SERVICE_USER — no change needed."
else
    # Insert User= after ExecStart= if no User= line exists
    sed -i "/^ExecStart=/a User=$SERVICE_USER" "$SERVICE_FILE"
    echo "      Inserted User=$SERVICE_USER into service file."
fi

# --- Step 5: Reload systemd and restart the web service ---
echo "[5/5] Reloading systemd and restarting netwatchm-web…"
systemctl daemon-reload
systemctl restart netwatchm-web
echo ""
echo "=== Done. netwatchm-web is now running as: $SERVICE_USER ==="
echo ""
systemctl status netwatchm-web --no-pager -l
