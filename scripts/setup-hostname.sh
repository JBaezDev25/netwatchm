#!/usr/bin/env bash
# setup-hostname.sh — Publish NetWatchM as "netwatch.local" on the LAN via mDNS
#
# After running this script any device on the local network can reach the
# NetWatchM web interface at:
#   https://netwatch.local:8765
#
# Requires: avahi-daemon (already installed and running on this machine)
# Run as root (uses sudo internally — do not run with sudo directly).

set -euo pipefail

ALIAS="netwatch"
SERVICE_FILE="/etc/avahi/services/netwatchm.service"
UNIT_FILE="/etc/systemd/system/netwatch-mdns.service"
NW_PORT=8765

echo "=== NetWatchM mDNS hostname setup ==="
echo "This will publish '${ALIAS}.local' on your LAN so any device"
echo "can reach NetWatchM at https://${ALIAS}.local:${NW_PORT}"
echo ""

# ── 1. Register an Avahi service so the name is discoverable ─────────────
echo "[1/3] Writing Avahi service record to ${SERVICE_FILE}..."
sudo tee "${SERVICE_FILE}" > /dev/null <<EOF
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">NetWatchM on %h</name>
  <service>
    <type>_https._tcp</type>
    <port>${NW_PORT}</port>
    <txt-record>path=/inventory.html</txt-record>
  </service>
  <service>
    <type>_http._tcp</type>
    <port>${NW_PORT}</port>
    <txt-record>path=/inventory.html</txt-record>
  </service>
</service-group>
EOF

# ── 2. Reload avahi to pick up the service file ───────────────────────────
echo "[2/3] Reloading avahi-daemon..."
sudo systemctl reload avahi-daemon

# ── 3. Create a systemd service that advertises the hostname alias ─────────
# avahi-publish-address publishes an extra A record for "netwatch.local"
# pointing to this machine's IP — browsers resolve it just like the system hostname.
echo "[3/3] Creating netwatch-mdns.service (persistent alias publisher)..."
sudo tee "${UNIT_FILE}" > /dev/null <<EOF
[Unit]
Description=Publish netwatch.local mDNS alias for NetWatchM
After=network.target avahi-daemon.service
Requires=avahi-daemon.service

[Service]
Type=simple
ExecStart=/usr/bin/avahi-publish -a ${ALIAS}.local -R $(hostname -I | awk '{print $1}')
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now netwatch-mdns.service

echo ""
echo "=== Done! ==="
echo ""
echo "NetWatchM is now reachable at:"
echo "  https://${ALIAS}.local:${NW_PORT}/inventory.html   — Device inventory"
echo "  https://${ALIAS}.local:${NW_PORT}/events.html      — Security alerts"
echo "  https://${ALIAS}.local:${NW_PORT}/analytics.html   — Analytics"
echo "  https://${ALIAS}.local:${NW_PORT}/ai.html          — AI Assistant"
echo "  https://${ALIAS}.local:${NW_PORT}/history.html     — Flow history"
echo ""
echo "Note: Windows clients need mDNS support (built-in on Win10+)."
echo "      macOS and Linux resolve .local natively."
echo "      Browser will show a certificate warning (self-signed) — click Advanced > Proceed."
