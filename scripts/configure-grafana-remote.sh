#!/usr/bin/env bash
set -euo pipefail

REMOTE_IP="10.0.0.180"
GRAFANA_INI="/etc/grafana/grafana.ini"
BACKUP="${GRAFANA_INI}.bak.$(date +%Y%m%d%H%M%S)"

echo "Backing up $GRAFANA_INI → $BACKUP"
sudo cp "$GRAFANA_INI" "$BACKUP"

echo "Patching [server] section..."
sudo sed -i "s/^;*\s*domain\s*=.*/domain = ${REMOTE_IP}/" "$GRAFANA_INI"
sudo sed -i "s|^;*\s*root_url\s*=.*|root_url = http://${REMOTE_IP}:3000/|" "$GRAFANA_INI"

if sudo ufw status | grep -q "Status: active"; then
    echo "Opening firewall port 3000/tcp..."
    sudo ufw allow 3000/tcp
fi

echo "Restarting grafana-server..."
sudo systemctl restart grafana-server

echo "Done. Grafana should be reachable at http://${REMOTE_IP}:3000"
