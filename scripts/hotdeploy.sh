#!/usr/bin/env bash
# hotdeploy.sh — Fast copy of netwatchm_server.py + static HTML to live + restart
# Run with: bash scripts/hotdeploy.sh
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
echo "[1/5] Copying netwatchm_server.py to /usr/local/lib/netwatchm/ ..."
sudo cp "$REPO/netwatchm_server.py" /usr/local/lib/netwatchm/netwatchm_server.py
echo "[2/5] Copying web/ portal templates to /usr/local/lib/netwatchm/web/ ..."
sudo mkdir -p /usr/local/lib/netwatchm/web
sudo cp "$REPO"/web/*.html /usr/local/lib/netwatchm/web/
echo "[3/5] Copying ai.html to /var/lib/netwatchm/ ..."
sudo cp "$REPO/ai.html" /var/lib/netwatchm/ai.html
echo "[4/5] Copying firewall.html to /var/lib/netwatchm/ ..."
sudo cp "$REPO/firewall.html" /var/lib/netwatchm/firewall.html
echo "[5/5] Restarting netwatchm-web ..."
sudo systemctl restart netwatchm-web
echo ""
echo "[OK] Done. Checking status..."
systemctl status netwatchm-web --no-pager -l | head -15
