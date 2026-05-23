#!/usr/bin/env bash
# hotdeploy.sh — Fast copy of netwatchm_server.py + static HTML to live + restart
# Run with: bash scripts/hotdeploy.sh
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
echo "[1/4] Copying netwatchm_server.py to /usr/local/lib/netwatchm/ ..."
sudo cp "$REPO/netwatchm_server.py" /usr/local/lib/netwatchm/netwatchm_server.py
echo "[2/4] Copying ai.html to /var/lib/netwatchm/ ..."
sudo cp "$REPO/ai.html" /var/lib/netwatchm/ai.html
echo "[3/4] Copying firewall.html to /var/lib/netwatchm/ ..."
sudo cp "$REPO/firewall.html" /var/lib/netwatchm/firewall.html
echo "[4/4] Restarting netwatchm-web ..."
sudo systemctl restart netwatchm-web
echo ""
echo "[OK] Done. Checking status..."
systemctl status netwatchm-web --no-pager -l | head -15
