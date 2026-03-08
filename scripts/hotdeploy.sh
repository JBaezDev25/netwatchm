#!/usr/bin/env bash
# hotdeploy.sh — Fast copy of netwatchm_server.py to live location + restart
# Run with: bash scripts/hotdeploy.sh
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
echo "[1/2] Copying netwatchm_server.py to /usr/local/lib/netwatchm/ ..."
sudo cp "$REPO/netwatchm_server.py" /usr/local/lib/netwatchm/netwatchm_server.py
echo "[2/2] Restarting netwatchm-web ..."
sudo systemctl restart netwatchm-web
echo ""
echo "[OK] Done. Checking status..."
systemctl status netwatchm-web --no-pager -l | head -15
