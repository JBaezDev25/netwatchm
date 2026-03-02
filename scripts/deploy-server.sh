#!/usr/bin/env bash
# Deploy netwatchm_server.py to /usr/local/bin and restart the web service.
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"

echo "Deploying netwatchm_server.py…"
sudo cp "$REPO/netwatchm_server.py" /usr/local/bin/netwatchm-server
sudo chmod +x /usr/local/bin/netwatchm-server
sudo systemctl daemon-reload
sudo systemctl restart netwatchm-web
echo "Done. Service restarted."
sudo systemctl status netwatchm-web --no-pager -l
