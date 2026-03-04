#!/usr/bin/env bash
# Deploy netwatchm_server.py to /usr/local/bin and restart the web service.
# Uses the uv venv Python so geoip2 and all project deps are available.
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PYTHON="$REPO/.venv/bin/python3"

echo "Reinstalling netwatchm CLI from venv…"
# Ensure the installed netwatchm CLI matches the current source
"$REPO/.venv/bin/pip" install -e "$REPO" --quiet 2>/dev/null || true
# Copy venv binary over the user-local one referenced by the service
cp "$REPO/.venv/bin/netwatchm" "$HOME/.local/bin/netwatchm" 2>/dev/null || true

echo "Deploying netwatchm_server.py…"
# Copy source to /usr/local/lib so the wrapper can reference it
sudo mkdir -p /usr/local/lib/netwatchm
sudo cp "$REPO/netwatchm_server.py" /usr/local/lib/netwatchm/netwatchm_server.py

# Write wrapper that invokes venv Python with the correct source path
sudo tee /usr/local/bin/netwatchm-server > /dev/null <<WRAPPER
#!/bin/bash
exec "$VENV_PYTHON" /usr/local/lib/netwatchm/netwatchm_server.py "\$@"
WRAPPER
sudo chmod +x /usr/local/bin/netwatchm-server

sudo systemctl daemon-reload
sudo systemctl restart netwatchm-web
echo "Done. Service restarted."
systemctl status netwatchm-web --no-pager -l 2>/dev/null || true
