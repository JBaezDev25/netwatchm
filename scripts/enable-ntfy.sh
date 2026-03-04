#!/usr/bin/env bash
# Deploy updated netwatchm.yaml (with ntfy enabled) and restart the service.
set -euo pipefail

echo "Copying config..."
sudo cp /tmp/netwatchm.yaml /etc/netwatchm/netwatchm.yaml

echo "Restarting netwatchm service..."
sudo systemctl daemon-reload
sudo systemctl restart netwatchm

echo "Restarting netwatchm-web service..."
sudo systemctl restart netwatchm-web

echo "Done. Checking service status..."
sudo systemctl status netwatchm --no-pager -l | head -20
