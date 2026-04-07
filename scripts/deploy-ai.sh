#!/usr/bin/env bash
# deploy-ai.sh — Deploy AI chat page and restart netwatchm-web service
# Run this after any change to ai.html or netwatchm_server.py

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
SERVE_DIR="/var/lib/netwatchm"
SERVICE="netwatchm-web"

echo "[1/3] Copying ai.html to ${SERVE_DIR}..."
sudo cp "${PROJECT}/ai.html" "${SERVE_DIR}/ai.html"

echo "[2/3] Copying netwatchm_server.py..."
sudo cp "${PROJECT}/netwatchm_server.py" "${SERVE_DIR}/netwatchm_server.py"

echo "[3/3] Restarting ${SERVICE}..."
sudo systemctl restart "${SERVICE}"

echo ""
echo "Done. AI Assistant available at:"
echo "  https://$(hostname -I | awk '{print $1}'):8765/ai.html"
echo "  https://netwatch.local:8765/ai.html  (after running setup-hostname.sh)"
