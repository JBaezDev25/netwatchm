#!/usr/bin/env bash
# setup-ai-key.sh — Inject OPENAI_API_KEY into the netwatchm-web service
#                   and install the openai package into the netwatchm venv.
# Run once after setting up the AI assistant feature.
# Run with: bash scripts/setup-ai-key.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$REPO/.venv/bin/python3"
DROP_IN_DIR="/etc/systemd/system/netwatchm-web.service.d"
DROP_IN_FILE="$DROP_IN_DIR/ai-env.conf"

# ── 1. Read the key ────────────────────────────────────────────────────────
if [[ -f "$REPO/../nic-asst-ai/.env" ]]; then
    KEY=$(grep "^OPENAI_API_KEY=" "$REPO/../nic-asst-ai/.env" | cut -d= -f2-)
fi

if [[ -z "${KEY:-}" ]]; then
    read -rsp "Paste your OPENAI_API_KEY (input hidden): " KEY
    echo ""
fi

if [[ -z "$KEY" ]]; then
    echo "Error: no API key provided." >&2
    exit 1
fi

# ── 2. Install openai into the netwatchm venv ──────────────────────────────
echo "[1/3] Installing openai package into netwatchm venv..."
cd "$REPO" && uv add openai --quiet

# ── 3. Write systemd drop-in with the key ─────────────────────────────────
echo "[2/3] Writing service environment drop-in to $DROP_IN_FILE..."
sudo mkdir -p "$DROP_IN_DIR"
sudo tee "$DROP_IN_FILE" > /dev/null <<EOF
[Service]
Environment=OPENAI_API_KEY=${KEY}
EOF
sudo chmod 600 "$DROP_IN_FILE"

# ── 4. Reload and restart ─────────────────────────────────────────────────
echo "[3/3] Reloading systemd and restarting netwatchm-web..."
sudo systemctl daemon-reload
sudo systemctl restart netwatchm-web

echo ""
echo "[OK] Done. AI assistant is live at:"
echo "  https://$(hostname -I | awk '{print $1}'):8765/ai.html"
