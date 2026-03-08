#!/usr/bin/env bash
# apply-config-fix.sh — Apply the production netwatchm.yaml and restart services
# Run: bash scripts/apply-config-fix.sh
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/netwatchm.yaml.production"

if [ ! -f "$SRC" ]; then
  echo "[ERROR] $SRC not found. Cannot apply config." >&2
  exit 1
fi

echo "[1/3] Backing up current config..."
sudo cp /etc/netwatchm/netwatchm.yaml /etc/netwatchm/netwatchm.yaml.bak
echo "      Backup: /etc/netwatchm/netwatchm.yaml.bak"

echo "[2/3] Applying production config from repo..."
sudo cp "$SRC" /etc/netwatchm/netwatchm.yaml

echo "[3/3] Restarting netwatchm service..."
sudo systemctl restart netwatchm

sleep 2
echo ""
echo "[OK] Done. Service status:"
systemctl status netwatchm --no-pager -l | head -15
