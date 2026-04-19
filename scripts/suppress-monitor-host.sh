#!/usr/bin/env bash
# Suppress PORT_SCAN and DATA_HOG alerts from the monitoring machine (192.168.1.180).
# ADULT_DOMAIN was already suppressed for this IP (session 6).
# BRUTE_FORCE, EXFILTRATION, TOR_EXIT remain active — real threats from the host still fire.
set -euo pipefail

CONFIG_SRC=/tmp/netwatchm-updated.yaml
CONFIG_DST=/etc/netwatchm/netwatchm.yaml
BACKUP=/etc/netwatchm/netwatchm.yaml.bak-$(date +%Y%m%d-%H%M%S)

if [[ ! -f "$CONFIG_SRC" ]]; then
  echo "ERROR: $CONFIG_SRC not found — run the sed command first"
  exit 1
fi

echo "Backing up $CONFIG_DST → $BACKUP"
sudo cp "$CONFIG_DST" "$BACKUP"

echo "Applying updated config..."
sudo cp "$CONFIG_SRC" "$CONFIG_DST"

echo "Restarting netwatchm service..."
sudo systemctl restart netwatchm


echo "Done. 192.168.1.180 is now suppressed for PORT_SCAN and DATA_HOG."
echo "BRUTE_FORCE, EXFILTRATION, TOR_EXIT, and NEW_IP remain active for that host."
