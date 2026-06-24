#!/usr/bin/env bash
set -e

echo "=== Phase 6: NAS Cutover ==="

echo "Step 1: Verify local data directories are ready..."
sudo test -d /mnt/jbaez_data/netwatchm/reports || { echo "ABORT: Local reports dir not ready."; exit 1; }
sudo test -d /mnt/jbaez_data/netwatchm/logs    || { echo "ABORT: Local logs dir not ready."; exit 1; }
sudo test -f /mnt/jbaez_data/netwatchm/flows.db || { echo "ABORT: flows.db not found — run Phase 4 first."; exit 1; }
echo "Local data dirs OK"

echo ""
echo "Step 2: Verify local data dir has all expected files..."
for f in flows.db events.db flow-history.db GeoLite2-City.mmdb inventory.json aliases.json verified.json suppressed.json oui.json; do
    if ! sudo test -f "/mnt/jbaez_data/netwatchm/$f"; then
        echo "ABORT: Missing /mnt/jbaez_data/netwatchm/$f — run Phase 4 first."
        exit 1
    fi
done
echo "All data files present"

echo ""
echo "Step 3: Reload systemd and restart services..."
sudo systemctl daemon-reload
sudo systemctl restart netwatchm-web
sudo systemctl restart netwatchm

echo ""
echo "Step 4: Service status..."
systemctl is-active netwatchm-web && echo "netwatchm-web: running" || echo "netwatchm-web: FAILED"
systemctl is-active netwatchm     && echo "netwatchm:     running" || echo "netwatchm:     FAILED"

echo ""
echo "=== Cutover complete — run Phase 7 verify script to confirm ==="
