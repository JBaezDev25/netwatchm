#!/usr/bin/env bash
set -e

echo "=== Phase 5a: Write systemd drop-in for new data paths ==="

sudo mkdir -p /etc/systemd/system/netwatchm-web.service.d

sudo tee /etc/systemd/system/netwatchm-web.service.d/nas-migration.conf > /dev/null << 'EOF'
[Service]
WorkingDirectory=/mnt/jbaez_data/netwatchm

Environment=NETWATCHM_SERVE_DIR=/mnt/jbaez_data/netwatchm
Environment=NETWATCHM_FLOW_DB=/mnt/jbaez_data/netwatchm/flows.db
Environment=NETWATCHM_EVENT_DB=/mnt/jbaez_data/netwatchm/events.db
Environment=NETWATCHM_FLOW_HISTORY_DB=/mnt/jbaez_data/netwatchm/flow-history.db
Environment=NETWATCHM_GEOIP_DB=/mnt/jbaez_data/netwatchm/GeoLite2-City.mmdb
Environment=NETWATCHM_ALIASES_FILE=/mnt/jbaez_data/netwatchm/aliases.json
Environment=NETWATCHM_VERIFIED_FILE=/mnt/jbaez_data/netwatchm/verified.json
Environment=NETWATCHM_SUPPRESSED_FILE=/mnt/jbaez_data/netwatchm/suppressed.json
EOF

echo "Drop-in written. Variable names set:"
sudo grep -o '^Environment=[^=]*' /etc/systemd/system/netwatchm-web.service.d/nas-migration.conf

echo ""
echo "=== Phase 5b: Create reports symlink (local dir -> NAS) ==="

# Reports symlink: app writes to /mnt/jbaez_data/netwatchm/reports/ -> goes to NAS
if [ ! -L /mnt/jbaez_data/netwatchm/reports ]; then
    sudo -u netwatchm ln -s /mnt/nas_netwatchm/reports /mnt/jbaez_data/netwatchm/reports
    echo "Symlink created: /mnt/jbaez_data/netwatchm/reports -> /mnt/nas_netwatchm/reports"
else
    echo "Symlink already exists"
fi

ls -la /mnt/jbaez_data/netwatchm/

echo ""
echo "=== Phase 5c: Update netwatchm.yaml log path to NAS ==="

CONFIG="/etc/netwatchm/netwatchm.yaml"
BACKUP="/etc/netwatchm/netwatchm.yaml.bak-$(date +%Y%m%d-%H%M%S)"

sudo cp "$CONFIG" "$BACKUP"
echo "Config backed up to $BACKUP"

sudo sed -i 's|path: /var/log/netwatchm/netwatchm.log|path: /mnt/nas_netwatchm/logs/netwatchm.log|' "$CONFIG"

echo "Log path updated:"
sudo grep "path:" "$CONFIG" | grep netwatchm

echo ""
echo "=== Phase 5 complete — ready for cutover ==="
