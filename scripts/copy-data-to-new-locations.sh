#!/usr/bin/env bash
set -e

SRC="/var/lib/netwatchm"
LOCAL_DST="/mnt/jbaez_data/netwatchm"
NAS_DST="/mnt/nas_netwatchm"

echo "=== Phase 4a: Copy databases and static files to local data disk ==="

# Checkpoint WAL before copy so databases are in a clean state
echo "Checkpointing agent_actions.db WAL..."
sudo sqlite3 "$SRC/agent_actions.db" "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true

echo "Copying databases..."
sudo cp "$SRC/flows.db"            "$LOCAL_DST/"
sudo cp "$SRC/events.db"           "$LOCAL_DST/"
sudo cp "$SRC/flow-history.db"     "$LOCAL_DST/"
sudo cp "$SRC/agent_actions.db"    "$LOCAL_DST/"

echo "Copying static/reference files..."
sudo cp "$SRC/GeoLite2-City.mmdb"  "$LOCAL_DST/"
sudo cp "$SRC/oui.json"            "$LOCAL_DST/"

echo "Copying JSON state files..."
sudo cp "$SRC/inventory.json"      "$LOCAL_DST/"
sudo cp "$SRC/aliases.json"        "$LOCAL_DST/"
sudo cp "$SRC/verified.json"       "$LOCAL_DST/"
sudo cp "$SRC/suppressed.json"     "$LOCAL_DST/"

sudo chown netwatchm:netwatchm "$LOCAL_DST"/*
echo "Local data disk contents:"
ls -lah "$LOCAL_DST/"

echo ""
echo "=== Phase 4b: Copy reports to NAS ==="
if [ -d "$SRC/reports" ] && [ "$(ls -A $SRC/reports 2>/dev/null)" ]; then
    sudo cp "$SRC/reports/"*.html "$NAS_DST/reports/" 2>/dev/null || true
    echo "Reports copied:"
    ls -lah "$NAS_DST/reports/" | tail -5
else
    echo "No reports to copy (reports/ is empty or missing)"
fi

echo ""
echo "=== Phase 4c: Archive current log to NAS ==="
sudo cp /var/log/netwatchm/netwatchm.log "$NAS_DST/logs/netwatchm.log.archive" 2>/dev/null || true
echo "Log archived:"
ls -lah "$NAS_DST/logs/"

echo ""
echo "=== Phase 4 complete ==="
