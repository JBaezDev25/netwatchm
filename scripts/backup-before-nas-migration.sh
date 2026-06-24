#!/usr/bin/env bash
set -e

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/mnt/jbaez_data/netwatchm-backup-$STAMP"

echo "=== Pre-migration backup to $BACKUP_DIR ==="
sudo mkdir -p "$BACKUP_DIR"

echo "Checkpointing WAL for agent_actions.db..."
sudo sqlite3 /var/lib/netwatchm/agent_actions.db "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true

echo "Copying /var/lib/netwatchm/ ..."
sudo cp -a /var/lib/netwatchm/. "$BACKUP_DIR/"

echo "Copying logs..."
sudo cp /var/log/netwatchm/netwatchm.log "$BACKUP_DIR/netwatchm.log.bak" 2>/dev/null || true

sudo chown -R jbaez120:jbaez120 "$BACKUP_DIR"

echo ""
echo "=== Backup complete: $BACKUP_DIR ==="
ls -lah "$BACKUP_DIR"
