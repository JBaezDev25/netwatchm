#!/usr/bin/env bash
# Copy GeoLite2-City.mmdb to /var/lib/netwatchm/ and restart web service.
set -euo pipefail
SRC="$(dirname "$0")/../geolite2-city-gzip/GeoLite2-City.mmdb"
DEST="/var/lib/netwatchm/GeoLite2-City.mmdb"

[[ -f "$SRC" ]] || { echo "ERROR: $SRC not found"; exit 1; }
echo "Copying $(basename "$SRC") ($(du -sh "$SRC" | cut -f1))..."
sudo cp "$SRC" "$DEST"
sudo chmod 644 "$DEST"
echo "Restarting netwatchm-web..."
sudo systemctl restart netwatchm-web
echo "Done — GeoIP live at $DEST"
