#!/usr/bin/env bash
# NetWatchM - Install self-signed certificate on Linux (Ubuntu/Debian)
# Run from your Linux laptop/desktop that needs to trust the NetWatchM portal
set -euo pipefail

SERVER_IP="${1:-192.168.1.180}"
PORT="${2:-8765}"
CERT_URL="https://${SERVER_IP}:${PORT}/cert"
CERT_FILE="/tmp/netwatchm.crt"
DEST="/usr/local/share/ca-certificates/netwatchm.crt"

echo "=== Downloading cert from ${CERT_URL} ==="
curl -k -o "$CERT_FILE" "$CERT_URL"
echo "Cert saved to $CERT_FILE"

echo ""
echo "=== Installing into system trusted roots ==="
sudo cp "$CERT_FILE" "$DEST"
sudo update-ca-certificates

echo ""
echo "=== Installing into Chrome/Chromium NSS store ==="
NSSDB="$HOME/.pki/nssdb"
mkdir -p "$NSSDB"
if [ ! -f "$NSSDB/cert9.db" ]; then
    certutil -N -d sql:"$NSSDB" --empty-password
fi
certutil -D -d sql:"$NSSDB" -n "NetWatchM" 2>/dev/null || true
certutil -A -d sql:"$NSSDB" -n "NetWatchM" -t "CT,," -i "$CERT_FILE"
echo "Added to Chrome NSS store."

echo ""
echo "Done! Restart Chrome/Chromium, then open:"
echo "  https://${SERVER_IP}:${PORT}/"
echo "No more certificate warning."
