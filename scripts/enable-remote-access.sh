#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="/var/lib/netwatchm"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

echo "=== Opening firewall port 8765/tcp ==="
if sudo ufw status | grep -q "Status: active"; then
    sudo ufw allow 8765/tcp
    echo "Port 8765 opened."
else
    echo "ufw not active — skipping."
fi

echo ""
echo "=== Regenerating TLS certificate with LAN IP + hostname in SAN ==="
LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/{print $7; exit}')
if [[ -z "$LOCAL_IP" ]]; then
    echo "Could not detect local IP. Set NETWATCHM_SERVER_IP and re-run."
    exit 1
fi
HOSTNAME=$(hostname)
echo "Detected local IP: $LOCAL_IP"
echo "Detected hostname: $HOSTNAME"

sudo openssl req -x509 \
    -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 3650 \
    -nodes \
    -subj "/CN=$LOCAL_IP/O=NetWatchM" \
    -addext "subjectAltName=DNS:localhost,DNS:${HOSTNAME}.local,DNS:${HOSTNAME},IP:127.0.0.1,IP:$LOCAL_IP"

sudo chmod 600 "$KEY_FILE"
echo "Certificate written with SAN: localhost, ${HOSTNAME}.local, ${HOSTNAME}, 127.0.0.1, $LOCAL_IP"

echo ""
echo "=== Restarting netwatchm-web ==="
sudo systemctl restart netwatchm-web

echo ""
echo "Done. Access the portal at:"
echo "  https://$LOCAL_IP:8765/"
echo "  (Accept the self-signed certificate warning in your browser)"
