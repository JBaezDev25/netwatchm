#!/usr/bin/env bash
# capture-switch.sh — Interactive tshark packet capture for a LAN device
# Requirements: tshark (sudo apt install tshark)

set -euo pipefail

echo "================================================================"
echo "          NetWatchM -- Packet Capture"
echo "================================================================"
echo ""

# ── Manual entry ─────────────────────────────────────────────────────

read -rp "  Target IP address: " TARGET_IP
if [ -z "$TARGET_IP" ]; then
    echo "Error: Target IP is required." >&2
    exit 1
fi

read -rp "  Save file to (e.g. /home/jbaez120/wshark-scan/capture.pcapng): " OUT_FILE
if [ -z "$OUT_FILE" ]; then
    echo "Error: Output file path is required." >&2
    exit 1
fi

read -rp "  Capture duration in seconds: " DURATION
if [ -z "$DURATION" ] || ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
    echo "Error: Duration must be a number." >&2
    exit 1
fi

read -rp "  Network interface (e.g. enp6s0, eth0, wlan0): " IFACE
if [ -z "$IFACE" ]; then
    echo "Error: Network interface is required." >&2
    exit 1
fi

echo ""
echo "================================================================"
echo "  Interface : $IFACE"
echo "  Target IP : $TARGET_IP"
echo "  Output    : $OUT_FILE"
echo "  Duration  : ${DURATION}s  (Ctrl+C to stop early)"
echo "================================================================"
echo "  While the capture runs, do ONE of these on the device:"
echo "    1. System Settings -> Internet -> Test Connection"
echo "    2. Open an app that uses the internet"
echo "    3. Check for updates"
echo "================================================================"
echo ""

# ── Prepare output file ──────────────────────────────────────────────

OUT_DIR="$(dirname "$OUT_FILE")"
mkdir -p "$OUT_DIR"

# Remove stale file (may be root-owned from a previous run)
sudo rm -f "$OUT_FILE" 2>/dev/null || rm -f "$OUT_FILE" 2>/dev/null || true

# Pre-create as current user so tshark (root) can write to it
touch "$OUT_FILE"
chmod 644 "$OUT_FILE"

echo "[*] Starting capture on $IFACE ..."
echo ""

sudo tshark \
    -i "$IFACE" \
    -f "host $TARGET_IP" \
    -a "duration:$DURATION" \
    -w "$OUT_FILE" \
    2>&1 | grep -v "^Running as user\|^Capturing on"

echo ""
echo "[OK] Capture saved to: $OUT_FILE"
echo "[OK] Upload it at:     https://localhost:8765/pcap.html"
