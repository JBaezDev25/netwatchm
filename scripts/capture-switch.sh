#!/usr/bin/env bash
# capture-switch.sh — Capture Nintendo Switch (192.168.1.217) traffic with tshark
# Usage: bash scripts/capture-switch.sh [duration_seconds] [output_file]
#
# What it does:
#   - Runs tshark on enp6s0 filtering only traffic to/from 192.168.1.217
#   - Saves the capture to /home/jbaez120/wshark-scan/switch-live.pcapng
#   - Stops automatically after the given duration (default: 120 s)
#   - Prints a reminder of what to do on the Switch during capture
#
# Requirements: tshark installed (sudo apt install tshark)

set -euo pipefail

IFACE="${CAPTURE_IFACE:-enp6s0}"
TARGET_IP="${CAPTURE_TARGET:-192.168.1.217}"
DURATION="${1:-120}"
OUT_DIR="/home/jbaez120/wshark-scan"
OUT_FILE="${2:-$OUT_DIR/switch-live.pcapng}"

mkdir -p "$OUT_DIR"

echo "================================================================"
echo "          NetWatchM -- Switch Packet Capture"
echo "================================================================"
echo "  Interface : $IFACE"
echo "  Target IP : $TARGET_IP"
echo "  Output    : $OUT_FILE"
echo "  Duration  : ${DURATION}s  (Ctrl+C to stop early)"
echo "================================================================"
echo "  On the Nintendo Switch, do ONE of these NOW:"
echo "    1. System Settings -> Internet -> Test Connection"
echo "    2. Open Nintendo eShop"
echo "    3. Check for system update"
echo "================================================================"
echo ""

# Remove stale output file if it exists
if [ -f "$OUT_FILE" ]; then
    echo "[*] Removing previous capture: $OUT_FILE"
    rm -f "$OUT_FILE"
fi

echo "[*] Starting capture -- waiting for Switch traffic on $IFACE ..."
echo ""

sudo tshark \
    -i "$IFACE" \
    -f "host $TARGET_IP" \
    -a "duration:$DURATION" \
    -w "$OUT_FILE" \
    2>&1 | grep -v "^Running as user\|^Capturing on"

echo ""
echo "[OK] Capture complete: $OUT_FILE"
echo "[OK] Upload it at: https://localhost:8765/pcap.html"
