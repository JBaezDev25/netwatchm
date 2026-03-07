#!/usr/bin/env bash
# capture-switch.sh — Interactive tshark packet capture for a LAN device
# Requirements: tshark (sudo apt install tshark)

set -euo pipefail

echo "================================================================"
echo "          NetWatchM -- Packet Capture"
echo "================================================================"
echo ""

# ── Ask: target IP ──────────────────────────────────────────────────
read -rp "  Target IP address [192.168.1.217]: " TARGET_IP
TARGET_IP="${TARGET_IP:-192.168.1.217}"

# ── Ask: output file ────────────────────────────────────────────────
DEFAULT_OUT="/home/jbaez120/wshark-scan/${TARGET_IP}-live.pcapng"
read -rp "  Save file to [$DEFAULT_OUT]: " OUT_FILE
OUT_FILE="${OUT_FILE:-$DEFAULT_OUT}"

# ── Ask: duration ───────────────────────────────────────────────────
read -rp "  Capture duration in seconds [120]: " DURATION
DURATION="${DURATION:-120}"

# ── Ask: interface ──────────────────────────────────────────────────
DEFAULT_IFACE="${CAPTURE_IFACE:-enp6s0}"
read -rp "  Network interface [$DEFAULT_IFACE]: " IFACE
IFACE="${IFACE:-$DEFAULT_IFACE}"

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

# ── Prepare output file ─────────────────────────────────────────────
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
