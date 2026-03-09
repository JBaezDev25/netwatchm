#!/usr/bin/env bash
# copy-deep-inspect-web.sh — Copy deep-inspect-web.html to SERVE_DIR
# Run with: bash scripts/copy-deep-inspect-web.sh
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SERVE_DIR="/var/lib/netwatchm"

echo "Copying deep-inspect-web.html to $SERVE_DIR..."
sudo cp "$REPO/deep-inspect-web.html" "$SERVE_DIR/deep-inspect-web.html"
echo "Done! File is now accessible at /deep-inspect-web.html"