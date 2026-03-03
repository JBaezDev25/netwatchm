#!/usr/bin/env bash
# Deploy summary.html to the web server's serve directory.
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"

sudo cp "$REPO/summary.html" /var/lib/netwatchm/summary.html
echo "Done — open https://localhost:8765/summary.html"
