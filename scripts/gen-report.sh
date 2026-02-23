#!/bin/bash
# Regenerate the connection report and deploy it to the web server.
# Usage: sudo bash scripts/gen-report.sh [duration_seconds]
DURATION=${1:-30}
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
/home/jbaez120/.local/bin/uv run netwatchm report --duration "$DURATION" --format html --output /tmp/connection-report.html
cp /tmp/connection-report.html /var/lib/netwatchm/connection-report.html
echo "Done. Report deployed to https://localhost:8765/connection-report.html"
