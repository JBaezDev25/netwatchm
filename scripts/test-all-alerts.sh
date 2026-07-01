#!/usr/bin/env bash
# test-all-alerts.sh — fire synthetic alerts across all 3 channels simultaneously:
#   1. events.db   → Events Portal + Grafana Alert History
#   2. ntfy.sh     → push notifications on phone (all levels, bypasses cooldown)
#   3. Grafana webhook bridge → confirms Grafana→ntfy pipeline
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UV="$HOME/.local/bin/uv"
HTTPS_API="https://localhost:8765"
HTTP_API="http://localhost:8766"
NTFY_SERVER="https://ntfy.sh"
NTFY_TOPIC="netwatchm-abc123"

echo "========================================"
echo "  NetWatchM — Full Alert Channel Test"
echo "========================================"
echo ""

# ── 1. Seed events.db ──────────────────────────────────────────────────────
echo "[1/3] Seeding events.db with MEDIUM / HIGH / CRITICAL alerts…"
sudo "$UV" run --project "$REPO" python3 - <<'PYEOF'
import sys
sys.path.insert(0, '/home/jbaez120/ai-projects/netwatchm/src')
from netwatchm.alerts.event_store import EventStore
from netwatchm.models import Alert, ThreatLevel

events = [
    Alert('EXFILTRATION', ThreatLevel.CRITICAL, '10.0.0.180', '203.0.113.50',
          '[TEST] CRITICAL — Exfiltration: 500 MB outbound to 203.0.113.50'),
    Alert('PORT_SCAN',    ThreatLevel.HIGH,      '10.0.0.5',     '10.0.0.1',
          '[TEST] HIGH — Port scan: 45 ports in 8s from 10.0.0.5'),
    Alert('BRUTE_FORCE',  ThreatLevel.HIGH,      '10.0.0.99',    '10.0.0.1',
          '[TEST] HIGH — Brute force SSH: 60 attempts in 30s from 10.0.0.99'),
    Alert('DATA_HOG',     ThreatLevel.HIGH,      '10.0.0.20', '0.0.0.0',
          '[TEST] HIGH — Data hog 10.0.0.20: 11.2 GB in 24h'),
    Alert('TOR_EXIT',     ThreatLevel.HIGH,      '198.51.100.1', '10.0.0.50',
          '[TEST] HIGH — Tor exit node connection from 198.51.100.1'),
    Alert('ADULT_DOMAIN', ThreatLevel.MEDIUM,    '10.0.0.42', '8.8.8.8',
          '[TEST] MEDIUM — Adult domain accessed: xvideos.com from 10.0.0.42'),
]

with EventStore('/var/lib/netwatchm/events.db') as s:
    for a in events:
        s.insert(a)
    print(f'  OK — inserted {len(events)} events  |  total in DB: {s.count()}')
    print(f'  Types present: {s.distinct_types()}')
PYEOF
echo ""

# ── 2. ntfy push notifications ─────────────────────────────────────────────
# Send directly to ntfy.sh for all levels — bypasses server cooldown/min_level
echo "[2/3] Sending ntfy push notifications for every threat level…"

send_ntfy() {
    local level="$1" priority="$2" title="$3" body="$4" tags="$5"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Priority: $priority" \
        -H "X-Title: $title"   \
        -H "X-Tags: $tags"     \
        -d "$body"              \
        "$NTFY_SERVER/$NTFY_TOPIC")
    printf "  %-10s HTTP %s — %s\n" "[$level]" "$code" "$title"
}

send_ntfy "CRITICAL" "5" \
    "[TEST] CRITICAL Alert — NetWatchM" \
    "EXFILTRATION detected: 500 MB outbound to 203.0.113.50 from 10.0.0.180" \
    "rotating_light,skull"

send_ntfy "HIGH" "4" \
    "[TEST] HIGH Alert — NetWatchM" \
    "PORT_SCAN: 45 ports in 8s from 10.0.0.5 → 10.0.0.1" \
    "warning,fire"

send_ntfy "MEDIUM" "3" \
    "[TEST] MEDIUM Alert — NetWatchM" \
    "ADULT_DOMAIN: xvideos.com accessed from 10.0.0.42 (DNS)" \
    "eyes"
echo ""

# ── 3. Grafana → ntfy webhook bridge ───────────────────────────────────────
echo "[3/3] Testing Grafana → ntfy webhook bridge…"
RESP=$(curl -s -X POST "$HTTP_API/api/grafana-ntfy" \
    -H "Content-Type: application/json" \
    -d '{
      "status": "firing",
      "title": "[TEST] Grafana bridge — NetWatchM",
      "alerts": [
        {
          "status": "firing",
          "labels": {"alertname": "High Threat Alert", "severity": "critical"},
          "annotations": {
            "summary": "[TEST] Grafana-to-ntfy bridge is live — all channels confirmed"
          },
          "startsAt": "2026-03-03T00:00:00Z"
        }
      ]
    }')
echo "  Response: $RESP"
echo ""

echo "========================================"
echo "  Test complete — check all 3 channels:"
echo "========================================"
echo ""
echo "  1. Events Portal  →  https://localhost:8765/events.html"
echo "     (filter: type=EXFILTRATION / level=CRITICAL to find test events)"
echo ""
echo "  2. Grafana         →  http://localhost:3000"
echo "     (Alert History panel — look for [TEST] rows)"
echo ""
echo "  3. Phone (ntfy)    →  topic: $NTFY_TOPIC"
echo "     (3 direct pushes + 1 via Grafana bridge = 4 notifications total)"
echo ""
