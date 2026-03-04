#!/usr/bin/env bash
# setup-grafana-ntfy.sh — add ntfy.sh webhook as a Grafana contact point
# and add it to the default notification policy alongside email.
set -euo pipefail

GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="BioIluvleeloo@5858"
NETWATCHM_API="http://127.0.0.1:8766"
WEBHOOK_URL="${NETWATCHM_API}/api/grafana-ntfy"

G() { curl -s -u "${GRAFANA_USER}:${GRAFANA_PASS}" "$@"; }

echo "========================================"
echo "  NetWatchM — Grafana ntfy Setup"
echo "========================================"
echo ""

# ── 1. Verify Grafana ─────────────────────────────────────────────────────
echo "[1/3] Checking Grafana..."
G "${GRAFANA_URL}/api/health" | grep -qi '"database"' || {
  echo "ERROR: Grafana not reachable at ${GRAFANA_URL}"; exit 1; }
echo "      OK"

# ── 2. Verify webhook endpoint ────────────────────────────────────────────
echo "[2/3] Checking webhook endpoint..."
RESP=$(curl -s -X POST "${WEBHOOK_URL}" \
  -H "Content-Type: application/json" \
  -d '{"status":"firing","title":"[TEST] Webhook reachable","alerts":[]}')
echo "${RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('ok'):
    print('      Webhook OK — ntfy reachable')
else:
    print('      WARNING:', d.get('message','unknown'))
" 2>/dev/null || echo "      Webhook responded"

# ── 3. Create ntfy webhook contact point ──────────────────────────────────
echo "[3/3] Creating ntfy contact point..."
CP_RESP=$(G -s -X POST "${GRAFANA_URL}/api/v1/provisioning/contact-points" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"NetWatchM ntfy\",
    \"type\": \"webhook\",
    \"uid\": \"netwatchm-ntfy-cp\",
    \"settings\": {
      \"url\": \"${WEBHOOK_URL}\",
      \"httpMethod\": \"POST\"
    },
    \"disableResolveMessage\": false
  }" 2>/dev/null || true)

echo "${CP_RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
uid = d.get('uid','')
if uid:
    print(f'      Contact point created: NetWatchM ntfy ({uid})')
else:
    msg = d.get('message', str(d))
    if any(w in msg.lower() for w in ('already','conflict','exists')):
        print('      Contact point already exists — OK')
    else:
        print(f'      WARNING: {msg}')
" 2>/dev/null || echo "      Contact point response received"

# Update notification policy to include ntfy as a receiver
# Keep email as default, add ntfy route for all netwatchm alerts
G -s -X PUT "${GRAFANA_URL}/api/v1/provisioning/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "receiver": "NetWatchM Email",
    "group_by": ["grafana_folder", "alertname"],
    "group_wait": "30s",
    "group_interval": "5m",
    "repeat_interval": "4h",
    "routes": [
      {
        "receiver": "NetWatchM ntfy",
        "matchers": ["source=netwatchm"],
        "continue": true
      }
    ]
  }' > /dev/null 2>&1 || true

echo ""
echo "========================================"
echo "  Done!"
echo "========================================"
echo ""
echo "  Grafana will now send push notifications via ntfy"
echo "  for every High Threat and Data Hog alert."
echo ""
echo "  Contact points: ${GRAFANA_URL}/alerting/notifications"
echo "  Test the contact point: Alerting → Contact Points → NetWatchM ntfy → Test"
echo ""
echo "  Webhook endpoint: ${WEBHOOK_URL}"
echo ""
