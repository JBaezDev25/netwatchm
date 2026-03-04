#!/usr/bin/env bash
# setup-grafana-alerts.sh — configure Grafana unified alerting for NetWatchM
# Creates:
#   • SMTP systemd drop-in  → Grafana sends email via Gmail
#   • Email contact point   → jbaez120@gmail.com
#   • Alert rule: High Threats   (HIGH device count > 0)
#   • Alert rule: Data Hog       (DATA_HOG events in last 24 h > 0)
set -euo pipefail

GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="BioIluvleeloo@5858"
NOTIFY_EMAIL="jbaez120@gmail.com"
DATASOURCE_UID="efeom56h7fx1ce"
GRAFANA_API_BASE="http://127.0.0.1:8766"

G() { curl -s -u "${GRAFANA_USER}:${GRAFANA_PASS}" "$@"; }

echo "========================================"
echo "  NetWatchM — Grafana Alert Setup"
echo "========================================"
echo ""

# ── 1. Verify Grafana is reachable ─────────────────────────────────────────
echo "[1/6] Checking Grafana..."
G "${GRAFANA_URL}/api/health" | grep -qi '"database"' || {
  echo "ERROR: Grafana not reachable at ${GRAFANA_URL}"; exit 1; }
echo "      Grafana 12.4 OK"

# ── 2. Verify NetWatchM alert endpoints ────────────────────────────────────
echo "[2/6] Checking alert metric endpoints..."
curl -s "${GRAFANA_API_BASE}/api/inventory/high" | grep -q '"value"' || {
  echo "ERROR: /api/inventory/high not working. Deploy server first."; exit 1; }
curl -s "${GRAFANA_API_BASE}/api/alerts/data-hog" | grep -q '"value"' || {
  echo "ERROR: /api/alerts/data-hog not working. Deploy server first."; exit 1; }
echo "      Both endpoints OK"

# ── 3. Configure SMTP via systemd drop-in ──────────────────────────────────
echo "[3/6] Configuring Grafana SMTP..."
echo ""
echo "  You need a Gmail App Password (NOT your regular password)."
echo "  Create one at: https://myaccount.google.com/apppasswords"
echo "  App name: 'NetWatchM Grafana'"
echo ""
read -rsp "  Enter Gmail App Password (input hidden): " GMAIL_APP_PASS
echo ""
[[ -z "${GMAIL_APP_PASS}" ]] && { echo "ERROR: Password required."; exit 1; }

DROPIN_DIR="/etc/systemd/system/grafana-server.service.d"
DROPIN_FILE="${DROPIN_DIR}/netwatchm-smtp.conf"
sudo mkdir -p "${DROPIN_DIR}"
sudo tee "${DROPIN_FILE}" > /dev/null <<DROPIN
[Service]
Environment="GF_SMTP_ENABLED=true"
Environment="GF_SMTP_HOST=smtp.gmail.com:587"
Environment="GF_SMTP_FROM_ADDRESS=${NOTIFY_EMAIL}"
Environment="GF_SMTP_FROM_NAME=NetWatchM Alerts"
Environment="GF_SMTP_USER=${NOTIFY_EMAIL}"
Environment="GF_SMTP_PASSWORD=${GMAIL_APP_PASS}"
Environment="GF_SMTP_STARTTLS_POLICY=MandatoryStartTLS"
DROPIN
echo "      SMTP drop-in written to ${DROPIN_FILE}"

sudo systemctl daemon-reload
sudo systemctl restart grafana-server
echo -n "      Waiting for Grafana to restart"
for i in {1..30}; do
  sleep 2
  G "${GRAFANA_URL}/api/health" 2>/dev/null | grep -qi '"database"' && break
  echo -n "."
done
echo ""
G "${GRAFANA_URL}/api/health" | grep -qi '"database"' || {
  echo "ERROR: Grafana did not come back up."; exit 1; }
echo "      Grafana restarted OK"

# ── 4. Create alert folder ─────────────────────────────────────────────────
echo "[4/6] Creating alert folder..."
FOLDER_RESP=$(G -X POST "${GRAFANA_URL}/api/folders" \
  -H "Content-Type: application/json" \
  -d '{"title":"NetWatchM Alerts"}' 2>/dev/null || true)

FOLDER_UID=$(echo "${FOLDER_RESP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('uid',''))" 2>/dev/null || true)
if [[ -z "${FOLDER_UID}" ]]; then
  # Folder may already exist — fetch it
  FOLDER_UID=$(G "${GRAFANA_URL}/api/folders" | python3 -c "
import sys, json
folders = json.load(sys.stdin)
for f in folders:
    if f.get('title') == 'NetWatchM Alerts':
        print(f['uid']); break
" 2>/dev/null || true)
fi
[[ -z "${FOLDER_UID}" ]] && { echo "ERROR: Could not create or find alert folder."; exit 1; }
echo "      Folder UID: ${FOLDER_UID}"

# ── 5. Create email contact point ─────────────────────────────────────────
echo "[5/6] Creating email contact point..."
CP_RESP=$(G -s -X POST "${GRAFANA_URL}/api/v1/provisioning/contact-points" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"NetWatchM Email\",
    \"type\": \"email\",
    \"uid\": \"netwatchm-email-cp\",
    \"settings\": {
      \"addresses\": \"${NOTIFY_EMAIL}\",
      \"subject\": \"[NetWatchM] {{ .GroupLabels.alertname }}\",
      \"message\": \"{{ range .Alerts }}{{ .Annotations.description }}\n{{ end }}\"
    },
    \"disableResolveMessage\": false
  }" 2>/dev/null || true)

echo "${CP_RESP}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
uid = d.get('uid','')
name = d.get('name','')
if uid:
    print(f'      Contact point created: {name} ({uid})')
else:
    err = d.get('message', str(d))
    # already exists is fine
    if 'already' in err.lower() or 'conflict' in err.lower() or 'exists' in err.lower():
        print('      Contact point already exists — OK')
    else:
        print(f'      WARNING: {err}')
" 2>/dev/null || echo "      Contact point response received"

# Set as default notification policy
G -s -X PUT "${GRAFANA_URL}/api/v1/provisioning/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "receiver": "NetWatchM Email",
    "group_by": ["grafana_folder", "alertname"],
    "group_wait": "30s",
    "group_interval": "5m",
    "repeat_interval": "4h"
  }' > /dev/null 2>&1 || true

# ── 6. Create alert rules ──────────────────────────────────────────────────
echo "[6/6] Creating alert rules..."

# Helper: build an Infinity+Reduce+Threshold rule JSON
make_rule() {
  local title="$1" uid="$2" url="$3" threshold="$4" description="$5"
  python3 - <<PYEOF
import json
rule = {
  "folderUID": "${FOLDER_UID}",
  "title": "${title}",
  "ruleGroup": "netwatchm",
  "condition": "C",
  "for": "1m",
  "noDataState": "OK",
  "execErrState": "OK",
  "annotations": {
    "summary": "${description}",
    "description": "${description}. Dashboard: https://localhost:3000"
  },
  "labels": {"source": "netwatchm"},
  "isPaused": False,
  "data": [
    {
      "refId": "A",
      "queryType": "",
      "relativeTimeRange": {"from": 300, "to": 0},
      "datasourceUid": "${DATASOURCE_UID}",
      "model": {
        "refId": "A",
        "type": "json",
        "source": "url",
        "url": "${url}",
        "url_options": {"method": "GET", "data": ""},
        "parser": "backend",
        "format": "table",
        "columns": [
          {"selector": "value", "text": "value", "type": "number"},
          {"selector": "time",  "text": "time",  "type": "timestamp_epoch_ms"}
        ],
        "filters": [],
        "root_selector": ""
      }
    },
    {
      "refId": "B",
      "queryType": "",
      "relativeTimeRange": {"from": 300, "to": 0},
      "datasourceUid": "__expr__",
      "model": {
        "refId": "B",
        "type": "reduce",
        "expression": "A",
        "reducer": "last",
        "conditions": []
      }
    },
    {
      "refId": "C",
      "queryType": "",
      "relativeTimeRange": {"from": 300, "to": 0},
      "datasourceUid": "__expr__",
      "model": {
        "refId": "C",
        "type": "threshold",
        "expression": "B",
        "conditions": [
          {
            "evaluator": {"params": [${threshold}], "type": "gt"},
            "operator":  {"type": "and"},
            "query":     {"params": ["C"]},
            "reducer":   {"params": [], "type": "last"},
            "type":      "query"
          }
        ]
      }
    }
  ]
}
print(json.dumps(rule))
PYEOF
}

# Rule 1: High Threats
RULE1=$(make_rule \
  "NetWatchM — High Threat Detected" \
  "netwatchm-high-threat" \
  "${GRAFANA_API_BASE}/api/inventory/high" \
  "0" \
  "One or more devices have HIGH threat level. Investigate immediately.")

RESP1=$(G -s -X POST "${GRAFANA_URL}/api/v1/provisioning/alert-rules" \
  -H "Content-Type: application/json" \
  -d "${RULE1}" 2>/dev/null || true)
echo "${RESP1}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
uid = d.get('uid','')
if uid:
    print(f'      Rule created: High Threat ({uid})')
else:
    msg = d.get('message', str(d))
    print(f'      High Threat rule: {msg}')
" 2>/dev/null || echo "      Rule 1 submitted"

# Rule 2: Data Hog
RULE2=$(make_rule \
  "NetWatchM — Data Hog Alert" \
  "netwatchm-data-hog" \
  "${GRAFANA_API_BASE}/api/alerts/data-hog" \
  "0" \
  "A device has exceeded the data hog threshold in the last 24 hours.")

RESP2=$(G -s -X POST "${GRAFANA_URL}/api/v1/provisioning/alert-rules" \
  -H "Content-Type: application/json" \
  -d "${RULE2}" 2>/dev/null || true)
echo "${RESP2}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
uid = d.get('uid','')
if uid:
    print(f'      Rule created: Data Hog ({uid})')
else:
    msg = d.get('message', str(d))
    print(f'      Data Hog rule: {msg}')
" 2>/dev/null || echo "      Rule 2 submitted"

echo ""
echo "========================================"
echo "  Setup complete!"
echo "========================================"
echo ""
echo "  Alerts visible at: ${GRAFANA_URL}/alerting/list"
echo "  Contact points:    ${GRAFANA_URL}/alerting/notifications"
echo "  Test email:        send a test from Alerting → Contact Points → Edit → Test"
echo ""
echo "  Trigger a real alert:"
echo "    bash scripts/seed-events.sh   (seeds synthetic HIGH events)"
echo ""
echo "  To update SMTP password:"
echo "    sudo nano ${DROPIN_FILE}"
echo "    sudo systemctl daemon-reload && sudo systemctl restart grafana-server"
