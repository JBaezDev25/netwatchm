#!/usr/bin/env bash
# Re-imports the NetWatchM Grafana dashboard
set -e

GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="BioIluvleeloo@5858"
DASHBOARD_JSON="/home/jbaez120/ai-projects/netwatchm/grafana-dashboard.json"

# Detect the server's LAN IP so panel links open on the right host from any browser
SERVER_IP="${NETWATCHM_SERVER_IP:-}"
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('8.8.8.8', 80))
print(s.getsockname()[0])
s.close()
" 2>/dev/null || echo "localhost")
fi
echo "Substituting localhost:8765 → ${SERVER_IP}:8765 in dashboard links..."
PATCHED_JSON=$(mktemp)
sed "s|localhost:8765|${SERVER_IP}:8765|g" "$DASHBOARD_JSON" > "$PATCHED_JSON"

echo "Looking up Infinity datasource UID..."
GRAFANA_UID=$(curl -s -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
  "${GRAFANA_URL}/api/datasources" | \
  python3 -c "
import sys, json
ds = [d for d in json.load(sys.stdin) if 'infinity' in d['type'].lower()]
print(ds[0]['uid'] if ds else 'NOTFOUND')
")

if [ "$GRAFANA_UID" = "NOTFOUND" ]; then
  echo "ERROR: Infinity datasource not found. Check credentials or datasource setup."
  exit 1
fi
echo "Datasource UID: $GRAFANA_UID"

echo "Importing dashboard..."
curl -s -X POST "${GRAFANA_URL}/api/dashboards/import" \
  -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"dashboard\": $(cat "$PATCHED_JSON"),
    \"overwrite\": true,
    \"inputs\": [{
      \"name\": \"DS_NETWATCHM\",
      \"type\": \"datasource\",
      \"pluginId\": \"yesoreyeram-infinity-datasource\",
      \"value\": \"$GRAFANA_UID\"
    }]
  }" | python3 -m json.tool

rm -f "$PATCHED_JSON"
echo "Done."
