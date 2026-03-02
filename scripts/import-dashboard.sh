#!/usr/bin/env bash
# Re-imports the NetWatchM Grafana dashboard
set -e

GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="BioIluvleeloo@5858"
DASHBOARD_JSON="/home/jbaez120/ai-projects/netwatchm/grafana-dashboard.json"

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
    \"dashboard\": $(cat "$DASHBOARD_JSON"),
    \"overwrite\": true,
    \"inputs\": [{
      \"name\": \"DS_NETWATCHM\",
      \"type\": \"datasource\",
      \"pluginId\": \"yesoreyeram-infinity-datasource\",
      \"value\": \"$GRAFANA_UID\"
    }]
  }" | python3 -m json.tool

echo "Done."
