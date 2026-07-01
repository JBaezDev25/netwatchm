#!/usr/bin/env bash
# Seed /var/lib/netwatchm/events.db with synthetic test events for smoke-testing.
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UV="$HOME/.local/bin/uv"

echo "Seeding live events.db with synthetic alerts…"

sudo "$UV" run --project "$REPO" python3 - <<'PYEOF'
import sys
sys.path.insert(0, '/home/jbaez120/ai-projects/netwatchm/src')
from netwatchm.alerts.event_store import EventStore
from netwatchm.models import Alert, ThreatLevel

events = [
    Alert('PORT_SCAN',    ThreatLevel.HIGH,     '10.0.0.5',     '10.0.0.1',  'Port scan detected: 23 ports in 10s'),
    Alert('TOR_EXIT',     ThreatLevel.HIGH,     '198.51.100.1', '10.0.0.50', 'Tor exit node inbound from Tor: 198.51.100.1'),
    Alert('ADULT_DOMAIN', ThreatLevel.MEDIUM,   '10.0.0.42', '8.8.8.8',      'Adult domain accessed (DNS): xvideos.com'),
    Alert('DATA_HOG',     ThreatLevel.HIGH,     '10.0.0.20', '0.0.0.0',      'Data hog 10.0.0.20: 11.2 GB in 24h (threshold: 10.0 GB)'),
    Alert('BRUTE_FORCE',  ThreatLevel.HIGH,     '10.0.0.99',    '10.0.0.1',  'Brute force SSH: 47 attempts in 30s'),
    Alert('NEW_IP',       ThreatLevel.LOW,      '172.16.0.88',  None,           'New IP observed: 172.16.0.88'),
]

with EventStore('/var/lib/netwatchm/events.db') as s:
    for a in events:
        s.insert(a)
    print(f'OK — inserted {len(events)} events, total in DB: {s.count()}')
    print('Types:', s.distinct_types())
PYEOF
