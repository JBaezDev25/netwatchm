#!/usr/bin/env bash
# configure-digest-mode.sh
#
# Switch the LIVE netwatchm config to "5-day digest" notifications:
#   - agent.mode = digest, every 5 days, beacons excluded
#   - alerts.ntfy enabled, min_level = CRITICAL (real-time push for genuine
#     threats only), BEACONING excluded from real-time push
#
# Edits /etc/netwatchm/netwatchm.yaml in place (backs it up first), validates
# the result with load_config before applying, then restarts the services.
# Prompts for the ntfy topic if one isn't already set (kept out of the repo).
#
# Rollback: sudo cp /etc/netwatchm/netwatchm.yaml.pre-digest /etc/netwatchm/netwatchm.yaml
#           && sudo systemctl restart netwatchm netwatchm-web
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LIVE="/etc/netwatchm/netwatchm.yaml"
WORK="/tmp/netwatchm.digest.yaml"

[ -f "$LIVE" ] || { echo "[ERROR] $LIVE not found" >&2; exit 1; }

# Pull the existing topic (if any) so we can default to it.
EXISTING_TOPIC="$(sudo grep -E '^\s*topic:' "$LIVE" 2>/dev/null | head -1 | sed -E 's/.*topic:\s*//; s/["'\'' ]//g' || true)"
read -rp "ntfy topic [${EXISTING_TOPIC:-none set}]: " TOPIC
TOPIC="${TOPIC:-$EXISTING_TOPIC}"
if [ -z "$TOPIC" ]; then
  echo "[ERROR] an ntfy topic is required for digest push. Aborting." >&2
  exit 1
fi

echo "[1/4] Merging digest settings into a working copy ..."
sudo cat "$LIVE" > "$WORK"
TOPIC="$TOPIC" uv --project "$REPO" run python - "$WORK" <<'PY'
import os, sys, yaml
path = sys.argv[1]
with open(path) as f:
    cfg = yaml.safe_load(f) or {}

alerts = cfg.setdefault("alerts", {})
ntfy = alerts.setdefault("ntfy", {})
ntfy.update({
    "enabled": True,
    "server": ntfy.get("server", "https://ntfy.sh"),
    "topic": os.environ["TOPIC"],
    "min_level": "CRITICAL",
    "cooldown_seconds": ntfy.get("cooldown_seconds", 300),
    "exclude_types": ["BEACONING"],
})

agent = cfg.setdefault("agent", {})
agent.update({
    "mode": "digest",
    "digest_interval_days": 5,
    "digest_lookback_days": 5,
    "digest_exclude_types": ["BEACONING"],
})

with open(path, "w") as f:
    f.write("# Machine-edited by scripts/configure-digest-mode.sh.\n")
    f.write("# Annotated reference: netwatchm.yaml.example in the repo.\n")
    yaml.safe_dump(cfg, f, sort_keys=False, default_flow_style=False)
print("merged OK")
PY

echo "[2/4] Validating with load_config ..."
uv --project "$REPO" run python -c "from netwatchm.config import load_config; c=load_config('$WORK'); assert c.agent.mode=='digest'; assert c.alerts.ntfy.enabled; print('valid: mode=%s topic=%s ntfy.min_level=%s' % (c.agent.mode, c.alerts.ntfy.topic, c.alerts.ntfy.min_level))"

echo "[3/4] Backing up + applying ..."
sudo cp "$LIVE" "${LIVE}.pre-digest"
sudo cp "$WORK" "$LIVE"
echo "      backup: ${LIVE}.pre-digest"

echo "[4/4] Restarting services ..."
sudo systemctl restart netwatchm netwatchm-web
sleep 4
journalctl -u netwatchm --since "10 sec ago" --no-pager | grep -iE "agent loop starting|digest tick" | tail -3 || true

echo
echo "Done. The first digest is generated at startup; subsequent ones every 5 days."
echo "Watch it:  journalctl -u netwatchm -f | grep -i digest"
