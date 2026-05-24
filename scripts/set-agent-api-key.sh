#!/usr/bin/env bash
# set-agent-api-key.sh
#
# Wire ANTHROPIC_API_KEY into the netwatchm systemd service so the agent
# (Session 30, model=claude-sonnet-4-6) can actually make API calls. Without
# this the agent logs "ANTHROPIC_API_KEY env var not set — agent cannot start"
# on every 5-min tick.
#
# The key is READ FROM a file (default: ~/ai-projects/uigen/.env), never
# hardcoded here. Override with:  KEY_FILE=/path/to/.env bash scripts/set-agent-api-key.sh
# or pass the key directly:        ANTHROPIC_API_KEY=sk-ant-... bash scripts/set-agent-api-key.sh
#
# Writes a 0600 root-owned drop-in so the key is not world-readable.
# Rollback: sudo rm /etc/systemd/system/netwatchm.service.d/anthropic-env.conf
set -euo pipefail

KEY_FILE="${KEY_FILE:-$HOME/ai-projects/uigen/.env}"
KEY="${ANTHROPIC_API_KEY:-}"

if [[ -z "$KEY" ]]; then
  # grab the first uncommented ANTHROPIC_API_KEY-ish line (case-insensitive), strip quotes
  KEY="$(grep -iE '^[[:space:]]*ANTHROPIC_API_KEY[[:space:]]*=' "$KEY_FILE" 2>/dev/null \
          | head -1 | cut -d= -f2- | tr -d '"'"'"' \r')"
fi

if [[ -z "$KEY" || "$KEY" != sk-ant-* ]]; then
  echo "ERROR: no sk-ant-... key found." >&2
  echo "  Set it inline:  ANTHROPIC_API_KEY=sk-ant-... bash $0" >&2
  echo "  Or point at a file:  KEY_FILE=/path/.env bash $0" >&2
  exit 1
fi
echo "==> Using key: ${KEY:0:14}…${KEY: -4}  (from ${ANTHROPIC_API_KEY:+inline env}${ANTHROPIC_API_KEY:-$KEY_FILE})"

DROPIN_DIR="/etc/systemd/system/netwatchm.service.d"
DROPIN="${DROPIN_DIR}/anthropic-env.conf"

sudo mkdir -p "$DROPIN_DIR"
# write without echoing the key to the terminal
printf '[Service]\nEnvironment=ANTHROPIC_API_KEY=%s\n' "$KEY" | sudo tee "$DROPIN" >/dev/null
sudo chmod 600 "$DROPIN"
sudo chown root:root "$DROPIN"
echo "==> Wrote $DROPIN (0600 root)"

sudo systemctl daemon-reload
sudo systemctl restart netwatchm
echo "==> netwatchm restarted; waiting 6s for first agent activity…"
sleep 6

echo "==> Recent agent log:"
sudo journalctl -u netwatchm --since "30 sec ago" --no-pager \
  | grep -iE "agent loop starting|decision|LLM call failed|ANTHROPIC_API_KEY" | tail -8 \
  || echo "  (no agent lines yet — first tick may be up to interval_seconds away)"

echo
echo "Done. Rollback: sudo rm $DROPIN && sudo systemctl daemon-reload && sudo systemctl restart netwatchm"
echo "Reminder: this key was flagged 'REVOKE' in api-keys-audit — rotate it when convenient."
