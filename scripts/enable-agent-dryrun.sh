#!/usr/bin/env bash
# enable-agent-dryrun.sh
#
# Flip the autonomous agent ON in DRY-RUN mode in the live config and
# restart the netwatchm service.
#
# Safety:
#   - Refuses to run if dry_run is already set to false in the live YAML
#     (that would be promoting straight to live actions — use a different
#     script when you are ready for that)
#   - Always writes dry_run: true and enabled: true under the agent: block,
#     preserving every other key (model, intervals, caps, etc.)
#   - Backs up live YAML with a timestamped suffix before applying
#   - Shows a unified diff and asks y/N before touching anything
#   - After restart, tails journalctl briefly to confirm the agent task
#     came up
#
# Run AFTER `bash scripts/deploy-server.sh` so the system venv (used by
# netwatchm-web) is also on Session 26 code — the main monitor uses the
# editable home venv so the service restart alone picks up Phase 2.
set -euo pipefail

CONFIG_DST="/etc/netwatchm/netwatchm.yaml"
CONFIG_TMP="/tmp/netwatchm-agent-enable.yaml"
BACKUP="/etc/netwatchm/netwatchm.yaml.bak-$(date +%Y%m%d-%H%M%S)"

# Prefer system venv python (has PyYAML); fall back to system python3.
PY="/usr/local/lib/netwatchm/venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="$(command -v python3)"
fi

echo "==> Reading live config: $CONFIG_DST"
sudo cp "$CONFIG_DST" "$CONFIG_TMP"
sudo chmod 666 "$CONFIG_TMP"

echo "==> Setting agent.enabled=true, agent.dry_run=true (preserving other keys)"
"$PY" - "$CONFIG_TMP" <<'PY'
import sys, yaml
path = sys.argv[1]

with open(path) as f:
    cfg = yaml.safe_load(f) or {}

agent = cfg.get("agent")
if not isinstance(agent, dict):
    agent = {}

# Refuse to silently re-enable a live-action config from this script.
if agent.get("dry_run") is False:
    print("REFUSE: agent.dry_run is currently false in the live config.")
    print("        Use a dedicated promotion script when ready for live actions.")
    sys.exit(2)

agent["enabled"] = True
agent["dry_run"] = True
cfg["agent"] = agent

with open(path, "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)

print(f"   wrote: {path}")
print(f"   agent.enabled = {agent['enabled']}")
print(f"   agent.dry_run = {agent['dry_run']}")
PY

sudo chmod 644 "$CONFIG_TMP"

echo
echo "==> Diff vs. live config:"
sudo diff -u "$CONFIG_DST" "$CONFIG_TMP" || true

echo
read -rp "Apply this change and restart netwatchm? [y/N] " ans
if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
  echo "Aborted. Updated config left at $CONFIG_TMP for review."
  exit 0
fi

echo "==> Backing up:  $CONFIG_DST -> $BACKUP"
sudo cp "$CONFIG_DST" "$BACKUP"

echo "==> Applying new config"
sudo cp "$CONFIG_TMP" "$CONFIG_DST"

echo "==> Restarting netwatchm"
sudo systemctl restart netwatchm

echo "==> Waiting 6s for the agent loop to register…"
sleep 6

echo "==> Service status:"
sudo systemctl is-active netwatchm

echo
echo "==> Recent journal entries mentioning agent (last 50 lines):"
sudo journalctl -u netwatchm -n 50 --no-pager | grep -iE 'agent|ollama' || \
  echo "  (no agent-related log lines yet — first tick can take a few minutes)"

echo
echo "Done. Agent is enabled in DRY-RUN mode."
echo "Backup: $BACKUP"
echo
echo "Watch decisions accrue (give it 5+ minutes for the first tick):"
echo "  sqlite3 /var/lib/netwatchm/agent_actions.db \\"
echo "    'SELECT datetime(ts,\"unixepoch\",\"localtime\"), max_severity, substr(rationale,1,80)"
echo "       FROM agent_decisions ORDER BY ts DESC LIMIT 20'"
