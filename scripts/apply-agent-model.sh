#!/usr/bin/env bash
#
# apply-agent-model.sh
#
# Point the NetWatchM agent at the local Ollama model qwen2.5-coder:7b.
# Applies the staged config from /tmp/netwatchm.yaml (already validated) to
# the live config, keeping a timestamped backup, then restarts the service.
#
# Safe to re-run. Does NOT touch any secrets — local Ollama needs no API key.
#
set -euo pipefail

STAGED="/tmp/netwatchm.yaml"
LIVE="/etc/netwatchm/netwatchm.yaml"
MODEL="qwen2.5-coder:7b"

[ -f "$STAGED" ] || { echo "ERROR: staged config $STAGED not found" >&2; exit 1; }

echo "==> Verifying the model is present in Ollama ..."
if ! ollama list | grep -q "^${MODEL}"; then
  echo "ERROR: ${MODEL} not found in 'ollama list'. Pull it first: ollama pull ${MODEL}" >&2
  exit 1
fi

echo "==> Validating staged YAML ..."
python3 - "$STAGED" "$MODEL" <<'PY'
import sys, yaml
path, model = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(path))
assert d["agent"]["model"] == model, "staged config does not set agent.model=%s" % model
print("    OK — agent.model =", d["agent"]["model"])
PY

echo "==> Backing up live config -> ${LIVE}.bak"
sudo cp -a "$LIVE" "${LIVE}.bak"

echo "==> Installing staged config -> ${LIVE}"
sudo cp "$STAGED" "$LIVE"

echo "==> Restarting netwatchm ..."
sudo systemctl restart netwatchm

echo "==> Waiting for the agent loop to log its model ..."
sleep 3
sudo journalctl -u netwatchm --since "1 min ago" --no-pager \
  | grep -iE "agent loop starting|model=|ollama|qwen|mistral|LLM call failed" \
  | tail -10 \
  || echo "    (no matching lines yet — check 'journalctl -u netwatchm -f')"

echo
echo "==> Done. Expected a line containing  model=${MODEL}."
echo "    Rollback: sudo cp ${LIVE}.bak ${LIVE} && sudo systemctl restart netwatchm"
