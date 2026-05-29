#!/usr/bin/env bash
#
# restart-agent-service.sh
#
# Restart the netwatchm monitor/agent service so it picks up the reverted
# agent code from the working tree (Ollama client, model: mistral:latest),
# then confirm the agent loop came up on the local model instead of Anthropic.
#
# Context: the Session 30 Anthropic swap was abandoned and the agent files
# were reverted to HEAD, but a long-running service still holds the old code
# in memory until restarted. See CHECKLIST.md → "DECISION: stay on local GPU
# Ollama".
#
set -euo pipefail

SERVICE="netwatchm"

echo "==> Restarting ${SERVICE} ..."
sudo systemctl restart "${SERVICE}"

echo "==> Waiting for the agent loop to log its startup line ..."
sleep 3

echo "==> Recent agent log lines:"
sudo journalctl -u "${SERVICE}" --since "1 min ago" --no-pager \
  | grep -iE "agent loop starting|model=|ollama|mistral|anthropic|LLM call failed" \
  | tail -12 \
  || echo "    (no matching lines yet — check 'journalctl -u ${SERVICE} -f')"

echo
echo "==> Expected: a line containing  model=mistral:latest  (NOT anthropic)."
echo "    If you see 'agent loop starting' with the mistral model, the revert is live."
