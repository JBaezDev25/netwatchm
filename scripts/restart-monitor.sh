#!/usr/bin/env bash
#
# restart-monitor.sh
#
# Restart the netwatchm monitor/capture service so it picks up code changes in
# the working tree (the service runs from the repo's editable .venv, so source
# edits to detectors/etc. go live on restart — no pip reinstall needed).
#
# Use after changing anything under src/netwatchm/ that runs in the capture
# pipeline (detectors, scorer, alert handlers, capture).
#
set -euo pipefail

SERVICE="netwatchm"

echo "==> Restarting ${SERVICE} ..."
sudo systemctl restart "${SERVICE}"

sleep 2
echo "==> Status:"
systemctl is-active "${SERVICE}" >/dev/null 2>&1 \
  && echo "    ${SERVICE} is active (running)" \
  || { echo "    ${SERVICE} failed to start — recent log:"; \
       sudo journalctl -u "${SERVICE}" --since "1 min ago" --no-pager | tail -20; exit 1; }

echo "==> Recent log lines:"
sudo journalctl -u "${SERVICE}" --since "1 min ago" --no-pager | tail -8 || true
