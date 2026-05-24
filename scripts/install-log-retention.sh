#!/usr/bin/env bash
# install-log-retention.sh
#
# Install a logrotate drop-in for /var/log/netwatchm/*.log with 15-day
# retention, daily rotation, gzip compression, and copytruncate (so the
# running netwatchm process keeps its open file handle valid through
# rotation — no signal needed).
#
# Runs via the system's daily cron.daily (logrotate is configured by
# the OS to run automatically), so this works even when the netwatchm
# service is down — unlike the in-process retention sweep, which only
# runs while the service is up.
#
# Idempotent. Rollback:
#   sudo rm /etc/logrotate.d/netwatchm
set -euo pipefail

DROPIN="/etc/logrotate.d/netwatchm"
LOG_DIR="/var/log/netwatchm"

if [[ ! -d "$LOG_DIR" ]]; then
  echo "==> $LOG_DIR does not exist — creating (owned by netwatchm:netwatchm, mode 0755)"
  sudo mkdir -p "$LOG_DIR"
  if getent passwd netwatchm >/dev/null; then
    sudo chown netwatchm:netwatchm "$LOG_DIR"
  fi
  sudo chmod 0755 "$LOG_DIR"
fi

echo "==> Writing $DROPIN"
sudo tee "$DROPIN" >/dev/null <<'CONF'
# Managed by scripts/install-log-retention.sh — do not edit by hand.
# 15-day retention for NetWatchM application logs. copytruncate keeps the
# running service's file descriptor valid across rotations, so no signal
# (kill -HUP) or service restart is needed.
/var/log/netwatchm/*.log {
    daily
    rotate 15
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 netwatchm netwatchm
    su netwatchm netwatchm
}
CONF
sudo chmod 0644 "$DROPIN"

echo
echo "==> Validating with logrotate --debug (dry-run, no rotation actually performed)"
if sudo logrotate --debug "$DROPIN"; then
  echo "    OK"
else
  echo "    WARN: dry-run reported issues — inspect output above" >&2
fi

echo
echo "Done."
echo "Drop-in: $DROPIN"
echo "Effective on the next system cron.daily run (usually ~06:25 UTC)."
echo "To roll back: sudo rm $DROPIN"
