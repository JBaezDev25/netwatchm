#!/usr/bin/env bash
# setup-sudoers.sh — grant passwordless sudo for NetWatchM dev commands.
# Run once with: sudo bash scripts/setup-sudoers.sh
set -euo pipefail

DROPIN="/etc/sudoers.d/netwatchm-dev"
USER="${SUDO_USER:-jbaez120}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo bash scripts/setup-sudoers.sh"
  exit 1
fi

echo "Writing sudoers drop-in for user: ${USER}"

cat > "${DROPIN}" <<EOF
# NetWatchM dev — passwordless sudo for deploy & service management
${USER} ALL=(ALL) NOPASSWD: /bin/cp ${REPO}/netwatchm_server.py /usr/local/bin/netwatchm-server
${USER} ALL=(ALL) NOPASSWD: /bin/chmod +x /usr/local/bin/netwatchm-server
${USER} ALL=(ALL) NOPASSWD: /bin/systemctl daemon-reload
${USER} ALL=(ALL) NOPASSWD: /bin/systemctl restart netwatchm-web
${USER} ALL=(ALL) NOPASSWD: /bin/systemctl restart netwatchm
${USER} ALL=(ALL) NOPASSWD: /bin/systemctl restart grafana-server
${USER} ALL=(ALL) NOPASSWD: /bin/systemctl status netwatchm-web
${USER} ALL=(ALL) NOPASSWD: /bin/systemctl status netwatchm
${USER} ALL=(ALL) NOPASSWD: /bin/mkdir -p /etc/systemd/system/grafana-server.service.d
${USER} ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/systemd/system/grafana-server.service.d/netwatchm-smtp.conf
${USER} ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/netwatchm/netwatchm.yaml
# apply-agent-model.sh — config apply with backup + journal confirm.
# Exact paths only (no wildcards): sudoers '*' matches '/', so a wildcarded
# destination would be a path-escape escalation. Backup is a fixed .bak path.
${USER} ALL=(ALL) NOPASSWD: /usr/bin/cp -a /etc/netwatchm/netwatchm.yaml /etc/netwatchm/netwatchm.yaml.bak
${USER} ALL=(ALL) NOPASSWD: /usr/bin/cp /tmp/netwatchm.yaml /etc/netwatchm/netwatchm.yaml
${USER} ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u netwatchm *
EOF

chmod 0440 "${DROPIN}"

# Validate — if visudo rejects it, remove immediately
if ! visudo -cf "${DROPIN}" 2>&1; then
  rm -f "${DROPIN}"
  echo "ERROR: sudoers syntax invalid — file removed. No changes made."
  exit 1
fi

echo "Done. Installed: ${DROPIN}"
echo ""
echo "You can now run deploy and setup scripts without a password prompt:"
echo "  bash scripts/deploy-server.sh"
echo "  bash scripts/setup-grafana-alerts.sh"
