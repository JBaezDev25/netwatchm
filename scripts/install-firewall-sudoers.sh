#!/usr/bin/env bash
# install-firewall-sudoers.sh
#
# Install a tight sudoers drop-in that lets the `netwatchm` system user
# run exactly the ufw subcommands the agent's FirewallController needs —
# and nothing else.
#
# Why: the agent service was hardened in Session 16 to run as the
# unprivileged `netwatchm` system user. That user cannot touch ufw on
# its own. Rather than re-root the whole service (high blast radius),
# this drop-in grants the smallest possible elevation: just five exact
# command shapes, all sudo, all NOPASSWD.
#
# The Python FirewallController validates IP/port shape BEFORE invoking
# sudo (ipaddress.ip_address() + numeric port check). Sudoers is the
# second fence; together they should not allow shell metacharacters or
# arbitrary commands to slip through.
#
# Idempotent: re-running overwrites the same drop-in. Rollback:
#   sudo rm /etc/sudoers.d/netwatchm-firewall
set -euo pipefail

DROPIN="/etc/sudoers.d/netwatchm-firewall"
USERNAME="${NETWATCHM_USER:-netwatchm}"
UFW="${UFW_BIN:-/usr/sbin/ufw}"

if ! command -v "$UFW" >/dev/null 2>&1 && [[ ! -x "$UFW" ]]; then
  echo "ERROR: ufw binary not found at $UFW. Install ufw first (apt install ufw)." >&2
  exit 1
fi

if ! getent passwd "$USERNAME" >/dev/null; then
  echo "ERROR: user '$USERNAME' does not exist. Did you run harden-service-user.sh?" >&2
  exit 1
fi

echo "==> Writing $DROPIN for user '$USERNAME' (ufw = $UFW)"
TMP="$(mktemp)"
cat >"$TMP" <<EOF
# Managed by scripts/install-firewall-sudoers.sh — do not edit by hand.
# Grants the netwatchm agent user the minimum ufw subcommands needed for
# Phase 5 auto-expiring blocks. Every shape is exact; * matches anything
# except whitespace under sudoers globbing.
$USERNAME ALL=(root) NOPASSWD: $UFW deny from *
$USERNAME ALL=(root) NOPASSWD: $UFW deny from * to any port *
$USERNAME ALL=(root) NOPASSWD: $UFW delete deny from *
$USERNAME ALL=(root) NOPASSWD: $UFW delete deny from * to any port *
$USERNAME ALL=(root) NOPASSWD: $UFW status numbered
EOF
chmod 0440 "$TMP"

echo "==> Validating with visudo -c"
if ! sudo visudo -cf "$TMP"; then
  echo "ERROR: visudo refused the drop-in. Not installed." >&2
  rm -f "$TMP"
  exit 1
fi

echo "==> Installing"
sudo install -m 0440 -o root -g root "$TMP" "$DROPIN"
rm -f "$TMP"

echo "==> Verifying full /etc/sudoers + drop-ins still parse"
sudo visudo -c

echo
echo "==> Smoke test: $USERNAME can run 'sudo -n ufw status numbered'"
if sudo -u "$USERNAME" sudo -n "$UFW" status numbered >/dev/null 2>&1; then
  echo "    OK"
else
  echo "    WARN: smoke test failed (run by hand to inspect)"
fi

echo
echo "Done."
echo "Drop-in: $DROPIN"
echo "To remove: sudo rm $DROPIN"
