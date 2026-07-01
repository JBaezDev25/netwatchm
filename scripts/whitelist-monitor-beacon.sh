#!/usr/bin/env bash
# Add 10.0.0.180 (this monitoring host) to detector_whitelist for
# BEACONING and TRACKER_DOMAIN, and restart netwatchm.
#
# Why: this host runs Discord/Edge/Office/Slack-style apps whose 45s
# heartbeats trip BEACONING, and whose telemetry trips TRACKER_DOMAIN.
# Other detectors (BRUTE_FORCE, EXFILTRATION, TOR_EXIT, MALWARE_DOMAIN,
# DNS_TUNNELING, NEW_IP) remain active for this host.
set -euo pipefail

MONITOR_IP="10.0.0.180"
CONFIG_DST="/etc/netwatchm/netwatchm.yaml"
CONFIG_TMP="/tmp/netwatchm-updated.yaml"
BACKUP="/etc/netwatchm/netwatchm.yaml.bak-$(date +%Y%m%d-%H%M%S)"

# Use the system venv's python (has PyYAML installed via netwatchm deps)
PY="/usr/local/lib/netwatchm/venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="$(command -v python3)"
fi

echo "==> Reading live config: $CONFIG_DST"
sudo cp "$CONFIG_DST" "$CONFIG_TMP"
sudo chmod 666 "$CONFIG_TMP"   # writable for non-sudo edit step

echo "==> Adding $MONITOR_IP to detector_whitelist.{BEACONING, TRACKER_DOMAIN}"
"$PY" - "$CONFIG_TMP" "$MONITOR_IP" <<'PY'
import sys, yaml
path, ip = sys.argv[1], sys.argv[2]

with open(path) as f:
    cfg = yaml.safe_load(f) or {}

dwl = cfg.setdefault("detector_whitelist", {})

for alert_type in ("BEACONING", "TRACKER_DOMAIN"):
    ips = dwl.get(alert_type) or []
    if not isinstance(ips, list):
        ips = []
    if ip not in ips:
        ips.append(ip)
    dwl[alert_type] = ips
    print(f"   {alert_type}: {ips}")

cfg["detector_whitelist"] = dwl

with open(path, "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
print(f"   wrote: {path}")
PY

# Restore restrictive perms before copying back
sudo chmod 644 "$CONFIG_TMP"

echo
echo "==> Diff vs. live config:"
sudo diff -u "$CONFIG_DST" "$CONFIG_TMP" || true

echo
read -p "Apply this change and restart netwatchm? [y/N] " ans
if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
  echo "Aborted. Updated config left at $CONFIG_TMP for review."
  exit 0
fi

echo "==> Backing up: $CONFIG_DST -> $BACKUP"
sudo cp "$CONFIG_DST" "$BACKUP"

echo "==> Applying new config"
sudo cp "$CONFIG_TMP" "$CONFIG_DST"

echo "==> Restarting netwatchm service"
sudo systemctl restart netwatchm

echo "==> Service status:"
sudo systemctl is-active netwatchm
echo
echo "Done. $MONITOR_IP is now whitelisted for BEACONING and TRACKER_DOMAIN."
echo "Backup: $BACKUP"
