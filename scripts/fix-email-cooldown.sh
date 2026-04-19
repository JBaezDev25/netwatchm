#!/usr/bin/env bash
# Update the live email cooldown from 300s (5 min) to 3600s (1 hour) per device.
# This reduces email frequency — the cooldown is now per (alert_type, device)
# so a busy device won't block alerts from other devices.
set -euo pipefail

CONFIG=/etc/netwatchm/netwatchm.yaml
BACKUP=/etc/netwatchm/netwatchm.yaml.bak-$(date +%Y%m%d-%H%M%S)

if ! sudo grep -q "cooldown_seconds:" "$CONFIG"; then
    echo "ERROR: cooldown_seconds not found in $CONFIG"
    exit 1
fi

echo "Backing up $CONFIG → $BACKUP"
sudo cp "$CONFIG" "$BACKUP"

# Update only the email cooldown line (first occurrence under alerts.email)
sudo python3 - "$CONFIG" <<'EOF'
import sys, re

path = sys.argv[1]
text = open(path).read()

# Replace the first cooldown_seconds: <number> # ...emails... line
text = re.sub(
    r'(cooldown_seconds:\s*)\d+(\s*#.*emails.*)',
    r'\g<1>3600\2',
    text,
    count=1,
)

open(path, 'w').write(text)
print("cooldown_seconds updated to 3600 in", path)
EOF

echo "Restarting netwatchm service..."
sudo systemctl restart netwatchm

echo "Done. Email cooldown is now 1 hour per (alert_type, device)."
echo "Also redeploy the netwatchm package to apply all email content fixes:"
echo "  bash scripts/deploy-server.sh"
