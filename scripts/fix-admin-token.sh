#!/usr/bin/env bash
# Remove placeholder NETWATCHM_ADMIN_TOKEN from service so default kicks in.
set -euo pipefail
SERVICE="/etc/systemd/system/netwatchm-web.service"
sudo sed -i '/NETWATCHM_ADMIN_TOKEN=your-secret-token/d' "$SERVICE"
sudo systemctl daemon-reload
sudo systemctl restart netwatchm-web
echo "Done. Admin token is now: netwatchm-admin (default)"
systemctl status netwatchm-web --no-pager -l | head -5
