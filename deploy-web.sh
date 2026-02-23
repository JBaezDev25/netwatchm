#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$DIR/report.html" /var/lib/netwatchm/report.html
cp "$DIR/netwatchm_server.py" /usr/local/bin/netwatchm-server
chmod +x /usr/local/bin/netwatchm-server
cp "$DIR/netwatchm-web.service" /etc/systemd/system/netwatchm-web.service
systemctl daemon-reload
systemctl restart netwatchm-web
systemctl status netwatchm-web --no-pager
