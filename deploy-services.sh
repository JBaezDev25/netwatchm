#!/usr/bin/env bash
set -x

D=/home/jbaez120/ai-projects/netwatchm

cp "$D/netwatchm-web.service"      /etc/systemd/system/netwatchm-web.service
cp "$D/netwatchm-notify@.service"  /etc/systemd/system/netwatchm-notify@.service
cp "$D/scripts/notify-down.py"     /usr/local/bin/netwatchm-notify
chmod +x /usr/local/bin/netwatchm-notify
cp "$D/report.html"                /var/lib/netwatchm/report.html

mkdir -p /etc/systemd/journald.conf.d
cp "$D/netwatchm-journald.conf"    /etc/systemd/journald.conf.d/netwatchm.conf

systemctl daemon-reload
systemctl enable --now netwatchm-web
systemctl restart systemd-journald

echo ""
echo "=== Status ==="
systemctl status netwatchm netwatchm-web --no-pager
