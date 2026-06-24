#!/usr/bin/env bash
set -e

echo "=== Phase 3: SSHFS NAS mount setup ==="

# Enable allow_other in FUSE so the netwatchm service user can access the mount
if ! grep -q "^user_allow_other" /etc/fuse.conf; then
    sudo sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf
    echo "Enabled user_allow_other in /etc/fuse.conf"
else
    echo "user_allow_other already enabled"
fi

# Create the mount point
sudo mkdir -p /mnt/nas_netwatchm

# Write the systemd mount unit
sudo tee /etc/systemd/system/mnt-nas_netwatchm.mount > /dev/null << 'EOF'
[Unit]
Description=SSHFS mount for NetWatchM NAS storage
After=network-online.target
Wants=network-online.target

[Mount]
What=YUNKE-01@192.168.1.245:/volume1/AI-Programming/netwatchm
Where=/mnt/nas_netwatchm
Type=fuse.sshfs
Options=_netdev,IdentityFile=/home/jbaez120/.ssh/nas_ugreen,allow_other,default_permissions,ServerAliveInterval=15,ServerAliveCountMax=3,reconnect,uid=995,gid=982,umask=027

[Install]
WantedBy=multi-user.target
EOF

# Write the systemd automount unit
sudo tee /etc/systemd/system/mnt-nas_netwatchm.automount > /dev/null << 'EOF'
[Unit]
Description=Automount for NetWatchM NAS
After=network-online.target
Wants=network-online.target

[Automount]
Where=/mnt/nas_netwatchm
TimeoutIdleSec=0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable mnt-nas_netwatchm.automount
sudo systemctl start mnt-nas_netwatchm.automount

echo ""
echo "=== Testing mount ==="
ls -la /mnt/nas_netwatchm/
echo "Mount verified."
