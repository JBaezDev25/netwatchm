#!/usr/bin/env bash
#
# Install a desktop launcher for the NetWatchM GUI installer, so it shows up in
# the application menu with the Frenchie icon. Per-user, no sudo.
#
# Usage: bash netwachmInstall/install-launcher.sh   [--uninstall]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor"
DESKTOP="$APPS/netwatchm-installer.desktop"

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$DESKTOP"
  for s in 16 32 48 64 128 256 512; do rm -f "$ICONS/${s}x${s}/apps/netwatchm.png"; done
  update-desktop-database "$APPS" 2>/dev/null || true
  echo "Removed the NetWatchM Installer launcher."
  exit 0
fi

mkdir -p "$APPS"
# install the icon into the hicolor theme at every size
for s in 16 32 48 64 128 256 512; do
  src="$SCRIPT_DIR/assets/netwatchm-icon-${s}.png"
  [ -f "$src" ] || continue
  d="$ICONS/${s}x${s}/apps"; mkdir -p "$d"
  cp "$src" "$d/netwatchm.png"
done
gtk-update-icon-cache "$ICONS" 2>/dev/null || true

cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=NetWatchM Installer
Comment=Install NetWatchM, local AI, and the nic-asst-ai assistant
Exec=python3 "$SCRIPT_DIR/installer_gui_linux.py"
Path=$SCRIPT_DIR
Icon=netwatchm
Terminal=false
Categories=System;Network;Settings;
Keywords=netwatchm;network;monitor;install;
EOF
chmod +x "$DESKTOP"
update-desktop-database "$APPS" 2>/dev/null || true

echo "Installed launcher 'NetWatchM Installer' — find it in your application menu."
echo "Icon: the NetWatchM Frenchie. Remove with: bash $0 --uninstall"
