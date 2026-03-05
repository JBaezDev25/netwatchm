# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for NetWatchM
# Builds two executables in one pass:
#   dist/netwatchm/netwatchm.exe        — CLI monitor
#   dist/netwatchm/netwatchm-server.exe — HTTPS web server
#
# Build (from repo root):
#   pip install pyinstaller
#   pyinstaller netwachmInstall/netwatchm.spec --clean --noconfirm
#
# Or use the build scripts:
#   bash netwachmInstall/build-linux.sh --clean
#   .\netwachmInstall\build-windows.ps1 -Clean

import os
from PyInstaller.utils.hooks import collect_submodules

# Resolve repo root (one level above this spec file)
root = os.path.abspath(os.path.join(SPECPATH, '..'))

# ── Common hidden imports ─────────────────────────────────────────────────────
_common_hidden = [
    'yaml', 'geoip2', 'geoip2.database', 'geoip2.models',
    'maxminddb', 'maxminddb.reader',
    'sqlite3', '_sqlite3',
]

# ── CLI executable ────────────────────────────────────────────────────────────
a_cli = Analysis(
    [os.path.join(root, 'src', 'netwatchm', '__main__.py')],
    pathex=[root, os.path.join(root, 'src')],
    binaries=[],
    datas=[
        (os.path.join(root, 'assets', 'alert.wav'), 'assets'),
        (os.path.join(root, 'netwatchm.yaml.example'), '.'),
    ],
    hiddenimports=_common_hidden + [
        'netwatchm.detector.port_scan',
        'netwatchm.detector.brute_force',
        'netwatchm.detector.exfiltration',
        'netwatchm.detector.new_ip',
        'netwatchm.detector.tor_exit',
        'netwatchm.detector.adult_domain',
        'netwatchm.detector.data_hog',
        'netwatchm.alerts.terminal',
        'netwatchm.alerts.logfile',
        'netwatchm.alerts.sound',
        'netwatchm.alerts.email_alert',
        'netwatchm.alerts.event_store',
        'netwatchm.alerts.event_handler',
        'netwatchm.alerts.ntfy_alert',
        'netwatchm.inventory.store',
        'netwatchm.inventory.resolver',
        'netwatchm.inventory.exporter',
        'netwatchm.inventory.arp_scanner',
        'netwatchm.reports.connection_report',
        'netwatchm.reports.flow_store',
        'netwatchm.reports.analytics_report',
        'netwatchm.reports.deep_inspect',
        'netwatchm.reports.investigate_report',
        'netwatchm.service.windows',
        'netwatchm.service.linux',
        'impacket', 'impacket.krb5', 'impacket.smb',
        'impacket.krb5.asn1', 'impacket.krb5.ccache',
        'pygame', 'pygame.mixer',
        'paramiko',
        'requests', 'urllib3', 'certifi',
        'win32service', 'win32serviceutil', 'win32event',
        'win32api', 'win32con', 'pywintypes',
        'servicemanager',
    ] + collect_submodules('impacket'),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'test', 'unittest'],
    noarchive=False,
)

pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data)

exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    [],
    exclude_binaries=True,
    name='netwatchm',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
)

# ── Server executable ─────────────────────────────────────────────────────────
a_server = Analysis(
    [os.path.join(root, 'netwatchm_server.py')],
    pathex=[root, os.path.join(root, 'src')],
    binaries=[],
    datas=[
        (os.path.join(root, 'netwatchm.yaml.example'), '.'),
    ],
    hiddenimports=_common_hidden + [
        'netwatchm.alerts.event_store',
        'netwatchm.reports.flow_store',
        'netwatchm.reports.deep_inspect',
        'netwatchm.reports.investigate_report',
        'yaml', 'requests', 'urllib3', 'certifi',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'test', 'unittest', 'pygame', 'impacket'],
    noarchive=False,
)

pyz_server = PYZ(a_server.pure, a_server.zipped_data)

exe_server = EXE(
    pyz_server,
    a_server.scripts,
    [],
    exclude_binaries=True,
    name='netwatchm-server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
)

# ── Combined distribution folder ──────────────────────────────────────────────
coll = COLLECT(
    exe_cli,
    a_cli.binaries,
    a_cli.zipfiles,
    a_cli.datas,
    exe_server,
    a_server.binaries,
    a_server.zipfiles,
    a_server.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='netwatchm',
)
