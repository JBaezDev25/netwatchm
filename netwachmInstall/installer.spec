# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for netwatchm-setup.exe (GUI installer)
#
# Build (from repo root on Windows):
#   pip install pyinstaller
#   pyinstaller netwachmInstall/installer.spec --clean --noconfirm
#
# Output: dist/netwatchm-setup.exe

import os

root = os.path.abspath(os.path.join(SPECPATH, '..'))

a = Analysis(
    [os.path.join(SPECPATH, 'installer_gui.py')],
    pathex=[root],
    binaries=[],
    datas=[
        (os.path.join(root, 'netwatchm.yaml.example'), '.'),
    ],
    hiddenimports=['tkinter', 'tkinter.ttk', 'tkinter.messagebox'],
    hookspath=[],
    runtime_hooks=[],
    excludes=['pygame', 'impacket', 'geoip2', 'paramiko'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='netwatchm-setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    console=False,   # no console window — GUI only
    onefile=True,
    icon=None,
    uac_admin=True,  # request admin via UAC manifest
)
