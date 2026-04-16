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

# netwatchm-src.zip is created by CI (release.yml) before the PyInstaller build.
# Include it when present so the installer works with a private GitHub repo.
_src_zip = os.path.join(SPECPATH, 'netwatchm-src.zip')
_extra_datas = [(_src_zip, '.')] if os.path.exists(_src_zip) else []

a = Analysis(
    [os.path.join(SPECPATH, 'installer_gui.py')],
    pathex=[root],
    binaries=[],
    datas=[
        (os.path.join(root, 'netwatchm.yaml.example'), '.'),
        *_extra_datas,
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
    version=os.path.join(SPECPATH, 'installer_version.txt'),
)
