# -*- mode: python ; coding: utf-8 -*-
import os

import PySide6
from PyInstaller.utils.hooks import collect_all

# Resolve Qt plugins from the interpreter that builds the exe (portable; no
# absolute personal paths in this file).
_pyside_dir = os.path.dirname(PySide6.__file__)
_plugins = os.path.join(_pyside_dir, "plugins")
datas = [
    (os.path.join(_plugins, "platforms"), "platforms"),
    (os.path.join(_plugins, "styles"), "styles"),
]
binaries = []
hiddenimports = ['PIL', 'requests', 'lan_server', 'clients', 'PySide6.QtNetwork']
tmp_ret = collect_all('ruamel.yaml')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('qrcode')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['main_gui.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CF-FlClash-Optimizer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
