# -*- mode: python ; coding: utf-8 -*-
# OneDIR build — required for Windows Service compatibility.
import os
ROOT = os.path.abspath(os.path.join(SPECPATH, '..', '..', '..', '..'))

a = Analysis(
    [os.path.join(ROOT, 'agent', 'os', 'windows', 'watchdog_svc.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[
        'agent.os.windows.config_model',
        'agent.os.windows.boot_persistence',
        'agent.os.windows.service',
        'agent.os.windows.startup_recovery',
        'win32service', 'win32serviceutil', 'win32event',
        'servicemanager', 'pywintypes', 'win32timezone',
    ],
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
    [],
    exclude_binaries=True,
    name='attacklens-watchdog',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='attacklens-watchdog',
)
