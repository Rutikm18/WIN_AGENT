# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['..\\watchdog_svc.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['win32service', 'win32serviceutil', 'win32event', 'servicemanager', 'pywintypes'],
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
    name='jarvis-watchdog',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='E:\\Project - AttacklensAgentwork\\PROJECT_CORE\\agent\\os\\windows\\pkg\\version_info_wd.txt',
)
