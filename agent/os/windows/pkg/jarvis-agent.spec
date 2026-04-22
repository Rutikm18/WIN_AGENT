# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['..\\agent_win_entry.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['agent.agent.collectors', 'agent.agent.crypto', 'agent.agent.sender', 'agent.agent.enrollment', 'agent.agent.keystore', 'agent.agent.normalizer', 'agent.agent.circuit_breaker', 'agent.os.windows.win_agent', 'agent.os.windows.tls_transport', 'agent.os.windows.service', 'agent.os.windows.keystore', 'agent.os.windows.normalizer', 'agent.os.windows.collectors', 'agent.os.windows.collectors.volatile', 'agent.os.windows.collectors.network', 'agent.os.windows.collectors.system', 'agent.os.windows.collectors.posture', 'agent.os.windows.collectors.inventory', 'agent.os.windows.collectors.eventlog', 'win32service', 'win32serviceutil', 'win32event', 'win32evtlog', 'servicemanager', 'win32crypt', 'pywintypes', 'psutil', 'cryptography', 'cryptography.hazmat.primitives.ciphers.aead', 'requests', 'urllib3'],
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
    name='jarvis-agent',
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
    version='E:\\Project - AttacklensAgentwork\\PROJECT_CORE\\agent\\os\\windows\\pkg\\version_info.txt',
)
