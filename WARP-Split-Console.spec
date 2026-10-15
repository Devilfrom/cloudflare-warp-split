# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['warp_split.py'],
    pathex=[],
    binaries=[],
    datas=[('index.html', '.'), ('china_cidr.txt', '.'), ('china_cidr_lite.txt', '.')],
    hiddenimports=['ctypes', 'ctypes.wintypes', 'ipaddress'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'numpy', 'PIL', 'pytest'],
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
    name='WARP-Split-Console',
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
    icon=['tools/warp.ico'],
)
