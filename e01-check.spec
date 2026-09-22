# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for e01-check (single-file Windows console EXE).

Build with:  pyinstaller --noconfirm e01-check.spec
"""

from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
for pkg in ("dissect", "dissect.evidence", "dissect.cstruct", "dissect.util", "rich", "pygments", "markdown_it", "mdurl"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    ["verify-e01.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["dissect.evidence.ad1", "dissect.evidence.asdf", "dissect.evidence.adcrypt"],
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
    name="e01-check",
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
)