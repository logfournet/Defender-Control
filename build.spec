# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec: builds the Defender Control executables.

Outputs (dist/):
  * dControl.exe       - windowed GUI + requireAdministrator manifest (like the original)
  * dcontrol-cli.exe   - console CLI variant (status/disable/enable)

Build:  pyinstaller --clean --noconfirm build.spec
"""

from pathlib import Path
import sys

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

ROOT = Path(SPECPATH).resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import defender_control as pkg  # noqa: E402

ASSETS = ROOT / "assets"

ICON = str(ASSETS / "dcontrol.ico")
MANIFEST = str(ASSETS / "app.manifest")

_VERSION_TUPLE = tuple(int(p) for p in pkg.__version__.split("."))
while len(_VERSION_TUPLE) < 4:
    _VERSION_TUPLE += (0,)
_VERSION_STR = ".".join(str(p) for p in _VERSION_TUPLE)

VERSION = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=_VERSION_TUPLE,
        prodvers=_VERSION_TUPLE,
        mask=0x3F,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    "080904b0",
                    [
                        StringStruct("Comments", "Defender Control (Python reimplementation)"),
                        StringStruct("CompanyName", "Defender Control"),
                        StringStruct("FileDescription", "Defender Control"),
                        StringStruct("FileVersion", _VERSION_STR),
                        StringStruct("InternalName", "dControl"),
                        StringStruct(
                            "LegalCopyright",
                            "Copyright (C) 2015-2022 www.sordum.org. "
                            "Python reimplementation, independent project.",
                        ),
                        StringStruct("OriginalFilename", "dControl.exe"),
                        StringStruct("ProductName", "Defender Control"),
                        StringStruct("ProductVersion", _VERSION_STR),
                    ],
                )
            ],
        ),
        VarFileInfo([VarStruct("Translation", [0x0809, 1200])]),
    ],
)

HIDDEN_IMPORTS = [
    "defender_control",
    "defender_control.cli",
    "defender_control.core",
    "defender_control.operations",
    "defender_control.service_catalog",
    "gui",
    "tkinter",
    "tkinter.ttk",
    "tkinter.messagebox",
    "tkinter.font",
]

EXCLUDES = [
    "pytest",
    "_pytest",
    "pefile",
    "PIL",
    "numpy",
    "pandas",
    "matplotlib",
    "setuptools",
    "pip",
    "unittest",
    "pydoc",
    "doctest",
]

DATAS = [(str(ASSETS / "dcontrol.ico"), "assets")]

COMMON_ANALYSIS_KWARGS = dict(
    pathex=[str(ROOT)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)

# --- GUI / main executable (windowed, requires Administrator) ---------------
gui_analysis = Analysis([str(ROOT / "launcher.py")], **COMMON_ANALYSIS_KWARGS)
gui_pyz = PYZ(gui_analysis.pure)
gui_exe = EXE(
    gui_pyz,
    gui_analysis.scripts,
    gui_analysis.binaries,
    gui_analysis.datas,
    [],
    name="dControl",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON,
    manifest=MANIFEST,
    version=VERSION,
)

# --- CLI executable (console) ----------------------------------------------
cli_analysis = Analysis([str(ROOT / "defender_control.py")], **COMMON_ANALYSIS_KWARGS)
cli_pyz = PYZ(cli_analysis.pure)
cli_exe = EXE(
    cli_pyz,
    cli_analysis.scripts,
    cli_analysis.binaries,
    cli_analysis.datas,
    [],
    name="dcontrol-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON,
    version=VERSION,
)