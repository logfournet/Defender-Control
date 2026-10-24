# Defender Control (Python reimplementation)

A pure-Python reimplementation of **Sordum "Defender Control" v2.1** (`dControl.exe`, by *BlueLife*,
https://www.sordum.org) for Windows 10/11. The original tool is no longer maintained, so this project
reimplements its documented behaviour with **no third-party runtime dependencies** (Python ≥ 3.9).

It ships as a small GUI (`dControl.exe`), a console CLI (`dcontrol-cli.exe`), and a Python package that
can be used directly from source.

> ⚠️ **Security notice.** Disabling Windows Defender leaves the machine unprotected. Run this only on
> machines you own, only with a full understanding of the consequences, and re-enable Defender when you
> are done.

---

## Features

* **Status** — read-only snapshot of Defender services, start types and policy values.
* **Disable Defender** — stops the Security Center and the Defender service family, writes the
  group-policy and direct registry values, blocks Defender tools through IFEO, and sets the Defender
  services to *Disabled*.
* **Enable Defender** — reverses every step: removes IFEO blocks, deletes the policy keys, restores
  startup entries, restores the original service start types and restarts the services.
* **GUI** — Tkinter window with status, action buttons, shortcuts to the Windows Security pages and a
  live log. Long operations run on a worker thread, so the window never freezes.
* **CLI** — scriptable `status` / `disable` / `enable` commands with automatic UAC elevation.
* **Self-elevation** — both the GUI and the CLI re-launch themselves through UAC when they are not
  running as Administrator (the packaged `dControl.exe` already carries a `requireAdministrator`
  manifest, exactly like the original).

## What "disable" actually does

The sequence mirrors the documented v2.1 behaviour (see `defender_control/service_catalog.py` for the
full catalogue):

1. Stop the **Security Center** service (`Wscsvc`) first, so it cannot restart Defender.
2. Stop the Defender service family (`WinDefend`, `WdFilter`, `WdNisDrv`, `WdNisSvc`, `WdBoot`, `Sense`,
   `SecurityHealthService`, …).
3. Terminate the remaining Defender processes.
4. Write the **Group Policy** values under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
   (`DisableAntiSpyware`, `Real-Time Protection`, `MpEngine`, `Spynet`, `NIS`, `Scan`, …) and
   `HKLM\SOFTWARE\Policies\Microsoft\MRT`.
5. Write the direct values under `HKLM\SOFTWARE\Microsoft\Windows Defender`.
6. Add **IFEO** blocks (`Debugger`) for the Defender executables.
7. Mark `SecurityHealth` as disabled in `StartupApproved\Run`.
8. Set the Defender services' start type to **Disabled (4)**.
9. Restart the Security Center if it is not running.

`enable` performs the reverse of every step and restores the original service start types.

## Analysis of the original binary

The original `dControl.exe` v2.1 was analysed statically before this reimplementation was written:

| Property  | Value |
|-----------|-------|
| Format    | PE32 (x86), GUI subsystem |
| Packing   | **UPX** — sections `UPX0` / `UPX1` / `.rsrc` (original file: 457,984 bytes) |
| Runtime   | **AutoIt v3** compiled script (`"This is a compiled AutoIt script..."` marker) |
| Product   | **dControl v2.1** — *Sordum Defender Control* (`www.sordum.org`) |
| Author    | BlueLife, © 2015–2022 |
| Manifest  | `requireAdministrator` |
| Resources | 12 icons, 8 group icons, 1 VERSION, 1 MANIFEST — **no RT_RCDATA** |

After unpacking (`upx -d`): 798,464 bytes, 4 sections, entry point `0x4165C1`. Ghidra 12.1.4 recovered
2,735 functions and 1,824 strings, which confirmed the AutoIt runtime layout (`AU3_WinMain` →
token/statement table → bytecode interpreter loop).

The embedded script does **not** use the standard AutoIt container: the `EA05` / `EA06` / `JB01` magic
values are absent, `AU3_HEADER` is not present even after a single-byte XOR over all 256 keys, and no
script keyword is visible as plaintext. A ~129 KB high-entropy overlay sits after the last section, is
never mapped by the PE loader, and is therefore the encrypted script blob that the custom runtime
protection decrypts in memory. Automatic extraction of that blob was not pursued; this project
reproduces the **documented and verified behaviour** instead, using the same service/registry/IFEO
catalogue and the same operation order. No AutoIt code is included.

The binary imports exactly the API set required for that behaviour: service control
(`OpenSCManager` / `ControlService`), registry writes (`RegSetValue…`), process termination and
`ShellExecuteW` with the `runas` verb for self-elevation.

## Download

Prebuilt binaries are attached to every [GitHub Release](../../releases):

| File               | Description                                                      |
|--------------------|------------------------------------------------------------------|
| `dControl.exe`     | Windowed GUI, `requireAdministrator` manifest (like the original) |
| `dcontrol-cli.exe` | Console CLI (`status`, `disable`, `enable`)                      |

Both are single-file, self-contained executables — no Python installation required.

## Usage from source

```powershell
# Read-only status (no admin required)
python defender_control.py status

# Disable Windows Defender (prompts for UAC)
python defender_control.py disable

# Enable Windows Defender (prompts for UAC)
python defender_control.py enable

# Skip the elevation prompt (must already be running elevated)
python defender_control.py disable --no-elevate
```

GUI:

```powershell
python gui.py
```

No dependencies are needed to run the project: Windows 10/11 and Python 3.9+ are enough.

## Build the executables

```powershell
python -m pip install pyinstaller
python -m PyInstaller --clean --noconfirm build.spec
```

Output lands in `dist\`:

* `dist\dControl.exe` — GUI (windowed, admin manifest, icon and version resource)
* `dist\dcontrol-cli.exe` — console CLI

## GitHub Actions

`.github/workflows/build.yml` builds both executables on every push and pull request, and uploads them
as a downloadable artifact. Pushing a tag such as `v2.1.0` (or starting the workflow manually) publishes
a **GitHub Release** with the executables attached.

```powershell
git tag v2.1.0
git push origin v2.1.0
```

## Project layout

```
Defender-Control/
├── defender_control.py          # CLI entry point
├── launcher.py                  # entry point for the frozen GUI build
├── gui.py                       # Tkinter GUI
├── build.spec                   # PyInstaller build definition
├── assets/
│   ├── dcontrol.ico             # application icon
│   ├── app.manifest             # requireAdministrator + DPI awareness
│   └── version_info.txt         # version resource reference
├── defender_control/
│   ├── __init__.py              # package version
│   ├── cli.py                   # argument parsing, elevation, main
│   ├── core.py                  # disable/enable orchestration + status
│   ├── operations.py            # registry/service/process primitives
│   └── service_catalog.py       # services, registry keys, IFEO catalogue
├── tests/test_core.py           # unit tests (fully mocked)
└── tools/extract_icon.py        # helper used to extract the original icon
```

## Tests

```powershell
python -m pytest tests -q
```

The tests mock the low-level operations, so they never touch the real registry or services.

## Disclaimer

This is an independent re-implementation written for interoperability and maintenance purposes. It is
not affiliated with Sordum or BlueLife, and it contains no code from the original AutoIt script. Use at
your own risk.
