"""Unified entry point for the frozen (PyInstaller) Defender Control build.

Behaviour:
  * ``dControl.exe``              -> GUI (matches the original dControl.exe)
  * ``dControl.exe disable``      -> runs the action, reports via message box
  * ``dcontrol-cli.exe status``   -> normal console CLI

The GUI executable is built with a ``requireAdministrator`` manifest, so it is
already elevated when it starts (same as the original binary).
"""

from __future__ import annotations

import sys

ACTIONS = ("status", "disable", "enable")


def _run_cli(argv: list[str]) -> int:
    from defender_control.cli import main as cli_main

    return cli_main(argv)


def _run_gui() -> int:
    import gui

    gui.main()
    return 0


def _run_windowed_action(argv: list[str]) -> int:
    """Execute an action without a console and report the result in a dialog."""
    import tkinter as tk
    from tkinter import messagebox

    from defender_control import core
    from defender_control import operations as ops

    action = argv[0].lower()

    if action != "status" and not ops.is_admin():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Defender Control",
            "Administrator privileges are required.\n\n"
            "Run the program as Administrator.",
        )
        root.destroy()
        return 1

    try:
        if action == "status":
            import json

            body = json.dumps(core.get_status(), indent=2)
            title = "Defender Control - status"
        else:
            rep = core.disable_defender() if action == "disable" else core.enable_defender()
            body = "\n".join(f"- {s}" for s in rep.steps)
            title = f"Defender Control - {action}"
    except Exception as exc:  # pragma: no cover - defensive
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Defender Control", f"Operation failed:\n{exc}")
        root.destroy()
        return 1

    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(title, body[:4000])
    root.destroy()
    return 0


def main() -> int:
    argv = sys.argv[1:]

    if argv and argv[0].lower() in ACTIONS:
        # Windowed builds have no stdout; fall back to a message box.
        if sys.stdout is None:
            return _run_windowed_action(argv)
        return _run_cli(argv)

    return _run_gui()


if __name__ == "__main__":
    raise SystemExit(main())