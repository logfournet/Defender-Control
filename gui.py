#!/usr/bin/env python3
"""Tkinter GUI for Defender Control.

Layout mirrors the original dControl.exe: a status line, Disable / Enable /
Check-status buttons and shortcut buttons to the Windows Security pages.

Design notes
------------
* All slow work (``sc query``, registry reads, service control) runs on a worker
  thread; the UI only touches Tk through a queue drained by ``after()``.
* The frozen ``dControl.exe`` is built with a ``requireAdministrator`` manifest,
  so it is already elevated. When running from source the GUI re-launches itself
  through UAC with ``--auto <action>`` so the user's click is resumed elevated.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from defender_control import __version__
from defender_control import core
from defender_control import operations as ops

APP_TITLE = "Defender Control"
ACTIONS = ("disable", "enable")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _enable_dpi_awareness() -> None:
    """Opt into per-monitor DPI so the window is not blurry on scaled displays."""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # pragma: no cover - best effort only
        pass


def _asset_path(name: str) -> str:
    """Resolve a bundled asset for both source runs and frozen builds."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidate = os.path.join(base, "assets", name)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", name)


def _parse_auto_action(argv: list[str]) -> str | None:
    """Return the action passed by the elevated relaunch, if any."""
    args = list(argv)
    for i, arg in enumerate(args):
        if arg == "--auto" and i + 1 < len(args):
            value = args[i + 1].lower()
            return value if value in ACTIONS else None
        if arg.startswith("--auto="):
            value = arg.split("=", 1)[1].lower()
            return value if value in ACTIONS else None
    # Allow ``gui.py disable`` / ``dControl.exe disable`` style invocation too.
    for arg in args:
        if arg.lower() in ACTIONS:
            return arg.lower()
    return None


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self, autostart: str | None = None) -> None:
        super().__init__()
        self.title(f"{APP_TITLE} {__version__}")
        self.minsize(520, 380)
        self.geometry("560x420")
        self._q: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._busy = False
        self._elevated = ops.is_admin()

        self._set_window_icon()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.after(60, self._drain_queue)
        self.refresh_status()

        if autostart in ACTIONS:
            # Resume the click that triggered the UAC prompt.
            self.after(250, lambda: self._run(autostart, confirm=False))

    # -- UI construction ---------------------------------------------------
    def _set_window_icon(self) -> None:
        icon = _asset_path("dcontrol.ico")
        if os.path.exists(icon):
            try:
                self.iconbitmap(default=icon)
            except Exception:  # pragma: no cover - icon is cosmetic
                pass

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 9), foreground="#555555")
        style.configure("Status.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Detail.TLabel", font=("Segoe UI", 9), foreground="#444444")

        root = ttk.Frame(self, padding=(16, 14, 16, 12))
        root.pack(fill="both", expand=True)

        ttk.Label(root, text="Windows Defender Control", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            root,
            text="Disable or enable Microsoft Defender on this machine.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(0, 12))

        card = ttk.LabelFrame(root, text="Status", padding=(12, 8))
        card.pack(fill="x")

        self.status_var = tk.StringVar(value="Checking…")
        self.status_lbl = ttk.Label(card, textvariable=self.status_var, style="Status.TLabel")
        self.status_lbl.pack(anchor="w")

        self.detail_var = tk.StringVar(value="")
        ttk.Label(card, textvariable=self.detail_var, style="Detail.TLabel").pack(
            anchor="w", pady=(4, 0)
        )

        self.priv_var = tk.StringVar(value="")
        ttk.Label(card, textvariable=self.priv_var, style="Detail.TLabel").pack(anchor="w")

        btns = ttk.Frame(root)
        btns.pack(fill="x", pady=(14, 6))

        self.btn_disable = ttk.Button(
            btns, text="Disable Defender", command=lambda: self._run("disable")
        )
        self.btn_disable.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        self.btn_enable = ttk.Button(
            btns, text="Enable Defender", command=lambda: self._run("enable")
        )
        self.btn_enable.grid(row=0, column=1, padx=(0, 8), sticky="ew")

        self.btn_status = ttk.Button(btns, text="Check status", command=self.refresh_status)
        self.btn_status.grid(row=0, column=2, sticky="ew")

        for col in range(3):
            btns.columnconfigure(col, weight=1)

        links = ttk.Frame(root)
        links.pack(fill="x", pady=(0, 10))
        self.btn_security = ttk.Button(
            links,
            text="Windows Security",
            command=lambda: self._open_uri("windowsdefender://"),
        )
        self.btn_security.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        self.btn_settings = ttk.Button(
            links,
            text="Defender settings",
            command=lambda: self._open_uri("ms-settings:windowsdefender"),
        )
        self.btn_settings.grid(row=0, column=1, sticky="ew")
        for col in range(2):
            links.columnconfigure(col, weight=1)

        log_frame = ttk.LabelFrame(root, text="Log", padding=(8, 6))
        log_frame.pack(fill="both", expand=True)

        self.log = tk.Text(
            log_frame, height=6, wrap="word", state="disabled",
            font=("Consolas", 9), relief="flat", borderwidth=0,
        )
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

        self._log("Ready.")
        if not self._elevated:
            self._log("Not running elevated: enable/disable will request UAC.")

    # -- helpers -----------------------------------------------------------
    def _log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _open_uri(self, uri: str) -> None:
        try:
            os.startfile(uri)  # type: ignore[attr-defined]
        except Exception:
            try:
                os.startfile("ms-settings:windowsdefender")  # type: ignore[attr-defined]
            except Exception as exc:  # pragma: no cover
                messagebox.showerror(APP_TITLE, f"Cannot open {uri}:\n{exc}")

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for btn in (
            self.btn_disable, self.btn_enable, self.btn_status,
            self.btn_security, self.btn_settings,
        ):
            btn.configure(state=state)
        self.configure(cursor="watch" if busy else "")

    # -- status ------------------------------------------------------------
    def refresh_status(self) -> None:
        if self._busy:
            return
        self._set_busy(True)
        self.status_var.set("Checking…")
        self.detail_var.set("")
        threading.Thread(target=self._status_worker, daemon=True).start()

    def _status_worker(self) -> None:
        try:
            self._q.put(("status", core.get_status()))
        except Exception as exc:  # pragma: no cover - defensive
            self._q.put(("error", f"Status check failed:\n{exc}"))
        finally:
            self._q.put(("idle", None))

    def _apply_status(self, st: dict) -> None:
        disabled = bool(st.get("defender_likely_disabled"))
        self.status_var.set(
            "Defender appears DISABLED" if disabled else "Defender appears ENABLED"
        )
        self.status_lbl.configure(foreground="#c00000" if disabled else "#0a7d00")

        state = st.get("winDefend_state") or "unknown"
        start = st.get("winDefend_start")
        start_name = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}.get(
            start, "unknown"
        )
        self.detail_var.set(
            f"WinDefend: {state.lower()} · start: {start_name} · "
            f"policy DisableAntiSpyware: {st.get('disable_antispyware')}"
        )
        self.priv_var.set(
            "Running as Administrator."
            if self._elevated
            else "Not elevated — read-only checks only."
        )

    # -- actions -----------------------------------------------------------
    def _run(self, action: str, confirm: bool = True) -> None:
        if self._busy:
            return

        if not ops.is_admin():
            if not messagebox.askyesno(
                APP_TITLE,
                "Administrator rights are required.\n\nElevate now?",
            ):
                return
            args = ["--auto", action]
            if not ops.relaunch_admin(None, args):
                messagebox.showerror(APP_TITLE, "Elevation was cancelled or failed.")
            else:
                self.destroy()
            return

        if confirm:
            verb = "DISABLE" if action == "disable" else "ENABLE"
            warning = (
                "\n\nWARNING: disabling Windows Defender leaves this machine "
                "without antivirus protection."
                if action == "disable"
                else ""
            )
            if not messagebox.askyesno(
                APP_TITLE, f"Are you sure you want to {verb} Windows Defender?{warning}"
            ):
                return

        self._set_busy(True)
        self.status_var.set(f"Working: {action}…")
        self._log(f"--- {action} requested ---")
        threading.Thread(target=self._action_worker, args=(action,), daemon=True).start()

    def _action_worker(self, action: str) -> None:
        try:
            rep = core.disable_defender() if action == "disable" else core.enable_defender()
            for step in rep.steps:
                self._q.put(("log", step))
            for warning in rep.warnings:
                self._q.put(("log", f"WARNING: {warning}"))
            self._q.put(("done", action))
        except Exception as exc:  # pragma: no cover - defensive
            self._q.put(("error", f"{action} failed:\n{exc}"))
        finally:
            self._q.put(("idle", None))

    # -- queue pump --------------------------------------------------------
    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "log":
                    self._log(str(payload))
                elif kind == "status":
                    self._apply_status(payload)  # type: ignore[arg-type]
                elif kind == "done":
                    self._log(f"--- {payload} finished; a reboot is recommended ---")
                    self.refresh_status()
                elif kind == "error":
                    self._log(f"ERROR: {payload}")
                    messagebox.showerror(APP_TITLE, str(payload))
                elif kind == "idle":
                    if self._busy:
                        self._set_busy(False)
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    def _on_close(self) -> None:
        if self._busy and not messagebox.askyesno(
            APP_TITLE, "An operation is still running. Close anyway?"
        ):
            return
        self.destroy()


# ---------------------------------------------------------------------------
def main() -> None:
    _enable_dpi_awareness()
    app = App(autostart=_parse_auto_action(sys.argv[1:]))
    app.mainloop()


if __name__ == "__main__":
    main()
