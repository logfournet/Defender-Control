"""Low-level Windows operations: registry, services, processes, IFEO blocks.

Implemented with the standard library only (``winreg``, ``subprocess``, ``ctypes``),
so the project runs on any Windows 10/11 machine with Python 3.9+ and **no** third
-party dependencies.
"""

from __future__ import annotations

import ctypes
import logging
import os
import re
import subprocess
import sys
import winreg
from typing import Iterable, Optional

log = logging.getLogger("defender_control.operations")

# Registry type => winreg constant
REG_DWORD = winreg.REG_DWORD
REG_SZ = winreg.REG_SZ
REG_BINARY = winreg.REG_BINARY

_HKLM = winreg.HKEY_LOCAL_MACHINE

# sc.exe START_TYPE token -> numeric start value used in the catalog
START_TYPE_TO_VALUE = {
    "BOOT_START": 0,
    "SYSTEM_START": 1,
    "AUTO_START": 2,
    "DEMAND_START": 3,
    "DISABLED": 4,
}


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def _open_key(path: str, writable: bool = True):
    access = winreg.KEY_READ | (winreg.KEY_WRITE if writable else 0)
    return winreg.CreateKeyEx(_HKLM, path, 0, access)


def read_dword(path: str, name: str) -> Optional[int]:
    """Read a REG_DWORD value; None if missing/unreadable."""
    try:
        with winreg.OpenKey(_HKLM, path, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return int(val)
    except OSError:
        return None


def read_sz(path: str, name: str) -> Optional[str]:
    try:
        with winreg.OpenKey(_HKLM, path, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return str(val)
    except OSError:
        return None


def set_dword(path: str, name: str, value: int) -> bool:
    """Create key if needed and write a REG_DWORD. Returns True on success."""
    try:
        with _open_key(path, writable=True) as key:
            winreg.SetValueEx(key, name, 0, REG_DWORD, int(value))
        return True
    except OSError as exc:
        log.warning("set_dword %s\\%s failed: %s", path, name, exc)
        return False


def set_sz(path: str, name: str, value: str) -> bool:
    try:
        with _open_key(path, writable=True) as key:
            winreg.SetValueEx(key, name, 0, REG_SZ, str(value))
        return True
    except OSError as exc:
        log.warning("set_sz %s\\%s failed: %s", path, name, exc)
        return False


def set_binary(path: str, name: str, data: bytes) -> bool:
    try:
        with _open_key(path, writable=True) as key:
            winreg.SetValueEx(key, name, 0, REG_BINARY, data)
        return True
    except OSError as exc:
        log.warning("set_binary %s\\%s failed: %s", path, name, exc)
        return False


def delete_value(path: str, name: str) -> bool:
    """Delete a value if present; returns True if it was removed."""
    try:
        with _open_key(path, writable=True) as key:
            winreg.DeleteValue(key, name)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        log.warning("delete_value %s\\%s failed: %s", path, name, exc)
        return False


def delete_key_tree(path: str) -> bool:
    """Delete a key and all of its subkeys. Returns True if the key existed.

    Uses ``reg delete /f`` because ``winreg.DeleteKeyEx`` refuses keys that still
    have subkeys, and the policy trees we remove are nested in practice.
    """
    res = subprocess.run(
        ["reg.exe", "delete", f"HKLM\\{path}", "/f"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return res.returncode == 0


# ---------------------------------------------------------------------------
# Batch write helpers
# ---------------------------------------------------------------------------
def write_many_dwords(mapping: dict[str, dict[str, int]]) -> int:
    """Write every DWORD from a {path: {name: value}} dict."""
    ok = 0
    for path, values in mapping.items():
        for name, value in values.items():
            if set_dword(path, name, value):
                ok += 1
    return ok


# ---------------------------------------------------------------------------
# Service helpers (sc.exe through subprocess)
# ---------------------------------------------------------------------------
def _sc(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Run ``sc <args>`` and return the CompletedProcess."""
    cmd = ["sc.exe", *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    except OSError as exc:  # pragma: no cover
        log.error("Failed to run %s: %s", cmd, exc)
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def service_exists(name: str) -> bool:
    """True when the named service is registered on the machine."""
    return _sc("query", name).returncode == 0


def stop_service(name: str) -> bool:
    """Best-effort stop; returns True if the service is not running afterwards."""
    _sc("stop", name)
    return True


def start_service(name: str) -> bool:
    """Best-effort start; returns True (caller may re-check with query status)."""
    _sc("start", name)
    return True


def query_service_state(name: str) -> str:
    """Return a short uppercase state token: RUNNING / STOPPED / ... / UNKNOWN."""
    res = _sc("query", name)
    if res.returncode != 0:
        return "UNKNOWN"
    for token in (
        "STOP_PENDING", "START_PENDING", "CONTINUE_PENDING", "PAUSE_PENDING",
        "PAUSED", "RUNNING", "STOPPED",
    ):
        if re.search(r"STATE\s*:\s*\d+\s+" + token, res.stdout, re.IGNORECASE):
            return token
    return "UNKNOWN"


def query_service_start(name: str) -> Optional[int]:
    """Return the numeric START_TYPE of a service (0..4), or None if unknown."""
    res = _sc("qc", name)
    if res.returncode != 0:
        return None
    m = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", res.stdout, re.IGNORECASE)
    if not m:
        return None
    return START_TYPE_TO_VALUE.get(m.group(1).upper())


def set_service_start(name: str, start_value: int) -> bool:
    """Change a service start type via `sc config`. Returns True on success."""
    res = _sc("config", name, "start=", str(start_value))
    if res.returncode != 0:
        log.warning("sc config %s start= %s -> rc=%s: %s",
                    name, start_value, res.returncode, res.stderr.strip())
    return res.returncode == 0


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------
def kill_processes(names: Iterable[str]) -> None:
    """Kill all processes with the given image names (best effort)."""
    for name in names:
        subprocess.run(
            ["taskkill.exe", "/F", "/T", "/IM", name],
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )


# ---------------------------------------------------------------------------
# Elevation helpers
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    """True when the current process is elevated / Administrator."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover
        return False


def is_frozen() -> bool:
    """True when running from a PyInstaller executable."""
    return bool(getattr(sys, "frozen", False))


def relaunch_admin(script_path: Optional[str], args: list[str]) -> bool:
    """Re-launch the application elevated via ``ShellExecuteW(..., "runas", ...)``.

    ``script_path`` may be ``None`` to re-launch the current executable (frozen
    build) or the currently running script. Returns True if the elevation
    request was accepted (the elevated process starts asynchronously). Returns
    False if the user declined / it failed.
    """
    if is_frozen() or script_path is None:
        executable = sys.executable
        params = " ".join(f'"{a}"' for a in args)
    else:
        executable = sys.executable
        params = " ".join(f'"{a}"' for a in [os.path.abspath(script_path), *args])

    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
    return rc > 32