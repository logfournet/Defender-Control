"""Core orchestration: disable / enable Windows Defender.

The sequence follows the documented behaviour of Sordum "Defender Control" v2.1
(see the official repair guide, points 4-8) and mirrors the order used by
Defender-control tools: security centre first, then the Defender service family,
registry/policy writes, IFEO blocks, service start values, and finally restart the
security centre.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from . import operations as ops
from . import service_catalog as cat

log = logging.getLogger("defender_control.core")


@dataclass
class Report:
    """Summary of what a disable/enable run attempted."""
    action: str
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def step(self, msg: str) -> None:
        self.steps.append(msg)
        log.info(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        log.warning(msg)


# ---------------------------------------------------------------------------
# Disable
# ---------------------------------------------------------------------------
def disable_defender(kill_processes: bool = True) -> Report:
    rep = Report(action="disable")

    # 1. Stop the Security Center first (so it cannot restart Defender).
    rep.step("Stopping Security Center (wscsvc)…")
    ops.stop_service(cat.SECURITY_CENTER_SERVICE)

    # 2. Stop the Defender service family (WinDefend first, then the rest).
    for name, _start in cat.PRIMARY_SERVICES:
        if ops.service_exists(name):
            rep.step(f"Stopping service {name}…")
            ops.stop_service(name)
    for name, _start in cat.DEFENDER_SERVICES:
        if ops.service_exists(name):
            ops.stop_service(name)

    # 3. Kill remaining Defender processes so the engine can be replaced/blocked.
    if kill_processes:
        rep.step("Terminating Defender processes…")
        ops.kill_processes(cat.DEFENDER_PROCESSES)

    # 4. Group-policy + direct registry values.
    rep.step("Writing Group Policy registry values…")
    written = ops.write_many_dwords(cat.POLICY_DISABLE_VALUES)
    rep.step(f"  wrote {written} policy values")

    rep.step("Writing direct Windows Defender registry values…")
    ops.write_many_dwords(cat.DIRECT_DISABLE_VALUES)

    # 5. Neutralise Defender command-line tools via IFEO.
    rep.step("Adding IFEO blocks for Defender tools…")
    for exe, debugger in cat.IFEO_BLOCKS.items():
        ops.set_sz(f"{cat.REG_IFEO}\\{exe}", "Debugger", debugger)

    # 6. Stop SecurityHealth from starting with Windows.
    rep.step("Disabling SecurityHealth auto-start…")
    for entry in cat.STARTUP_BLOCKED_ENTRIES:
        # 03 00 ... = disabled in StartupApproved
        ops.set_binary(cat.REG_STARTUP_APPROVED, entry, b"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

    # 7. Set service start values to Disabled (4).  ->  The Security Center
    # (wscsvc) is only stopped temporarily; it must stay auto-start so the
    # Windows Security tray icon keeps working while Defender is off.
    rep.step("Setting Defender service start values to Disabled…")
    for name, _orig in (*cat.PRIMARY_SERVICES, *cat.DEFENDER_SERVICES):
        if name.lower() == cat.SECURITY_CENTER_SERVICE.lower():
            continue
        if ops.service_exists(name):
            ops.set_service_start(name, 4)

    # 8. Restart Security Center if it is not running.
    if ops.query_service_state(cat.SECURITY_CENTER_SERVICE) != "RUNNING":
        rep.step("Restarting Security Center (wscsvc)…")
        ops.start_service(cat.SECURITY_CENTER_SERVICE)

    rep.step("Done. A reboot is recommended for full effect.")
    return rep


# ---------------------------------------------------------------------------
# Enable
# ---------------------------------------------------------------------------
def enable_defender(kill_processes: bool = False) -> Report:
    rep = Report(action="enable")

    # 1. Remove IFEO blocks.
    rep.step("Removing IFEO blocks…")
    for exe in cat.IFEO_BLOCKS:
        ops.delete_value(f"{cat.REG_IFEO}\\{exe}", "Debugger")

    # 2. Clear the direct DisableAntiSpyware / RTP values.
    rep.step("Clearing direct Windows Defender registry values…")
    for path, values in cat.DIRECT_DISABLE_VALUES.items():
        for name in values:
            ops.delete_value(path, name)

    # 3. Delete the whole group-policy subkeys that were created.
    rep.step("Removing Group Policy keys…")
    for path in cat.POLICY_PATHS_TO_DELETE:
        ops.delete_key_tree(path)
    # reset the root DisableAntiSpyware rather than deleting the root key
    ops.set_dword(cat.REG_POLICY_DEFENDER, "DisableAntiSpyware", 0)
    ops.delete_value(cat.REG_POLICY_DEFENDER, "DisableRoutinelyTakingAction")

    # 4. Restore SecurityHealth auto-start.
    rep.step("Restoring SecurityHealth auto-start…")
    for entry in cat.STARTUP_BLOCKED_ENTRIES:
        ops.delete_value(cat.REG_STARTUP_APPROVED, entry)

    # 5. Restore service start values to their original state.
    rep.step("Restoring Defender service start values…")
    for name, orig_start in (*cat.PRIMARY_SERVICES, *cat.DEFENDER_SERVICES):
        if ops.service_exists(name):
            ops.set_service_start(name, orig_start)

    # 6. Start the Security Center and the primary Defender service.
    rep.step("Starting Security Center (wscsvc)…")
    ops.start_service(cat.SECURITY_CENTER_SERVICE)
    if ops.service_exists("WinDefend"):
        rep.step("Starting Windows Defender (WinDefend)…")
        ops.start_service("WinDefend")

    rep.step("Done. A reboot is recommended.")
    return rep


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
def get_status() -> dict:
    """Return a read-only snapshot of the current Defender control state."""
    svc: dict[str, dict[str, object]] = {}
    for name, _ in (*cat.PRIMARY_SERVICES, *cat.DEFENDER_SERVICES):
        if ops.service_exists(name):
            svc[name] = {
                "state": ops.query_service_state(name),
                "start": ops.query_service_start(name),
            }

    policy_das = ops.read_dword(cat.REG_POLICY_DEFENDER, "DisableAntiSpyware")
    direct_das = ops.read_dword(cat.REG_DEFENDER, "DisableAntiSpyware")
    rtp = ops.read_dword(cat.REG_DEFENDER_RTP, "DisableRealtimeMonitoring")

    # A machine is considered "disabled" primarily from the authoritative
    # WinDefend service state: it must be STOPPED *and* its start type DISABLED.
    # Only when service info is unavailable do we fall back to the registry
    # heuristic (Group-Policy DisableAntiSpyware + real-time monitoring off).
    win = svc.get("WinDefend") or {}
    policy_off = policy_das == 1 and rtp == 1
    if win.get("state") is not None:
        likely_disabled = win.get("state") == "STOPPED" and win.get("start") == 4
    else:
        likely_disabled = policy_off

    return {
        "disable_antispyware": policy_das,
        "disable_antispyware_direct": direct_das,
        "disable_realtime": rtp,
        "policy_disabled": bool(policy_off),
        "winDefend_state": win.get("state"),
        "winDefend_start": win.get("start"),
        "defender_likely_disabled": bool(likely_disabled),
        "services": svc,
    }