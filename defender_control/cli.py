"""Command-line interface for the Defender Control reimplementation."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from . import __version__
from . import core
from . import operations as ops


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
    )


def _print_report(rep: core.Report) -> None:
    print(f"\n== {rep.action.upper()} ==")
    for step in rep.steps:
        print(f"  • {step}")
    if rep.warnings:
        print("\n  Warnings:")
        for w in rep.warnings:
            print(f"    ⚠ {w}")


def _ensure_admin(argv: list[str], no_elevate: bool) -> bool:
    """Ensure we are elevated. Returns True if we may continue running the action."""
    if ops.is_admin():
        return True
    if no_elevate:
        print("ERROR: this action requires Administrator privileges.", file=sys.stderr)
        print("       Re-run from an elevated prompt.", file=sys.stderr)
        return False

    print("Requesting Administrator privileges (UAC)…")
    if ops.is_frozen():
        # Frozen build: relaunch this executable with the same arguments.
        ok = ops.relaunch_admin(None, argv)
    else:
        script = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "defender_control.py")
        )
        ok = ops.relaunch_admin(script, argv)
    if ok:
        print("An elevated window was launched. Complete the action there.")
    else:
        print("Elevation was cancelled or failed.", file=sys.stderr)
    # The original raised process handles the action; this one exits.
    return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="defender_control",
        description="Reimplementation of Sordum Defender Control v2.1 (Python).",
    )
    p.add_argument("--version", action="version", version=f"defender-control {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose logging")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show current Defender control state (read-only)")

    pd = sub.add_parser("disable", help="disable Windows Defender")
    pd.add_argument("--no-elevate", action="store_true", help="do not attempt UAC elevation")
    pd.add_argument("--keep-processes", action="store_true",
                    help="do not kill Defender processes")

    pe = sub.add_parser("enable", help="enable Windows Defender")
    pe.add_argument("--no-elevate", action="store_true", help="do not attempt UAC elevation")

    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    _configure_logging(args.verbose)

    if args.command == "status":
        print(json.dumps(core.get_status(), indent=2))
        return 0

    if not _ensure_admin(argv, getattr(args, "no_elevate", False)):
        return 1

    if args.command == "disable":
        rep = core.disable_defender(kill_processes=not args.keep_processes)
        _print_report(rep)
        return 0

    if args.command == "enable":
        rep = core.enable_defender()
        _print_report(rep)
        return 0

    return 2