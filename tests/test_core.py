"""Tests for the Defender Control reimplementation.

The tests mock the low-level operations module so they run on any OS
(no registry/service calls are made against the real machine).
"""

from __future__ import annotations

import importlib
import sys
import types
from unittest import mock

import pytest

import defender_control.core as core
import defender_control.service_catalog as cat


def _fake_ops() -> types.ModuleType:
    """Build a fake ``operations`` module with recorded calls."""
    fake = types.ModuleType("defender_control.operations")

    fake.stop_service = mock.Mock(return_value=True)
    fake.start_service = mock.Mock(return_value=True)
    fake.service_exists = mock.Mock(return_value=True)
    fake.set_service_start = mock.Mock(return_value=True)
    fake.query_service_state = mock.Mock(return_value="RUNNING")
    fake.query_service_start = mock.Mock(return_value=2)
    fake.kill_processes = mock.Mock()
    fake.set_sz = mock.Mock(return_value=True)
    fake.set_binary = mock.Mock(return_value=True)
    fake.set_dword = mock.Mock(return_value=True)
    fake.delete_value = mock.Mock(return_value=True)
    fake.delete_key_tree = mock.Mock(return_value=True)
    fake.write_many_dwords = mock.Mock(return_value=1)
    fake.read_dword = mock.Mock(return_value=1)
    fake.read_sz = mock.Mock(return_value=None)
    fake.REG_SZ = 1
    fake.REG_DWORD = 4
    fake.REG_BINARY = 3
    return fake


@pytest.fixture()
def ops(monkeypatch):
    fake = _fake_ops()
    fake_kill = fake.kill_processes
    fake_svc = fake.service_exists
    monkeypatch.setattr(core, "ops", fake)
    monkeypatch.setattr(core, "cat", cat)
    return fake


def test_disable_order(ops):
    rep = core.disable_defender(kill_processes=True)
    stops = [c.args[0] for c in ops.stop_service.call_args_list]
    assert "wscsvc" in stops
    assert "WinDefend" in stops
    # security center must be stopped before winDefend
    assert stops.index("wscsvc") < stops.index("WinDefend")
    # every Defender service was attempted to be disabled
    for name, _ in cat.PRIMARY_SERVICES:
        assert name in stops
    # IFEO blocks have been written
    assert ops.set_sz.call_count == len(cat.IFEO_BLOCKS)
    # Start values set to disabled(4)
    for (name, val), kw in ops.set_service_start.call_args_list:
        assert val == 4
    assert rep.action == "disable"


def test_enable_calls(ops):
    rep = core.enable_defender()
    assert ops.delete_key_tree.call_count == len(cat.POLICY_PATHS_TO_DELETE)
    for (path, name), kw in ops.delete_value.call_args_list:
        assert path.startswith("SOFTWARE")
    # restore start values to originals
    start_vals = [kw for c, kw in [(c, c.args[1]) for c in ops.set_service_start.call_args_list]]
    for name, orig in cat.PRIMARY_SERVICES:
        assert orig in start_vals
    assert rep.action == "enable"


def test_status_shape(ops):
    st = core.get_status()
    assert set(st) >= {"disable_antispyware", "disable_realtime", "defender_likely_disabled", "services"}
    assert isinstance(st["services"], dict)


def test_disable_reports_warning_on_svc_missing(ops):
    ops.service_exists = mock.Mock(return_value=False)
    rep = core.disable_defender()
    # should not crash when no service exists
    assert rep.action == "disable"


def test_catalog_consistency():
    # All IFEO exes referenced in catalog
    assert "msmpeng.exe" in cat.IFEO_BLOCKS
    # Startup entries exist
    assert "SecurityHealth" in cat.STARTUP_BLOCKED_ENTRIES
    # Primary services must be present
    names = [n for n, _ in cat.PRIMARY_SERVICES]
    assert "WinDefend" in names and "Wscsvc" in names
    # Policy paths non-empty
    assert len(cat.POLICY_DISABLE_VALUES) > 0
    assert len(cat.DIRECT_DISABLE_VALUES) > 0