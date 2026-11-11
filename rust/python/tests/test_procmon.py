"""py-procmon: the monitor on a snapshot file (nothing of this machine is read), matched read-only."""

from __future__ import annotations

import sys

import pytest

from secmonk_modules.client import ModuleClient

from . import contracts
from .dbfactory import FIX

SNAP = str(FIX / "collectors/process/snapshot.json")


@pytest.fixture
def procmon(env, grant):
    with ModuleClient("py-procmon", env=env, grants={"db_read": grant},
                      settings={"process": {"target": SNAP, "options": []}, "min_confidence": 0.5}) as c:
        yield c


def test_payload_watch_inventory(procmon):
    p = procmon.call("procmon.payload", {"refresh": True})
    contracts.check("api/processes.schema.json", p)
    assert p["source"] == "snapshot" and p["matched"] is True and p["processes"]
    w1 = procmon.call("procmon.watch", {})
    assert w1["baseline"] is True and w1["events"] == []
    w2 = procmon.call("procmon.watch", {})
    assert w2["baseline"] is False and w2["events"] == []        # the same snapshot: nothing new
    contracts.check("api/watch.schema.json", w2)
    inv = procmon.call("procmon.inventory", {})["inventory"]
    contracts.check("inventory/inventory.schema.json", inv)
    assert inv["classified"] is True and inv["asset"]["id"] == p["asset"]


def test_without_a_database_it_still_answers_unmatched(env):
    with ModuleClient("py-procmon", env=env, settings={"process": {"target": SNAP}}) as c:
        p = c.call("procmon.payload", {})
        assert p["matched"] is False and p["processes"]


def test_a_snapshot_that_is_not_there_is_a_collect_error(env, grant, tmp_path):
    with ModuleClient("py-procmon", env=env, grants={"db_read": grant},
                      settings={"process": {"target": str(tmp_path / "nope.json")}}) as c:
        e = c.request("procmon.payload", {}).error
        assert e["code"] == "collect-error" and "Traceback" not in e["error"]


def test_snapshot_out_is_ignored(env, grant, tmp_path):
    out = tmp_path / "out.json"
    with ModuleClient("py-procmon", env=env, grants={"db_read": grant},
                      settings={"process": {"target": SNAP, "options": [f"snapshot_out={out}"]}}) as c:
        c.call("procmon.payload", {"refresh": True})
    assert not out.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="live snapshots exist on macOS and Linux")
def test_live_snapshot_is_unsupported_on_windows(env, grant):
    with ModuleClient("py-procmon", env=env, grants={"db_read": grant}) as c:
        assert c.request("procmon.payload", {}).error["code"] == "unsupported-platform"
