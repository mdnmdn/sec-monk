from __future__ import annotations

from . import contracts


def test_store_builds(grant):
    import sqlite3

    c = sqlite3.connect(grant["state"])
    assert c.execute("select count(*) from finding").fetchone()[0] >= 1, "log4j finding expected"


def test_probe_fs(probe):
    from .conftest import FIX

    r = probe.request("collector.collect", {"collector": "fs", "target": str(FIX / "lang/javascript/npm-v3"),
                                            "options": []}).ok()
    assert r.items[0]["kind"] == "asset"
    for it in r.items:
        contracts.check("inventory/collect-item.schema.json", it)
