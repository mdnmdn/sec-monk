"""MSRC CVRF v3 source. The fixture is SYNTHETIC (API blocked); the builds follow the real CNA record."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from secmonk.collectors import windows as w
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.sources import msrc
from secmonk.sources.base import REGISTRY, SyncOptions

ROOT = Path(__file__).parents[1] / "fixtures"
CVRF = ROOT / "sources" / "msrc" / "cvrf-2024-Aug.synthetic.json"
WIN11 = ROOT / "collectors" / "windows" / "inventory-win11.json"
SERVER = ROOT / "collectors" / "windows" / "inventory-server2022.json"


def test_registered():
    assert REGISTRY["msrc"] is msrc.MsrcSource


def test_normalize_product_name():
    n = msrc.normalize_product_name
    assert n("Windows 11 Version 23H2 for x64-based Systems") == "windows 11 version 23h2"
    assert n("Windows 11 Version 23H2 for ARM64-based Systems") == "windows 11 version 23h2"
    assert n("Windows 10 Version 22H2 for 32-bit Systems") == "windows 10 version 22h2"
    assert n("Windows Server 2022 (Server Core installation)") == "windows server 2022"
    assert n("Windows Server 2022") == "windows server 2022"
    assert n("Windows Server, version 23H2 (Server Core installation)") == \
        "windows server 2022, 23h2 edition (server core installation)"


def test_import(conn):
    n = msrc.import_cvrf(conn, json.loads(CVRF.read_text()))
    assert n == 2
    v = conn.execute("SELECT * FROM vulnerability WHERE source='msrc' AND id='CVE-2024-38063'").fetchone()
    assert v["cvss_score"] == 9.8 and v["severity"] == "CRITICAL" and v["cvss_version"] == "3.1"
    assert json.loads(v["extra"])["kbs"] == ["KB5041160", "KB5041573", "KB5041580", "KB5041585"]
    rows = conn.execute("SELECT * FROM affected WHERE source='msrc' AND vuln_id='CVE-2024-38063' ORDER BY product"
                        ).fetchall()
    # arch variants and the Server Core product collapse into one row per product + fixed build
    assert [r["product"] for r in rows] == [
        "windows 10 version 22h2", "windows 11 version 23h2", "windows server 2022",
        "windows server 2022, 23h2 edition (server core installation)"]
    r = rows[1]
    assert r["vendor"] == "microsoft" and r["range_type"] == "CVE"
    assert json.loads(r["events"]) == [{"introduced": "0"}, {"fixed": "10.0.22631.4037"}]
    extra = json.loads(r["extra"])
    assert extra["kb"] == ["KB5041585"] and extra["product_ids"] == ["12086", "12087"]
    # Office click-to-run has no FixedBuild: vulnerability stored, no affected row
    assert conn.execute("SELECT COUNT(*) FROM affected WHERE vuln_id='CVE-2024-38172'").fetchone()[0] == 0
    # re-import is idempotent
    msrc.import_cvrf(conn, json.loads(CVRF.read_text()))
    assert conn.execute("SELECT COUNT(*) FROM affected WHERE source='msrc'").fetchone()[0] == 4


def test_sync_path_and_e2e(conn):
    res = msrc.MsrcSource().sync(conn, SyncOptions(path=CVRF))
    assert res.status == "ok" and res.records == 2 and res.cursor == "2024-08-14T07:00:00Z"
    for fixture, name, fixed in ((WIN11, "Windows 11 Version 23H2", "10.0.22631.4037"),
                                 (SERVER, "Windows Server 2022", "10.0.20348.2700")):
        inv = w.parse_inventory_json(w.load_json_file(fixture))
        save_inventory(conn, inv)
        match_asset(conn, inv.asset.id)
        row = conn.execute(
            """SELECT f.matched_by, f.fixed_version FROM finding f JOIN component c ON c.id=f.component_id
               WHERE f.asset_id=? AND c.name=? AND f.vuln_id='CVE-2024-38063'""", (inv.asset.id, name)).fetchone()
        assert row is not None and row["matched_by"] == "cve-product" and row["fixed_version"] == fixed


def test_sync_missing_path(conn, tmp_path):
    assert msrc.MsrcSource().sync(conn, SyncOptions(path=tmp_path / "nope")).status == "error"


def test_sync_download(conn, monkeypatch):
    doc = json.loads(CVRF.read_text())

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/updates"):
            return httpx.Response(200, json={"value": [
                {"ID": "2024-Aug", "CurrentReleaseDate": "2024-08-14T07:00:00Z",
                 "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Aug"}]})
        assert req.headers["accept"] == "application/json"
        return httpx.Response(200, json=doc)

    monkeypatch.setattr(msrc, "http_client", lambda **kw: httpx.Client(transport=httpx.MockTransport(handler)))
    res = msrc.MsrcSource().sync(conn, SyncOptions())
    assert res.status == "ok" and res.records == 2
