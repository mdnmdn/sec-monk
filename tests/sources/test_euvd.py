"""EUVD source tests: local import, alias bridge, EPSS insert-or-ignore. No network."""

from __future__ import annotations

from pathlib import Path

from secmonk.sources import euvd
from secmonk.sources.base import SyncOptions


def test_import_fixture(conn, fixtures: Path):
    res = euvd.EuvdSource().sync(conn, SyncOptions(path=fixtures / "euvd" / "exploited-sample.json"))
    assert res.status == "ok" and res.records == 2

    vuln = conn.execute("SELECT * FROM vulnerability WHERE source='euvd' AND id='EUVD-2021-30001'").fetchone()
    assert vuln["cvss_score"] == 10
    assert vuln["cvss_version"] == "3.1"
    assert vuln["severity"] == "CRITICAL"
    assert vuln["published"] == "2021-12-10T00:00:00.000Z"
    assert '"exploited":true' in vuln["extra"]


def test_cve_alias_bridge(conn, fixtures: Path):
    euvd.EuvdSource().sync(conn, SyncOptions(path=fixtures / "euvd" / "exploited-sample.json"))
    row = conn.execute("SELECT vuln_id, alias, source FROM alias WHERE source='euvd'").fetchone()
    assert (row["vuln_id"], row["alias"]) == ("EUVD-2021-30001", "CVE-2021-44228")
    # The record without an alias stays EUVD-only.
    n = conn.execute("SELECT COUNT(*) FROM alias WHERE vuln_id='EUVD-2026-00002'").fetchone()[0]
    assert n == 0


def test_epss_inserted_only_when_absent(conn, fixtures: Path):
    conn.execute("INSERT INTO epss(cve_id, score, percentile, date, source) "
                 "VALUES ('CVE-2021-44228', 0.5, 0.6, '2026-11-05', 'epss')")
    conn.commit()
    euvd.EuvdSource().sync(conn, SyncOptions(path=fixtures / "euvd" / "exploited-sample.json"))
    row = conn.execute("SELECT score, source FROM epss WHERE cve_id='CVE-2021-44228'").fetchone()
    assert row["score"] == 0.5 and row["source"] == "epss"  # FIRST data kept


def test_epss_inserted_when_missing(conn, fixtures: Path):
    euvd.EuvdSource().sync(conn, SyncOptions(path=fixtures / "euvd" / "exploited-sample.json"))
    row = conn.execute("SELECT score, source FROM epss WHERE cve_id='CVE-2021-44228'").fetchone()
    assert row["score"] == 0.97431 and row["source"] == "euvd"


def test_response_shapes():
    rec = {"id": "EUVD-1"}
    assert euvd._items([rec]) == [rec]
    assert euvd._items({"items": [rec]}) == [rec]
    assert euvd._items({"content": [rec]}) == [rec]
