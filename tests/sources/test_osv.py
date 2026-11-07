from __future__ import annotations

import json

import pytest

from secmonk.db import get_sync_cursor, loads
from secmonk.sources import osv
from secmonk.sources.base import SyncOptions


@pytest.fixture
def osv_dir(fixtures):
    return fixtures / "osv"


def _rows(conn, vid, **where):
    q = "SELECT * FROM affected WHERE source='osv' AND vuln_id=?"
    args = [vid]
    for k, v in where.items():
        q += f" AND {k}=?"
        args.append(v)
    return conn.execute(q, args).fetchall()


def _load(osv_dir, name):
    return json.loads((osv_dir / name).read_text())


def test_import_all_fixture_jsons(conn, osv_dir):
    n = 0
    for p in sorted(osv_dir.glob("*.json")):
        assert osv.import_record(conn, json.loads(p.read_text()))
        n += 1
    conn.commit()
    assert conn.execute("SELECT count(*) FROM vulnerability WHERE source='osv'").fetchone()[0] == n


def test_zip_import_via_sync(conn, osv_dir):
    res = osv.OsvSource().sync(conn, SyncOptions(path=osv_dir / "sample-all.zip"))
    assert res.status == "ok" and res.records == 6
    assert conn.execute("SELECT count(*) FROM vulnerability").fetchone()[0] == 6
    assert res.cursor


def test_dir_and_single_file_import(conn, osv_dir):
    res = osv.OsvSource().sync(conn, SyncOptions(path=osv_dir / "go-GO-2024-2428.json"))
    assert res.records == 1
    res = osv.OsvSource().sync(conn, SyncOptions(path=osv_dir, limit=3))
    assert res.records == 3


def test_maven_log4j(conn, osv_dir):
    osv.import_record(conn, _load(osv_dir, "maven-GHSA-jfh8-c2jp-5v3q.json"))
    rows = _rows(conn, "GHSA-jfh8-c2jp-5v3q", package="org.apache.logging.log4j:log4j-core")
    assert rows and all(r["ecosystem"] == "Maven" for r in rows)
    assert any({"fixed": "2.15.0"} in loads(r["events"]) for r in rows)
    assert rows[0]["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core"
    assert conn.execute("SELECT 1 FROM alias WHERE vuln_id='GHSA-jfh8-c2jp-5v3q' AND alias='CVE-2021-44228'").fetchone()
    v = conn.execute("SELECT * FROM vulnerability WHERE id='GHSA-jfh8-c2jp-5v3q'").fetchone()
    assert v["cvss_version"] == "3.1" and v["cvss_score"] == 10.0 and v["severity"]


def test_debian_ubuntu_redhat(conn, osv_dir):
    for f in ("debian-DEBIAN-CVE-2024-2199.json", "ubuntu-UBUNTU-CVE-2024-58384.json",
              "redhat-RHSA-2026_39976.json"):
        osv.import_record(conn, _load(osv_dir, f))
    assert _rows(conn, "DEBIAN-CVE-2024-2199", ecosystem="Debian:12", package="389-ds-base")
    ub = {r["ecosystem"] for r in _rows(conn, "UBUNTU-CVE-2024-58384")}
    assert {"Ubuntu:16.04", "Ubuntu:18.04"} <= ub
    assert _rows(conn, "RHSA-2026:39976", ecosystem="Red Hat:10")
    assert conn.execute("SELECT 1 FROM alias WHERE vuln_id='RHSA-2026:39976' AND alias='CVE-2026-14544'").fetchone()
    ubrow = _rows(conn, "UBUNTU-CVE-2024-58384")[0]
    assert "binaries" in loads(ubrow["extra"])


def test_git_only_creates_no_eco_rows(conn, osv_dir):
    osv.import_record(conn, _load(osv_dir, "git-CVE-2026-70659.json"))
    assert not _rows(conn, "CVE-2026-70659", range_type="ECOSYSTEM")
    assert conn.execute("SELECT 1 FROM alias WHERE vuln_id='CVE-2026-70659' AND alias='GHSA-6q7q-2v9c-x8m7'").fetchone()


def test_pysec_git_and_ecosystem_ranges(conn, osv_dir):
    osv.import_record(conn, _load(osv_dir, "pypi-PYSEC-2021-375.json"))
    types = sorted(r["range_type"] for r in _rows(conn, "PYSEC-2021-375"))
    assert "GIT" in types and "ECOSYSTEM" in types and "VERSIONS" not in types


def test_versions_only_and_withdrawn(conn):
    osv.import_record(conn, {"id": "X-1", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "Foo_Bar"}, "versions": ["1.0", "1.1"]}]})
    r = _rows(conn, "X-1")
    assert len(r) == 1 and r[0]["range_type"] == "VERSIONS" and r[0]["package"] == "foo-bar"
    osv.import_record(conn, {"id": "X-2", "withdrawn": "2024-01-01T00:00:00Z", "details": "line1\nline2",
                             "affected": [{"package": {"ecosystem": "PyPI", "name": "a"}, "versions": ["1"]}]})
    assert not _rows(conn, "X-2")
    v = conn.execute("SELECT * FROM vulnerability WHERE id='X-2'").fetchone()
    assert v["withdrawn"] and v["summary"] == "line1"
    assert not osv.import_record(conn, {"summary": "no id"})


def test_reimport_replaces_children(conn, osv_dir):
    rec = _load(osv_dir, "maven-GHSA-jfh8-c2jp-5v3q.json")
    osv.import_record(conn, rec)
    n = len(_rows(conn, rec["id"]))
    osv.import_record(conn, rec)
    assert len(_rows(conn, rec["id"])) == n


def test_store_raw_toggle(conn, monkeypatch):
    monkeypatch.setenv("SECMONK_OSV_STORE_RAW", "0")
    osv.import_record(conn, {"id": "X-3"})
    assert conn.execute("SELECT count(*) FROM raw_record").fetchone()[0] == 0
    monkeypatch.setenv("SECMONK_OSV_STORE_RAW", "1")
    osv.import_record(conn, {"id": "X-3"})
    assert conn.execute("SELECT count(*) FROM raw_record").fetchone()[0] == 1


@pytest.mark.parametrize("vec,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
])
def test_cvss3(vec, expected):
    assert osv.cvss3_score(vec) == expected


def test_cvss_non_v3():
    assert osv.cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert osv.cvss3_score("garbage") is None


def test_ids_modified_since(osv_dir):
    lines = (osv_dir / "PyPI.modified_id.csv").read_text().splitlines()
    allids = osv.ids_modified_since(lines, None)
    assert len(allids) == len([ln for ln in lines if ln.strip()])
    assert allids[0] == ("2026-11-07T08:45:03.213207645Z", "MAL-2026-18746")
    got = osv.ids_modified_since(lines, "2026-11-07T08:30:03.083732494Z")
    assert [i for _, i in got] == ["MAL-2026-18746"]
    # mixed precision: seconds-only cursor, equal instant is not newer
    got = osv.ids_modified_since(["2026-11-07T08:30:03.000000000Z,A", "2026-11-07T08:30:04Z,B"],
                                 "2026-11-07T08:30:03Z")
    assert [i for _, i in got] == ["B"]


def test_release_qualified_rejected(conn):
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["Debian:12"]))
    assert res.status == "error" and "base name" in res.message


def test_cursor_roundtrip(conn, osv_dir):
    osv.OsvSource().sync(conn, SyncOptions(path=osv_dir / "sample-all.zip"))
    assert get_sync_cursor(conn, "osv:PyPI") is None  # path mode does not set per-ecosystem cursors
