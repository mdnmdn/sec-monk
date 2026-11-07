import json

import pytest

from secmonk.db import dumps, loads
from secmonk.sources import base, cvelist
from secmonk.sources.base import SyncOptions
from secmonk.sources.cvelist import (
    CveListSource,
    convert_version_entry,
    cve_path,
    fetch_missing,
    import_record,
    parse_version_expression,
)


@pytest.fixture
def cvedir(fixtures):
    return fixtures / "cvelist"


def load(cvedir, cid):
    return json.loads((cvedir / f"{cid}.json").read_text())


def affected(conn, cid):
    return conn.execute("SELECT * FROM affected WHERE vuln_id=? ORDER BY rowid_", (cid,)).fetchall()


def vuln(conn, cid):
    return conn.execute("SELECT * FROM vulnerability WHERE id=? AND source='cvelist'", (cid,)).fetchone()


def test_log4shell_changes_events(conn, cvedir):
    assert import_record(conn, load(cvedir, "CVE-2021-44228")) == "CVE-2021-44228"
    rows = affected(conn, "CVE-2021-44228")
    assert len(rows) == 1
    r = rows[0]
    assert r["range_type"] == "CVE"
    assert r["vendor"] == "apache software foundation" and r["product"] == "apache log4j2"
    assert loads(r["events"]) == [
        {"introduced": "2.0-beta9"}, {"fixed": "2.3.1"}, {"introduced": "2.4"}, {"fixed": "2.12.2"},
        {"introduced": "2.13.0"}, {"fixed": "2.15.0"},
    ]
    v = vuln(conn, "CVE-2021-44228")
    assert v["cvss_version"] == "3.1" and v["cvss_score"] == 10
    ex = loads(v["extra"])
    assert ex["cvss_source"] == "adp:CISA-ADP"
    assert ex["ssvc"]["Exploitation"] == "active"
    assert ex["ssvc"]["Automatable"] == "yes"
    assert ex["ssvc"]["Technical Impact"] == "total"
    assert "adp_kev" in ex
    assert conn.execute("SELECT COUNT(*) FROM raw_record WHERE source='cvelist'").fetchone()[0] == 1


def test_reimport_replaces_children(conn, cvedir):
    rec = load(cvedir, "CVE-2021-44228")
    import_record(conn, rec)
    import_record(conn, rec)
    assert len(affected(conn, "CVE-2021-44228")) == 1


def test_npm_package(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2025-7783"))
    rows = affected(conn, "CVE-2025-7783")
    assert len(rows) == 3
    assert {r["ecosystem"] for r in rows} == {"npm"}
    assert {r["package"] for r in rows} == {"form-data"}
    assert all(r["range_type"] == "CVE" for r in rows)
    evs = [loads(r["events"]) for r in rows]
    assert [{"introduced": "0"}, {"fixed": "2.5.4"}] in evs
    assert [{"introduced": "3.0.0"}, {"last_affected": "3.0.3"}] in evs
    assert loads(rows[0]["extra"])["collection_url"] == "https://npmjs.com/form-data"
    assert vuln(conn, "CVE-2025-7783")["cvss_version"] == "4.0"


def test_wordpress_changes_ignored_when_closed(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2025-24746"))
    (r,) = affected(conn, "CVE-2025-24746")
    assert loads(r["events"]) == [{"introduced": "0"}, {"last_affected": "1.20.2"}]
    assert r["ecosystem"] is None and r["package"] == "popup-maker"
    assert loads(r["extra"])["default_status"] == "unaffected"


def test_chrome(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2025-1914"))
    (r,) = affected(conn, "CVE-2025-1914")
    assert (r["vendor"], r["product"]) == ("google", "chrome")
    assert loads(r["events"]) == [{"introduced": "0"}, {"fixed": "134.0.6998.35"}]


def test_firefox_unaffected_only(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2025-1013"))
    rows = affected(conn, "CVE-2025-1013")
    assert {r["product"] for r in rows} == {"firefox", "thunderbird"}
    assert all(r["status"] == "unaffected" and r["events"] is None for r in rows)


def test_freetext_versions(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2026-19868"))
    rows = affected(conn, "CVE-2026-19868")
    assert [loads(r["events"]) for r in rows] == [
        [{"introduced": "0"}, {"last_affected": "7.3.3-7015"}],
        [{"introduced": "0"}, {"last_affected": "8.2.2-8015"}],
    ]
    assert loads(vuln(conn, "CVE-2026-19868")["extra"])["ssvc"]["Exploitation"] == "active"


def test_rejected(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2025-24468"))
    v = vuln(conn, "CVE-2025-24468")
    assert v["state"] == "REJECTED" and v["summary"] == "Not used"
    assert v["withdrawn"] == "2025-08-23T02:55:10.552Z"
    assert affected(conn, "CVE-2025-24468") == []


def test_adp_affected_and_unparsed(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2025-48709"))
    rows = affected(conn, "CVE-2025-48709")
    assert {loads(r["extra"])["container"] for r in rows} == {"cna", "adp:CISA-ADP"}
    assert any(r["range_type"] == "CVE-UNPARSED" for r in rows)


def test_cpe_applicability(conn, cvedir):
    import_record(conn, load(cvedir, "CVE-2025-24077"))
    cpe_rows = [r for r in affected(conn, "CVE-2025-24077") if r["range_type"] == "CPE"]
    assert cpe_rows
    mac = next(r for r in cpe_rows if "office_macos_2021" in r["cpe"])
    assert mac["vendor"] == "microsoft"
    assert loads(mac["events"]) == [{"introduced": "16.0.1"}, {"fixed": "16.95.25030928"}]
    url_row = next(r for r in cpe_rows if "365_apps" in r["cpe"])
    assert loads(url_row["events"]) == [{"introduced": "16.0.1"}]  # URL bound dropped
    cna_rows = [r for r in affected(conn, "CVE-2025-24077") if r["range_type"] == "CVE-UNPARSED"]
    assert cna_rows  # lessThan is a URL, no changes[]


@pytest.mark.parametrize("expr,expected", [
    ("< 2.5.4", [{"introduced": "0"}, {"fixed": "2.5.4"}]),
    ("<= 1.2", [{"introduced": "0"}, {"last_affected": "1.2"}]),
    (">= 1.0, <= 1.2", [{"introduced": "1.0"}, {"last_affected": "1.2"}]),
    (">=1.0 <1.2", [{"introduced": "1.0"}, {"fixed": "1.2"}]),
    ("3.0.0 - 3.0.3", [{"introduced": "3.0.0"}, {"last_affected": "3.0.3"}]),
    ("2.3 and earlier", [{"introduced": "0"}, {"last_affected": "2.3"}]),
    ("7.3.3-7015 and older versions", [{"introduced": "0"}, {"last_affected": "7.3.3-7015"}]),
    ("prior to 4.5", [{"introduced": "0"}, {"fixed": "4.5"}]),
    ("1.0 or later", [{"introduced": "1.0"}]),
    ("1.2.3", None),
    ("log4j-core*", None),
    ("some random text", None),
    ("< foo*", None),
])
def test_parse_version_expression(expr, expected):
    assert parse_version_expression(expr) == expected


def test_convert_edge_cases():
    assert convert_version_entry({"version": "0", "lessThan": "*", "status": "affected"}) == (
        "events", [{"introduced": "0"}])
    assert convert_version_entry({"version": "1.0", "lessThan": "2.0"}) == (
        "events", [{"introduced": "1.0"}, {"fixed": "2.0"}])
    assert convert_version_entry({"version": "1.4"}) == ("versions", ["1.4"])
    assert convert_version_entry({"version": "n/a"})[0] == "skip"
    assert convert_version_entry({"version": "1.0", "lessThan": "2.*"})[0] == "unparsed"
    kind, ev = convert_version_entry(
        {"version": "a" * 40, "lessThan": "b" * 40, "versionType": "git"})
    assert kind == "git" and ev[1] == {"fixed": "b" * 40}


def test_cve_path():
    assert cve_path("CVE-2021-44228") == "cves/2021/44xxx/CVE-2021-44228.json"
    assert cve_path("CVE-2025-1914") == "cves/2025/1xxx/CVE-2025-1914.json"
    assert cve_path("CVE-2023-0001") == "cves/2023/0xxx/CVE-2023-1.json"
    assert cve_path("CVE-2026-119977") == "cves/2026/119xxx/CVE-2026-119977.json"
    with pytest.raises(ValueError):
        cve_path("GHSA-xxxx")


def test_sync_directory_and_limit(conn, cvedir):
    expected = len(list(cvedir.rglob("CVE-*.json")))  # sync walks sub-folders too
    res = CveListSource().sync(conn, SyncOptions(path=cvedir))
    assert res.status == "ok" and res.records == expected
    assert conn.execute("SELECT COUNT(*) FROM vulnerability").fetchone()[0] == expected
    # unchanged records are skipped on re-import
    assert CveListSource().sync(conn, SyncOptions(path=cvedir)).records == 0
    assert CveListSource().sync(conn, SyncOptions(path=cvedir, full=True, limit=2)).records == 2


def test_sync_single_file(conn, cvedir):
    res = CveListSource().sync(conn, SyncOptions(path=cvedir / "CVE-2025-1914.json"))
    assert res.records == 1


def test_referenced_and_fetch_missing(conn, cvedir, monkeypatch):
    conn.execute("INSERT INTO alias VALUES ('GHSA-1','CVE-2025-1914','osv')")
    conn.execute("INSERT INTO alias VALUES ('GHSA-1','CVE-2021-44228','osv')")
    conn.execute("INSERT INTO kev(cve_id) VALUES ('CVE-2025-7783')")
    import_record(conn, load(cvedir, "CVE-2021-44228"))
    urls = []

    class Resp:
        def __init__(self, cid):
            self.status_code = 200 if cid else 404
            self.cid = cid

        def raise_for_status(self):
            pass

        def json(self):
            return load(cvedir, self.cid)

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            urls.append(url)
            return Resp(url.rsplit("/", 1)[1][:-5])

    monkeypatch.setattr(cvelist, "http_client", lambda **kw: Client())
    assert cvelist.referenced_ids(conn) == ["CVE-2025-1914", "CVE-2025-7783"]
    res = fetch_missing(conn, None, SyncOptions(ids=["@referenced"], limit=1))
    assert res.records == 1 and urls == [cvelist.raw_url("CVE-2025-1914")]
    assert vuln(conn, "CVE-2025-1914") is not None
    res = CveListSource().sync(conn, SyncOptions(ids=["CVE-2025-7783"]))
    assert res.records == 1
    assert base.REGISTRY["cvelist"] is CveListSource
    assert dumps(None) is None
