"""Regression tests for the source-importer review findings (S#/SEC#/E#). All offline."""

from __future__ import annotations

import copy
import gzip
import io
import json
import lzma
import os
import stat
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from secmonk import db
from secmonk.engine.purl import normalize_ecosystem
from secmonk.sources import base, cvelist, epss, euvd, kev, msrc, nvd, osv
from secmonk.sources import debian_tracker as dt
from secmonk.sources.base import SyncOptions

YEAR = str(datetime.now(UTC).year)


def rows(conn, sql, *a):
    return [dict(r) for r in conn.execute(sql, a)]


def mock_http(monkeypatch, module, handler):
    monkeypatch.setattr(module, "http_client",
                        lambda timeout=60.0, **kw: httpx.Client(transport=httpx.MockTransport(handler)))


# =========================================================================== db / paths


def test_set_sync_state_error_keeps_last_good(conn):
    db.set_sync_state(conn, "x", status="ok", records=7, cursor="c1", message="fine")
    before = rows(conn, "SELECT * FROM source_sync WHERE source='x'")[0]
    db.set_sync_state(conn, "x", status="error", records=0, cursor="zzz", message="boom")
    after = rows(conn, "SELECT * FROM source_sync WHERE source='x'")[0]
    assert after["status"] == "error" and after["message"] == "boom"
    assert (after["records"], after["cursor"], after["last_sync"]) == (7, "c1", before["last_sync"])
    db.set_sync_state(conn, "y", status="error", message="never worked")
    assert rows(conn, "SELECT last_sync FROM source_sync WHERE source='y'")[0]["last_sync"] is None
    db.set_sync_state(conn, "x", status="partial", records=3, message="p")
    assert rows(conn, "SELECT records, status FROM source_sync WHERE source='x'")[0] == {"records": 3, "status": "partial"}


def test_init_schema_never_downgrades_user_version(tmp_path):
    p = tmp_path / "x.db"
    c = db.connect(p)
    c.execute("PRAGMA user_version=99")
    c.commit()
    c.close()
    c = db.connect(p)
    assert c.execute("PRAGMA user_version").fetchone()[0] == 99


def test_connect_creates_private_db_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SECMONK_DB", str(tmp_path / "data" / "s.db"))
    db.connect().close()
    mode = stat.S_IMODE(os.stat(tmp_path / "data" / "s.db").st_mode)
    assert mode & 0o077 == 0
    assert db.default_db_path() == tmp_path / "data" / "s.db"


def test_alias_kind_column_and_add_alias(conn):
    base.add_alias(conn, "osv", "UBUNTU-1", "CVE-1", kind="upstream")
    base.add_alias(conn, "osv", "UBUNTU-1", "GHSA-1")
    base.add_alias(conn, "osv", "UBUNTU-1", "CVE-1", kind="alias")     # alias wins over upstream
    got = {r["alias"]: r["kind"] for r in rows(conn, "SELECT * FROM alias")}
    assert got == {"CVE-1": "alias", "GHSA-1": "alias"}
    base.add_alias(conn, "osv", "UBUNTU-1", "CVE-2", kind="upstream")
    base.add_alias(conn, "osv", "UBUNTU-1", "CVE-2")                    # no downgrade the other way
    assert rows(conn, "SELECT kind FROM alias WHERE alias='CVE-2'")[0]["kind"] == "alias"


def test_alias_kind_migrated_on_old_db(tmp_path):
    import sqlite3
    p = tmp_path / "old.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE alias (vuln_id TEXT NOT NULL, alias TEXT NOT NULL, source TEXT NOT NULL, "
              "PRIMARY KEY (vuln_id, alias, source))")
    c.execute("INSERT INTO alias VALUES ('a','b','osv')")
    c.commit()
    c.close()
    c = db.connect(p)
    assert rows(c, "SELECT kind FROM alias WHERE kind='alias'") == [{"kind": "alias"}]


# =========================================================================== purl (S20)


def test_normalize_ecosystem_red_hat_and_ubuntu():
    assert normalize_ecosystem("Red Hat:enterprise_linux:9::appstream") == "Red Hat:9"
    assert normalize_ecosystem("Red Hat:enterprise_linux:10.2") == "Red Hat:10"
    assert normalize_ecosystem("Red Hat:rhel_eus:9.6::baseos") == "Red Hat:9"
    assert normalize_ecosystem("Red Hat:openshift:4.14::el9") == "Red Hat:openshift:4.14::el9"
    assert normalize_ecosystem("Red Hat:ansible_automation_platform:2.4::el8") \
        == "Red Hat:ansible_automation_platform:2.4::el8"
    assert normalize_ecosystem("Ubuntu:Pro:FIPS-updates:22.04:LTS") == "Ubuntu:22.04"
    assert normalize_ecosystem("Ubuntu:22.04:LTS") == "Ubuntu:22.04"


def test_ubuntu_variant_kept_in_extra(conn):
    osv.import_record(conn, {"id": "UBUNTU-X", "modified": "2026-01-01T00:00:00Z", "affected": [
        {"package": {"ecosystem": "Ubuntu:Pro:FIPS-updates:22.04:LTS", "name": "openssl"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}]})
    r = rows(conn, "SELECT ecosystem, extra FROM affected")[0]
    ex = json.loads(r["extra"])
    assert r["ecosystem"] == "Ubuntu:22.04"
    assert ex["ecosystem_variant"] == "Pro:FIPS-updates" and ex["raw_ecosystem"].startswith("Ubuntu:Pro")


# =========================================================================== OSV record import


def test_osv_go_custom_ranges_replace_open_ended_row(conn, fixtures):
    osv.import_record(conn, json.loads((fixtures / "osv" / "go-GO-2024-2428.json").read_text()))
    got = rows(conn, "SELECT range_type, events, extra FROM affected")
    assert len(got) == 1
    assert got[0]["range_type"] == "ECOSYSTEM"
    assert json.loads(got[0]["events"]) == [{"introduced": "0"}, {"fixed": "1.9.0"}]
    assert json.loads(got[0]["extra"])["custom_range"] is True


def test_osv_custom_ranges_each_own_row(conn):
    osv.import_record(conn, {"id": "GO-1", "modified": "2026-01-01T00:00:00Z", "affected": [{
        "package": {"ecosystem": "Go", "name": "example.com/m"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        "ecosystem_specific": {"custom_ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]}}]})
    evs = [json.loads(r["events"]) for r in rows(conn, "SELECT events FROM affected ORDER BY rowid_")]
    assert evs == [[{"introduced": "0"}, {"fixed": "1.2.0"}], [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]]


V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"


def _rec(i, **kw):
    return {"id": i, "modified": "2026-01-01T00:00:00Z", "summary": "x", "affected": [], **kw}


def test_osv_v4_only_derives_conservative_score(conn):
    osv.import_record(conn, _rec("T-1", severity=[{"type": "CVSS_V4", "score": V4}],
                                 database_specific={"severity": "HIGH"}))
    osv.import_record(conn, _rec("T-2", severity=[{"type": "CVSS_V4", "score": V4}]))
    osv.import_record(conn, _rec("T-3", severity=[{"type": "CVSS_V4", "score": V4}, {"type": "CVSS_V3", "score": V3}]))
    t1, t2, t3 = (rows(conn, "SELECT * FROM vulnerability WHERE id=?", i)[0] for i in ("T-1", "T-2", "T-3"))
    assert (t1["cvss_score"], t1["cvss_vector"], t1["cvss_version"]) == (8.0, V4, "4.0")
    assert json.loads(t1["extra"])["score_derived"] is True
    assert t2["cvss_score"] is None and t2["cvss_vector"] == V4          # nothing to derive from
    assert t3["cvss_vector"] == V3 and t3["cvss_score"] == 7.3           # real v3 score, v4 kept in extra
    assert json.loads(t3["extra"])["cvss_v4_vector"] == V4
    assert "score_derived" not in json.loads(t3["extra"])


@pytest.mark.parametrize("label,score", [("LOW", 3.0), ("MODERATE", 5.5), ("MEDIUM", 5.5),
                                         ("HIGH", 8.0), ("CRITICAL", 9.5)])
def test_osv_derived_score_table(conn, label, score):
    osv.import_record(conn, _rec("D", severity=[{"type": "CVSS_V4", "score": V4}],
                                 database_specific={"severity": label}))
    assert rows(conn, "SELECT cvss_score FROM vulnerability")[0]["cvss_score"] == score


def test_severity_vocabulary(conn):
    osv.import_record(conn, _rec("S-1", database_specific={"severity": "MODERATE"}))
    osv.import_record(conn, _rec("S-2", severity=[{"type": "Ubuntu", "score": "negligible"}]))
    osv.import_record(conn, _rec("S-3", severity=[{"type": "Ubuntu", "score": "untriaged"}]))
    got = {r["id"]: r["severity"] for r in rows(conn, "SELECT id, severity FROM vulnerability")}
    assert got == {"S-1": "MEDIUM", "S-2": "LOW", "S-3": None}
    assert base.normalize_severity("Moderate") == "MEDIUM" and base.normalize_severity(None) is None


def test_osv_upstream_is_not_a_plain_alias(conn):
    osv.import_record(conn, _rec("UBUNTU-CVE-2024-1", aliases=["CVE-2024-1"], upstream=["CVE-2024-9"]))
    got = {r["alias"]: r["kind"] for r in rows(conn, "SELECT alias, kind FROM alias")}
    assert got == {"CVE-2024-1": "alias", "CVE-2024-9": "upstream"}


def test_osv_raw_storage_off_by_default(conn, monkeypatch):
    monkeypatch.delenv("SECMONK_OSV_STORE_RAW", raising=False)
    osv.import_record(conn, _rec("R-1"))
    assert rows(conn, "SELECT COUNT(*) n FROM raw_record")[0]["n"] == 0
    monkeypatch.setenv("SECMONK_OSV_STORE_RAW", "1")
    osv.import_record(conn, _rec("R-2"))
    assert rows(conn, "SELECT record_id FROM raw_record") == [{"record_id": "R-2"}]


# =========================================================================== OSV sync


def _orec(i, mod):
    return {"id": f"GHSA-000{i}", "modified": mod, "summary": f"r{i}",
            "affected": [{"package": {"ecosystem": "PyPI", "name": f"p{i}"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}


@pytest.fixture
def osv_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SECMONK_CACHE", str(tmp_path / "cache"))
    recs = [_orec(5, "2026-05-05T00:00:00Z"), _orec(4, "2026-04-04T00:00:00Z"), _orec(3, "2026-03-03T00:00:00Z"),
            _orec(2, "2026-02-02T00:00:00Z"), _orec(1, "2026-01-01T00:00:00Z")]
    state = {"recs": recs, "bad": set(), "npm_500": False}

    def zip_bytes():
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for r in state["recs"]:
                z.writestr(f"{r['id']}.json", json.dumps(r))
        return b.getvalue()

    def handler(req):
        p = req.url.path
        if "/npm/" in p and state["npm_500"]:
            return httpx.Response(500)
        if p.endswith("all.zip"):
            return httpx.Response(200, content=zip_bytes())
        if p.endswith("modified_id.csv"):
            return httpx.Response(200, text="\n".join(
                f"{r['modified']},{r['id']}" for r in sorted(state["recs"], key=lambda r: r["modified"], reverse=True)))
        rid = p.rsplit("/", 1)[1][:-5]
        if rid in state["bad"]:
            return httpx.Response(200, text="<html>hiccup</html>")
        r = next((r for r in state["recs"] if r["id"] == rid), None)
        return httpx.Response(200, json=r) if r else httpx.Response(404)

    mock_http(monkeypatch, osv, handler)
    return state


def _osv_state(conn, key="osv:PyPI"):
    return rows(conn, "SELECT status, cursor FROM source_sync WHERE source=?", key)[0]


def test_osv_limited_full_sync_is_partial_without_cursor(conn, osv_env):
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"], limit=1))
    assert res.status == "partial" and res.records == 1
    assert _osv_state(conn) == {"status": "partial", "cursor": None}
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))       # must be a full run, not a delta
    assert res.status == "ok" and res.records == 5 and res.total == 5
    assert _osv_state(conn)["status"] == "ok" and _osv_state(conn)["cursor"] == "2026-05-05T00:00:00Z"


def test_osv_does_not_write_main_row(conn, osv_env, tmp_path):
    osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    assert rows(conn, "SELECT source FROM source_sync") == [{"source": "osv:PyPI"}]
    p = tmp_path / "one.json"
    p.write_text(json.dumps(_orec(9, "2026-09-09T00:00:00Z")))
    osv.OsvSource().sync(conn, SyncOptions(path=p))
    assert rows(conn, "SELECT source FROM source_sync") == [{"source": "osv:PyPI"}]


def test_osv_delta_skips_bad_id_and_holds_cursor(conn, osv_env):
    osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    osv_env["recs"] = [_orec(7, "2026-07-07T00:00:00Z"), _orec(6, "2026-06-06T00:00:00Z"), *osv_env["recs"]]
    osv_env["bad"] = {"GHSA-0006"}
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    assert res.status == "partial" and res.records == 1
    assert rows(conn, "SELECT 1 FROM vulnerability WHERE id='GHSA-0007'")            # later good id imported
    assert _osv_state(conn)["cursor"] == "2026-05-05T00:00:00Z"                        # cursor not past the failure
    osv_env["bad"] = set()                                                             # retried next run
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    assert res.status == "ok" and rows(conn, "SELECT 1 FROM vulnerability WHERE id='GHSA-0006'")
    assert _osv_state(conn)["cursor"] == "2026-07-07T00:00:00Z"


def test_osv_delta_cursor_advances_to_last_success_before_failure(conn, osv_env):
    osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    osv_env["recs"] = [_orec(7, "2026-07-07T00:00:00Z"), _orec(6, "2026-06-06T00:00:00Z"), *osv_env["recs"]]
    osv_env["bad"] = {"GHSA-0007"}
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    assert res.status == "partial"
    assert _osv_state(conn)["cursor"] == "2026-06-06T00:00:00Z"


def test_osv_status_partial_when_one_ecosystem_fails(conn, osv_env):
    osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    osv_env["npm_500"] = True
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI", "npm"]))
    assert res.status == "partial" and "npm" in res.message
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["npm"]))
    assert res.status == "error"


def test_osv_zip_download_private_and_capped(conn, osv_env, tmp_path, monkeypatch):
    osv.OsvSource().sync(conn, SyncOptions(ecosystems=["PyPI"]))
    cache = tmp_path / "cache" / "osv"
    assert [p.name for p in cache.iterdir()] == ["PyPI.zip"]                  # no leftover temp file
    assert stat.S_IMODE(os.stat(cache / "PyPI.zip").st_mode) & 0o077 == 0
    monkeypatch.setattr(osv, "MAX_ZIP_BYTES", 50)
    res = osv.OsvSource().sync(conn, SyncOptions(ecosystems=["Go"]))
    assert res.status == "error" and "limit" in res.message
    assert [p.name for p in cache.iterdir()] == ["PyPI.zip"]


def test_osv_zip_member_cap_on_real_read(conn, tmp_path, monkeypatch):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.json", json.dumps(_rec("BIG", details="x" * 5000)))
        zf.writestr("ok.json", json.dumps(_rec("OK")))
    monkeypatch.setattr(osv, "MAX_MEMBER_SIZE", 1000)
    osv.OsvSource().sync(conn, SyncOptions(path=z))
    assert [r["id"] for r in rows(conn, "SELECT id FROM vulnerability")] == ["OK"]


# =========================================================================== cvelist records


def crec(cve, cna=None, adp=None, state="PUBLISHED", updated="2026-01-01T00:00:00.000Z"):
    return {"cveMetadata": {"cveId": cve, "state": state, "dateUpdated": updated},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": "d"}], **(cna or {})}, "adp": adp or []}}


def cpe_rec(cve, match):
    return crec(cve, {"cpeApplicability": [{"nodes": [{"operator": "OR", "cpeMatch": [match]}]}]})


def test_cve_path_keeps_zero_padding():
    assert cvelist.cve_path("CVE-2014-0160") == "cves/2014/0xxx/CVE-2014-0160.json"
    assert cvelist.cve_path("CVE-2021-0123") == "cves/2021/0xxx/CVE-2021-0123.json"
    assert cvelist.cve_path("CVE-2021-44228") == "cves/2021/44xxx/CVE-2021-44228.json"
    assert cvelist.cve_path("CVE-2019-1010022") == "cves/2019/1010xxx/CVE-2019-1010022.json"
    assert cvelist.raw_url("CVE-2014-0160").endswith("/cves/2014/0xxx/CVE-2014-0160.json")


def test_cvelist_start_excluding_and_wildcard(conn):
    base_cpe = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
    cvelist.import_record(conn, cpe_rec("CVE-2026-1002", {"vulnerable": True, "criteria": base_cpe,
                                                          "versionStartExcluding": "1.0", "versionEndExcluding": "2.0"}))
    cvelist.import_record(conn, cpe_rec("CVE-2026-1003", {"vulnerable": True, "criteria": base_cpe,
                                                          "versionStartExcluding": "5.0"}))
    cvelist.import_record(conn, cpe_rec("CVE-2026-1004", {"vulnerable": True, "criteria": base_cpe}))
    cvelist.import_record(conn, cpe_rec("CVE-2026-1005", {"vulnerable": True, "criteria": base_cpe,
                                                          "versionStartExcluding": "see advisory",
                                                          "versionEndExcluding": "2.0"}))
    cvelist.import_record(conn, cpe_rec("CVE-2026-1006", {"vulnerable": True, "criteria": base_cpe,
                                                          "versionEndExcluding": "2.0"}))
    got = {r["vuln_id"]: (r["range_type"], json.loads(r["events"]) if r["events"] else None)
           for r in rows(conn, "SELECT * FROM affected")}
    assert got["CVE-2026-1002"] == ("CPE", [{"introduced_exclusive": "1.0"}, {"fixed": "2.0"}])
    assert got["CVE-2026-1003"] == ("CPE", [{"introduced_exclusive": "5.0"}])
    assert got["CVE-2026-1004"] == ("CPE", [{"introduced": "0"}])
    assert got["CVE-2026-1005"][0] == "CVE-UNPARSED"
    assert got["CVE-2026-1006"] == ("CPE", [{"introduced": "0"}, {"fixed": "2.0"}])


def test_cvelist_cpe_unescape_dedupe_and_update_field(conn):
    cvelist.import_record(conn, cpe_rec("CVE-2026-1", {
        "vulnerable": True, "criteria": "cpe:2.3:a:Vendor_Co:prod\\:name:*:*:*:*:*:*:*:*", "matchCriteriaId": "A"}))
    r = rows(conn, "SELECT vendor, product FROM affected")[0]
    assert (r["vendor"], r["product"]) == ("vendor co", "prod:name")
    rec = crec("CVE-2026-2", {"cpeApplicability": [{"nodes": [
        {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:g:chrome:1.0:beta:*:*:*:*:*:*", "matchCriteriaId": "B"}]},
        {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:g:chrome:1.0:beta:*:*:*:*:*:*", "matchCriteriaId": "B"}]}]}]})
    cvelist.import_record(conn, rec)
    got = rows(conn, "SELECT range_type, extra FROM affected WHERE vuln_id='CVE-2026-2'")
    assert len(got) == 1 and got[0]["range_type"] == "CVE-UNPARSED"
    assert json.loads(got[0]["extra"])["cpe_update"] == "beta"


def test_cvelist_package_name_normalized_and_default_status(conn):
    cvelist.import_record(conn, crec("CVE-2026-1005", {"affected": [{
        "packageName": "Zope.Interface", "collectionURL": "https://pypi.org/project/zope.interface",
        "versions": [{"version": "1.0", "status": "affected"}]}]}))
    assert rows(conn, "SELECT ecosystem, package FROM affected")[0] == {"ecosystem": "PyPI", "package": "zope-interface"}
    cvelist.import_record(conn, crec("CVE-2026-1001", {"affected": [
        {"vendor": "acme", "product": "widget", "defaultStatus": "affected"}]}))
    r = rows(conn, "SELECT * FROM affected WHERE vuln_id='CVE-2026-1001'")
    assert len(r) == 1 and r[0]["range_type"] == "CVE-UNPARSED" and r[0]["status"] == "affected"
    assert json.loads(r[0]["extra"])["default_status"] == "affected"


def test_cvelist_severity_vocabulary(conn):
    cvelist.import_record(conn, crec("CVE-2026-7", {"metrics": [{"cvssV3_1": {
        "baseScore": 5.0, "version": "3.1", "baseSeverity": "Moderate"}}]}))
    assert rows(conn, "SELECT severity FROM vulnerability")[0]["severity"] == "MEDIUM"


@pytest.mark.parametrize("entry,expected", [
    ({"version": "2.4.0", "lessThan": "*", "status": "affected", "versionType": "semver",
      "changes": [{"at": "2.4.58", "status": "unaffected"}]},
     [{"introduced": "2.4.0"}, {"fixed": "2.4.58"}]),
    ({"version": "1.0", "lessThan": "2.0", "status": "affected", "versionType": "semver",
      "changes": [{"at": "1.5", "status": "unaffected"}]},
     [{"introduced": "1.0"}, {"fixed": "1.5"}]),
    ({"version": "1.0", "lessThan": "2.0", "status": "affected", "versionType": "semver",
      "changes": [{"at": "1.7", "status": "affected"}, {"at": "1.5", "status": "unaffected"}]},
     [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "1.7"}, {"fixed": "2.0"}]),
    ({"version": "1.0", "lessThan": "2.0", "status": "affected", "versionType": "semver",
      "changes": [{"at": "3.0", "status": "unaffected"}]},
     [{"introduced": "1.0"}, {"fixed": "2.0"}]),
])
def test_cvelist_changes_inside_bounded_entry(entry, expected):
    assert cvelist.convert_version_entry(entry) == ("events", expected)


def test_cvelist_failed_record_is_rolled_back_atomically(conn, tmp_path):
    good = crec("CVE-2026-2000", {"affected": [{"vendor": "acme", "product": "gadget",
                                                 "versions": [{"version": "1.0", "status": "affected"}]}]})
    cvelist.import_record(conn, good)
    conn.commit()
    bad = copy.deepcopy(good)
    bad["cveMetadata"]["dateUpdated"] = "2026-02-01T00:00:00.000Z"
    bad["containers"]["cna"]["metrics"] = [{"cvssV3_1": {"baseScore": "n/a", "version": "3.1"}}]
    bad2 = crec("CVE-2026-3000", {"metrics": ["junk"]})                      # AttributeError, not ValueError
    ok = crec("CVE-2026-3001")
    for name, r in (("a", bad), ("b", bad2), ("c", ok)):
        (tmp_path / f"CVE-{name}.json").write_text(json.dumps(r))
    res = cvelist.CveListSource().sync(conn, SyncOptions(path=tmp_path))
    assert res.status == "partial" and res.records == 1
    assert len(rows(conn, "SELECT * FROM affected WHERE vuln_id='CVE-2026-2000'")) == 1
    assert rows(conn, "SELECT modified FROM vulnerability WHERE id='CVE-2026-2000'")[0]["modified"] == "2026-01-01T00:00:00.000Z"
    assert rows(conn, "SELECT modified FROM raw_record WHERE record_id='CVE-2026-2000'")[0]["modified"] == "2026-01-01T00:00:00.000Z"
    assert not rows(conn, "SELECT 1 FROM vulnerability WHERE id='CVE-2026-3000'")
    assert rows(conn, "SELECT 1 FROM vulnerability WHERE id='CVE-2026-3001'")
    assert not conn.in_transaction


def test_cvelist_fetch_ids_isolates_bad_records(conn, monkeypatch):
    docs = {"CVE-2026-1001": crec("CVE-2026-1001"), "CVE-2026-1002": crec("CVE-2026-1002", {"metrics": ["junk"]})}

    def handler(req):
        cid = req.url.path.rsplit("/", 1)[1][:-5]
        return httpx.Response(200, json=docs[cid])

    mock_http(monkeypatch, cvelist, handler)
    res = cvelist.CveListSource().sync(conn, SyncOptions(ids=["CVE-2026-1002", "CVE-2026-1001"]))
    assert res.status == "partial" and res.records == 1
    assert [r["id"] for r in rows(conn, "SELECT id FROM vulnerability")] == ["CVE-2026-1001"]


def test_cvelist_renormalize_from_raw(conn):
    cvelist.import_record(conn, cpe_rec("CVE-2026-9", {"vulnerable": True, "criteria": "cpe:2.3:a:a:b:*:*:*:*:*:*:*:*",
                                                       "versionEndExcluding": "2.0"}))
    conn.execute("UPDATE affected SET events='[{\"fixed\":\"1\"}]'")
    assert cvelist.renormalize(conn) == (1, 0)
    assert json.loads(rows(conn, "SELECT events FROM affected")[0]["events"]) == [{"introduced": "0"}, {"fixed": "2.0"}]


# =========================================================================== cvelist git mode


def _git(cwd, *a):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", *a], cwd=cwd, check=True,
                          capture_output=True, text=True, env=env).stdout.strip()


class Origin:
    def __init__(self, path: Path):
        self.path = path
        path.mkdir()
        _git(path, "init", "-q", "-b", "main")
        _git(path, "config", "uploadpack.allowFilter", "true")
        _git(path, "config", "uploadpack.allowAnySHA1InWant", "true")

    def put(self, year, n, desc, updated):
        cve = f"CVE-{year}-{n:04d}"
        p = self.path / "cves" / str(year) / f"{n // 1000}xxx" / f"{cve}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "cveMetadata": {"cveId": cve, "state": "PUBLISHED", "dateUpdated": updated},
            "containers": {"cna": {"descriptions": [{"lang": "en", "value": desc}]}}}))

    def commit(self, msg="c"):
        _git(self.path, "add", "-A")
        _git(self.path, "commit", "-qm", msg)
        return _git(self.path, "rev-parse", "HEAD")


@pytest.fixture
def origin(tmp_path, monkeypatch):
    o = Origin(tmp_path / "origin")
    monkeypatch.setattr(cvelist, "REPO_URL", f"file://{o.path}")
    monkeypatch.setattr(cvelist, "CACHE_REPO", tmp_path / "cache")
    return o


def _summaries(conn):
    return {r["id"]: r["summary"] for r in rows(conn, "SELECT id, summary FROM vulnerability")}


def test_git_full_always_fetches_upstream_head(conn, origin):
    origin.put(YEAR, 1001, "v1", "2026-01-01T00:00:00.000Z")
    origin.commit()
    r1 = cvelist.CveListSource().sync(conn, SyncOptions())
    assert r1.status == "ok" and r1.records == 1
    origin.put(YEAR, 1001, "v2 UPDATED", "2026-02-01T00:00:00.000Z")
    head = origin.commit()
    r2 = cvelist.CveListSource().sync(conn, SyncOptions(full=True))
    assert r2.cursor == head and _summaries(conn)[f"CVE-{YEAR}-1001"] == "v2 UPDATED"
    # internal rows only; the main row belongs to the CLI
    assert {r["source"] for r in rows(conn, "SELECT source FROM source_sync")} == {"cvelist:git", "cvelist:years"}
    assert r2.total == 1


def test_git_delta_via_cursor_and_no_cursor_walk(conn, origin):
    origin.put(YEAR, 1001, "v1", "2026-01-01T00:00:00.000Z")
    origin.put(YEAR, 1002, "other", "2026-01-01T00:00:00.000Z")
    origin.commit()
    cvelist.CveListSource().sync(conn, SyncOptions())
    origin.put(YEAR, 1001, "v2", "2026-02-01T00:00:00.000Z")
    head = origin.commit()
    r = cvelist.CveListSource().sync(conn, SyncOptions())
    assert r.records == 1 and r.cursor == head                      # diff mode touched only the changed file
    assert _summaries(conn)[f"CVE-{YEAR}-1001"] == "v2"
    r = cvelist.CveListSource().sync(conn, SyncOptions())
    assert r.records == 0 and r.status == "ok"


def test_git_since_backfill_is_persisted(conn, origin):
    old = int(YEAR) - 5
    origin.put(old, 5000, "old v1", "2024-01-01T00:00:00.000Z")
    origin.put(YEAR, 1000, "new v1", "2026-01-01T00:00:00.000Z")
    origin.commit()
    r = cvelist.CveListSource().sync(conn, SyncOptions(since=str(old)))
    assert r.records == 2
    origin.put(old, 5000, "old v2", "2026-11-01T00:00:00.000Z")
    origin.commit()
    r = cvelist.CveListSource().sync(conn, SyncOptions())         # plain sync must not abandon the backfill
    assert r.records == 1 and _summaries(conn)[f"CVE-{old}-5000"] == "old v2"
    assert rows(conn, "SELECT cursor FROM source_sync WHERE source='cvelist:years'")[0]["cursor"] == str(old)


def test_git_foreign_cache_is_not_trusted(conn, origin, tmp_path):
    origin.put(YEAR, 1001, "v1", "2026-01-01T00:00:00.000Z")
    origin.commit()
    marker = tmp_path / "PWNED"
    evil = tmp_path / "evil.sh"
    evil.write_text(f"#!/bin/sh\ntouch {marker}\n")
    evil.chmod(0o755)
    cache = tmp_path / "cache"
    (cache / ".git").mkdir(parents=True)
    (cache / ".git" / "config").write_text(
        f'[core]\n\trepositoryformatversion = 0\n\tfsmonitor = {evil}\n[remote "origin"]\n\turl = https://evil.example/x.git\n')
    (cache / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    res = cvelist.CveListSource().sync(conn, SyncOptions())
    assert res.status == "ok" and res.records == 1
    assert not marker.exists()
    assert _git(cache, "config", "--local", "--get", "remote.origin.url") == f"file://{origin.path}"


def test_git_origin_url_mismatch_triggers_reclone(conn, origin, tmp_path):
    origin.put(YEAR, 1001, "v1", "2026-01-01T00:00:00.000Z")
    origin.commit()
    cvelist.CveListSource().sync(conn, SyncOptions())
    cache = tmp_path / "cache"
    _git(cache, "remote", "set-url", "origin", "https://evil.example/x.git")
    origin.put(YEAR, 1001, "v2", "2026-02-01T00:00:00.000Z")
    origin.commit()
    res = cvelist.CveListSource().sync(conn, SyncOptions())
    assert res.status == "ok" and _summaries(conn)[f"CVE-{YEAR}-1001"] == "v2"


def test_git_malicious_stored_cursor_is_ignored(conn, origin):
    origin.put(YEAR, 1001, "v1", "2026-01-01T00:00:00.000Z")
    origin.commit()
    cvelist.CveListSource().sync(conn, SyncOptions())
    db.set_sync_state(conn, cvelist.GIT_KEY, status="ok", cursor="--output=/tmp/should-not-exist")
    origin.put(YEAR, 1001, "v2", "2026-02-01T00:00:00.000Z")
    origin.commit()
    res = cvelist.CveListSource().sync(conn, SyncOptions())
    assert res.status == "ok" and _summaries(conn)[f"CVE-{YEAR}-1001"] == "v2"
    assert not os.path.exists("/tmp/should-not-exist")


def test_git_env_is_hardened(monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/nowhere")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    env = cvelist._git_env()
    assert "GIT_DIR" not in env and "GIT_CONFIG_COUNT" not in env
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert "core.fsmonitor=" in cvelist._GIT_HARDEN


def test_cache_dirs_are_per_user_not_cwd(tmp_path, monkeypatch):
    monkeypatch.setenv("SECMONK_CACHE", str(tmp_path / "c"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cvelist, "CACHE_REPO", None)
    assert cvelist._cache_repo() == tmp_path / "c" / "cvelistV5"
    assert stat.S_IMODE(os.stat(tmp_path / "c").st_mode) == 0o700
    assert base.CACHE_DIR.is_absolute()


# =========================================================================== MSRC


def _cvrf(month_id, released, pid, name, fixed, kb):
    return {"DocumentTracking": {"Identification": {"ID": {"Value": month_id}}, "CurrentReleaseDate": released,
                                 "InitialReleaseDate": released},
            "ProductTree": {"FullProductName": [{"ProductID": pid, "Value": name}]},
            "Vulnerability": [{"CVE": "CVE-2024-9999", "Title": {"Value": "t"}, "Notes": [], "CVSSScoreSets": [],
                               "Remediations": [{"Type": 2, "Description": {"Value": kb}, "FixedBuild": fixed,
                                                 "ProductID": [pid]}]}]}


JAN = _cvrf("2024-Jan", "2024-01-09T08:00:00Z", "11568", "Windows 10 Version 22H2 for x64-based Systems",
            "10.0.19045.3930", "5034122")
FEB = _cvrf("2024-Feb", "2024-02-13T08:00:00Z", "12001", "Windows 11 Version 23H2 for x64-based Systems",
            "10.0.22631.3155", "5034765")


def _prods(conn):
    return sorted(r["product"] for r in rows(conn, "SELECT product FROM affected"))


def test_msrc_documents_do_not_delete_each_other(conn, tmp_path):
    (tmp_path / "2024-Jan.json").write_text(json.dumps(JAN))
    (tmp_path / "2024-Feb.json").write_text(json.dumps(FEB))
    res = msrc.MsrcSource().sync(conn, SyncOptions(path=tmp_path))
    assert res.status == "ok" and res.cursor == "2024-02-13T08:00:00Z" and res.total == 1
    assert _prods(conn) == ["windows 10 version 22h2", "windows 11 version 23h2"]
    assert rows(conn, "SELECT modified FROM vulnerability")[0]["modified"] == "2024-02-13T08:00:00Z"
    assert not rows(conn, "SELECT 1 FROM source_sync")               # CLI owns the main row


def test_msrc_older_document_imported_later_keeps_newest_vuln_row(conn):
    msrc.import_cvrf(conn, FEB)
    msrc.import_cvrf(conn, JAN)
    assert _prods(conn) == ["windows 10 version 22h2", "windows 11 version 23h2"]
    v = rows(conn, "SELECT modified, extra FROM vulnerability")[0]
    assert v["modified"] == "2024-02-13T08:00:00Z"
    assert set(json.loads(v["extra"])["kbs"]) == {"KB5034122", "KB5034765"}
    msrc.import_cvrf(conn, FEB)                                         # re-import replaces only its own rows
    assert len(_prods(conn)) == 2


def test_msrc_local_files_sorted_by_release_date(tmp_path):
    (tmp_path / "a-newer.json").write_text(json.dumps(FEB))
    (tmp_path / "b-older.json").write_text(json.dumps(JAN))
    assert [n for n, _ in msrc._local_docs(tmp_path)] == ["b-older.json", "a-newer.json"]


def test_msrc_download_skips_months_before_cursor(conn, monkeypatch):
    fetched = []

    def handler(req):
        p = req.url.path
        if p.endswith("/updates"):
            return httpx.Response(200, json={"value": [
                {"ID": "2024-Jan", "CurrentReleaseDate": "2024-01-09T08:00:00Z", "CvrfUrl": "https://x/jan"},
                {"ID": "2024-Feb", "CurrentReleaseDate": "2024-02-13T08:00:00Z", "CvrfUrl": "https://x/feb"}]})
        fetched.append(p)
        return httpx.Response(200, json=JAN if p.endswith("jan") else FEB)

    mock_http(monkeypatch, msrc, handler)
    db.set_sync_state(conn, "msrc", status="ok", cursor="2024-01-09T08:00:00Z")
    res = msrc.MsrcSource().sync(conn, SyncOptions())
    assert fetched == ["/feb"] and res.records == 1


# =========================================================================== NVD


def _page(vulns):
    return {"resultsPerPage": 2000, "startIndex": 0, "totalResults": len(vulns),
            "vulnerabilities": [{"cve": v} for v in vulns]}


@pytest.fixture
def nvd_cve(fixtures):
    return json.loads((fixtures / "nvd" / "cve-2021-44228.json").read_text())["vulnerabilities"][0]["cve"]


@pytest.fixture
def sleeps(monkeypatch):
    got: list[float] = []
    monkeypatch.setattr(nvd.time, "sleep", got.append)
    return got


def test_nvd_end_only_bounds_get_introduced_zero(conn):
    for key, cid in (("versionEndExcluding", "CVE-1"), ("versionEndIncluding", "CVE-2")):
        nvd._add_cpe(conn, cid, {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", key: "120.0"})
    got = {r["vuln_id"]: json.loads(r["events"]) for r in rows(conn, "SELECT * FROM affected")}
    assert got["CVE-1"] == [{"introduced": "0"}, {"fixed": "120.0"}]
    assert got["CVE-2"] == [{"introduced": "0"}, {"last_affected": "120.0"}]


def test_nvd_update_field_is_unmatchable_and_dedupe(conn, nvd_cve):
    nvd._add_cpe(conn, "CVE-X", {"vulnerable": True, "criteria": "cpe:2.3:a:g:chrome:1.0:rc1:*:*:*:*:*:*"})
    r = rows(conn, "SELECT range_type, extra FROM affected")[0]
    assert r["range_type"] == "CVE-UNPARSED" and json.loads(r["extra"])["cpe_update"] == "rc1"
    c = copy.deepcopy(nvd_cve)
    cm = c["configurations"][0]["nodes"][0]["cpeMatch"][0]
    c["configurations"].append({"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [cm]}]})
    conn.execute("DELETE FROM affected")
    nvd._store_cve(conn, c)
    n = rows(conn, "SELECT COUNT(*) n, COUNT(DISTINCT json_extract(extra,'$.matchCriteriaId')) d FROM affected")[0]
    assert n["n"] == n["d"]


def test_nvd_rejected_replaces_children_and_marks_withdrawn(conn, nvd_cve):
    nvd._store_cve(conn, nvd_cve)
    assert rows(conn, "SELECT COUNT(*) n FROM affected")[0]["n"] > 0
    rej = copy.deepcopy(nvd_cve)
    rej["vulnStatus"], rej["lastModified"] = "Rejected", "2026-11-01T00:00:00.000"
    assert nvd._store_cve(conn, rej) is False
    v = rows(conn, "SELECT state, withdrawn, modified FROM vulnerability")[0]
    assert v == {"state": "REJECTED", "withdrawn": "2026-11-01T00:00:00.000", "modified": "2026-11-01T00:00:00.000"}
    assert rows(conn, "SELECT COUNT(*) n FROM affected")[0]["n"] == 0


def test_nvd_best_cvss_primary_beats_secondary_v4():
    metrics = {
        "cvssMetricV40": [{"type": "Secondary", "cvssData": {"version": "4.0", "vectorString": "v4", "baseScore": 6.9,
                                                              "baseSeverity": "MEDIUM"}}],
        "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "v3", "baseScore": 10.0,
                                                            "baseSeverity": "CRITICAL"}}],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
    }
    assert nvd._best_cvss(metrics) == (10.0, "v3", "3.1", "CRITICAL")
    del metrics["cvssMetricV31"]
    assert nvd._best_cvss(metrics)[2] == "2.0"                      # Primary v2 still beats Secondary v4
    metrics["cvssMetricV2"] = []
    assert nvd._best_cvss(metrics)[2] == "4.0"


def test_nvd_retries_throttling_with_retry_after(conn, nvd_cve, monkeypatch, sleeps):
    calls = []

    def handler(req):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        if len(calls) == 2:
            return httpx.Response(503)
        if len(calls) == 3:
            return httpx.Response(403)
        return httpx.Response(200, json=_page([nvd_cve]))

    mock_http(monkeypatch, nvd, handler)
    res = nvd.NvdSource().sync(conn, SyncOptions(full=True))
    assert res.status == "ok" and res.records == 1 and len(calls) == 4
    assert 7.0 in sleeps and nvd.BACKOFF_BASE * 2 in sleeps and nvd.BACKOFF_BASE * 4 in sleeps


def test_nvd_gives_up_after_max_retries(conn, monkeypatch, sleeps):
    mock_http(monkeypatch, nvd, lambda req: httpx.Response(503))
    res = nvd.NvdSource().sync(conn, SyncOptions(full=True))
    assert res.status == "error" and "503" in res.message


def test_nvd_partial_failure_keeps_completed_windows(conn, nvd_cve, monkeypatch, sleeps):
    monkeypatch.setattr(nvd, "MAX_RETRIES", 0)
    conn.execute("INSERT INTO source_sync(source,cursor,status) VALUES('nvd','2025-01-01T00:00:00.000Z','ok')")
    conn.commit()
    calls: list[dict] = []

    def handler(req):
        calls.append(dict(req.url.params))
        if len(calls) == 3:
            return httpx.Response(503)
        c = copy.deepcopy(nvd_cve)
        c["id"] = f"CVE-2026-{len(calls)}"
        return httpx.Response(200, json=_page([c]))

    mock_http(monkeypatch, nvd, handler)
    res = nvd.NvdSource().sync(conn, SyncOptions())
    assert res.status == "partial" and res.records == 2
    assert res.cursor == calls[1]["lastModEndDate"]
    assert rows(conn, "SELECT COUNT(*) n FROM vulnerability")[0]["n"] == 2
    assert rows(conn, "SELECT cursor FROM source_sync WHERE source='nvd:progress'")[0]["cursor"] == res.cursor
    # the rerun resumes after the completed windows instead of redoing them
    calls.clear()
    mock_http(monkeypatch, nvd, lambda req: calls.append(dict(req.url.params)) or httpx.Response(200, json=_page([])))
    nvd.NvdSource().sync(conn, SyncOptions())
    assert calls[0]["lastModStartDate"] == res.cursor


def test_nvd_since_accepts_year_and_never_skips_a_gap(conn, monkeypatch, sleeps):
    mock_http(monkeypatch, nvd, lambda req: httpx.Response(200, json=_page([])))
    assert nvd.parse_since("2020") == datetime(2020, 1, 1, tzinfo=UTC)
    assert nvd.parse_since("2020-05-17") == datetime(2020, 5, 17, tzinfo=UTC)
    # no stored cursor: a --since pull cannot claim the whole history
    res = nvd.NvdSource().sync(conn, SyncOptions(since="2026-10-01"))
    assert res.status == "ok" and res.cursor is None
    conn.execute("INSERT INTO source_sync(source,cursor,status) VALUES('nvd','2025-01-01T00:00:00.000Z','ok')")
    # since newer than the stored cursor would leave an unsynced gap: cursor must not move
    assert nvd.NvdSource().sync(conn, SyncOptions(since="2026-10-01T00:00:00Z")).cursor is None
    # since older than the stored cursor re-covers it: cursor advances
    res = nvd.NvdSource().sync(conn, SyncOptions(since="2024"))
    assert res.cursor is not None and res.status == "ok"
    assert rows(conn, "SELECT cursor FROM source_sync WHERE source='nvd'")[0]["cursor"] == "2025-01-01T00:00:00.000Z"


def test_nvd_limit_is_honored(conn, nvd_cve, monkeypatch, sleeps):
    mock_http(monkeypatch, nvd, lambda req: httpx.Response(
        200, json=_page([dict(nvd_cve, id=f"CVE-2026-{i}") for i in range(1, 6)])))
    res = nvd.NvdSource().sync(conn, SyncOptions(full=True, limit=2))
    assert res.records == 2 and res.status == "partial" and res.cursor is None
    assert rows(conn, "SELECT COUNT(*) n FROM vulnerability")[0]["n"] == 2


def test_nvd_never_follows_redirects_with_api_key(conn, monkeypatch, sleeps):
    assert nvd._NvdClient("k")._http.follow_redirects is False
    seen = []

    def handler(req):
        seen.append(req.url.host)
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    mock_http(monkeypatch, nvd, handler)
    res = nvd.NvdSource().sync(conn, SyncOptions(full=True, api_key="SECRET"))
    assert res.status == "error" and seen == ["services.nvd.nist.gov"]


def test_nvd_renormalize_from_raw(conn, nvd_cve):
    nvd._store_cve(conn, nvd_cve)
    n = rows(conn, "SELECT COUNT(*) n FROM affected")[0]["n"]
    conn.execute("DELETE FROM affected")
    assert nvd.renormalize(conn) == 1
    assert rows(conn, "SELECT COUNT(*) n FROM affected")[0]["n"] == n


# =========================================================================== EPSS / KEV / EUVD / Debian


EPSS_TEXT = ("#model_version:v2025.03.14,score_date:2026-11-07T12:55:00Z\ncve,epss,percentile\n"
             + "".join(f"CVE-2024-{1000 + i},0.01,0.9\n" for i in range(50)))


def test_epss_truncated_or_corrupt_gzip_is_an_error(conn, tmp_path):
    gz = gzip.compress(EPSS_TEXT.encode())
    (tmp_path / "cut.csv.gz").write_bytes(gz[:-14])
    res = epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "cut.csv.gz"))
    assert res.status == "error" and "truncated" in res.message
    assert rows(conn, "SELECT COUNT(*) n FROM epss")[0]["n"] == 0                   # rolled back
    (tmp_path / "bad.csv.gz").write_bytes(b"\x1f\x8b" + b"garbage" * 20)
    assert epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "bad.csv.gz")).status == "error"
    (tmp_path / "ok.csv.gz").write_bytes(gz)
    res = epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "ok.csv.gz"))
    assert res.status == "ok" and res.records == 50 and res.cursor == "2026-11-07"


def test_epss_guard_refuses_tiny_file_unless_full(conn, tmp_path):
    (tmp_path / "big.csv").write_text(EPSS_TEXT)
    epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "big.csv"))
    (tmp_path / "tiny.csv").write_text("cve,epss,percentile\nCVE-2099-1,0.5,0.5\n")
    res = epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "tiny.csv"))
    assert res.status == "error" and "refusing" in res.message
    assert rows(conn, "SELECT COUNT(*) n FROM epss")[0]["n"] == 50
    (tmp_path / "empty.csv").write_text("cve,epss,percentile\n")
    assert epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "empty.csv", full=True)).status == "error"
    assert epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "tiny.csv", full=True)).status == "ok"


def test_epss_caps_decompressed_size_and_line_length(conn, tmp_path, monkeypatch):
    (tmp_path / "bomb.csv.gz").write_bytes(gzip.compress(b"0" * 200_000))
    monkeypatch.setattr(epss, "MAX_DECOMPRESSED", 10_000)
    res = epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "bomb.csv.gz"))
    assert res.status == "error" and "limit" in res.message
    monkeypatch.setattr(epss, "MAX_DECOMPRESSED", 1 << 30)
    monkeypatch.setattr(epss, "MAX_LINE", 100)
    (tmp_path / "long.csv").write_text("cve,epss,percentile\n" + "A" * 500 + "\n")
    assert epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "long.csv")).status == "error"


def test_epss_limit_honored(conn, tmp_path):
    (tmp_path / "e.csv").write_text(EPSS_TEXT)
    res = epss.EpssSource().sync(conn, SyncOptions(path=tmp_path / "e.csv", limit=5))
    assert res.records == 5 and res.status == "partial" and res.cursor is None


def _kev_doc(n):
    return {"catalogVersion": "v", "count": n, "vulnerabilities": [
        {"cveID": f"CVE-2024-{i}", "vendorProject": "v", "product": "p", "vulnerabilityName": "n",
         "dateAdded": "2024-01-01", "dueDate": "2024-02-01", "knownRansomwareCampaignUse": "Unknown"}
        for i in range(n)]}


def test_kev_guard_and_limit(conn, tmp_path):
    big, small, empty = (tmp_path / f"{n}.json" for n in ("big", "small", "empty"))
    big.write_text(json.dumps(_kev_doc(10)))
    small.write_text(json.dumps(_kev_doc(2)))
    empty.write_text(json.dumps(_kev_doc(0)))
    assert kev.KevSource().sync(conn, SyncOptions(path=big)).status == "ok"
    for p in (empty, small):
        res = kev.KevSource().sync(conn, SyncOptions(path=p))
        assert res.status == "error" and "refusing" in res.message
        assert rows(conn, "SELECT COUNT(*) n FROM kev")[0]["n"] == 10
    res = kev.KevSource().sync(conn, SyncOptions(path=small, limit=1))        # subset upsert, no replace
    assert res.status == "partial" and rows(conn, "SELECT COUNT(*) n FROM kev")[0]["n"] == 10
    assert kev.KevSource().sync(conn, SyncOptions(path=small, full=True)).status == "ok"
    assert rows(conn, "SELECT COUNT(*) n FROM kev")[0]["n"] == 2


def test_euvd_refreshes_its_own_epss_but_not_first(conn, fixtures, tmp_path):
    rec = json.loads((fixtures / "euvd" / "exploited-sample.json").read_text())["items"][0]
    a = tmp_path / "a.json"
    a.write_text(json.dumps([rec]))
    euvd.EuvdSource().sync(conn, SyncOptions(path=a))
    first = rows(conn, "SELECT cve_id, score, source FROM epss")
    assert first and first[0]["source"] == "euvd"
    cve = first[0]["cve_id"]
    b = tmp_path / "b.json"
    b.write_text(json.dumps([dict(rec, epss=0.10, dateUpdated="2026-11-07T00:00:00.000Z")]))
    euvd.EuvdSource().sync(conn, SyncOptions(path=b))
    got = rows(conn, "SELECT score, date FROM epss WHERE cve_id=?", cve)[0]
    assert got == {"score": 0.10, "date": "2026-11-07"}
    conn.execute("UPDATE epss SET source='epss', score=0.9 WHERE cve_id=?", (cve,))
    b.write_text(json.dumps([dict(rec, epss=0.55)]))
    euvd.EuvdSource().sync(conn, SyncOptions(path=b))
    assert rows(conn, "SELECT score FROM epss WHERE cve_id=?", cve)[0]["score"] == 0.9
    assert euvd.EuvdSource().sync(conn, SyncOptions(path=b, limit=1)).records == 1


def test_debian_guard_errors_and_limit(conn, fixtures, tmp_path):
    fx = fixtures / "debian-tracker" / "tracker-sample.json"
    assert dt.DebianTrackerSource().sync(conn, SyncOptions(path=fx)).status == "ok"
    n = rows(conn, "SELECT COUNT(*) n FROM distro_triage")[0]["n"]
    (tmp_path / "empty.json").write_text("{}")
    res = dt.DebianTrackerSource().sync(conn, SyncOptions(path=tmp_path / "empty.json"))
    assert res.status == "error" and "refusing" in res.message
    assert rows(conn, "SELECT COUNT(*) n FROM distro_triage")[0]["n"] == n
    res = dt.DebianTrackerSource().sync(conn, SyncOptions(path=fx, limit=1))     # subset: no wipe
    assert res.status == "partial" and rows(conn, "SELECT COUNT(*) n FROM distro_triage")[0]["n"] == n
    (tmp_path / "odd.json").write_text(json.dumps({"openssl": {"CVE-2024-1": "not-a-dict"}}))
    assert dt.DebianTrackerSource().sync(conn, SyncOptions(path=tmp_path / "odd.json")).status == "error"


def test_debian_truncated_or_bomb_archives_are_errors(conn, fixtures, tmp_path, monkeypatch):
    fx = fixtures / "debian-tracker" / "tracker-sample.json"
    raw = fx.read_bytes()
    (tmp_path / "t.json.xz").write_bytes(lzma.compress(raw)[:-30])
    res = dt.DebianTrackerSource().sync(conn, SyncOptions(path=tmp_path / "t.json.xz"))
    assert res.status == "error" and "truncated" in res.message
    (tmp_path / "t.json.gz").write_bytes(gzip.compress(raw)[:-20])
    assert dt.DebianTrackerSource().sync(conn, SyncOptions(path=tmp_path / "t.json.gz")).status == "error"
    import bz2
    (tmp_path / "t.json.bz2").write_bytes(bz2.compress(raw)[:-20])
    assert dt.DebianTrackerSource().sync(conn, SyncOptions(path=tmp_path / "t.json.bz2")).status == "error"
    monkeypatch.setattr(dt, "MAX_DECOMPRESSED", 100)
    (tmp_path / "ok.json.gz").write_bytes(gzip.compress(raw))
    res = dt.DebianTrackerSource().sync(conn, SyncOptions(path=tmp_path / "ok.json.gz"))
    assert res.status == "error" and "limit" in res.message


def test_decompress_stream_roundtrip_all_formats():
    import bz2
    data = os.urandom(10) * 100_000
    for fmt, blob in (("gz", gzip.compress(data)), ("bz2", bz2.compress(data)), ("xz", lzma.compress(data))):
        chunks = [blob[i:i + 777] for i in range(0, len(blob), 777)]
        assert b"".join(base.decompress_stream(chunks, fmt, 10**9)) == data
        with pytest.raises(base.DecompressError):
            b"".join(base.decompress_stream([blob[:-5]], fmt, 10**9))
        with pytest.raises(base.DecompressError):
            b"".join(base.decompress_stream([blob], fmt, 1000))
