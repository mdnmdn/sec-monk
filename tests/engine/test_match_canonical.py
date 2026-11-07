"""Canonicalization, dedupe and finding lifecycle regressions (review E2, E3, E9, E10, E12, E13, E18)."""

from __future__ import annotations

import json

import pytest

from secmonk.engine import match as M
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import canonical_ids, match_asset
from secmonk.engine.scoring import priority
from secmonk.models import CAT_LIBRARY, CAT_OS_PACKAGE, CAT_PACKAGE, Asset, Component, Inventory
from secmonk.sources.base import add_affected, add_alias, upsert_vulnerability
from secmonk.sources.cvelist import import_record as cve_import
from secmonk.sources.osv import import_record


def _inv(conn, comps, aid="t:1", meta=None):
    save_inventory(conn, Inventory(Asset(aid, "server", "t", meta=meta or {}), "test", comps))


def _findings(conn, aid="t:1", status=None):
    rows = [dict(r) for r in conn.execute(
        "SELECT vuln_id, advisory_ids, fixed_version, priority, status, triage FROM finding WHERE asset_id=? "
        "ORDER BY vuln_id, status", (aid,))]
    return [r for r in rows if status is None or r["status"] == status]


def _alias(conn, vid, alias, kind="alias"):
    add_alias(conn, "osv", vid, alias, kind=kind)


def _has_kind(conn):
    if not M._alias_has_kind(conn):
        pytest.skip("alias.kind column not present yet")


# --------------------------------------------------------------------------- E2

def _rhsa(conn, rid, cves, fixed):
    upsert_vulnerability(conn, "osv", rid, cvss_score=7.5)
    for c in cves:
        _alias(conn, rid, c, kind="upstream")
    add_affected(conn, "osv", rid, ecosystem="Red Hat:10", package="hplip", range_type="ECOSYSTEM",
                 events=[{"introduced": "0"}, {"fixed": fixed}])


def _hplip(v):
    return [Component("hplip", v, CAT_OS_PACKAGE, ecosystem="Red Hat:10", purl=f"pkg:rpm/redhat/hplip@{v}",
                      meta={"source_package": "hplip", "source_version": v})]


def test_upstream_cves_are_separate_findings(conn):
    _has_kind(conn)
    _rhsa(conn, "RHSA-2099:0001", ["CVE-2099-0001", "CVE-2099-0002"], "0:3.23.12-10.el10")
    _rhsa(conn, "RHSA-2099:0002", ["CVE-2099-0002", "CVE-2099-0003"], "0:3.23.12-20.el10")
    _inv(conn, _hplip("0:3.23.12-15.el10"))
    match_asset(conn, "t:1")
    assert [(f["vuln_id"], f["fixed_version"]) for f in _findings(conn)] == [
        ("CVE-2099-0002", "0:3.23.12-20.el10"), ("CVE-2099-0003", "0:3.23.12-20.el10")]

    _inv(conn, _hplip("0:3.23.12-5.el10"), aid="t:2")
    match_asset(conn, "t:2")
    assert [(f["vuln_id"], f["fixed_version"]) for f in _findings(conn, "t:2")] == [
        ("CVE-2099-0001", "0:3.23.12-10.el10"),
        ("CVE-2099-0002", "0:3.23.12-20.el10"),      # both RHSAs needed: highest fix
        ("CVE-2099-0003", "0:3.23.12-20.el10")]

    # a REJECTED sibling only removes its own finding
    upsert_vulnerability(conn, "cvelist", "CVE-2099-0001", state="REJECTED")
    match_asset(conn, "t:2")
    assert [f["vuln_id"] for f in _findings(conn, "t:2", status="open")] == ["CVE-2099-0002", "CVE-2099-0003"]


def test_upstream_edges_do_not_merge_cves_across_assets(conn):
    _has_kind(conn)
    for cid, fixed in [("CVE-2099-0003", "8.10.0"), ("CVE-2099-0005", "8.12.0")]:
        cve_import(conn, {"cveMetadata": {"cveId": cid, "state": "PUBLISHED", "dateUpdated": "2026-01-01"},
                          "containers": {"cna": {"descriptions": [{"lang": "en", "value": "x"}], "affected": [
                              {"vendor": "haxx", "product": "curl", "versions": [
                                  {"version": "7.0", "lessThan": fixed, "status": "affected",
                                   "versionType": "semver"}]}]}}})
    _inv(conn, [Component("curl", "8.7.1", CAT_PACKAGE, purl="pkg:brew/curl@8.7.1", vendor="haxx",
                          meta={"brew_kind": "formula", "brew_name": "curl"})])
    upsert_vulnerability(conn, "osv", "DSA-9999-1")
    _alias(conn, "DSA-9999-1", "CVE-2099-0003", kind="upstream")
    _alias(conn, "DSA-9999-1", "CVE-2099-0005", kind="upstream")
    match_asset(conn, "t:1")
    assert [(f["vuln_id"], f["fixed_version"], f["status"]) for f in _findings(conn)] == [
        ("CVE-2099-0003", "8.10.0", "open"), ("CVE-2099-0005", "8.12.0", "open")]
    assert "DSA-9999-1" not in canonical_ids(conn, "CVE-2099-0003")[1]


def test_upstream_from_osv_import_is_not_an_alias(conn, fixtures):
    _has_kind(conn)
    rec = json.loads((fixtures / "osv" / "debian-DSA-5562-1.legacy.json").read_text())
    rec.update(id="DSA-9999-1", upstream=["CVE-2099-0003", "CVE-2099-0005"])
    import_record(conn, rec)
    assert canonical_ids(conn, "CVE-2099-0003") == ("CVE-2099-0003", {"CVE-2099-0003"})


def test_advisory_with_two_cve_aliases_yields_two_findings(conn):
    upsert_vulnerability(conn, "osv", "GHSA-2222-2222-2222")
    _alias(conn, "GHSA-2222-2222-2222", "CVE-2099-0011")
    _alias(conn, "GHSA-2222-2222-2222", "CVE-2099-0012")
    add_affected(conn, "osv", "GHSA-2222-2222-2222", ecosystem="PyPI", package="foo", range_type="ECOSYSTEM",
                 events=[{"introduced": "0"}, {"fixed": "2.0"}])
    _inv(conn, [Component("foo", "1.0", CAT_LIBRARY, ecosystem="PyPI", purl="pkg:pypi/foo@1.0")])
    match_asset(conn, "t:1")
    assert [f["vuln_id"] for f in _findings(conn)] == ["CVE-2099-0011", "CVE-2099-0012"]


def test_canonical_ids_is_deterministic_and_follows_alias_edges_only(conn):
    _alias(conn, "GHSA-aaaa-aaaa-aaaa", "CVE-2099-0002")
    _alias(conn, "PYSEC-2099-1", "GHSA-aaaa-aaaa-aaaa")
    _alias(conn, "PYSEC-2099-1", "CVE-2099-0001")
    if M._alias_has_kind(conn):
        _alias(conn, "PYSEC-2099-1", "CVE-2099-0009", kind="related")
    canon, ids = canonical_ids(conn, "GHSA-aaaa-aaaa-aaaa")
    assert canon == "CVE-2099-0001"
    assert ids == {"GHSA-aaaa-aaaa-aaaa", "PYSEC-2099-1", "CVE-2099-0001", "CVE-2099-0002"}
    assert canonical_ids(conn, "CVE-2099-0002")[0] == "CVE-2099-0002"     # a CVE is its own key
    assert M._canonical is canonical_ids


# --------------------------------------------------------------------------- E3

def test_withdrawn_duplicate_does_not_hide_valid_advisory(conn, fixtures):
    good = json.loads((fixtures / "osv" / "pypi-GHSA-fhq3-2gf3-8f3j.json").read_text())
    import_record(conn, good)
    pkg = good["affected"][0]["package"]["name"]
    _inv(conn, [Component(pkg, "0.0.1", CAT_LIBRARY, ecosystem="PyPI", purl=f"pkg:pypi/{pkg}@0.0.1")])
    import_record(conn, {"id": "GHSA-dup0-dup0-dup0", "modified": "2026-01-01T00:00:00Z",
                         "withdrawn": "2026-01-01T00:00:00Z", "aliases": good["aliases"],
                         "affected": good["affected"]})
    stats = match_asset(conn, "t:1")
    assert stats["withdrawn"] == 0
    assert [f["vuln_id"] for f in _findings(conn, status="open")] == ["CVE-2026-44363"]


def test_finding_dropped_when_all_matched_advisories_withdrawn(conn):
    upsert_vulnerability(conn, "osv", "GHSA-wwww-wwww-wwww", withdrawn="2026-01-01T00:00:00Z")
    _alias(conn, "GHSA-wwww-wwww-wwww", "CVE-2099-0100")
    add_affected(conn, "osv", "GHSA-wwww-wwww-wwww", ecosystem="npm", package="p", range_type="SEMVER",
                 events=[{"introduced": "0"}])
    _inv(conn, [Component("p", "1.0.0", CAT_LIBRARY, ecosystem="npm", purl="pkg:npm/p@1.0.0")])
    assert match_asset(conn, "t:1")["withdrawn"] == 1
    assert _findings(conn) == []


def test_rejected_cve_drops_finding_case_insensitive(conn):
    upsert_vulnerability(conn, "osv", "GHSA-rrrr-rrrr-rrrr")
    _alias(conn, "GHSA-rrrr-rrrr-rrrr", "CVE-2099-0101")
    upsert_vulnerability(conn, "nvd", "CVE-2099-0101", state="Rejected")
    add_affected(conn, "osv", "GHSA-rrrr-rrrr-rrrr", ecosystem="npm", package="p", range_type="SEMVER",
                 events=[{"introduced": "0"}])
    _inv(conn, [Component("p", "1.0.0", CAT_LIBRARY, ecosystem="npm", purl="pkg:npm/p@1.0.0")])
    assert match_asset(conn, "t:1")["withdrawn"] == 1


# --------------------------------------------------------------------------- E9

def test_severity_label_stands_in_for_missing_cvss(conn):
    meta = {"env": "prod", "internet_facing": True}
    assert priority(cvss=None, epss=None, kev=False, asset_meta=meta, severity="CRITICAL") == "P1"
    assert priority(cvss=None, epss=None, kev=False, severity="HIGH") == "P3"
    assert priority(cvss=None, epss=None, kev=False, severity="LOW") == "P4"
    assert priority(cvss=6.0, epss=None, kev=False, severity="CRITICAL") == "P4"   # score wins
    upsert_vulnerability(conn, "osv", "GHSA-v4v4-v4v4-v4v4", severity="CRITICAL")
    add_affected(conn, "osv", "GHSA-v4v4-v4v4-v4v4", ecosystem="npm", package="left-pad", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "1.3.1"}])
    _inv(conn, [Component("left-pad", "1.3.0", CAT_LIBRARY, ecosystem="npm", purl="pkg:npm/left-pad@1.3.0")],
         meta=meta)
    match_asset(conn, "t:1")
    assert _findings(conn)[0]["priority"] == "P1"


# --------------------------------------------------------------------------- E10

def _leftpad(conn):
    upsert_vulnerability(conn, "osv", "GHSA-aaaa-bbbb-cccc", summary="x")
    add_affected(conn, "osv", "GHSA-aaaa-bbbb-cccc", ecosystem="npm", package="left-pad", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "1.3.1"}])
    _inv(conn, [Component("left-pad", "1.3.0", CAT_LIBRARY, ecosystem="npm", purl="pkg:npm/left-pad@1.3.0")])
    match_asset(conn, "t:1")


@pytest.mark.parametrize("status", ["suppressed", "open"])
def test_canonical_drift_rekeys_existing_finding(conn, status):
    _leftpad(conn)
    conn.execute("UPDATE finding SET status=?, first_seen='2020-01-01'", (status,))
    conn.commit()
    _alias(conn, "GHSA-aaaa-bbbb-cccc", "CVE-2099-7000")
    conn.commit()
    match_asset(conn, "t:1")
    rows = [dict(r) for r in conn.execute("SELECT vuln_id, status, first_seen FROM finding")]
    assert rows == [{"vuln_id": "CVE-2099-7000", "status": status, "first_seen": "2020-01-01"}]


# --------------------------------------------------------------------------- E12 / E13

@pytest.mark.parametrize("order", [
    [("DEBIAN-CVE-2099-1100", "unimportant"), ("DLA-9999-1", None)],
    [("DLA-9999-1", None), ("DEBIAN-CVE-2099-1100", "unimportant")],
])
def test_urgency_survives_merge_in_any_order(conn, order):
    upsert_vulnerability(conn, "nvd", "CVE-2099-1100", cvss_score=9.8)
    for vid, urg in order:
        upsert_vulnerability(conn, "osv", vid)
        _alias(conn, vid, "CVE-2099-1100")
        add_affected(conn, "osv", vid, ecosystem="Debian:12", package="glibc", range_type="ECOSYSTEM",
                     events=[{"introduced": "0"}], extra={"urgency": urg} if urg else None)
    _inv(conn, [Component("libc6", "2.36-9", CAT_OS_PACKAGE, ecosystem="Debian:12",
                          purl="pkg:deb/debian/libc6@2.36-9",
                          meta={"source_package": "glibc", "source_version": "2.36-9"})],
         meta={"internet_facing": True})
    match_asset(conn, "t:1")
    f = _findings(conn)[0]
    assert (f["vuln_id"], f["triage"], f["priority"]) == ("CVE-2099-1100", "unimportant", "P4")


def test_merged_fixed_version_is_the_highest(conn):
    for vid, fixed in [("GHSA-1111-1111-1111", "1.3.1"), ("PYSEC-2099-1", "1.4.0"), ("OSV-2099-1", "1.10.0")]:
        upsert_vulnerability(conn, "osv", vid)
        _alias(conn, vid, "CVE-2099-8000")
        add_affected(conn, "osv", vid, ecosystem="PyPI", package="foo", range_type="ECOSYSTEM",
                     events=[{"introduced": "0"}, {"fixed": fixed}])
    _inv(conn, [Component("foo", "1.0", CAT_LIBRARY, ecosystem="PyPI", purl="pkg:pypi/foo@1.0")])
    match_asset(conn, "t:1")
    assert [(f["vuln_id"], f["fixed_version"]) for f in _findings(conn)] == [("CVE-2099-8000", "1.10.0")]


# --------------------------------------------------------------------------- E18

def test_canonicalization_is_cached_per_alias_component(conn):
    for i in range(30):
        vid = f"GHSA-{i:04d}-0000-0000"
        upsert_vulnerability(conn, "osv", vid)
        _alias(conn, vid, "CVE-2099-0001")
        add_affected(conn, "osv", vid, ecosystem="npm", package="p", range_type="SEMVER",
                     events=[{"introduced": "0"}])
    _inv(conn, [Component("p", "1.0.0", CAT_LIBRARY, ecosystem="npm", purl="pkg:npm/p@1.0.0")])
    cache: dict = {}
    canonical_ids(conn, "GHSA-0000-0000-0000", cache=cache)
    assert len(cache) == 31 and all(v[0] == "CVE-2099-0001" for v in cache.values())
    alias_queries = []
    conn.set_trace_callback(lambda sql: alias_queries.append(sql) if "FROM alias WHERE vuln_id" in sql
                            and "UNION" in sql else None)
    assert match_asset(conn, "t:1")["findings"] == 1
    conn.set_trace_callback(None)
    assert len(alias_queries) == 31          # one BFS over the 31-node component, nothing more
