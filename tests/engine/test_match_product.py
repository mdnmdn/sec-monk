"""Name-based (CVE/CPE) matching regressions (review E5, E11, E15)."""

from __future__ import annotations

import pytest

from secmonk.engine.classify import brew_seed, classify
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.models import CAT_APPLICATION, CAT_OS, CAT_PACKAGE, Asset, Component, Inventory
from secmonk.sources import nvd
from secmonk.sources.base import add_affected, upsert_vulnerability
from secmonk.sources.cvelist import import_record as cve_import


def _inv(conn, comps, aid="t:1"):
    save_inventory(conn, Inventory(Asset(aid, "server", "t"), "test", comps))


def _findings(conn):
    return [tuple(r) for r in conn.execute(
        "SELECT vuln_id, fixed_version, confidence FROM finding WHERE status='open' ORDER BY vuln_id")]


def _nvd(conn, cid, criteria, lo, hi):
    nvd._store_cve(conn, {"id": cid, "vulnStatus": "Analyzed", "metrics": {}, "descriptions": [],
                          "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                              "vulnerable": True, "criteria": criteria,
                              "versionStartIncluding": lo, "versionEndExcluding": hi}]}]}]})


def _brew(name, version):
    return Component(name, version, CAT_PACKAGE, purl=f"pkg:brew/{name}@{version}",
                     meta={"brew_kind": "formula", "brew_name": name})


# --------------------------------------------------------------------------- E5

def test_brew_seed_is_normalized_like_affected_rows():
    rows = brew_seed()
    assert rows["krb5"][0]["product"] == "kerberos 5"
    assert {r["vendor"] for r in rows["lz4"]} == {"lz4 project"}
    assert all("_" not in r["vendor"] + r["product"] for rs in rows.values() for r in rs)
    c = classify(_brew("krb5", "1.21.2"))
    assert (c.vendor, c.meta["product"]) == ("mit", "kerberos 5")
    assert c.cpe.startswith("cpe:2.3:a:mit:kerberos_5:1.21.2:")


@pytest.mark.parametrize("formula,version,criteria,lo,hi", [
    ("httpd", "2.4.57", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "2.4.0", "2.4.58"),
    ("expat", "2.5.0", "cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*", "2.0.0", "2.6.0"),
    ("krb5", "1.21.2", "cpe:2.3:a:mit:kerberos_5:*:*:*:*:*:*:*:*", "1.0", "1.21.3"),
    ("lz4", "1.9.3", "cpe:2.3:a:lz4_project:lz4:*:*:*:*:*:*:*:*", "1.0", "1.9.4"),
])
def test_brew_seed_with_underscores_matches_cpe_rows(conn, formula, version, criteria, lo, hi):
    _nvd(conn, "CVE-2099-3000", criteria, lo, hi)
    _inv(conn, [_brew(formula, version)])
    match_asset(conn, "t:1")
    assert _findings(conn) == [("CVE-2099-3000", hi, 0.85)]


def test_component_vendor_with_underscore_is_normalized(conn):
    _nvd(conn, "CVE-2099-3010", "cpe:2.3:a:lz4_project:lz4:*:*:*:*:*:*:*:*", "1.0", "1.9.4")
    _inv(conn, [Component("lz4", "1.9.3", CAT_APPLICATION, vendor="LZ4_Project", meta={"product": "lz4"})])
    match_asset(conn, "t:1")
    assert [f[0] for f in _findings(conn)] == ["CVE-2099-3010"]


# --------------------------------------------------------------------------- E11

def _macos_cve(conn, cid, bounds):
    cve_import(conn, {"cveMetadata": {"cveId": cid, "state": "PUBLISHED", "dateUpdated": "2026-01-01"},
                      "containers": {"cna": {"descriptions": [{"lang": "en", "value": "x"}], "affected": [
                          {"vendor": "Apple", "product": "macOS", "versions": [
                              {"version": "unspecified", "lessThan": b, "status": "affected",
                               "versionType": "custom"}]} for b in bounds]}}})


@pytest.mark.parametrize("version,expected", [
    ("13.6.6", []),                              # Ventura, fully patched
    ("13.6.4", [("CVE-2099-9100", "13.6.5")]),   # Ventura, missing the train fix
    ("14.3", [("CVE-2099-9100", "14.4")]),       # Sonoma
    ("14.4.1", []),
    ("12.7", [("CVE-2099-9100", "13.6.5")]),     # older than every listed train: still affected
])
def test_apple_release_line_entries(conn, version, expected):
    _macos_cve(conn, "CVE-2099-9100", ["14.4", "13.6.5"])
    _inv(conn, [Component("macOS", version, CAT_OS, vendor="apple")])
    match_asset(conn, "t:1")
    assert [f[:2] for f in _findings(conn)] == expected


def test_single_line_entry_unchanged(conn):
    _macos_cve(conn, "CVE-2099-9101", ["14.4"])
    _inv(conn, [Component("macOS", "13.6.6", CAT_OS, vendor="apple")])
    match_asset(conn, "t:1")
    assert [f[0] for f in _findings(conn)] == ["CVE-2099-9101"]


# --------------------------------------------------------------------------- E15

def test_versions_without_digits_never_match(conn):
    upsert_vulnerability(conn, "cvelist", "CVE-2099-9000")
    add_affected(conn, "cvelist", "CVE-2099-9000", vendor="google", product="chrome", range_type="CVE",
                 events=[{"introduced": "0"}, {"fixed": "121"}])
    _inv(conn, [Component("Google Chrome", "Version ??? (beta)", CAT_APPLICATION,
                          meta={"bundle_id": "com.google.Chrome"})])
    match_asset(conn, "t:1")
    assert _findings(conn) == []


def test_unparseable_version_lowers_confidence(conn):
    upsert_vulnerability(conn, "cvelist", "CVE-2099-9001")
    add_affected(conn, "cvelist", "CVE-2099-9001", vendor="google", product="chrome", range_type="CVE",
                 events=[{"introduced": "0"}, {"fixed": "121"}])
    _inv(conn, [Component("Google Chrome", "build 120", CAT_APPLICATION, meta={"bundle_id": "com.google.Chrome"})])
    match_asset(conn, "t:1")
    assert _findings(conn) == [("CVE-2099-9001", "121", 0.6)]
