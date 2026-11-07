"""Distro triage: OSV urgency + distro_triage rows drive dropping and priority caps."""

from __future__ import annotations

import json

import pytest

from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.engine.scoring import priority
from secmonk.models import CAT_OS_PACKAGE, Asset, Component, Inventory
from secmonk.sources.base import add_affected, upsert_vulnerability
from secmonk.sources.osv import import_record


@pytest.mark.parametrize("triage,kev,cvss,expected", [
    ("unimportant", False, 9.8, "P4"),
    ("end-of-life", False, 9.8, "P4"),
    ("ignored", False, 7.5, "P4"),
    ("no-dsa", False, 9.8, "P3"),        # cvss 9 not exposed -> P3 anyway; cap keeps it
    ("postponed", False, 9.8, "P3"),
    ("unimportant", True, 9.8, "P1"),    # KEV always wins
    (None, False, 9.8, "P3"),
    ("medium", False, 9.8, "P3"),
])
def test_priority_caps(triage, kev, cvss, expected):
    assert priority(cvss=cvss, epss=0.0, kev=kev, triage=triage) == expected


def test_deferred_caps_an_exposed_critical():
    meta = {"exposed": True}
    assert priority(cvss=9.8, epss=0.5, kev=False, asset_meta=meta) == "P1"
    assert priority(cvss=9.8, epss=0.5, kev=False, asset_meta=meta, triage="no-dsa") == "P3"


def test_osv_import_keeps_debian_urgency(conn, fixtures):
    rec = json.loads((fixtures / "osv" / "debian-DEBIAN-CVE-2024-2199.json").read_text())
    import_record(conn, rec)
    urg = {json.loads(r["extra"]).get("urgency") for r in conn.execute(
        "SELECT extra FROM affected WHERE vuln_id='DEBIAN-CVE-2024-2199' AND range_type='ECOSYSTEM'")}
    assert urg == {"not yet assigned"}


def _setup(conn, urgency: str | None, version="2.36-9+deb12u7"):
    upsert_vulnerability(conn, "osv", "DEBIAN-CVE-2099-0001", summary="test", cvss_score=9.8, severity="CRITICAL")
    conn.execute("INSERT INTO alias(vuln_id, alias, source) VALUES ('DEBIAN-CVE-2099-0001','CVE-2099-0001','osv')")
    add_affected(conn, "osv", "DEBIAN-CVE-2099-0001", ecosystem="Debian:12", package="glibc", range_type="ECOSYSTEM",
                 events=[{"introduced": "0"}], extra={"urgency": urgency} if urgency else None)
    inv = Inventory(Asset("t:1", "server", "t"), "test", [Component(
        "libc6", version, CAT_OS_PACKAGE, ecosystem="Debian:12",
        purl=f"pkg:deb/debian/libc6@{version}?distro=debian-12",
        meta={"source_package": "glibc", "source_version": version})])
    save_inventory(conn, inv)


def _finding(conn):
    return conn.execute("SELECT * FROM finding WHERE asset_id='t:1' AND status='open'").fetchone()


def test_osv_urgency_lands_on_finding(conn):
    _setup(conn, "unimportant")
    match_asset(conn, "t:1")
    f = _finding(conn)
    assert f["vuln_id"] == "CVE-2099-0001" and f["triage"] == "unimportant" and f["triage_source"] == "osv"
    assert f["priority"] == "P4"


def _triage_row(conn, **kw):
    row = {"ecosystem": "Debian:12", "package": "glibc", "cve_id": "CVE-2099-0001", "status": "open",
           "urgency": None, "fixed_version": None, "nodsa": None, "note": None, "advisory": None,
           "source": "debian-tracker", **kw}
    conn.execute(f"INSERT INTO distro_triage({','.join(row)}) VALUES ({','.join('?' * len(row))})",
                 tuple(row.values()))


def test_tracker_nodsa_overrides_osv_urgency(conn):
    _setup(conn, "not yet assigned")
    _triage_row(conn, nodsa="no-dsa", urgency="low")
    match_asset(conn, "t:1")
    f = _finding(conn)
    assert f["triage"] == "no-dsa" and f["triage_source"] == "debian-tracker" and f["priority"] == "P3"


def test_tracker_not_affected_drops_finding(conn):
    _setup(conn, None)
    _triage_row(conn, status="not-affected", fixed_version="0")
    stats = match_asset(conn, "t:1")
    assert _finding(conn) is None and stats["not_affected"] == 1


def test_tracker_fixed_version_already_installed_drops_finding(conn):
    _setup(conn, None, version="2.36-9+deb12u9")
    _triage_row(conn, status="resolved", fixed_version="2.36-9+deb12u8")
    match_asset(conn, "t:1")
    assert _finding(conn) is None


def test_tracker_fixed_in_newer_version_keeps_finding(conn):
    _setup(conn, None, version="2.36-9+deb12u7")
    _triage_row(conn, status="resolved", fixed_version="2.36-9+deb12u8", urgency="medium")
    match_asset(conn, "t:1")
    f = _finding(conn)
    assert f is not None and f["triage"] == "medium"


def test_debian_tracker_source_feeds_matcher(conn, fixtures):
    """End to end: tracker JSON -> distro_triage -> finding triage label (tracker beats OSV)."""
    from secmonk.sources.base import SyncOptions
    from secmonk.sources.debian_tracker import DebianTrackerSource

    res = DebianTrackerSource().sync(conn, SyncOptions(path=fixtures / "debian-tracker" / "tracker-sample.json"))
    assert res.status == "ok"
    upsert_vulnerability(conn, "osv", "DEBIAN-CVE-2019-1010022", summary="glibc", cvss_score=9.8)
    conn.execute("INSERT INTO alias(vuln_id, alias, source) VALUES ('DEBIAN-CVE-2019-1010022','CVE-2019-1010022','osv')")
    add_affected(conn, "osv", "DEBIAN-CVE-2019-1010022", ecosystem="Debian:12", package="glibc",
                 range_type="ECOSYSTEM", events=[{"introduced": "0"}], extra={"urgency": "not yet assigned"})
    v = "2.36-9+deb12u7"
    save_inventory(conn, Inventory(Asset("t:2", "server", "t"), "test", [Component(
        "libc6", v, CAT_OS_PACKAGE, ecosystem="Debian:12", purl=f"pkg:deb/debian/libc6@{v}?distro=debian-12",
        meta={"source_package": "glibc", "source_version": v})]))
    match_asset(conn, "t:2")
    f = conn.execute("SELECT * FROM finding WHERE asset_id='t:2'").fetchone()
    assert f["triage"] == "unimportant" and f["triage_source"] == "debian-tracker" and f["priority"] == "P4"


def test_per_asset_paths_and_meta_are_not_shared(conn):
    """Two copies on one asset keep both paths; a second asset does not overwrite the first's meta."""
    from secmonk.engine.inventory import current_components
    from secmonk.models import CAT_APPLICATION

    def app(path, users):
        return Component("Foo", "1.0", CAT_APPLICATION, source_path=path, meta={"users": users})

    save_inventory(conn, Inventory(Asset("a:1", "desktop", "a"), "test",
                                   [app("/Applications/Foo.app", ["alice"]), app("/Users/bob/Applications/Foo.app", ["bob"])]))
    save_inventory(conn, Inventory(Asset("a:2", "desktop", "b"), "test", [app("/Applications/Foo.app", ["carol"])]))
    row = current_components(conn, "a:1")[0]
    assert json.loads(row["paths"]) == ["/Applications/Foo.app", "/Users/bob/Applications/Foo.app"]
    assert json.loads(row["asset_meta"])["users"] == ["alice"]
    assert json.loads(current_components(conn, "a:2")[0]["asset_meta"])["users"] == ["carol"]
