"""Debian tracker source tests: JSON + repo-text import into distro_triage. No network."""

from __future__ import annotations

import gzip
from pathlib import Path

import httpx
import pytest

from secmonk.sources import debian_tracker as dt
from secmonk.sources.base import SyncOptions

JSON_NAME = "tracker-sample.json"


@pytest.fixture
def jpath(fixtures: Path) -> Path:
    return fixtures / "debian-tracker" / JSON_NAME


@pytest.fixture
def repo(fixtures: Path) -> Path:
    return fixtures / "debian-tracker" / "repo"


def sync(conn, path: Path, **kw):
    res = dt.DebianTrackerSource().sync(conn, SyncOptions(path=path, **kw))
    assert res.status == "ok", res.message
    return res


def row(conn, eco: str, pkg: str, cve: str):
    return conn.execute(
        "SELECT * FROM distro_triage WHERE ecosystem=? AND package=? AND cve_id=?", (eco, pkg, cve)
    ).fetchone()


def test_json_import_counts_and_policy(conn, jpath):
    res = sync(conn, jpath)
    n = conn.execute("SELECT COUNT(*) FROM distro_triage").fetchone()[0]
    assert n == res.records == 33
    assert {r[0] for r in conn.execute("SELECT DISTINCT source FROM distro_triage")} == {"debian-tracker"}
    # sid skipped, TEMP skipped, both reported
    assert conn.execute("SELECT COUNT(*) FROM distro_triage WHERE ecosystem LIKE '%sid%'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM distro_triage WHERE cve_id LIKE 'TEMP-%'").fetchone()[0] == 0
    assert "1 TEMP" in res.message and "sid entries" in res.message
    assert res.cursor and len(res.cursor) == 64


def test_json_codename_mapping_and_open(conn, jpath):
    sync(conn, jpath)
    for eco in ("Debian:11", "Debian:12", "Debian:13", "Debian:14"):
        r = row(conn, eco, "glibc", "CVE-2019-1010022")
        assert (r["status"], r["urgency"], r["fixed_version"], r["nodsa"]) == ("open", "unimportant", None, None)
    assert row(conn, "Debian:10", "linux", "CVE-2024-1086")["urgency"] == "end-of-life"


def test_json_resolved_not_affected_undetermined(conn, jpath):
    sync(conn, jpath)
    r = row(conn, "Debian:12", "openssl", "CVE-2024-5535")
    assert (r["status"], r["fixed_version"], r["advisory"]) == ("resolved", "3.0.14-1~deb12u2", None)
    r = row(conn, "Debian:11", "curl", "CVE-2023-38545")
    assert (r["status"], r["fixed_version"]) == ("not-affected", "0")
    assert row(conn, "Debian:12", "samba", "CVE-2023-4091")["status"] == "undetermined"


def test_json_nodsa_variants(conn, jpath):
    sync(conn, jpath)
    r = row(conn, "Debian:12", "imagemagick", "CVE-2023-34152")
    assert (r["status"], r["nodsa"], r["note"]) == ("open", "no-dsa", "Minor issue")
    r = row(conn, "Debian:11", "tomcat9", "CVE-2024-23672")
    assert (r["nodsa"], r["note"]) == ("postponed", "Fix along with next DSA")
    assert row(conn, "Debian:12", "ruby3.1", "CVE-2023-28755")["nodsa"] == "ignored"
    assert row(conn, "Debian:13", "imagemagick", "CVE-2023-34152")["nodsa"] is None


def test_json_urgency_star_stripped(conn, jpath):
    sync(conn, jpath)
    r = row(conn, "Debian:12", "linux", "CVE-2024-1086")
    assert r["urgency"] == "high"
    assert "'*'" in r["note"]


def test_json_limit_caps_packages(conn, jpath):
    sync(conn, jpath, limit=2)
    assert {r[0] for r in conn.execute("SELECT DISTINCT package FROM distro_triage")} == {"389-ds-base", "apache2"}


def test_gz_and_unsupported_json(conn, jpath, tmp_path):
    gz = tmp_path / "tracker.json.gz"
    gz.write_bytes(gzip.compress(jpath.read_bytes()))
    a = sync(conn, gz)
    b = sync(conn, jpath)
    assert a.records == b.records and a.cursor == b.cursor      # cursor = hash of decompressed content
    bad = tmp_path / "bad.json"
    bad.write_text("[1,2]")
    res = dt.DebianTrackerSource().sync(conn, SyncOptions(path=bad))
    assert res.status == "error"
    assert conn.execute("SELECT COUNT(*) FROM distro_triage").fetchone()[0] == b.records  # untouched


def test_repo_text_forms(conn, repo):
    res = sync(conn, repo)
    assert "1 TEMP" in res.message
    # fixed version, urgency inherited from the sid line
    r = row(conn, "Debian:12", "openssh", "CVE-2024-6387")
    assert (r["status"], r["fixed_version"], r["urgency"]) == ("resolved", "1:9.2p1-2+deb12u3", "high")
    # sid line without urgency -> default
    assert row(conn, "Debian:12", "openssl", "CVE-2024-5535")["urgency"] == "not yet assigned"
    # <not-affected>
    r = row(conn, "Debian:11", "curl", "CVE-2023-38545")
    assert (r["status"], r["fixed_version"], r["note"]) == ("not-affected", "0", "Vulnerable code introduced later")
    # <no-dsa>, <postponed>, <ignored>
    r = row(conn, "Debian:12", "imagemagick", "CVE-2023-34152")
    assert (r["status"], r["nodsa"], r["urgency"], r["note"]) == ("open", "no-dsa", "low", "Minor issue")
    r = row(conn, "Debian:11", "tomcat9", "CVE-2024-23672")
    assert (r["nodsa"], r["urgency"]) == ("postponed", "medium")   # '(medium; bug #...)' on sid
    r = row(conn, "Debian:12", "ruby3.1", "CVE-2023-28755")
    assert (r["nodsa"], r["note"]) == ("ignored", "Minor issue; too intrusive to backport")
    # <end-of-life>
    r = row(conn, "Debian:10", "linux", "CVE-2024-1086")
    assert (r["status"], r["urgency"], r["nodsa"]) == ("open", "end-of-life", "ignored")
    # <undetermined>
    assert row(conn, "Debian:12", "samba", "CVE-2023-4091")["status"] == "undetermined"


def test_repo_sid_policy(conn, repo):
    sync(conn, repo)
    # unbracketed <unfixed> propagates to the supported releases, no sid rows, no bare fixed propagation
    for eco in ("Debian:11", "Debian:12", "Debian:13", "Debian:14"):
        assert row(conn, eco, "glibc", "CVE-2019-1010022")["urgency"] == "unimportant"
    assert row(conn, "Debian:13", "openssl", "CVE-2024-5535") is None
    # explicit bracket wins over propagation
    assert row(conn, "Debian:12", "ruby3.1", "CVE-2023-28755")["nodsa"] == "ignored"
    assert row(conn, "Debian:13", "ruby3.1", "CVE-2023-28755")["nodsa"] is None
    # RESERVED / REJECTED / NOT-FOR-US / <removed> / <itp> produce nothing
    assert conn.execute("SELECT COUNT(*) FROM distro_triage WHERE package IN ('oldpkg','newpkg')").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM distro_triage WHERE cve_id IN "
                        "('CVE-2024-0002','CVE-2024-0003','CVE-2024-0004')").fetchone()[0] == 0


def test_repo_advisories(conn, repo):
    sync(conn, repo)
    assert row(conn, "Debian:12", "openssh", "CVE-2024-6387")["advisory"] == "DSA-5724-1"
    assert row(conn, "Debian:11", "openssh", "CVE-2024-6387")["advisory"] == "DLA-3901-1"
    assert row(conn, "Debian:11", "openssl", "CVE-2024-5535")["advisory"] == "DLA-3896-1"
    assert row(conn, "Debian:12", "tor", "CVE-2023-99001")["advisory"] == "DSA-5562-1"
    assert row(conn, "Debian:12", "openssl", "CVE-2024-5535")["advisory"] is None


def test_repo_data_dir_and_limit(conn, repo):
    sync(conn, repo / "data", limit=1)
    assert {r[0] for r in conn.execute("SELECT DISTINCT package FROM distro_triage")} == {"389-ds-base"}


def test_full_replace(conn, jpath, repo):
    conn.execute("INSERT INTO distro_triage(ecosystem,package,cve_id,status,source) "
                 "VALUES ('Debian:12','stale','CVE-1999-0001','open','debian-tracker')")
    conn.execute("INSERT INTO distro_triage(ecosystem,package,cve_id,status,source) "
                 "VALUES ('Debian:12','keep','CVE-1999-0002','open','other-tracker')")
    conn.commit()
    sync(conn, jpath)
    assert row(conn, "Debian:12", "stale", "CVE-1999-0001") is None
    assert conn.execute("SELECT COUNT(*) FROM distro_triage WHERE source='other-tracker'").fetchone()[0] == 1
    n_json = conn.execute("SELECT COUNT(*) FROM distro_triage WHERE source='debian-tracker'").fetchone()[0]
    sync(conn, repo)                                   # replaces, does not accumulate
    assert row(conn, "Debian:13", "389-ds-base", "CVE-2024-2199") is None      # json-only row gone
    assert conn.execute("SELECT COUNT(*) FROM distro_triage WHERE source='debian-tracker'").fetchone()[0] != n_json


def test_json_and_text_are_equivalent(conn, jpath, repo):
    """For rows the text export states explicitly, both formats give the same triage."""
    sync(conn, jpath)
    from_json = {(r["ecosystem"], r["package"], r["cve_id"]): dict(r)
                 for r in conn.execute("SELECT * FROM distro_triage")}
    sync(conn, repo)
    from_text = {(r["ecosystem"], r["package"], r["cve_id"]): dict(r)
                 for r in conn.execute("SELECT * FROM distro_triage")}
    common = set(from_json) & set(from_text)
    assert len(common) >= 20
    for key in common:
        j, t = from_json[key], from_text[key]
        if key[1] == "linux" and key[0] == "Debian:10":
            assert j["nodsa"] is None and t["nodsa"] == "ignored"       # documented end-of-life divergence
            j["nodsa"], j["note"] = t["nodsa"], t["note"]
        for col in ("status", "urgency", "fixed_version", "nodsa"):
            assert j[col] == t[col], (key, col)
        if j["nodsa"]:
            assert j["note"] == t["note"], key
    # the only text rows JSON lacks: advisories and DSA/DLA-only data
    assert set(from_text) - set(from_json) == set()


def test_network_error_is_error_result(conn, monkeypatch):
    def boom():
        raise httpx.ConnectError("blocked")

    monkeypatch.setattr(dt, "_download", boom)
    res = dt.DebianTrackerSource().sync(conn, SyncOptions())
    assert res.status == "error" and "blocked" in res.message


def test_download_uses_etag_cursor(conn, monkeypatch, jpath):
    monkeypatch.setattr(dt, "_download", lambda: (jpath.read_bytes(), '"abc123"'))
    res = dt.DebianTrackerSource().sync(conn, SyncOptions())
    assert res.status == "ok" and res.cursor == '"abc123"'


def test_registered():
    import secmonk.sources  # noqa: F401
    from secmonk.sources.base import REGISTRY

    assert REGISTRY["debian-tracker"] is dt.DebianTrackerSource

