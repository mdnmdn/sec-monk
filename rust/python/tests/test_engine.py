"""py-engine: read-only database access (rust ADR-0006), the finding set of a persisted match, classify and versions."""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from secmonk_modules import db
from secmonk_modules.client import ModuleClient

from . import contracts, dbfactory

ASSET = "dir:/srv/payments-api"


def sha(p: str) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def match(engine, **kw):
    p = {"mode": "persisted", "asset_id": ASSET, "min_confidence": 0.5, "view_limit": 100, **kw}
    return engine.request("engine.match", p).ok().result


def test_windows_verbatim_paths_make_valid_file_uris():
    # regression: Rust's canonicalize on Windows yields \\?\C:\... which broke the file: URI of the grant
    assert db.plain_path("\\\\?\\C:\\Users\\u\\AppData\\Local\\sec-monk\\db\\state.sqlite3") == \
        "C:\\Users\\u\\AppData\\Local\\sec-monk\\db\\state.sqlite3"
    assert db.plain_path("\\\\?\\UNC\\srv\\share\\db\\m.sqlite3") == "\\\\srv\\share\\db\\m.sqlite3"
    assert db.plain_path("/data/sec-monk/db/state.sqlite3") == "/data/sec-monk/db/state.sqlite3"
    win = PureWindowsPath(db.plain_path("\\\\?\\C:\\data dir\\db\\state.sqlite3"))
    assert db.file_uri(win) == "file:///C:/data%20dir/db/state.sqlite3?mode=ro"
    unc = PureWindowsPath(db.plain_path("\\\\?\\UNC\\srv\\share\\m.sqlite3"))
    assert db.file_uri(unc) == "file://srv/share/m.sqlite3?mode=ro"
    # URI metacharacters in a POSIX path stay part of the path
    assert db.file_uri(PurePosixPath("/d/a?b#c%d.sqlite3")) == "file:///d/a%3Fb%23c%25d.sqlite3?mode=ro"


def test_requests_never_modify_the_database_files(engine, grant):
    before = (sha(grant["state"]), sha(grant["mirror"]))
    match(engine)
    for m in ("reports.overview", "reports.assets", "reports.status", "reports.unmatched"):
        engine.call(m, {})
    engine.call("reports.findings", {"limit": 10, "include_closed": True})
    engine.call("reports.sbom", {"asset_id": ASSET, "with_vulns": True})
    assert (sha(grant["state"]), sha(grant["mirror"])) == before
    assert not list(Path(grant["state"]).parent.glob("*-journal"))


def test_persisted_match_is_the_python_match_on_the_same_data(engine, grant, tmp_path):
    """The finding set returned equals the `finding` table `match_asset` leaves on a writable copy of the data."""
    from secmonk import db as dbm
    from secmonk.engine.match import match_asset

    r = match(engine)
    v2 = tmp_path / "copy.sqlite3"
    shutil.copy(Path(grant["state"]).parent / "v2.sqlite3", v2)
    conn = dbm.connect(v2)
    stats = match_asset(conn, ASSET, min_confidence=0.5)
    rows = conn.execute("SELECT * FROM finding WHERE asset_id=? ORDER BY component_id, vuln_id", (ASSET,)).fetchall()
    assert r["stats"] == stats
    assert len(r["finding_set"]) == len(rows) >= 1
    for got, want in zip(r["finding_set"], rows, strict=True):
        for k in ("component_id", "vuln_id", "matched_by", "confidence", "fixed_version", "severity", "cvss_score",
                  "epss", "priority", "status", "triage", "triage_source"):
            assert got[k] == want[k], k
        assert got["kev"] == bool(want["kev"])
        assert got["advisory_ids"] == dbm.loads(want["advisory_ids"], [])
    assert r["based_on"]["latest_scan_id"] == conn.execute("SELECT MAX(id) FROM scan").fetchone()[0]
    contracts.check("engine/match.schema.json#/$defs/result", r)


def test_suppressed_stays_sticky_and_missing_findings_close(engine, grant, tmp_path):
    """The host writes the finding set; the next match reads it back: suppression survives, a gone finding is fixed."""
    state = tmp_path / "state.sqlite3"
    shutil.copy(grant["state"], state)
    con = sqlite3.connect(state)
    con.execute("UPDATE finding SET status='suppressed'")
    con.execute("INSERT INTO finding(asset_id, component_id, vuln_id, status, priority, first_seen, last_seen) "
                "VALUES (?, 1, 'CVE-1999-9999', 'open', 'P4', 'x', 'x')", (ASSET,))
    con.commit()
    con.close()
    from secmonk_modules.client import isolated_env

    with ModuleClient("py-engine", env=isolated_env(tmp_path / "d"),
                      grants={"db_read": {**grant, "state": str(state)}}) as c:
        r = match(c)
    by = {f["vuln_id"]: f for f in r["finding_set"]}
    assert by["CVE-2021-44228"]["status"] == "suppressed"
    assert by["CVE-1999-9999"]["status"] == "fixed" and by["CVE-1999-9999"]["fixed_at"]
    assert r["view"] == []                                       # the view lists open findings only


def test_ephemeral_match_writes_nothing_and_ignores_stored_assets(engine, grant):
    inv = {"schema": "secmonk-inventory/1", "classified": False, "collector": "fs", "warnings": [], "partial": False,
           "partial_reason": None, "asset": {"id": ASSET, "type": "directory", "name": "same id as a stored asset"},
           "components": [{**dbfactory.LOG4J, "version": "2.17.1", "purl": "pkg:maven/org.apache.logging.log4j/"
                           "log4j-core@2.17.1", "meta": {}}]}
    before = sha(grant["state"])
    r = engine.request("engine.match", {"mode": "ephemeral", "inventory": inv, "min_confidence": 0.5}).ok().result
    assert r["stats"]["findings"] == 0 and r["view"] == []       # patched version, stored (vulnerable) one is shadowed
    assert sha(grant["state"]) == before
    assert match(engine)["stats"]["findings"] == 1               # the stored asset is untouched


def test_match_params_are_validated(engine):
    for p in ({"mode": "persisted", "min_confidence": 0.5},
              {"mode": "persisted", "asset_id": ASSET, "min_confidence": 2},
              {"mode": "persisted", "asset_id": ASSET, "min_confidence": 0.5, "inventory": {}},
              {"mode": "ephemeral", "min_confidence": 0.5},
              {"mode": "other", "min_confidence": 0.5},
              {"mode": "persisted", "asset_id": ASSET, "min_confidence": 0.5, "view_limit": 99999},
              {"mode": "ephemeral", "min_confidence": 0.5, "inventory": {"asset": {}, "components": [], "warnings": []}}):
        assert engine.request("engine.match", p).error["code"] == "invalid-params", p


def test_readonly_connection_cannot_write_or_attach(grant, tmp_path):
    conn = db.open_readonly(grant["state"], grant["mirror"], temp_writes=True)
    try:
        for sql in ("INSERT INTO finding(asset_id, component_id, vuln_id) VALUES ('a', 1, 'b')",
                    "DELETE FROM asset", "UPDATE kev SET vendor='x'", "CREATE TABLE evil(x)", "DROP TABLE finding",
                    f"ATTACH DATABASE '{tmp_path / 'other.db'}' AS other", "INSERT INTO mirror.kev(cve_id) VALUES ('x')"):
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute(sql)
        conn.execute("CREATE TEMP TABLE scratch(x)")             # TEMP is the only writable place
        conn.execute("INSERT INTO scratch VALUES (1)")
        assert conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] > 0       # the mirror is visible, unqualified
    finally:
        conn.close()
    plain = db.open_readonly(grant["state"], grant["mirror"])
    try:
        with pytest.raises(sqlite3.DatabaseError):
            plain.execute("CREATE TEMP TABLE nope(x)")           # query_only: a report cannot even write TEMP
    finally:
        plain.close()


def test_read_snapshot_is_consistent_while_a_writer_commits(grant, tmp_path):
    """A request keeps its snapshot: a commit after the first read stays invisible until the next request (WAL)."""
    state = tmp_path / "s.sqlite3"
    shutil.copy(grant["state"], state)
    w = sqlite3.connect(state)
    w.execute("PRAGMA journal_mode=WAL")
    w.commit()
    conn = db.open_readonly(str(state), grant["mirror"])
    try:
        n = conn.execute("SELECT COUNT(*) FROM asset").fetchone()[0]
        w.execute("INSERT INTO asset(id, type, name) VALUES ('dir:/new', 'directory', 'n')")
        w.commit()
        assert conn.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == n
    finally:
        conn.close()
    again = db.open_readonly(str(state), grant["mirror"])
    assert again.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == n + 1
    again.close()
    w.close()


def test_no_database_is_a_no_db_error(env, tmp_path):
    with ModuleClient("py-engine", env=env) as c:               # no grant at all
        assert c.request("reports.overview", {}).error["code"] == "no-db"
    missing = {"state": str(tmp_path / "x.sqlite3"), "mirror": str(tmp_path / "y.sqlite3")}
    with ModuleClient("py-engine", env=env, grants={"db_read": missing}) as c:
        assert c.request("reports.status", {}).error["code"] == "no-db"
    empty = tmp_path / "empty.sqlite3"
    sqlite3.connect(empty).close()
    with ModuleClient("py-engine", env=env, grants={"db_read": {"state": str(empty), "mirror": str(empty)}}) as c:
        e = c.request("reports.overview", {}).error
        assert e["code"] == "no-db"
        assert not Path(str(empty) + "-wal").exists()
    # versions and classify need no database
    with ModuleClient("py-engine", env=env) as c:
        assert c.call("versions.compare", {"a": "1", "b": "2", "scheme": "generic"}) == {"result": -1}


def test_a_grant_to_a_module_without_db_read_is_refused(env, grant):
    with ModuleClient("py-probe", env=env, grants={"db_read": grant}, send_host_hello=True) as c:
        f = c.recv(10)
        assert f["code"] == "protocol-error"


def test_error_codes_of_reports(engine):
    assert engine.request("reports.asset_detail", {"id": "nope"}).error["code"] == "unknown-asset"
    assert engine.request("reports.findings", {"limit": 5, "asset": "nope"}).error["code"] == "unknown-asset"
    assert engine.request("reports.sbom", {"asset_id": "nope"}).error["code"] == "unknown-asset"
    assert engine.request("reports.vuln_detail", {"id": "CVE-0-0"}).error["code"] == "unknown-vuln"
    assert engine.request("reports.vuln_search", {"limit": 5}).error["code"] == "invalid-params"
    assert engine.request("reports.findings", {"limit": 0}).error["code"] == "invalid-params"
    assert engine.request("reports.findings", {"limit": 5, "priority": "P9"}).error["code"] == "invalid-params"


def test_classify_equals_python_and_is_idempotent(engine):
    import dataclasses

    from secmonk.engine.classify import classify
    from secmonk.models import Component

    comps = [{"name": "Visual Studio Code", "version": "1.95.0", "category": "application", "meta": {}},
             {"name": "curl", "version": "8.4.0", "category": "package", "vendor": None,
              "meta": {"brew_kind": "formula", "brew_name": "curl"}},
             {"name": "left-pad", "version": "1.3.0", "category": "library", "purl": "pkg:npm/left-pad@1.3.0",
              "meta": {}}]
    out = engine.call("engine.classify", {"components": comps})["components"]
    for got, src in zip(out, comps, strict=True):
        want = dataclasses.asdict(classify(Component(**{"vendor": None, **src})))
        assert got == want
    assert engine.call("engine.classify", {"components": out})["components"] == out
    assert out[2]["ecosystem"] == "npm"


def test_classify_caps_and_validates(engine):
    many = [{"name": "a", "version": "1", "category": "library", "meta": {}}] * 5001
    assert engine.request("engine.classify", {"components": many}).error["code"] == "invalid-params"
    for bad in ({"name": "", "version": "1", "category": "library"}, {"name": "a", "category": "nope"},
                {"name": "a", "category": "library", "extra": 1}, "a string"):
        assert engine.request("engine.classify", {"components": [bad]}).error["code"] == "invalid-params"


def test_versions_equal_the_python_oracle(engine):
    from secmonk.engine import versions

    pairs = [("1.2.3", "1.10.0", "semver"), ("1.0.0-rc1", "1.0.0", "semver"), ("2.0.0", "2.0.0", "generic"),
             ("1:1.0-1", "1.0-2", "deb"), ("1.0.post1", "1.0", "pypi"), ("v1.2", "1.2", "generic"), ("9", "10", "maven")]
    for a, b, scheme in pairs:
        r = engine.call("versions.compare", {"a": a, "b": b, "scheme": scheme})["result"]
        assert r == (versions.compare(a, b, scheme) > 0) - (versions.compare(a, b, scheme) < 0), (a, b, scheme)
    ev = [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"last_affected": "2.3"}]
    for v in ("0.9", "1.0", "1.4.9", "1.5", "2.2", "2.4"):
        assert engine.call("versions.in_range", {"version": v, "events": ev, "scheme": "semver"}) == {
            "affected": versions.in_osv_range(v, ev, "semver")}
        assert engine.call("versions.first_fixed", {"version": v, "events": ev, "scheme": "semver"}) == {
            "fixed": versions.first_fixed_after(v, ev, "semver")}
    for eco in (None, "PyPI", "npm", "Debian:12", "Alpine:v3.20", "Maven", "Go"):
        assert engine.call("versions.scheme", {"ecosystem": eco})["scheme"] == versions.scheme_for_ecosystem(eco)
    assert engine.request("versions.in_range", {"version": "1", "events": [1], "scheme": "x"}).error["code"] == \
        "invalid-params"


def test_scoring_equals_the_python_oracle(engine):
    from secmonk.engine import scoring

    for cvss, epss, kev, meta, triage, sev in [(9.8, 0.5, False, {"internet_facing": True}, None, None),
                                               (None, None, False, None, None, "HIGH"),
                                               (5.0, 0.0, True, {"env": "prod"}, "unimportant", None),
                                               (7.1, 0.0, False, None, "no-dsa", None)]:
        got = engine.call("scoring.priority", {"cvss": cvss, "epss": epss, "kev": kev, "asset_meta": meta,
                                               "triage": triage, "severity": sev})["priority"]
        assert got == scoring.priority(cvss=cvss, epss=epss, kev=kev, asset_meta=meta, triage=triage, severity=sev)
