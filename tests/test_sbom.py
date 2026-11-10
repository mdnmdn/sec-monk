"""CycloneDX export (`secmonk inventory export`, `GET /api/assets/<id>/sbom`) and SBOM import (collector `sbom`)."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk import ops, sbom
from secmonk.cli import app
from secmonk.collectors import sbom as sbom_collector
from secmonk.db import connect
from secmonk.engine.inventory import current_components
from secmonk.web.api import ProcessMonitor
from secmonk.web.server import make_server, serve_in_thread

FIX = Path(__file__).parent / "fixtures"
SB = FIX / "sbom"
JS = FIX / "lang/javascript"
SNAP = FIX / "collectors/process/snapshot.json"
TS = "2026-11-11T09:00:00+00:00"
runner = CliRunner()


def run(*args, code=0):
    res = runner.invoke(app, [str(a) for a in args])
    assert res.exit_code == code, f"exit {res.exit_code} != {code}\n{res.output}\n{res.exception!r}"
    return res


@pytest.fixture
def db(tmp_path, monkeypatch) -> Path:
    """The javascript fixture collected (fs) + two open findings and one fixed one on its components."""
    p = tmp_path / "s.db"
    monkeypatch.setenv("SECMONK_DB", str(p))
    conn = connect(p)
    try:
        ops.save_and_match(conn, ops.collect("fs", str(JS), {}))
        aid = conn.execute("SELECT id FROM asset").fetchone()[0]
        cids = [r[0] for r in conn.execute("SELECT component_id FROM asset_component ORDER BY component_id LIMIT 3")]
        rows = [(cids[0], "CVE-2024-0001", '["CVE-2024-0001","GHSA-aaaa-bbbb-cccc"]', "HIGH", 7.5, "2.0.0",
                 "unimportant", "debian-tracker", "P2", 1, "open"),
                (cids[1], "CVE-2024-0001", '["CVE-2024-0001"]', "HIGH", 8.1, None, None, None, "P2", 0, "open"),
                (cids[2], "GHSA-zzzz-yyyy-xxxx", "[]", None, None, None, None, None, "P4", 0, "open"),
                (cids[2], "CVE-2020-9999", "[]", "LOW", 2.0, None, None, None, "P4", 0, "fixed")]
        for cid, vid, adv, sev, cvss, fixed, triage, tsrc, prio, kev, st in rows:
            conn.execute("INSERT INTO finding(asset_id, component_id, vuln_id, advisory_ids, matched_by, confidence, "
                         "fixed_version, severity, cvss_score, epss, kev, priority, status, triage, triage_source) "
                         "VALUES (?,?,?,?,'osv-package',1.0,?,?,?,0.01,?,?,?,?,?)",
                         (aid, cid, vid, adv, fixed, sev, cvss, kev, prio, st, triage, tsrc))
        conn.commit()
    finally:
        conn.close()
    return p


def _aid(db: Path) -> str:
    with sqlite3.connect(db) as c:
        return c.execute("SELECT id FROM asset").fetchone()[0]


def _keys(db: Path, aid: str) -> set[str]:
    conn = connect(db)
    try:
        return {r["key"] for r in current_components(conn, aid)}
    finally:
        conn.close()


def _export(db: Path, **kw) -> dict:
    conn = connect(db)
    try:
        return sbom.export_asset(conn, _aid(db), timestamp=TS, **kw)
    finally:
        conn.close()


# --------------------------------------------------------------------------- export

def test_export_shape_and_determinism(db):
    doc = _export(db)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6" and doc["version"] == 1
    assert doc["serialNumber"].startswith("urn:uuid:") and "vulnerabilities" not in doc
    tool = doc["metadata"]["tools"]["components"][0]
    assert tool["name"] == "secmonk" and tool["version"]
    subj = doc["metadata"]["component"]
    assert subj["type"] == "application" and subj["name"] == "javascript"
    assert {"name": "secmonk:asset_id", "value": _aid(db)} in subj["properties"]
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == sorted(refs) and set(refs) == _keys(db, _aid(db))            # current components, sorted
    for c in doc["components"]:
        assert c["type"] in ("library", "application") and c["name"]
        if "purl" in c:
            assert c["purl"].startswith("pkg:") and c["bom-ref"] == c["purl"]
        names = [p["name"] for p in c["properties"]]
        assert names == sorted(names) and "secmonk:category" in names
    assert doc["dependencies"] == [{"ref": subj["bom-ref"], "dependsOn": refs}]
    assert _export(db) == doc                                                   # deterministic
    assert sbom.dumps(doc) == sbom.dumps(_export(db))


def test_export_vulnerabilities(db):
    doc = _export(db, with_vulns=True)
    vulns = {v["id"]: v for v in doc["vulnerabilities"]}
    assert list(vulns) == ["CVE-2024-0001", "GHSA-zzzz-yyyy-xxxx"]              # open only, sorted
    cve = vulns["CVE-2024-0001"]
    assert cve["source"] == {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}
    assert cve["ratings"] == [{"source": cve["source"], "severity": "high", "score": 8.1}]
    assert cve["references"] == [{"id": "GHSA-aaaa-bbbb-cccc", "source": {
        "name": "GitHub", "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}}]
    assert cve["recommendation"] == "Upgrade to 2.0.0"
    assert cve["analysis"] == {"state": "in_triage", "detail": "debian-tracker: unimportant"}
    refs = {c["bom-ref"] for c in doc["components"]}
    assert len(cve["affects"]) == 2 and all(a["ref"] in refs for a in cve["affects"])
    assert {"name": "secmonk:kev", "value": "true"} in cve["properties"]
    ghsa = vulns["GHSA-zzzz-yyyy-xxxx"]
    assert "ratings" not in ghsa and ghsa["source"]["name"] == "GitHub"


def test_cli_export(db, tmp_path):
    aid = _aid(db)
    doc = json.loads(run("inventory", "export", aid).stdout)
    assert doc["bomFormat"] == "CycloneDX" and "vulnerabilities" not in doc
    out = tmp_path / "a.cdx.json"
    res = run("inventory", "export", aid, "--with-vulns", "-o", out)
    assert "wrote" in res.stderr and len(json.loads(out.read_text())["vulnerabilities"]) == 2
    assert "unknown asset" in run("inventory", "export", "ghost", code=1).output
    run("inventory", "export", aid, "--format", "spdx", code=2)


# --------------------------------------------------------------------------- API

def _get(srv, path, *, csrf=True):
    req = urllib.request.Request(f"http://127.0.0.1:{srv.port}{path}",
                                 headers={"X-SecMonk-Request": "1"} if csrf else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_api_sbom(db):
    srv = make_server(ProcessMonitor(db_path=db, target=str(SNAP)), "127.0.0.1", 0, mode="snapshot")
    serve_in_thread(srv)
    try:
        aid = _aid(db)
        path = f"/api/assets/{urllib.parse.quote(aid, safe='')}/sbom"
        s, h, body = _get(srv, path)
        assert s == 200 and h["Content-Type"].startswith("application/vnd.cyclonedx+json")
        cd = h["Content-Disposition"]
        assert cd.startswith('attachment; filename="dir_') and cd.endswith('.cdx.json"') and "/" not in cd
        assert "default-src 'self'" in h["Content-Security-Policy"] and h["X-Content-Type-Options"] == "nosniff"
        doc = json.loads(body)
        assert doc["metadata"]["component"]["name"] == "javascript" and "vulnerabilities" not in doc
        assert len(json.loads(_get(srv, path + "?vulns=1")[2])["vulnerabilities"]) == 2
        s, _, body = _get(srv, "/api/assets/ghost/sbom")
        assert s == 404 and json.loads(body)["code"] == "unknown-asset"
        assert _get(srv, path, csrf=False)[0] == 403                           # like every API call
        assert _get(srv, "/api/assets//sbom")[0] == 404
    finally:
        srv.shutdown()
        srv.server_close()


# --------------------------------------------------------------------------- import

def test_import_cyclonedx():
    inv = sbom_collector.SbomCollector().collect(str(SB / "synthetic.cdx.json"))
    a = inv.asset
    assert (a.id, a.type, a.name) == ("sbom:example/shop@1.4.2", "container-image", "example/shop")
    assert a.meta["format"] == "cyclonedx" and a.meta["spec_version"] == "1.5"
    assert a.meta["tools"] == ["example-sbom-tool 2.0"] and a.meta["serial_number"].endswith("0001")
    by = {c.name: c for c in inv.components}
    assert set(by) == {"debian", "openssl", "django", "asgiref", "typing-extensions", "nginx", "broken-purl",
                       "bad-cpe", "openjdk"}                                     # nested flattened
    assert by["debian"].category == "os" and by["openssl"].category == "os-package"
    assert by["django"].category == "library" and by["openjdk"].category == "runtime"
    assert by["nginx"].vendor == "F5" and by["nginx"].cpe.startswith("cpe:2.3:a:f5:nginx")
    assert by["broken-purl"].purl is None and by["bad-cpe"].cpe is None
    w = " ".join(inv.warnings)
    assert "1 component(s) without a usable name" in w and "1 invalid or over-long purl" in w
    assert "1 invalid cpe" in w
    assert sbom_collector.SbomCollector().collect(str(SB / "synthetic.cdx.json"), asset_id="sbom:mine").asset.id \
        == "sbom:mine"


def test_import_spdx():
    inv = sbom_collector.SbomCollector().collect(str(SB / "synthetic.spdx.json"))
    assert inv.asset.id == "sbom:example-service@0.9.0" and inv.asset.meta["format"] == "spdx"
    assert inv.asset.meta["tools"] == ["example-spdx-tool-1.2"]
    by = {c.name: c for c in inv.components}
    assert by["lodash"].purl == "pkg:npm/lodash@4.17.20" and by["lodash"].vendor == "OpenJS"
    assert by["zlib"].category == "os-package" and by["zlib"].cpe.startswith("cpe:2.3:a:zlib")


def test_import_rejects_and_caps(tmp_path, monkeypatch):
    col = sbom_collector.SbomCollector()
    for name, data, msg in (("a.json", "{not json", "not a JSON document"), ("b.json", "[1]", "not an object"),
                            ("c.json", '{"hello": 1}', "not a CycloneDX JSON"),
                            ("d.xml", "<bom/>", "not a JSON document")):
        (tmp_path / name).write_text(data)
        with pytest.raises(ValueError, match=msg):
            col.collect(str(tmp_path / name))
    with pytest.raises(FileNotFoundError):
        col.collect(str(tmp_path / "missing.json"))
    with pytest.raises(ValueError):
        col.collect(None)
    monkeypatch.setattr(sbom_collector, "MAX_BYTES", 100)
    with pytest.raises(ValueError, match="larger than"):
        col.collect(str(SB / "synthetic.cdx.json"))
    monkeypatch.undo()
    monkeypatch.setattr(sbom, "MAX_COMPONENTS", 3)
    monkeypatch.setattr(sbom, "MAX_DEPTH", 0)
    long = {"bomFormat": "CycloneDX", "specVersion": "1.3",
            "components": [{"name": "x" * 2000}, {"name": "a", "components": [{"name": "deep"}]},
                           {"name": "b"}, {"name": "c"}, {"name": "d"}]}
    (tmp_path / "e.json").write_text(json.dumps(long))
    inv = col.collect(str(tmp_path / "e.json"))
    assert [c.name for c in inv.components] == ["a", "b", "c"]
    w = " ".join(inv.warnings)
    assert "specVersion 1.3" in w and "more than 3 components" in w and "deeper than 0 levels" in w
    assert "without a usable name" in w                                         # the over-long name


def test_cli_scan_sbom_and_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("SECMONK_DB", str(tmp_path / "i.db"))
    run("scan", "sbom", SB / "synthetic.cdx.json", "-q")
    rows = json.loads(run("inventory", "show", "sbom:example/shop@1.4.2", "-f", "json").stdout)
    assert {r["name"] for r in rows} >= {"openssl", "django", "nginx"}
    (tmp_path / "bad.json").write_text("[]")
    res = run("scan", "sbom", tmp_path / "bad.json", code=1)
    assert "not an object" in res.output and "Traceback" not in res.output


def test_round_trip_keeps_component_keys(db, tmp_path):
    """export -> import: the same component keys (purls, and name keys with category / vendor)."""
    aid = _aid(db)
    out = tmp_path / "rt.cdx.json"
    run("inventory", "export", aid, "-o", out)
    run("scan", "sbom", out, "-q")
    imported = f"sbom:javascript@{json.loads(out.read_text())['serialNumber']}"
    assert _keys(db, imported) == _keys(db, aid)
    with sqlite3.connect(db) as c:
        typ = c.execute("SELECT type FROM asset WHERE id=?", (imported,)).fetchone()[0]
    assert typ == "directory"                                                   # secmonk:asset_type kept


def test_exported_fixture_parses():
    inv = sbom_collector.SbomCollector().collect(str(SB / "exported-fs.cdx.json"))
    assert len(inv.components) == 8 and not inv.warnings and inv.asset.type == "directory"
    assert all(c.purl and c.category == "library" for c in inv.components)
    assert inv.components[0].source_path == "bun/bun.lock" and inv.asset.name == "javascript"
