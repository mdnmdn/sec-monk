"""Local web UI: JSON API, security checks and static files (server in a thread on a free port, fixture snapshot)."""

from __future__ import annotations

import json
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk.cli import app
from secmonk.collectors.process import snapshot as snapfile
from secmonk.collectors.process.model import LaunchItem
from secmonk.db import connect
from secmonk.sources.base import add_affected, upsert_vulnerability
from secmonk.web.api import ProcessMonitor
from secmonk.web.server import STATIC, make_server, serve_in_thread

FIX = Path(__file__).parent / "fixtures"
SNAP = FIX / "collectors/process/snapshot.json"


@pytest.fixture
def root(process_root) -> Path:
    return process_root


@pytest.fixture
def mirror(tmp_path) -> Path:
    db = tmp_path / "m.db"
    c = connect(db)
    upsert_vulnerability(c, "osv", "GO-2022-1059", severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GO-2022-1059", ecosystem="Go", package="golang.org/x/text", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "0.3.8"}])
    c.commit()
    c.close()
    return db


@pytest.fixture
def server(root, mirror):
    mon = ProcessMonitor(db_path=mirror, target=str(SNAP), opts={"root": str(root)})
    srv = make_server(mon, "127.0.0.1", 0, mode="snapshot")
    serve_in_thread(srv)
    yield srv
    srv.shutdown()
    srv.server_close()


def call(srv, path, *, method="GET", headers=None, host=None, csrf=True, addr="127.0.0.1"):
    """Request like the app does: API calls carry X-SecMonk-Request unless csrf=False."""
    hdrs = dict(headers or {})
    if csrf and path.startswith("/api/"):
        hdrs.setdefault("X-SecMonk-Request", "1")
    req = urllib.request.Request(f"http://{addr}:{srv.port}{path}", method=method, headers=hdrs)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_meta_and_processes_payload(server, mirror):
    s, h, body = call(server, "/api/meta")
    assert s == 200 and h["Content-Type"].startswith("application/json") and h["Cache-Control"] == "no-store"
    meta = json.loads(body)
    assert meta["mode"] == "snapshot" and meta["db"]["exists"] and meta["actions"] is True
    assert {"processes", "overview", "assets", "findings", "vulns", "sources", "scan", "jobs"} <= set(meta["features"])
    s, _, body = call(server, "/api/processes")
    p = json.loads(body)
    assert s == 200 and p["asset"] == "process:fixture-mac" and p["matched"] and p["source"] == "snapshot"
    assert p["summary"]["processes"] == 21 and p["summary"]["missing_programs"] == 1
    hello = next(r for r in p["processes"] if r["pid"] == 404)
    assert hello["findings_detail"][0]["vuln_id"] == "GO-2022-1059" and hello["depth"] == 5
    sw = next(x for x in p["software"] if x["name"] == "golang.org/x/text")
    assert sw["findings"].startswith("P") and sw["pids"] == [404]
    li = {x["label"]: x for x in p["launch_items"]}
    assert li["com.sync.agent"]["running_pids"] == [320] and li["com.openssh.sshd"]["missing_program"]
    # matching ran in an overlay: nothing written
    with sqlite3.connect(mirror) as c:
        assert c.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == 0


def test_save_requires_post_and_csrf_header(server, mirror):
    assert call(server, "/api/processes/save", method="POST", csrf=False)[0] == 403
    assert call(server, "/api/processes/save")[0] == 404                      # GET is not an action
    s, _, body = call(server, "/api/processes/save", method="POST")
    assert s == 200 and json.loads(body)["asset"] == "process:fixture-mac"
    with sqlite3.connect(mirror) as c:
        assert c.execute("SELECT id FROM asset").fetchall() == [("process:fixture-mac",)]
        assert c.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1
    assert call(server, "/api/processes/save", method="PUT")[0] == 405


def test_host_header_allow_list(server):
    assert call(server, "/api/meta", host="evil.example:80")[0] == 421       # DNS rebinding
    assert call(server, "/", host=f"localhost:{server.port}")[0] == 200
    assert call(server, "/api/meta", host=f"127.0.0.1:{server.port + 1}")[0] == 421


def test_static_files_and_security_headers(server):
    s, h, body = call(server, "/")
    assert s == 200 and b'id="app"' in body
    csp = h["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp
    assert "http" not in csp                                                # no third-party origin allowed
    assert h["X-Content-Type-Options"] == "nosniff"
    s, h, _ = call(server, "/static/js/secmonk-ui.js")
    assert s == 200 and "javascript" in h["Content-Type"]
    for bad in ("/static/../server.py", "/static/%2e%2e/server.py", "/static/js/../../api.py", "/nope", "/api/nope"):
        assert call(server, bad)[0] == 404, bad


def test_index_loads_only_local_scripts_and_no_inline_script():
    html = (STATIC / "index.html").read_text()
    srcs = re.findall(r'<script src="([^"]+)"', html)
    assert srcs[:2] == ["/static/vendor/vue@3.5.13/vue.global.prod.js",
                        "/static/vendor/vue-router@4.5.0/vue-router.global.prod.js"]
    assert all(s.startswith("/static/") for s in srcs)                       # vendored: nothing external
    assert not re.search(r"<script>(?!\s*</script>)", html)                  # CSP: no inline scripts
    js = (STATIC / "js/secmonk-views.js").read_text() + (STATIC / "js/secmonk-ui.js").read_text()
    assert re.findall(r'v-html="[^"]*"', js) == ['v-html="svg"']              # only the static icon paths


def test_design_pages_use_the_shared_files():
    """_design must link the app's own css/js, never a copy (single component library)."""
    design = Path(__file__).parents[1] / "_design"
    pages = list((design / "pages").glob("*.html")) + [design / "storybook/index.html"]
    assert len(pages) >= 8
    for p in pages:
        html = p.read_text()
        assert "http://" not in html and "https://" not in html, p.name  # no CDN: works offline
        for f in ("css/secmonk.css", "js/secmonk-ui.js", "js/secmonk-views.js", "vendor/vue@3.5.13/vue.global.prod.js",
                  "vendor/vue-router@4.5.0/vue-router.global.prod.js"):
            assert f"../../src/secmonk/web/static/{f}" in html, (p.name, f)
    assert not list(design.rglob("secmonk.css")) and not list(design.rglob("secmonk-ui.js"))
    mock = (design / "mock/data.js").read_text()
    assert mock.startswith("/* Generated by scripts/design_mock.py")


def _baseline_without_hello(tmp_path) -> Path:
    """The fixture snapshot with pid 404 running zsh instead of the Go binary, so hello appears only later."""
    base = snapfile.load(SNAP)
    next(p for p in base.processes if p.pid == 404).exe = "/bin/zsh"
    f = tmp_path / "base.json"
    snapfile.dump(base, f)
    return f


def _later(tmp_path) -> Path:
    later = snapfile.load(SNAP)                                             # hello runs again as pid 404
    later.launch_items.append(LaunchItem("launchd-agent", "com.new", "/x", source="/p.plist", scope="user:alice"))
    f = tmp_path / "later.json"
    snapfile.dump(later, f)
    return f


def test_watch_baseline_then_events(root, mirror, tmp_path):
    mon = ProcessMonitor(db_path=mirror, target=str(_baseline_without_hello(tmp_path)), opts={"root": str(root)})
    first = mon.watch()
    assert first["baseline"] and first["events"] == []
    mon.target = str(_later(tmp_path))
    ev = mon.watch()["events"]
    assert [e["event"] for e in ev] == ["new-executable", "new-launch-item"]
    assert ev[0]["findings_detail"][0]["vuln_id"] == "GO-2022-1059"
    hello = next(r for r in mon.payload()["processes"] if r["pid"] == 404)  # tick folded into the next payload
    assert hello["identity_method"] == "go-binary"


def test_refresh_while_watching_keeps_changes(root, mirror, tmp_path):
    """A refresh between two ticks must not swallow the change: it is reported on the next tick."""
    mon = ProcessMonitor(db_path=mirror, target=str(_baseline_without_hello(tmp_path)), opts={"root": str(root)})
    mon.watch()                                                             # baseline
    mon.target = str(_later(tmp_path))
    mon.payload(refresh=True)                                               # the change lands in a refresh
    ev = mon.watch()["events"]
    assert [e["event"] for e in ev] == ["new-executable", "new-launch-item"]
    assert mon.watch()["events"] == []


def test_live_snapshot_unsupported_is_a_503_with_hint(mirror, monkeypatch):
    monkeypatch.setattr("secmonk.collectors.process.collector.current_platform", lambda: "plan9")
    srv = make_server(ProcessMonitor(db_path=mirror), "127.0.0.1", 0)
    serve_in_thread(srv)
    try:
        s, _, body = call(srv, "/api/processes")
        err = json.loads(body)
        assert s == 503 and "not implemented on plan9" in err["error"] and "--snapshot" in err["hint"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_ui_rejects_missing_snapshot(tmp_path):
    r = CliRunner().invoke(app, ["ui", "--snapshot", str(tmp_path / "nope.json")])
    assert r.exit_code == 2 and "no snapshot file" in r.output


def test_vendored_libraries_match_manifest():
    """static/vendor holds exactly the files in MANIFEST.json, unmodified (scripts/vendor_web.py --check)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("vendor_web", Path(__file__).parents[1] / "scripts/vendor_web.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.check() == []
    assert (STATIC / "vendor/vue@3.5.13/LICENSE").read_text().startswith("The MIT License")


def test_vendored_files_are_served(server):
    s, h, body = call(server, "/static/vendor/vue@3.5.13/vue.global.prod.js")
    assert s == 200 and "javascript" in h["Content-Type"] and len(body) > 100_000


def test_every_api_call_needs_the_csrf_header(server):
    """GETs too: a cross-site page could otherwise advance the watcher (stealing events) or force snapshots."""
    for path in ("/api/meta", "/api/processes", "/api/processes?refresh=1", "/api/processes/watch"):
        s, _, body = call(server, path, csrf=False)
        assert s == 403 and b"X-SecMonk-Request" in body, path
    assert call(server, "/", csrf=False)[0] == 200                          # static files need no header
    assert call(server, "/static/css/secmonk.css", csrf=False)[0] == 200
    assert server.monitor.watcher is None                                   # rejected calls changed nothing


def test_split_host():
    from secmonk.web.server import _split_host

    assert _split_host("LocalHost:8765") == ("localhost", 8765)
    assert _split_host("[::1]:8765") == ("::1", 8765)
    assert _split_host("example") == ("example", None)
    assert _split_host("fe80::1") == ("fe80::1", None)                       # bare IPv6, no port


def test_ipv6_loopback_bind(root, mirror):
    import socket

    if not socket.has_ipv6:
        pytest.skip("no IPv6")
    try:
        srv = make_server(ProcessMonitor(db_path=mirror, target=str(SNAP), opts={"root": str(root)}), "::1", 0)
    except OSError as e:
        pytest.skip(f"IPv6 loopback unavailable: {e}")
    serve_in_thread(srv)
    try:
        assert srv.bind == f"http://[::1]:{srv.port}"
        assert call(srv, "/api/meta", addr="[::1]")[0] == 200
        assert call(srv, "/api/meta", addr="[::1]", host=f"[::1]:{srv.port}")[0] == 200
    finally:
        srv.shutdown()
        srv.server_close()


def test_wildcard_bind_accepts_ip_literals_and_allowed_names(root, mirror):
    srv = make_server(ProcessMonitor(db_path=mirror, target=str(SNAP), opts={"root": str(root)}), "0.0.0.0", 0,
                      allow_hosts=["secmonk.lan"])
    serve_in_thread(srv)
    try:
        p = srv.port
        assert call(srv, "/api/meta", host=f"192.168.1.5:{p}")[0] == 200       # a LAN client using the IP
        assert call(srv, "/api/meta", host=f"secmonk.lan:{p}")[0] == 200       # --allow-host
        assert call(srv, "/api/meta", host=f"evil.example:{p}")[0] == 421      # rebinding domain
        assert call(srv, "/api/meta", host=f"192.168.1.5:{p + 1}")[0] == 421   # wrong port
    finally:
        srv.shutdown()
        srv.server_close()
    loop = make_server(ProcessMonitor(db_path=mirror), "127.0.0.1", 0)
    try:
        assert not loop.host_allowed(f"192.168.1.5:{loop.port}")                # loopback bind: no IP literals
    finally:
        loop.server_close()


# --------------------------------------------------------------------------- data areas (overview, assets, findings,
# vulnerabilities, sources) and jobs (scan, sync)

KEV = FIX / "sources/kev/known_exploited_vulnerabilities.json"
JAVA = FIX / "lang/java"


def _json(srv, path, **kw):
    s, _, body = call(srv, path, **kw)
    return s, json.loads(body)


def _post_json(srv, path, body, *, ctype="application/json"):
    hdrs = {"X-SecMonk-Request": "1", "Content-Type": ctype}
    req = urllib.request.Request(f"http://127.0.0.1:{srv.port}{path}", method="POST",
                                 data=json.dumps(body).encode(), headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _wait(srv, job_id):
    import time

    for _ in range(400):
        s, j = _json(srv, f"/api/jobs/{job_id}")
        assert s == 200
        if j["status"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.fixture
def log4j_db(tmp_path) -> Path:
    """Mirror with the real Log4Shell records (OSV GHSA + KEV) and the java fixture scanned: one P1 KEV finding."""
    from secmonk import ops
    from secmonk.sources.base import SyncOptions

    db = tmp_path / "l.db"
    c = connect(db)
    reg = ops.sources_registry()
    for name, path in (("kev", KEV), ("osv", FIX / "sources/osv/maven-GHSA-jfh8-c2jp-5v3q.json")):
        assert ops.sync_source(c, name, reg[name], SyncOptions(path=path))[0].status == "ok"
    ops.save_and_match(c, ops.collect("fs", str(JAVA), {}))
    c.close()
    return db


@pytest.fixture
def data_server(log4j_db):
    srv = make_server(ProcessMonitor(db_path=log4j_db, target=str(SNAP)), "127.0.0.1", 0, mode="snapshot")
    serve_in_thread(srv)
    yield srv
    srv.shutdown()
    srv.server_close()


def test_overview_assets_and_asset_detail(data_server):
    s, ov = _json(data_server, "/api/overview")
    assert s == 200 and ov["totals"]["assets"] == 1 and ov["totals"]["P1"] == 1 and ov["totals"]["kev"] == 1
    assert ov["top_findings"][0]["vuln_id"] == "CVE-2021-44228" and {r["source"] for r in ov["sources"]} >= {"kev", "osv"}
    s, assets = _json(data_server, "/api/assets")
    aid = assets[0]["id"]
    assert s == 200 and aid == f"dir:{JAVA.resolve()}" and assets[0]["findings_by_priority"]["P1"] == 1
    s, d = _json(data_server, "/api/assets/detail?id=" + urllib.parse.quote(aid))
    assert s == 200 and d["summary"]["open"]["kev"] == 1 and d["scans"][0]["collector"] == "fs"
    log4j = next(c for c in d["components"] if c["name"].endswith("log4j-core"))
    assert log4j["findings"]["P1"] == 1 and d["findings"][0]["component_id"] == log4j["id"]
    assert _json(data_server, "/api/assets/detail?id=ghost")[0] == 404
    assert _json(data_server, "/api/assets/detail")[0] == 400
    s, m = _json(data_server, "/api/assets/match?id=" + urllib.parse.quote(aid), method="POST")
    assert s == 200 and m["stats"]["findings"] == 1
    assert call(data_server, "/api/assets/match?id=x")[0] == 404           # GET is not an action
    assert _json(data_server, "/api/unmatched") == (200, [])


def test_findings_endpoint_matches_the_cli(data_server, log4j_db, monkeypatch):
    s, f = _json(data_server, "/api/findings?priority=p1&limit=10")
    assert s == 200 and not f["limit_reached"] and [x["vuln_id"] for x in f["findings"]] == ["CVE-2021-44228"]
    monkeypatch.setenv("SECMONK_DB", str(log4j_db))
    cli_rows = json.loads(CliRunner().invoke(app, ["findings", "-f", "json"]).stdout)
    assert cli_rows == f["findings"]                                       # one payload builder (reports.py)
    assert _json(data_server, "/api/findings?priority=P7")[0] == 400
    assert _json(data_server, "/api/findings?limit=0")[0] == 400
    assert _json(data_server, "/api/findings?asset=ghost")[0] == 404
    assert _json(data_server, "/api/findings?priority=P2")[1]["findings"] == []


def test_vulnerability_show_and_search(data_server):
    s, v = _json(data_server, "/api/vulns/show?id=GHSA-jfh8-c2jp-5v3q")
    assert s == 200 and v["id"] == "CVE-2021-44228" and "GHSA-jfh8-c2jp-5v3q" in v["aliases"]
    assert v["kev"]["cve_id"] == "CVE-2021-44228" and v["findings"][0]["priority"] == "P1" and "raw" not in v
    assert all(isinstance(r["references"], list) for r in v["records"]) and v["affected"][0]["events"]
    assert "raw" in _json(data_server, "/api/vulns/show?id=CVE-2021-44228&raw=1")[1]
    s, e = _json(data_server, "/api/vulns/show?id=CVE-0000-0001")
    assert s == 404 and e["code"] == "unknown-vuln"
    q = "/api/vulns/search?ecosystem=Maven&package=org.apache.logging.log4j:log4j-core"
    assert {r["vuln_id"] for r in _json(data_server, q + "&version=2.14.1")[1]["results"]} == {"GHSA-jfh8-c2jp-5v3q"}
    assert _json(data_server, q + "&version=2.17.1")[1]["results"] == []
    assert _json(data_server, "/api/vulns/search")[0] == 400


def test_sources_and_collectors(data_server):
    s, src = _json(data_server, "/api/sources")
    assert s == 200 and src["db"]["exists"] and {"kev", "osv", "nvd"} <= {r["name"] for r in src["registry"]}
    assert src["status"]["tables"]["kev"] > 0
    assert "fs" in {c["name"] for c in _json(data_server, "/api/collectors")[1]}


def test_no_database_is_a_404_with_a_code(tmp_path):
    srv = make_server(ProcessMonitor(db_path=tmp_path / "none.db", target=str(SNAP)), "127.0.0.1", 0, mode="snapshot")
    serve_in_thread(srv)
    try:
        for path in ("/api/overview", "/api/assets", "/api/findings", "/api/vulns/show?id=x"):
            s, e = _json(srv, path)
            assert s == 404 and e["code"] == "no-db", path
        s, src = _json(srv, "/api/sources")                                  # works: offers the first sync
        assert s == 200 and src["status"] is None and not src["db"]["exists"]
        assert not (tmp_path / "none.db").exists()                            # reads never create the database
    finally:
        srv.shutdown()
        srv.server_close()


def test_scan_and_sync_jobs(data_server, log4j_db):
    s, j = _post_json(data_server, "/api/jobs", {"kind": "scan", "collector": "fs", "target": str(FIX / "lang/javascript"),
                                                 "save": False})
    assert s == 202 and j["status"] == "running" and j["title"].startswith("scan fs")
    done = _wait(data_server, j["id"])
    assert done["status"] == "ok" and done["result"]["saved"] is False and done["result"]["stats"]["components"] > 0
    assert any("components" in line for line in done["log"])
    with sqlite3.connect(log4j_db) as c:                                     # --no-save: nothing written
        assert c.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == 1
    s, j = _post_json(data_server, "/api/jobs", {"kind": "sync", "sources": ["kev"], "path": str(KEV)})
    done = _wait(data_server, j["id"])
    assert s == 202 and done["status"] == "ok" and done["result"]["sources"][0]["records"] == 9
    s, jobs = _json(data_server, "/api/jobs")
    assert [x["id"] for x in jobs] == [2, 1] and "log" not in jobs[0]
    assert _json(data_server, "/api/jobs/99")[0] == 404
    s, j = _post_json(data_server, "/api/jobs", {"kind": "scan", "collector": "fs", "target": "/nonexistent/x"})
    failed = _wait(data_server, j["id"])
    assert failed["status"] == "error" and failed["error"]


def test_job_validation(data_server):
    bad = [({"kind": "nope"}, 400), ({"kind": "sync", "sources": []}, 400), ({"kind": "sync", "sources": ["nope"]}, 400),
           ({"kind": "sync", "sources": ["kev"], "limit": -1}, 400), ({"kind": "sync", "sources": ["kev"], "path": "/no/such"}, 400),
           ({"kind": "scan", "collector": "nope"}, 400), ({"kind": "scan", "collector": "fs", "options": ["novalue"]}, 400),
           ({"kind": "scan", "collector": "fs", "min_confidence": 2}, 400)]
    for body, status in bad:
        assert _post_json(data_server, "/api/jobs", body)[0] == status, body
    assert _post_json(data_server, "/api/jobs", {"kind": "sync"}, ctype="text/plain")[0] == 415
    assert _post_json(data_server, "/api/jobs", ["kind"])[0] == 400


def test_one_job_at_a_time(data_server, monkeypatch):
    import threading

    from secmonk.web import jobs as jobs_mod

    gate = threading.Event()
    monkeypatch.setattr(jobs_mod.JobRunner, "_sync", lambda self, job, reg, p: (gate.wait(10), ("ok", {"sources": []}))[1])
    s, j = _post_json(data_server, "/api/jobs", {"kind": "sync", "sources": ["kev"]})
    assert s == 202
    s, e = _post_json(data_server, "/api/jobs", {"kind": "sync", "sources": ["kev"]})
    assert s == 409 and "running" in e["error"]
    gate.set()
    assert _wait(data_server, j["id"])["status"] == "ok"


def test_actions_off_refuses_jobs_but_not_reads(log4j_db):
    srv = make_server(ProcessMonitor(db_path=log4j_db, target=str(SNAP)), "127.0.0.1", 0, mode="snapshot", actions=False)
    serve_in_thread(srv)
    try:
        assert _json(srv, "/api/meta")[1]["actions"] is False
        s, e = _post_json(srv, "/api/jobs", {"kind": "sync", "sources": ["kev"]})
        assert s == 403 and "--allow-actions" in e["hint"]
        assert _json(srv, "/api/overview")[0] == 200
    finally:
        srv.shutdown()
        srv.server_close()


def test_actions_default_follows_the_bind_address(root, mirror):
    from secmonk.web.server import UIServer

    mon = ProcessMonitor(db_path=mirror, target=str(SNAP))
    loop = UIServer(("127.0.0.1", 0), mon, mode="snapshot")
    wild = UIServer(("0.0.0.0", 0), mon, mode="snapshot")
    forced = UIServer(("0.0.0.0", 0), mon, mode="snapshot", actions=True)
    try:
        assert loop.actions and not wild.actions and not wild.jobs.enabled and forced.actions
    finally:
        for s in (loop, wild, forced):
            s.server_close()


def test_views_render_untrusted_urls_only_as_http_links():
    """Advisory references are data: only http(s) URLs become links (fmt.safeUrl), never via v-html."""
    ui = (STATIC / "js/secmonk-ui.js").read_text()
    views = (STATIC / "js/secmonk-views.js").read_text()
    assert "safeUrl(u) { return typeof u === \"string\" && /^https?:\\/\\//i.test(u)" in ui
    hrefs = re.findall(r':href="([^"]+)"', views)
    assert hrefs == ["r.href"] and "fmt.safeUrl(u)" in views
