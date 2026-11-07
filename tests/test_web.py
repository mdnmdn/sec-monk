"""Local web UI: JSON API, security checks and static files (server in a thread on a free port, fixture snapshot)."""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk.cli import app
from secmonk.collectors.process import snapshot as snapfile
from secmonk.collectors.process.model import LaunchItem, ProcessRecord
from secmonk.db import connect
from secmonk.sources.base import add_affected, upsert_vulnerability
from secmonk.web.api import ProcessMonitor
from secmonk.web.server import STATIC, make_server, serve_in_thread

FIX = Path(__file__).parent / "fixtures"
SNAP = FIX / "collectors/process/snapshot.json"


@pytest.fixture
def root(tmp_path) -> Path:
    r = tmp_path / "root"
    shutil.copytree(FIX / "collectors/macos/root", r, symlinks=True)
    shutil.copytree(FIX / "collectors/process/root", r, symlinks=True, dirs_exist_ok=True)
    (r / "usr/local/bin").mkdir(parents=True)
    shutil.copy(FIX / "lang/go/hello-darwin-arm64", r / "usr/local/bin/hello")
    return r


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


def call(srv, path, *, method="GET", headers=None, host=None):
    req = urllib.request.Request(f"http://127.0.0.1:{srv.port}{path}", method=method, headers=headers or {})
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
    assert meta["mode"] == "snapshot" and meta["db"]["exists"] and meta["features"] == ["processes"]
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
    assert call(server, "/api/processes/save", method="POST")[0] == 403
    assert call(server, "/api/processes/save")[0] == 404                      # GET is not an action
    s, _, body = call(server, "/api/processes/save", method="POST", headers={"X-SecMonk-Request": "1"})
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
    assert h["X-Content-Type-Options"] == "nosniff"
    s, h, _ = call(server, "/static/js/secmonk-ui.js")
    assert s == 200 and "javascript" in h["Content-Type"]
    for bad in ("/static/../server.py", "/static/%2e%2e/server.py", "/static/js/../../api.py", "/nope", "/api/nope"):
        assert call(server, bad)[0] == 404, bad


def test_index_loads_only_pinned_cdn_and_no_inline_script():
    html = (STATIC / "index.html").read_text()
    srcs = re.findall(r'<script src="([^"]+)"', html)
    cdn = [s for s in srcs if s.startswith("http")]
    assert cdn == ["https://unpkg.com/vue@3.5.13/dist/vue.global.prod.js",
                   "https://unpkg.com/vue-router@4.5.0/dist/vue-router.global.prod.js"]
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
        for f in ("css/secmonk.css", "js/secmonk-ui.js", "js/secmonk-views.js"):
            assert f"../../src/secmonk/web/static/{f}" in html, (p.name, f)
    assert not list(design.rglob("secmonk.css")) and not list(design.rglob("secmonk-ui.js"))
    mock = (design / "mock/data.js").read_text()
    assert mock.startswith("/* Generated by scripts/design_mock.py")


def test_watch_baseline_then_events(root, mirror, tmp_path):
    mon = ProcessMonitor(db_path=mirror, target=str(SNAP), opts={"root": str(root)})
    first = mon.watch()
    assert first["baseline"] and first["events"] == []
    later = snapfile.load(SNAP)
    later.processes.append(ProcessRecord(910, 1, "/usr/local/bin/hello", uid=501, user="alice"))
    later.launch_items.append(LaunchItem("launchd-agent", "com.new", "/x", source="/p.plist", scope="user:alice"))
    mon.snap.processes = [p for p in mon.snap.processes if p.pid != 404]
    mon.watcher.seen_exes.pop("/usr/local/bin/hello")
    f = tmp_path / "later.json"
    snapfile.dump(later, f)
    mon.target = str(f)
    ev = mon.watch()["events"]
    assert [e["event"] for e in ev] == ["new-executable", "new-launch-item"]
    assert ev[0]["findings_detail"][0]["vuln_id"] == "GO-2022-1059"
    assert mon.payload()["summary"]["processes"] == 22                     # tick folded into the next payload


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
