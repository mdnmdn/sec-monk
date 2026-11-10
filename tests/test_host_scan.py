"""Host mode: discovery payload, batch scans (ops.scan_items), `POST /api/jobs` with items, `GET /api/discover`,
`secmonk discover` and `secmonk scan-host`.

`secmonk.discover` (agent A's module) is replaced by a fake: candidates over the fake collector `multi`
(comma-separated targets; `bad` fails to collect; `none` matches nothing). No host is contacted.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
import types
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

import secmonk
from secmonk import cli, ops, reports
from secmonk.cli import app
from secmonk.collectors.base import REGISTRY, Collector
from secmonk.db import connect
from secmonk.models import Asset, Component, Inventory
from secmonk.sources.base import add_affected, upsert_vulnerability
from secmonk.web.api import ProcessMonitor
from secmonk.web.jobs import JobRunner
from secmonk.web.server import make_server, serve_in_thread

SNAP = Path(__file__).parent / "fixtures/collectors/process/snapshot.json"
runner = CliRunner()


class Multi(Collector):
    name = "multi"

    def expand_targets(self, target, **opts):
        if target == "none":
            raise ValueError("no container matches 'none'")
        return [t for t in (target or "").split(",") if t] or [target]

    def collect(self, target=None, **opts):
        if target == "bad":
            raise OSError("cannot reach bad")
        return Inventory(Asset(f"multi:{target}", "server", str(target)), "multi",
                         [Component("left-pad", "1.0.0", "library", purl="pkg:npm/left-pad@1.0.0", ecosystem="npm")])


CANDIDATES = [
    {"id": "apps", "collector": "multi", "target": "a", "options": ["lang=yes"], "label": "Applications",
     "description": "apps", "available": True, "selected": True, "details": {"count": 3}},
    {"id": "docker", "collector": "multi", "target": "b,c", "options": [], "label": "Docker containers",
     "available": True, "selected": False},
    {"id": "brew", "collector": "multi", "target": "x", "label": "Homebrew", "available": False,
     "reason": "not installed", "selected": False},
    {"id": "gone", "collector": "multi", "target": "none", "label": "Vanished", "available": True, "selected": False},
    {"id": "broken", "collector": "multi", "target": "bad", "label": "Broken", "available": True, "selected": True},
]


@pytest.fixture
def calls(monkeypatch):
    """Fake secmonk.discover; returns the list of (target, opts) it was called with."""
    seen: list = []

    def discover_host(target=None, **opts):
        seen.append((target, opts))
        if target == "bad host":
            raise ValueError("invalid ssh target 'bad host'")
        if target == "down":
            raise OSError("ssh: kex failed; remote said <banner secret>")
        return {"host": {"kind": "ssh" if target else "local", "target": target, "name": "box", "os": "linux",
                         "os_version": "12", "arch": "arm64"},
                "candidates": [dict(c) for c in CANDIDATES], "warnings": ["no sudo: https://u:pw@x.example/a"]}

    fake = types.ModuleType("secmonk.discover")
    fake.discover_host = discover_host
    monkeypatch.setitem(sys.modules, "secmonk.discover", fake)
    monkeypatch.setattr(secmonk, "discover", fake, raising=False)
    monkeypatch.setitem(REGISTRY, "multi", Multi)
    return seen


@pytest.fixture
def mirror(tmp_path, monkeypatch) -> Path:
    db = tmp_path / "m.db"
    c = connect(db)
    upsert_vulnerability(c, "osv", "GHSA-test-left-pad", severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GHSA-test-left-pad", ecosystem="npm", package="left-pad", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "1.0.1"}])
    c.commit()
    c.close()
    monkeypatch.setenv("SECMONK_DB", str(db))
    return db


# --------------------------------------------------------------------------- ops / reports

def test_scan_item_validation(calls):
    it = ops.scan_item("multi", " a ", "lang=yes\n\nsudo=no")
    assert (it.collector, it.target, it.options, it.opts) == ("multi", "a", ["lang=yes", "sudo=no"],
                                                              {"lang": True, "sudo": False})
    for args, msg in ((("nope",), "unknown collector"), (("multi", 3), "target must be a string"),
                      (("multi", "a", ["novalue"]), "expected key=value"), (("multi", "a", [1]), "options must")):
        with pytest.raises(ValueError, match=msg):
            ops.scan_item(*args)


def test_scan_items_batch(calls, mirror):
    items = [ops.scan_item("multi", "a"), ops.scan_item("multi", "none"), ops.scan_item("multi", "b,bad")]
    seen = []
    conn = connect(mirror)
    try:
        entries = ops.scan_items(conn, items, save=True, on_entry=lambda e, inv: seen.append(e["target"]))
        with pytest.raises(ValueError):
            ops.scan_items(conn, items[1:2], save=True, strict_expand=True)
    finally:
        conn.close()
    assert [(e["collector"], e["target"], bool(e["error"])) for e in entries] == [
        ("multi", "a", False), ("multi", "none", True), ("multi", "b", False), ("multi", "bad", True)]
    assert "no container matches" in entries[1]["error"] and seen == ["a", "none", "b", "bad"]
    status, result, _ = ops.scan_result(entries, saved=True)
    assert status == "partial" and result["counts"]["total"] == 2


def test_discover_payload_and_candidate_items(calls):
    p = ops.discover_host("ssh://deploy:pw@box", {"identity": "/k"})
    assert calls == [("ssh://deploy:pw@box", {"identity": "/k"})]
    assert p["host"] == {"kind": "ssh", "target": "ssh://deploy@box", "name": "box", "os": "linux",
                         "os_version": "12", "arch": "arm64"}
    assert p["warnings"] == ["no sudo: https://u@x.example/a"]
    docker = p["candidates"][1]
    assert set(docker) == {"id", "collector", "target", "options", "label", "description", "available", "reason",
                           "selected", "details"}
    assert docker["details"] == {} and docker["reason"] is None and p["candidates"][0]["details"] == {"count": 3}
    assert [i.target for i in ops.candidate_items(p, ["apps", "docker"])] == ["a", "b,c"]
    with pytest.raises(ValueError, match="unknown candidate nope"):
        ops.candidate_items(p, ["apps", "nope"])
    with pytest.raises(ValueError, match=r"not available: brew \(not installed\)"):
        ops.candidate_items(p, ["brew"])
    assert reports.discover_payload({})["host"]["kind"] == "local"


def test_batch_params_and_title(calls):
    items = [ops.scan_item("multi", "ssh://me:pw@h", ["password=x", "lang=yes"]), ops.scan_item("multi", "b")]
    p = ops.batch_params(items, save=False, min_confidence=0.7, host="ssh://me:pw@h:22")
    assert p == {"mode": "host", "host": "ssh://me@h:22", "save": False, "min_confidence": 0.7,
                 "items": [{"id": None, "collector": "multi", "target": "ssh://me@h",
                            "options": ["password=***", "lang=yes"]},
                           {"id": None, "collector": "multi", "target": "b", "options": []}]}
    assert ops.batch_params(items, save=True, min_confidence=0.5, host=None)["host"] == "local"
    assert ops.scan_item("multi", "a", None, "fs-home.1").id == "fs-home.1"
    for bad in ("", "Has Space", "-x", "x" * 65, 3, "ü"):
        with pytest.raises(ValueError, match="id: expected a short slug"):
            ops.scan_item("multi", "a", None, bad)
    assert ops.batch_title("box", ["macos", "process", "macos", "docker"]) == "scan host box: macos, process, docker"
    assert ops.batch_title(None, ["fs"]) == "scan host local: fs"


# --------------------------------------------------------------------------- web

def _req(srv, path, *, method="GET", body=None):
    hdrs = {"X-SecMonk-Request": "1"}
    data = None
    if body is not None:
        hdrs["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{srv.port}{path}", method=method, data=data, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def make_srv():
    servers = []

    def make(db, **kw):
        srv = make_server(ProcessMonitor(db_path=db, target=str(SNAP)), "127.0.0.1", 0, mode="snapshot", **kw)
        serve_in_thread(srv)
        servers.append(srv)
        return srv

    yield make
    for s in servers:
        s.shutdown()
        s.server_close()


def _wait(srv, jid):
    for _ in range(400):
        _s, j = _req(srv, f"/api/jobs/{jid}")
        if j["status"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_batch_job(calls, mirror, make_srv):
    srv = make_srv(mirror)
    body = {"kind": "scan", "host": "ssh://deploy:pw@box", "save": False, "min_confidence": 0.6,
            "items": [{"id": "apps", "collector": "multi", "target": "a", "options": ["password=hunter2"]},
                      {"collector": "multi", "target": "none"},
                      {"id": "docker", "collector": "multi", "target": "b,c", "options": "lang=yes"}]}
    s, j = _req(srv, "/api/jobs", method="POST", body=body)
    assert s == 202 and j["title"] == "scan host ssh://deploy@box: apps, multi, docker"
    assert j["params"] == {"mode": "host", "host": "ssh://deploy@box", "save": False, "min_confidence": 0.6,
                           "items": [{"id": "apps", "collector": "multi", "target": "a", "options": ["password=***"]},
                                     {"id": None, "collector": "multi", "target": "none", "options": []},
                                     {"id": "docker", "collector": "multi", "target": "b,c",
                                      "options": ["lang=yes"]}]}
    done = _wait(srv, j["id"])
    r = done["result"]
    assert done["status"] == "partial" and set(r) == {"saved", "targets", "stats", "counts"} and r["saved"] is False
    assert [(t["collector"], t["target"], bool(t["error"])) for t in r["targets"]] == [
        ("multi", "a", False), ("multi", "none", True), ("multi", "b", False), ("multi", "c", False)]
    assert r["counts"]["total"] == 3 and done["summary"]["errors"] == 1
    assert all(t["tags"] == [] and "requested_refs" not in t for t in r["targets"])     # not image assets
    assert "hunter2" not in mirror.read_bytes().decode("latin-1")
    with sqlite3.connect(mirror) as c:
        assert c.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == 0     # save: false


def test_single_collector_job_unchanged(calls, mirror, make_srv):
    srv = make_srv(mirror)
    s, j = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "collector": "multi", "target": "a"})
    assert s == 202 and set(j["params"]) == {"collector", "target", "options", "save", "min_confidence"}
    done = _wait(srv, j["id"])
    assert done["status"] == "ok" and done["result"]["targets"][0]["collector"] == "multi"
    _s, j = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "collector": "multi", "target": "none"})
    failed = _wait(srv, j["id"])                                  # single: no match = the job's error
    assert failed["status"] == "error" and "no container matches" in failed["error"] and failed["result"] is None


def test_batch_job_validation(calls, mirror, make_srv):
    srv = make_srv(mirror)
    ok = {"collector": "multi", "target": "a"}
    for items, msg in (([], "non-empty"), ("x", "non-empty"), ([ok] * 21, "at most 20"), ([1], "items[1]"),
                       ([ok, {"collector": "nope"}], "items[2]: unknown collector"),
                       ([{"collector": "multi", "options": ["novalue"]}], "expected key=value"),
                       ([{"collector": "multi", "id": "Bad Id"}], "items[1]: id: expected a short slug")):
        s, e = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "items": items})
        assert s == 400 and msg in e["error"], (items, e)
    s, e = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "items": [ok], "min_confidence": 3})
    assert s == 400
    s, j = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "items": [
        {"id": "docker", "collector": "multi", "target": "a", "options": ["remote_docker=/usr/bin/docker"]}]})
    assert s == 202 and j["params"]["items"][0]["options"] == ["remote_docker=/usr/bin/docker"]   # allowed, not secret
    _wait(srv, j["id"])
    for opt in ("ssh_bin=/tmp/x", "transport=openssh", "ssh_option=ProxyCommand=nc x 22"):
        s, e = _req(srv, "/api/jobs", method="POST",
                    body={"kind": "scan", "items": [ok, {"collector": "multi", "options": [opt]}]})
        assert s == 400 and "items[2]: option not accepted from the browser" in e["error"], opt
        s, e = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "collector": "multi", "options": [opt]})
        assert s == 400 and "not accepted from the browser" in e["error"], opt
    assert [j["title"] for j in _req(srv, "/api/jobs")[1]] == ["scan host local: docker"]   # no rejected one started


def test_discover_endpoint(calls, mirror, make_srv):
    srv = make_srv(mirror)
    q = urllib.parse.urlencode([("target", "deploy@box"), ("opt", "identity=/k"), ("opt", "connect_timeout=5")])
    s, p = _req(srv, "/api/discover?" + q)
    assert s == 200 and p["host"]["name"] == "box" and [c["id"] for c in p["candidates"]][:2] == ["apps", "docker"]
    assert calls[-1] == ("deploy@box", {"identity": "/k", "connect_timeout": "5"})
    assert _req(srv, "/api/discover")[0] == 200 and calls[-1] == (None, {})
    for bad in ("ssh_option=ProxyCommand=x", "ssh_bin=/tmp/x", "transport=openssh", "socket=/x"):
        s, e = _req(srv, "/api/discover?opt=" + urllib.parse.quote(bad))
        assert s == 400 and "not accepted" in e["error"], bad
    s, e = _req(srv, "/api/discover?target=" + urllib.parse.quote("bad host"))
    assert s == 400 and "invalid ssh target" in e["error"] and e["hint"]
    s, e = _req(srv, "/api/discover?target=down")
    assert s == 502 and "banner secret" not in json.dumps(e) and e["error"] == "cannot explore the host (OSError)"
    off = make_srv(mirror, actions=False)
    s, e = _req(off, "/api/discover")
    assert s == 403 and "--allow-actions" in e["hint"]


def test_runner_discover_without_server(calls, mirror):
    assert JobRunner(mirror).discover(target=None, options=[])["host"]["kind"] == "local"


def test_one_discovery_at_a_time(calls, mirror, monkeypatch):
    import threading

    gate, started = threading.Event(), threading.Event()
    real = sys.modules["secmonk.discover"].discover_host

    def slow(target=None, **opts):
        started.set()
        gate.wait(10)
        return real(target, **opts)

    monkeypatch.setattr(sys.modules["secmonk.discover"], "discover_host", slow)
    r = JobRunner(mirror)
    t = threading.Thread(target=r.discover, kwargs={"target": None, "options": []})
    t.start()
    assert started.wait(10)
    with pytest.raises(Exception) as busy:
        r.discover(target=None, options=[])
    assert busy.value.status == 409 and "already running" in busy.value.message
    gate.set()
    t.join(10)
    assert r.discover(target=None, options=[])["host"]["kind"] == "local"     # free again


def test_image_patterns_are_selectors():
    from secmonk.collectors import docker_engine

    if hasattr(docker_engine, "is_image_pattern"):
        assert ops.is_selector("docker-engine", "image:*") and ops.is_selector("docker-engine", "image:re:^app")
        assert not ops.is_selector("docker-engine", "image:nginx:1.27")


# --------------------------------------------------------------------------- CLI

def run(*args, code=0, input=None):
    res = runner.invoke(app, [str(a) for a in args], input=input)
    assert res.exit_code == code, f"exit {res.exit_code} != {code}\n{res.output}\n{res.exception!r}"
    return res


def test_cli_discover(calls, mirror):
    doc = json.loads(run("discover", "deploy@box", "-o", "identity=/k", "-f", "json").stdout)
    assert doc["host"]["name"] == "box" and len(doc["candidates"]) == 5
    assert calls[-1] == ("deploy@box", {"identity": "/k"})
    res = run("discover")
    assert "apps" in res.stdout and "not installed" in res.stdout and "box" in res.stderr
    assert "warning" in res.stderr
    assert "invalid ssh target" in run("discover", "bad host", code=2).output
    res = run("discover", "down", code=1)
    assert "kex failed" in res.output and "Traceback" not in res.output
    run("discover", "-f", "csv", code=2)


def test_cli_scan_host_choices(calls, mirror):
    doc = json.loads(run("scan-host", "--only", "apps,docker", "-f", "json").stdout)
    assert set(doc) == {"saved", "targets", "stats", "counts"}
    assert [t["target"] for t in doc["targets"]] == ["a", "b", "c"] and doc["counts"]["total"] == 3
    res = run("scan-host", "--yes", "-f", "json", code=1)        # default selection: apps + broken
    assert [t["target"] for t in json.loads(res.stdout)["targets"]] == ["a", "bad"]
    assert "1 of 2 target(s) failed" in res.output
    doc = json.loads(run("scan-host", "--only", "gone,apps", "-f", "json", code=1).stdout)
    assert doc["targets"][0]["error"] and doc["targets"][1]["asset"] == "multi:a"   # a failed item: others run
    assert "unknown candidate nope" in run("scan-host", "--only", "nope", code=2).output
    assert "not available: brew" in run("scan-host", "--only", "brew", code=2).output
    assert "choose one of" in run("scan-host", "--all", "--yes", code=2).output
    assert "--only id,id" in run("scan-host", code=2).output                       # not a terminal, no choice
    res = run("scan-host", "--all", code=1)                                        # every available one, table
    assert "multi:a" in res.stdout and "multi:c" in res.stdout and "Findings" in res.stdout
    assert "cannot reach bad" in res.stderr

    rows = json.loads(run("history", "-f", "json").stdout)
    last = rows[0]
    assert last["title"] == "scan host box: apps, docker, gone, broken" and last["origin"] == "cli"
    assert last["params"]["mode"] == "host" and last["params"]["host"] == "local"
    assert [i["id"] for i in last["params"]["items"]] == ["apps", "docker", "gone", "broken"]
    assert [i["target"] for i in last["params"]["items"]] == ["a", "b,c", "none", "bad"]
    first = rows[-1]
    assert first["params"]["items"][0] == {"id": "apps", "collector": "multi", "target": "a", "options": ["lang=yes"]}


def _json_after_echo(out: str):
    """CliRunner echoes the typed answer to stdout (a terminal would show it on the tty)."""
    return json.loads(out[out.index("{"):])


def test_cli_scan_host_prompt(calls, mirror, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    res = run("scan-host", "ssh://deploy:pw@box", "-f", "json", input="1,docker\n")
    assert [t["target"] for t in _json_after_echo(res.stdout)["targets"]] == ["a", "b", "c"]
    assert "Scan candidates" in res.stderr
    res = run("scan-host", "-f", "json", input="\n", code=1)                       # default: the selected ones
    assert [t["target"] for t in _json_after_echo(res.stdout)["targets"]] == ["a", "bad"]
    assert "no candidate number 9" in run("scan-host", input="9\n", code=2).output
    assert "unknown candidate" in run("scan-host", input="\u0661\n", code=2).output     # Arabic-Indic digit: an id
    assert "unknown candidate 1-2" in run("scan-host", input="1-2\n", code=2).output
    rows = json.loads(run("history", "-f", "json").stdout)
    assert rows[-1]["params"]["host"] == "ssh://deploy@box" and rows[-1]["title"] == "scan host box: apps, docker"


def test_cli_scan_host_no_save_needs_a_mirror(calls, tmp_path, monkeypatch):
    monkeypatch.setenv("SECMONK_DB", str(tmp_path / "none.db"))
    assert "no database" in run("scan-host", "--yes", "--no-save", code=1).output
    assert not calls                                                               # not even discovered
