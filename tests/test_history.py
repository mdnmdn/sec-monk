"""Multi-target scans (Collector.expand_targets) and the run history (table `job`): ops, JobRunner, web API, CLI.

Everything runs against a fake collector `multi` (target spec = comma list; `bad` fails, `half` is partial) and a
tiny synthetic mirror; the docker endpoints use monkeypatched engine functions (no engine needed).
"""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk import db as dbm
from secmonk import ops, reports
from secmonk.cli import app
from secmonk.collectors.base import REGISTRY, Collector, redact_option
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
    description = "test: comma-separated targets"

    def expand_targets(self, target, **opts):
        if target == "none":
            return []
        if target == "unreachable":
            raise OSError("engine down")
        return [t for t in (target or "").split(",") if t]

    def collect(self, target=None, **opts):
        if target == "bad":
            raise OSError("cannot reach bad")
        inv = Inventory(Asset(f"multi:{target}", "server", target), "multi",
                        [Component("left-pad", "1.0.0", "library", purl="pkg:npm/left-pad@1.0.0", ecosystem="npm")],
                        warnings=[f"note about {target}"])
        if target == "half":
            inv.mark_partial("test")
        return inv


class Plain:                     # a collector without expand_targets (duck-typed, like older test collectors)
    name = "plain"

    def collect(self, target=None, **opts):
        return Inventory(Asset("plain:1", "server", "p"), "plain")


@pytest.fixture(autouse=True)
def fake_collectors(monkeypatch):
    monkeypatch.setitem(REGISTRY, "multi", Multi)
    monkeypatch.setitem(REGISTRY, "plain", Plain)


@pytest.fixture
def mirror(tmp_path) -> Path:
    db = tmp_path / "m.db"
    c = connect(db)
    upsert_vulnerability(c, "osv", "GHSA-test-left-pad", severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GHSA-test-left-pad", ecosystem="npm", package="left-pad", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "1.0.1"}])
    c.commit()
    c.close()
    return db


# --------------------------------------------------------------------------- ops: expansion, aggregation, redaction

def test_expand_targets():
    assert ops.expand_targets("multi", "a,b", {}) == ["a", "b"]
    assert ops.expand_targets("plain", "x", {}) == ["x"]
    assert ops.expand_targets("fs", "/tmp", {}) == ["/tmp"]              # base Collector default
    with pytest.raises(KeyError):
        ops.expand_targets("nope", None, {})
    with pytest.raises(ValueError, match="no multi target matches"):
        ops.expand_targets("multi", "none", {})
    assert {"all", "tls_verify"} <= ops.BOOL_OPTS and ops.parse_opts(["all=yes"]) == {"all": True}


def test_scan_targets_and_aggregation(mirror):
    conn = connect(mirror)
    try:
        entries = [ops.scan_target(conn, "multi", t, {}, save=True)[0] for t in ("a", "bad", "half")]
    finally:
        conn.close()
    a, bad, half = entries
    assert a["asset"] == "multi:a" and a["scan_id"] and a["counts"]["total"] == 1 and a["error"] is None
    assert a["findings"][0]["vuln_id"] == "GHSA-test-left-pad" and a["warnings"] == ["note about a"]
    assert bad["error"] == "OSError: cannot reach bad" and bad["asset"] is None and bad["findings"] == []
    assert half["partial"] and half["error"] is None
    status, result, error = ops.scan_result(entries, saved=True)
    assert status == "partial" and error is None and result["saved"] is True
    assert result["stats"]["components"] == 2 and result["counts"]["total"] == 2 and len(result["targets"]) == 3
    assert ops.scan_result([a], saved=True)[0] == "ok"
    assert ops.scan_result([a, bad], saved=True)[0] == "partial"
    assert ops.scan_result([half], saved=True)[0] == "partial"
    st, _, err = ops.scan_result([bad, dict(bad)], saved=True)
    assert st == "error" and err.startswith("all 2 targets failed")
    assert ops.scan_result([bad], saved=False)[2] == "OSError: cannot reach bad"


def test_redaction():
    assert redact_option("password", "hunter2") == "***"
    assert redact_option("passphrase", "x") == "***" and redact_option("api_token", "x") == "***"
    assert redact_option("ssh_key", "x") == "***" and redact_option("client_secret", "x") == "***"
    assert redact_option("identity", "~/.ssh/id_ed25519") == "~/.ssh/id_ed25519"      # a path, not a secret
    assert redact_option("tls_key", "/certs/key.pem") == "/certs/key.pem"
    assert redact_option("host", "tcp://u:pw@docker.example:2376?t=1") == "tcp://u@docker.example:2376"
    assert redact_option("host", "ssh://deploy@h:2222") == "ssh://deploy@h:2222"            # a user is no secret
    assert redact_option("host", "unix:///var/run/docker.sock") == "unix:///var/run/docker.sock"
    assert redact_option("platform", "linux/arm64") == "linux/arm64"
    for key in ("tls_password", "tls_key_passphrase", "identity_passphrase", "pass", "ssh_pass", "registry_token"):
        assert redact_option(key, "s3cret") == "***", key
    for key in ("tls_ca", "tls_cert", "known_hosts", "ssh_config", "password_file", "cache_path"):
        assert redact_option(key, "/some/file") == "/some/file", key
    assert redact_option("ssh_option", "ProxyCommand=sshpass -p s3cret ssh -W %h:%p jump") == \
        "ProxyCommand=sshpass -p *** ssh -W %h:%p jump"
    assert redact_option("ssh_option", ["--password=x", "StrictHostKeyChecking=yes"]) == \
        ["--password=<redacted>", "StrictHostKeyChecking=yes"]
    assert redact_option("note", "see https://u:pw@x.example/a?token=1") == "see https://u@x.example/a"
    p = ops.scan_params("ssh", "ssh://root:pw@h:22", ["password=hunter2", "identity=/k", "sudo=yes", "flag"],
                        save=False, min_confidence=0.5)
    assert p == {"collector": "ssh", "target": "ssh://root@h:22", "options": ["password=***", "identity=/k", "sudo=yes",
                                                                          "flag"], "save": False, "min_confidence": 0.5}
    assert ops.scan_title("ssh", "ssh://u:pw@h") == "scan ssh ssh://u@h" and ops.redact_target(None) is None


# --------------------------------------------------------------------------- db: history table

def test_history_table_survives_overlay_and_prunes(mirror, monkeypatch):
    conn = connect(mirror)
    try:
        dbm.ephemeral_overlay(conn)                     # a --no-save scan: inventory shadowed, history not
        temp = {r[0] for r in conn.execute("SELECT name FROM sqlite_temp_master WHERE type='table'")}
        assert "job" not in temp and "asset" in temp
        jid = dbm.job_insert(conn, kind="scan", origin="cli", title="t", params={"a": 1})
        dbm.job_finish(conn, jid, status="ok", result={"saved": False, "targets": []}, log=["x"] * 500)
    finally:
        conn.close()
    with sqlite3.connect(mirror) as c:
        status, log = c.execute("SELECT status, log FROM job WHERE id=?", (jid,)).fetchone()
    assert status == "ok" and len(json.loads(log)) == dbm.JOB_LOG_LINES
    monkeypatch.setattr(dbm, "JOB_KEEP", 3)
    conn = connect(mirror)
    try:
        ids = [dbm.job_insert(conn, kind="sync", origin="ui", title=str(i), params={}) for i in range(5)]
        rows = dbm.job_rows(conn, limit=50)
        assert [r["id"] for r in rows] == ids[::-1][:3] and rows[0].keys().count("log") == 0  # sqlite3.Row: keys() is a list
        assert [r["id"] for r in dbm.job_rows(conn, kind="scan")] == []
        assert dbm.job_mark_interrupted(conn) == 0              # owned by this (live) process
    finally:
        conn.close()


def _dead_pid() -> int:
    import subprocess
    import sys

    p = subprocess.Popen([sys.executable, "-c", ""])
    p.wait()
    return p.pid


def _set_owner(db, jid, owner):
    with sqlite3.connect(db) as c:
        c.execute("UPDATE job SET owner=? WHERE id=?", (json.dumps(owner), jid))


def test_owner_liveness():
    import os
    import socket

    host = socket.gethostname()
    assert dbm.owner_alive({"pid": os.getpid(), "host": host})
    assert dbm.owner_alive({"pid": os.getppid(), "host": host})               # another live process
    assert not dbm.owner_alive({"pid": _dead_pid(), "host": host})
    assert not dbm.owner_alive({"pid": os.getpid(), "host": host + "-elsewhere"})
    assert not dbm.owner_alive(None) and not dbm.owner_alive({"pid": "x", "host": host})


def test_backstop_scrubbing_and_caps(mirror):
    from secmonk.collectors.base import scrub_text

    assert scrub_text("GET tcp://u:pw@h:2376/v1?x=1 failed") == "GET tcp://u@h:2376/v1 failed"
    # trailing punctuation after a URL in a message is no "<invalid-url>"
    assert scrub_text("cannot talk to ssh://deploy@127.0.0.1:1: refused") == \
        "cannot talk to ssh://deploy@127.0.0.1:1: refused"
    assert scrub_text("at unix:///var/run/docker.sock.") == "at unix:///var/run/docker.sock."
    assert scrub_text(None) is None and scrub_text("plain") == "plain"
    rows = [{"vuln_id": f"V{i}"} for i in range(700)]
    res = {"saved": True, "targets": [{"target": "a", "findings": rows, "error": "x https://a:b@h/p"}],
           "stats": {}, "counts": {}}
    stored = ops.stored_result("scan", res)
    assert len(stored["targets"][0]["findings"]) == ops.STORED_FINDINGS and stored["targets"][0]["error"] == "x https://a@h/p"
    assert len(res["targets"][0]["findings"]) == 700                           # the caller's copy is untouched
    conn = connect(mirror)
    try:
        jid = dbm.job_insert(conn, kind="scan", origin="cli", title="t", params={})
        ops.finish_run(conn, jid, "scan", status="error", result=res, error="boom ssh://me:pw@h",
                       log=["line ssh://me:pw@h"])
        d = reports.job_dict(dbm.job_row(conn, jid))
        listed = reports.job_dict(dbm.job_rows(conn)[0], include_log=False)
    finally:
        conn.close()
    assert d["error"] == "boom ssh://me@h" and d["log"] == ["line ssh://me@h"] and ":pw" not in json.dumps(d)
    assert listed["log_lines"] == 1 and listed["summary"] == d["summary"] and "log" not in listed


def test_record_run_marks_interruption(mirror):
    with pytest.raises(KeyboardInterrupt), ops.record_run(mirror, "sync", "cli", "sync kev", {}) as rec:
        raise KeyboardInterrupt
    with pytest.raises(RuntimeError), ops.record_run(mirror, "sync", "cli", "sync kev", {}):
        raise RuntimeError("bad")
    conn = connect(mirror)
    try:
        rows = {r["id"]: r["error"] for r in dbm.job_rows(conn)}
    finally:
        conn.close()
    assert rows[rec.id] == "interrupted" and rows[rec.id + 1] == "RuntimeError: bad"


def test_job_payload_summary():
    scan = {"saved": True, "targets": [{"error": None}, {"error": "x"}], "stats": {"components": 4},
            "counts": {"P1": 1, "P2": 0, "P3": 2, "P4": 0, "kev": 1, "total": 3}}
    assert reports.job_summary("scan", scan) == {"targets": 2, "errors": 1, "components": 4, "P1": 1, "P2": 0,
                                                 "P3": 2, "P4": 0, "kev": 1, "total": 3}
    sync = {"sources": [{"status": "ok", "records": 5}, {"status": "error", "records": 0}]}
    assert reports.job_summary("sync", sync) == {"sources": 2, "errors": 1, "records": 5}
    assert reports.job_summary("scan", None) == {}


# --------------------------------------------------------------------------- JobRunner: persistence

def _wait(get, job_id):
    for _ in range(400):
        j = get(job_id)
        if j["status"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_jobs_persist_across_runners(mirror):
    r1 = JobRunner(mirror)
    j = r1.start({"kind": "scan", "collector": "multi", "target": "a,bad", "options": ["password=hunter2"],
                  "save": False})
    assert j["origin"] == "ui" and j["params"]["options"] == ["password=***"]
    done = _wait(r1.get, j["id"])
    assert done["status"] == "partial" and done["result"]["saved"] is False
    assert [t["target"] for t in done["result"]["targets"]] == ["a", "bad"]
    assert done["summary"]["targets"] == 2 and done["summary"]["errors"] == 1
    assert any("2 target(s)" in line for line in done["log"])
    r2 = JobRunner(mirror)                                     # a new server: reads the stored run
    again = r2.get(j["id"])
    assert again == done
    assert "hunter2" not in Path(mirror).read_bytes().decode("latin-1")
    assert [x["id"] for x in r2.list()] == [j["id"]] and "log" not in r2.list()[0]
    with sqlite3.connect(mirror) as c:                         # --no-save: no inventory stored
        assert c.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == 0


def test_expansion_error_is_a_job_error(mirror):
    r = JobRunner(mirror)
    for target, msg in (("none", "no multi target matches"), ("unreachable", "engine down")):
        done = _wait(r.get, r.start({"kind": "scan", "collector": "multi", "target": target})["id"])
        assert done["status"] == "error" and msg in done["error"] and done["result"] is None


def test_interrupted_runs(mirror):
    import os
    import socket

    conn = connect(mirror)
    try:
        dead = dbm.job_insert(conn, kind="sync", origin="ui", title="sync kev", params={})
        live = dbm.job_insert(conn, kind="scan", origin="cli", title="scan fs", params={})
    finally:
        conn.close()
    host = socket.gethostname()
    _set_owner(mirror, dead, {"pid": _dead_pid(), "host": host})       # the server that ran it died
    _set_owner(mirror, live, {"pid": os.getppid(), "host": host})      # a CLI scan still running elsewhere

    off = JobRunner(mirror, enabled=False)                     # actions off: reads only, nothing written
    assert off.get(dead)["status"] == "error" and off.get(dead)["error"] == "interrupted"
    with sqlite3.connect(mirror) as c:
        assert c.execute("SELECT status FROM job WHERE id=?", (dead,)).fetchone()[0] == "running"
    r = JobRunner(mirror)                                      # a new server with actions: makes it permanent
    j = r.get(dead)
    assert j["status"] == "error" and j["error"] == "interrupted" and j["finished"]
    assert r.get(live)["status"] == "running" and not r.busy
    with sqlite3.connect(mirror) as c:
        assert dict(c.execute("SELECT id, status FROM job").fetchall()) == {dead: "error", live: "running"}


def test_runner_start_survives_a_locked_database(mirror):
    holder = sqlite3.connect(mirror, timeout=0)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        JobRunner(mirror)                                      # marking fails quietly: the server still starts
    finally:
        holder.rollback()
        holder.close()


# --------------------------------------------------------------------------- web API

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


def test_api_jobs_merge_history(mirror, make_srv, monkeypatch):
    monkeypatch.setenv("SECMONK_DB", str(mirror))
    assert runner.invoke(app, ["scan", "multi", "a", "--quiet"]).exit_code == 0          # job 1, origin cli
    srv = make_srv(mirror)
    s, j = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "collector": "multi", "target": "b,c"})
    assert s == 202 and j["id"] == 2 and j["origin"] == "ui"
    done = _wait(lambda i: _req(srv, f"/api/jobs/{i}")[1], j["id"])
    assert done["status"] == "ok" and [t["asset"] for t in done["result"]["targets"]] == ["multi:b", "multi:c"]
    s, jobs = _req(srv, "/api/jobs")
    assert s == 200 and [(x["id"], x["origin"]) for x in jobs] == [(2, "ui"), (1, "cli")]
    assert {"id", "kind", "origin", "title", "params", "started", "finished", "status", "error", "result",
            "summary", "log_lines"} == set(jobs[1])
    s, one = _req(srv, "/api/jobs/1")                          # persisted CLI run, log from the database
    assert s == 200 and one["origin"] == "cli" and one["result"]["targets"][0]["asset"] == "multi:a" and one["log"]
    assert [x["id"] for x in _req(srv, "/api/jobs?kind=sync")[1]] == []
    assert [x["id"] for x in _req(srv, "/api/jobs?limit=1")[1]] == [2]
    for bad in ("/api/jobs?kind=nope", "/api/jobs?limit=0", "/api/jobs?limit=201", "/api/jobs?limit=x"):
        assert _req(srv, bad)[0] == 400, bad
    assert _req(srv, "/api/jobs/99")[0] == 404


def test_api_docker_endpoints(mirror, make_srv, monkeypatch):
    from secmonk.collectors import docker_engine

    seen = {}

    def list_containers(all=False, **opts):
        seen.update(opts, all=all)
        return [{"Id": "aaaaaaaaaaaa1111", "Names": ["/web-1"], "Image": "nginx", "State": "running", "Status": "Up"},
                {"Id": "bbbbbbbbbbbb2222", "Names": ["/db"], "Image": "postgres", "State": "exited", "Status": "Exited"}]

    def select_containers(selector, containers):
        if selector.startswith("re:("):
            raise ValueError("bad regex")
        if selector == "web-*":
            return ["web-1"]
        raise ValueError(f"no container matches {selector!r}; available: web-1, db")

    monkeypatch.setattr(docker_engine, "list_containers", list_containers)
    monkeypatch.setattr(docker_engine, "select_containers", select_containers, raising=False)
    monkeypatch.setattr(docker_engine, "list_contexts", lambda **o: [
        {"name": "default", "host": "unix:///var/run/docker.sock", "description": "local", "current": True},
        {"name": "prod", "host": "ssh://deploy@prod.example", "description": "", "current": False}], raising=False)
    srv = make_srv(mirror)
    s, ctx = _req(srv, "/api/docker/contexts")
    assert s == 200 and [c["name"] for c in ctx] == ["default", "prod"] and ctx[1]["host"] == "ssh://prod.example"
    assert ctx[0]["host"] == "unix:///var/run/docker.sock"
    s, c = _req(srv, "/api/docker/containers?host=ssh://deploy@prod.example&all=1&match=web-*")
    assert s == 200 and c["engine"] == "ssh://prod.example" and seen == {"host": "ssh://deploy@prod.example",
                                                                          "all": True}
    assert [(r["name"], r["matched"]) for r in c["containers"]] == [("web-1", True), ("db", False)]
    assert set(c["containers"][0]) == {"id", "name", "image", "state", "status", "matched"}
    s, c = _req(srv, "/api/docker/containers?match=web-*,nope-*")          # a pattern matching nothing: no match
    assert s == 200 and [r["matched"] for r in c["containers"]] == [True, False]
    seen.clear()
    s, c = _req(srv, "/api/docker/containers?context=prod&opt=tls_verify=yes&opt=identity=/k&opt=timeout=5")
    assert s == 200 and c["engine"] == "context prod" and all(r["matched"] for r in c["containers"])
    assert seen == {"context": "prod", "tls_verify": True, "identity": "/k", "timeout": "5", "all": False}
    assert _req(srv, "/api/docker/containers?opt=novalue")[0] == 400
    for bad in ("ssh_bin=/tmp/evil", "socket=/var/run/x.sock", "context=other", "host=tcp://x:1", "all=yes"):
        s, e = _req(srv, "/api/docker/containers?opt=" + urllib.parse.quote(bad))
        assert s == 400 and "not accepted" in e["error"], bad
    s, e = _req(srv, "/api/docker/containers?match=re:(")
    assert s == 400 and e["hint"]
    monkeypatch.setattr(docker_engine, "list_containers",
                        lambda **k: (_ for _ in ()).throw(RuntimeError("engine said: <html>secret page</html>")))
    s, e = _req(srv, "/api/docker/containers")
    assert s == 502 and "secret page" not in e["error"] and e["error"].startswith("cannot reach") and e["hint"]
    off = make_srv(mirror, actions=False)
    for path in ("/api/docker/contexts", "/api/docker/containers"):
        s, e = _req(off, path)
        assert s == 403 and "--allow-actions" in e["hint"], path
    assert _req(off, "/api/jobs")[0] == 200                     # the history stays readable


# --------------------------------------------------------------------------- CLI

def run(*args, code=0):
    res = runner.invoke(app, [str(a) for a in args])
    assert res.exit_code == code, f"exit {res.exit_code} != {code}\n{res.output}\n{res.exception!r}"
    return res


def test_cli_multi_target_scan_and_history(mirror, monkeypatch):
    monkeypatch.setenv("SECMONK_DB", str(mirror))
    doc = json.loads(run("scan", "multi", "a,b", "-f", "json").stdout)
    assert set(doc) == {"saved", "targets", "stats", "counts"}                 # = the stored scan result
    assert doc["saved"] is True and doc["counts"]["total"] == 2 and doc["stats"]["components"] == 2
    assert [t["asset"] for t in doc["targets"]] == ["multi:a", "multi:b"]
    assert set(doc["targets"][0]) == {"collector", "target", "asset", "scan_id", "stats", "warnings", "partial",
                                      "findings", "counts", "error", "reused", "reused_scan_id", "tags"}
    assert doc["targets"][0]["counts"]["total"] == 1
    assert json.loads(run("scan", "multi", "a", "-f", "json", "--priority", "P1").stdout)["findings"] == []
    single = json.loads(run("scan", "multi", "a", "-f", "json").stdout)
    assert set(single) == {"asset", "stats", "warnings", "partial", "findings"}         # today's shape
    res = run("scan", "multi", "a,bad", "-o", "password=hunter2", code=1)
    assert "multi:a" in res.stdout and "cannot reach bad" in res.output and "1 of 2 target(s) failed" in res.output
    assert "Findings" in res.stdout
    res = run("scan", "multi", "bad", code=1)                                           # single: same message as before
    assert "multi: OSError: cannot reach bad" in res.output
    assert "no multi target matches" in run("scan", "multi", "none", code=1).output
    run("scan", "multi", "c", "--no-save", "--quiet")
    run("scan", "multi", "a,b", "--fail-on", "P4", code=3)

    rows = json.loads(run("history", "-f", "json").stdout)
    assert [r["status"] for r in rows[:5]] == ["ok", "ok", "error", "error", "partial"]
    nosave = rows[1]
    assert nosave["origin"] == "cli" and nosave["params"]["save"] is False and nosave["result"]["saved"] is False
    with sqlite3.connect(mirror) as c:
        assert c.execute("SELECT COUNT(*) FROM asset WHERE id='multi:c'").fetchone()[0] == 0
    failed = rows[4]
    assert failed["params"]["options"] == ["password=***"] and failed["summary"]["errors"] == 1
    assert rows[2]["error"] == "ValueError: no multi target matches 'none'"
    assert len(json.loads(run("history", "--kind", "sync", "-f", "json").stdout)) == 0
    assert len(json.loads(run("history", "-n", "2", "-f", "json").stdout)) == 2
    table = run("history").stdout
    assert "History" in table and "scan multi a,bad" in table and "1 failed" in table
    assert run("history", "-f", "csv").stdout.startswith("id,kind,origin,title,status,started,summary")
    shown = json.loads(run("history", "show", str(failed["id"]), "-f", "json").stdout)
    assert shown["result"]["targets"][1]["error"] == "OSError: cannot reach bad" and shown["log"]
    out = run("history", "show", str(failed["id"]), "--log").stdout
    assert "multi:a" in out and "cannot reach bad" in out and "GHSA-test-left-pad" in out
    run("history", "show", "999", code=1)
    run("history", "show", "1", "-f", "csv", code=2)


def test_cli_output_shapes(mirror, monkeypatch):
    monkeypatch.setenv("SECMONK_DB", str(mirror))
    out = run("scan", "multi", "a,b", "-f", "csv", "-q").stdout                 # one CSV document for all targets
    lines = out.strip().splitlines()
    assert sum(line.startswith("priority,") for line in lines) == 1 and len(lines) == 3
    assert "multi:a" in out and "multi:b" in out
    # a comma list that yields one target keeps the multi-target document; a lone name keeps the old one
    assert "targets" in json.loads(run("scan", "multi", "a,", "-f", "json").stdout)
    assert "asset" in json.loads(run("scan", "multi", "a", "-f", "json").stdout)
    # a failed target and a --fail-on hit: both reported, exit 1 wins
    res = run("scan", "multi", "a,bad", "--fail-on", "P4", code=1)
    assert "at or above P4" in res.output and "1 of 2 target(s) failed" in res.output


def test_is_selector(monkeypatch):
    from secmonk.collectors import docker_engine

    assert ops.is_selector("fs", "a,b") and not ops.is_selector("fs", "/srv") and not ops.is_selector("fs", None)
    if hasattr(docker_engine, "is_pattern"):
        assert ops.is_selector("docker-engine", "web-*") and ops.is_selector("docker-engine", "re:^web")
        assert not ops.is_selector("docker-engine", "web ") and not ops.is_selector("docker-engine", "image:nginx")


def test_strip_url_secrets_is_lenient():
    from secmonk.collectors.base import strip_url_secrets

    assert strip_url_secrets("unix:///var/run/docker.sock") == "unix:///var/run/docker.sock"
    assert strip_url_secrets("ssh://deploy@127.0.0.1:1") == "ssh://127.0.0.1:1"
    assert strip_url_secrets("ssh://deploy:pw@127.0.0.1:1", keep_user=True) == "ssh://deploy@127.0.0.1:1"
    assert strip_url_secrets("tcp://h:notaport/x?q#f") == "tcp://h:notaport/x"
    assert strip_url_secrets("ssh://[::1]:22") == "ssh://[::1]:22"


def test_cli_scan_history_keeps_ssh_user(mirror, monkeypatch):
    """A failed remote-engine scan: the stored host keeps its user (to run it again), never a password."""
    monkeypatch.setenv("SECMONK_DB", str(mirror))
    run("scan", "multi", "bad", "-o", "host=ssh://deploy:pw@127.0.0.1:1", "-o", "socket=unix:///run/d.sock", code=1)
    row = json.loads(run("history", "-f", "json").stdout)[0]
    assert row["params"]["options"] == ["host=ssh://deploy@127.0.0.1:1", "socket=unix:///run/d.sock"]


def test_cli_sync_is_recorded(tmp_path, monkeypatch):
    db = tmp_path / "s.db"
    monkeypatch.setenv("SECMONK_DB", str(db))
    kev = Path(__file__).parent / "fixtures/sources/kev/known_exploited_vulnerabilities.json"
    run("sync", "kev", "--path", kev)
    rows = json.loads(run("history", "-f", "json").stdout)
    assert rows[0]["kind"] == "sync" and rows[0]["status"] == "ok" and rows[0]["origin"] == "cli"
    assert rows[0]["result"]["sources"][0]["records"] == 9 and rows[0]["summary"]["records"] == 9
    assert "kev" in run("history", "show", str(rows[0]["id"])).stdout


def test_cli_history_needs_a_database(tmp_path, monkeypatch):
    monkeypatch.setenv("SECMONK_DB", str(tmp_path / "none.db"))
    assert "no database" in run("history", code=1).output


def test_cli_containers_options(monkeypatch):
    from secmonk.collectors import docker_engine

    seen = {}

    def list_containers(all=False, **opts):
        seen.update(opts)
        return [{"Id": "aaaaaaaaaaaa1111", "Names": ["/web-1"], "Image": "nginx", "State": "running", "Status": "Up"},
                {"Id": "bbbbbbbbbbbb2222", "Names": ["/db"], "Image": "postgres", "State": "running", "Status": "Up"}]

    monkeypatch.setattr(docker_engine, "list_containers", list_containers)
    monkeypatch.setattr(docker_engine, "select_containers", lambda sel, cs: ["web-1"], raising=False)
    rows = json.loads(run("containers", "--context", "prod", "--match", "web-*", "-f", "json").stdout)
    assert [r["name"] for r in rows] == ["web-1"] and seen == {"context": "prod"}
    run("containers", "-o", "host=ssh://me@h.example", "-o", "tls_verify=no", "-o", "ssh_bin=/opt/ssh")
    assert seen == {"context": "prod", "host": "ssh://me@h.example", "tls_verify": False, "ssh_bin": "/opt/ssh"}
    seen.clear()
    out = run("containers", "--host", "tcp://u:pw@d.example:2376").stdout
    assert "web-1" in out and "db" in out and "d.example" in out and "pw" not in out
    assert seen["host"] == "tcp://u:pw@d.example:2376"
