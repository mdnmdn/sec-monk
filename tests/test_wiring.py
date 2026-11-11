"""Wiring of the Linux/remote process backend and the k8s collector into the CLI, ops and the web API:
`procs ssh://… --watch`, the remote `process` discovery candidate, option parsing, the browser option policy and
`GET /api/k8s/kubeconfigs`. Remote snapshots and kubeconfig listings are faked (no ssh, no cluster)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk import cli, ops
from secmonk.cli import app
from secmonk.collectors.process import remote
from secmonk.collectors.process import snapshot as snapfile
from secmonk.web.api import ProcessMonitor
from secmonk.web.server import make_server, serve_in_thread

FIX = Path(__file__).parent / "fixtures"
SNAP = FIX / "collectors/process/snapshot.json"
runner = CliRunner()


def run(*args, code=0):
    res = runner.invoke(app, [str(a) for a in args])
    assert res.exit_code == code, f"exit {res.exit_code} != {code}\n{res.output}\n{res.exception!r}"
    return res


# --------------------------------------------------------------------------- options

def test_parse_opts_k8s_and_process_keys():
    assert ops.parse_opts(["namespace=shop,payments", "kernel_threads=yes", "packages=no", "sudo=true"]) == {
        "namespace": ["shop", "payments"], "kernel_threads": True, "packages": False, "sudo": True}
    assert ops.parse_opts(["namespace=shop"]) == {"namespace": "shop"}


# --------------------------------------------------------------------------- procs over ssh

@pytest.fixture
def fake_remote(monkeypatch, tmp_path):
    calls, sleeps = [], []

    def take(target, **opts):
        calls.append((target, opts))
        return snapfile.load(SNAP)

    monkeypatch.setattr(remote, "take_remote_snapshot", take)
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)
    monkeypatch.setenv("SECMONK_DB", str(tmp_path / "none.db"))
    return calls, sleeps


def test_procs_remote_target_and_watch(fake_remote):
    calls, sleeps = fake_remote
    doc = json.loads(run("procs", "ssh://ops@web1", "-o", "sudo=true", "-o", "identity=/k", "-f", "json").stdout)
    assert doc["processes"] and calls == [("ssh://ops@web1", {"sudo": True, "identity": "/k"})]
    res = run("-q", "procs", "ssh://ops@web1:2222", "--watch", "2", "--max-ticks", "2")
    assert sleeps == [10.0, 10.0]                               # remote minimum interval
    assert [c[0] for c in calls[1:]] == ["ssh://ops@web1:2222"] * 3   # baseline + 2 ticks, same host
    assert "Traceback" not in res.output
    run("-q", "procs", "ssh://ops@web1", "--watch", "30", "--max-ticks", "1")
    assert sleeps[-1] == 30.0
    assert "not a file" in " ".join(run("procs", str(SNAP), "--watch", "5", code=2).output.split())   # snapshot files: no watch
    assert "ssh://user@host" in run("procs", "--help").output


def test_procs_remote_watch_survives_a_failed_snapshot(fake_remote, monkeypatch):
    _calls, sleeps = fake_remote
    n = {"i": 0}
    good = remote.take_remote_snapshot

    def flaky(target, **opts):
        n["i"] += 1
        if n["i"] == 2:
            raise OSError("connection reset")
        return good(target, **opts)

    monkeypatch.setattr(remote, "take_remote_snapshot", flaky)
    res = run("procs", "ssh://ops@web1", "--watch", "10", "--max-ticks", "2")
    assert "snapshot failed: connection reset" in res.output and sleeps == [10.0, 10.0]


# --------------------------------------------------------------------------- discovery candidate

def test_remote_process_candidate():
    from secmonk import discover

    c = discover._remote_process_candidate("ops@web1:2222", "linux", ["identity=/k"], {"sudo": True})
    assert (c["collector"], c["target"], c["available"], c["selected"]) == ("process", "ssh://ops@web1:2222", True, True)
    assert c["options"] == ["identity=/k", "sudo=true"]
    mac = discover._remote_process_candidate("me@mac", "macos", [], {})
    assert not mac["available"] and not mac["selected"] and "Linux" in mac["reason"] and mac["options"] == []
    assert discover._remote_process_candidate("h", "linux", [], {"sudo": "no"})["options"] == []


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
def make_srv(tmp_path):
    servers = []

    def make(**kw):
        srv = make_server(ProcessMonitor(db_path=tmp_path / "w.db", target=str(SNAP)), "127.0.0.1", 0,
                          mode="snapshot", **kw)
        serve_in_thread(srv)
        servers.append(srv)
        return srv

    yield make
    for s in servers:
        s.shutdown()
        s.server_close()


def test_browser_scan_option_policy(make_srv):
    srv = make_srv()
    for opt in ("kubectl=/tmp/evil", "ssh_config=/tmp/cfg"):
        s, e = _req(srv, "/api/jobs", method="POST", body={"kind": "scan", "collector": "k8s", "options": [opt]})
        assert s == 400 and "not accepted from the browser" in e["error"], opt
        s, e = _req(srv, "/api/jobs", method="POST",
                    body={"kind": "scan", "items": [{"collector": "process", "target": "ssh://u@h", "options": [opt]}]})
        assert s == 400 and "items[1]" in e["error"], opt
    for opt in ("kubectl=/x", "ssh_config=/x", "ssh_option=A=1", "transport=paramiko"):
        s, e = _req(srv, "/api/discover?opt=" + urllib.parse.quote(opt))
        assert s == 400 and "not accepted" in e["error"], opt
    assert {"kubeconfig", "namespace", "sudo", "context"} <= ops.DISCOVER_WEB_OPTS


def test_k8s_kubeconfigs_endpoint(make_srv, monkeypatch):
    from secmonk.collectors import k8s

    monkeypatch.setattr(k8s, "list_kubeconfigs", lambda **o: [
        {"path": "/home/u/.kube/config", "error": None,
         "contexts": [{"name": "prod", "cluster": "prod-eu", "server": "https://admin:s3cret@k8s.example:6443",
                       "namespace": "shop", "current": True, "user": "admin", "token": "abc"}]},
        {"path": "/home/u/.kube/broken.yaml", "contexts": [], "error": "not YAML: https://u:pw@x.example/"}])
    srv = make_srv()
    s, rows = _req(srv, "/api/k8s/kubeconfigs")
    assert s == 200 and [r["path"] for r in rows] == ["/home/u/.kube/config", "/home/u/.kube/broken.yaml"]
    assert rows[0]["contexts"] == [{"name": "prod", "cluster": "prod-eu", "server": "https://k8s.example:6443",
                                    "namespace": "shop", "current": True}]          # no user / token / password
    assert rows[1]["error"] == "not YAML: https://u@x.example/"
    off = make_srv(actions=False)
    s, e = _req(off, "/api/k8s/kubeconfigs")
    assert s == 403 and "--allow-actions" in e["hint"]


def test_docker_image_source_option_is_a_plain_string():
    from secmonk.web.jobs import _web_item

    assert ops.parse_opts(["source=registry"]) == {"source": "registry"}
    item = _web_item("docker-image", "alpine:3.20", ["source=registry"], "items[1]", "k8s-images")
    assert item.opts == {"source": "registry"} and item.id == "k8s-images"        # accepted from the browser
    assert ops.batch_params([item], save=True, min_confidence=0.5, host=None)["items"][0]["options"] == \
        ["source=registry"]                                                         # stored as is, not a secret


# --------------------------------------------------------------------------- UI payload gaps

def _seed_assets(conn):
    from secmonk.engine.inventory import save_inventory
    from secmonk.models import Asset, Component, Inventory

    images = [{"image": f"reg.example/app{i}:1", "namespace": "shop", "pods": 1} for i in range(2500)]
    access = {"version": "ok", "pods": "partial", "denied_namespaces": ["kube-system", "vault"]}
    big = {"images": images, "access": access, "context": "prod"}
    k8s = Inventory(Asset("k8s:prod@k8s.example:6443", "cluster", "prod", meta=big), "k8s", [
        Component("kubernetes", "1.31.0-rc.1", "runtime", purl="pkg:golang/k8s.io/kubernetes@v1.31.0-rc.1",
                  meta={"pre_release": True, "vendor_build": True, "git_version": "v1.31.0-rc.1+abc"})])
    proc = Inventory(Asset("process:ssh:web1", "host-processes", "web1", meta=big), "process", [
        Component("nginx", "1.24.0", "application",
                  meta={"process": {"version_is_installed_not_running": True, "count": 2}, "product": "nginx"})])
    save_inventory(conn, k8s)
    save_inventory(conn, proc)


def test_asset_detail_keeps_cluster_tables_and_component_meta(tmp_path):
    from secmonk import reports
    from secmonk.db import connect

    conn = connect(tmp_path / "u.db")
    try:
        _seed_assets(conn)
        d = reports.asset_detail(conn, "k8s:prod@k8s.example:6443")
        other = reports.asset_detail(conn, "process:ssh:web1")
        rows = reports.component_rows(conn, "process:ssh:web1")
    finally:
        conn.close()
    m = d["asset"]["meta"]
    assert len(m["images"]) == 2000 and m["images"][0] == {"image": "reg.example/app0:1", "namespace": "shop",
                                                           "pods": 1}
    assert m["access"]["denied_namespaces"] == ["kube-system", "vault"] and m["context"] == "prod"
    assert other["asset"]["meta"]["images"] == "(2500 items)"            # other asset types: still summarized
    assert d["components"][0]["meta"] == {"pre_release": True, "vendor_build": True}
    assert rows[0]["meta"] == {"version_is_installed_not_running": True}


def test_discover_payload_keeps_host_facts_by_kind():
    from secmonk import reports

    k = reports.discover_payload({"host": {"kind": "k8s", "target": "k8s://prod", "name": "prod", "context": "prod",
                                           "server": "https://u:pw@k8s.example:6443", "kubernetes_version": "v1.31.0",
                                           "distro": ["eks"], "access": {"pods": "ok"}, "other_contexts": ["dev"],
                                           "secret_stuff": "x"}})
    h = k["host"]
    assert h["server"] == "https://k8s.example:6443" and h["kubernetes_version"] == "v1.31.0"
    assert h["distro"] == ["eks"] and h["access"] == {"pods": "ok"} and h["other_contexts"] == ["dev"]
    assert "secret_stuff" not in h
    s = reports.discover_payload({"host": {"kind": "ssh", "target": "u@h", "remote_hostname": "web-01",
                                           "context": "nope"}})["host"]
    assert s["remote_hostname"] == "web-01" and "context" not in s
    assert set(reports.discover_payload({"host": {"kind": "local", "server": "x"}})["host"]) == {
        "kind", "target", "name", "os", "os_version", "arch"}


def test_list_kubeconfigs_without_kube_dir(tmp_path, monkeypatch):
    from secmonk.collectors import k8s

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("KUBECONFIG", raising=False)
    assert k8s.list_kubeconfigs() == []                                   # no ~/.kube: nothing, not an error
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "named.yaml"))
    assert k8s.list_kubeconfigs() == [{"path": str(tmp_path / "named.yaml"), "contexts": [], "error": "not found"}]
    monkeypatch.delenv("KUBECONFIG")
    (tmp_path / ".kube").mkdir()
    (tmp_path / ".kube" / "config").write_text("contexts: [unclosed")
    rows = k8s.list_kubeconfigs()
    assert len(rows) == 1 and rows[0]["error"]                           # exists but broken: reported


def test_discover_k8s_errors(make_srv, monkeypatch):
    import sys
    import types

    import secmonk
    from secmonk.collectors import k8s

    state = {}

    def discover_host(target=None, **opts):
        raise state["e"]

    fake = types.ModuleType("secmonk.discover")
    fake.discover_host = discover_host
    monkeypatch.setitem(sys.modules, "secmonk.discover", fake)
    monkeypatch.setattr(secmonk, "discover", fake, raising=False)
    srv = make_srv()
    cases = [
        (k8s.KubectlError("kubectl not found on PATH (install it, or pass -o kubectl=/path/to/kubectl)"), 424,
         "kubectl-missing", "Install kubectl"),
        (k8s.KubectlError("Unable to connect to the server: <html>internal secret page</html>"), 502,
         "k8s-unreachable", "VPN"),
        (k8s.KubectlError("Forbidden: user u cannot list pods", denied=True), 502, "k8s-denied", "RBAC"),
    ]
    for err, status, code, hint in cases:
        state["e"] = err
        s, e = _req(srv, "/api/discover?target=" + urllib.parse.quote("k8s://prod"))
        assert (s, e["code"]) == (status, code) and hint in e["hint"], (err, e)
        assert "secret page" not in json.dumps(e) and "cannot list pods" not in json.dumps(e)
    state["e"] = OSError("ssh: banner")
    s, e = _req(srv, "/api/discover?target=u@h")
    assert s == 502 and e["error"] == "cannot explore the host (OSError)" and "ssh" in e["hint"]
