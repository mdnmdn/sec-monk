"""py-probe: untrusted-target rules, redaction, no classification, no writes outside the allowed directories."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from secmonk_modules.client import ModuleClient, isolated_env
from secmonk_modules.wire import scrub

from . import contracts
from .dbfactory import FIX, REPO


def collect(probe, collector, target, *options, timeout=120):
    return probe.request("collector.collect", {"collector": collector, "target": str(target),
                                               "options": list(options)}, timeout=timeout)


def components(r):
    return [c for i in r.items if i["kind"] == "components" for c in i["components"]]


def git_status() -> str:
    return subprocess.run(["git", "status", "--porcelain", "--", "tests/fixtures"], cwd=REPO, capture_output=True,
                          text=True, check=False).stdout


def test_symlinks_out_of_the_tree_are_not_followed(probe, tmp_path):
    secret = tmp_path / "outside" / "requirements.txt"
    secret.parent.mkdir()
    secret.write_text("leaked-package==9.9.9\n")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "requirements.txt").symlink_to(secret)
    (tree / "package-lock.json").symlink_to("/etc/passwd")
    (tree / "loop").symlink_to(tree)
    (tree / "package.json").write_text('{"name":"t","version":"1.0.0"}')
    r = collect(probe, "fs", tree)
    assert r.error is None
    assert "leaked-package" not in json.dumps(r.items)
    assert all(c["name"] != "leaked-package" for c in components(r))
    for i in r.items:
        contracts.check("inventory/collect-item.schema.json", i)


def test_a_huge_file_is_skipped_not_read(probe, tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    big = tree / "package-lock.json"
    with open(big, "wb") as f:
        f.truncate(300 * 1024 * 1024)                          # sparse: costs no disk
    (tree / "requirements.txt").write_text("requests==2.31.0\n")
    r = collect(probe, "fs", tree)
    assert r.error is None
    assert [c["name"] for c in components(r)] == ["requests"]
    assert r.result["warnings"] >= 1 or r.result["components"] == 1


def test_no_secret_leaves_the_module(probe, tmp_path):
    tree = tmp_path / "repo"
    (tree / ".git").mkdir(parents=True)
    (tree / ".git" / "config").write_text('[remote "origin"]\n\turl = https://user:hunter2@example.invalid/x.git\n')
    (tree / "requirements.txt").write_text("requests==2.31.0\n")
    r = collect(probe, "fs", tree)
    assert "hunter2" not in json.dumps(r.frames)
    r = probe.request("docker.containers", {"host": "tcp://user:hunter2@127.0.0.1:1", "options": ["timeout=1"]},
                      timeout=60)
    assert r.error["code"] == "engine-unreachable" and "hunter2" not in json.dumps(r.frames)
    r = probe.request("collector.collect", {"collector": "docker-engine", "target": "c1", "options": [
        "host=tcp://user:hunter2@127.0.0.1:1", "timeout=1"]}, timeout=60)
    assert r.error["code"] in ("engine-unreachable", "collect-error")
    assert "hunter2" not in json.dumps(r.frames) and "Traceback" not in r.error["error"]


def test_scrub_removes_url_credentials():
    assert scrub("failed https://u:pw@h.example/p?token=1#f now") == "failed https://u@h.example/p now"
    assert scrub("no url here") == "no url here"
    assert "pw" not in scrub("ssh://a:pw@host:22 and https://b:pw2@x/y")


def test_collection_is_unclassified(probe):
    """Classification is the engine's job on ingest (rust ADR-0002): collectors' own facts only."""
    r = collect(probe, "windows", FIX / "collectors/windows/inventory-win11.json")
    assert r.items[0]["classified"] is False
    apps = [c for c in components(r) if c["category"] == "application"]
    assert apps and all("product_source" not in c["meta"] for c in apps)


def test_the_module_refuses_options_that_write_files(probe, tmp_path):
    out = tmp_path / "snap.json"
    r = probe.request("collector.collect", {"collector": "process", "target": str(FIX / "collectors/process/snapshot.json"),
                                            "options": [f"snapshot_out={out}"]})
    assert r.error["code"] == "invalid-params" and not out.exists()


def test_unknown_collector_and_bad_options(probe):
    assert probe.request("collector.collect", {"collector": "nope", "target": None, "options": []}).error["code"] == \
        "unknown-collector"
    assert probe.request("collector.collect", {"collector": "fs", "target": None, "options": ["x"]}).error["code"] == \
        "invalid-params"
    assert probe.request("collector.collect", {"collector": "fs", "target": None, "options": [1]}).error["code"] == \
        "invalid-params"
    assert probe.request("process.snapshot", {"collector": "fs", "target": None, "options": []}).error["code"] == \
        "invalid-params"


def test_collect_errors_are_collect_errors_without_tracebacks(probe, tmp_path):
    r = collect(probe, "fs", tmp_path / "does-not-exist")
    assert r.error and r.error["code"] == "collect-error" and "Traceback" not in r.error["error"]
    r = collect(probe, "sbom", tmp_path / "missing.json")
    assert r.error and r.error["code"] == "collect-error"


def test_fixtures_are_never_modified(probe):
    before = git_status()
    for d in ("javascript/npm-v3", "python/poetry", "go"):
        collect(probe, "fs", FIX / "lang" / d, "binaries=true")
    collect(probe, "rootfs", FIX / "collectors/docker/alpine-3.20/rootfs")
    assert git_status() == before


def test_nothing_is_written_outside_the_data_dir(tmp_path):
    """Run with an empty working directory and a fresh HOME: afterwards only the module's own state exists."""
    home = tmp_path / "dd"
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    with ModuleClient("py-probe", env=isolated_env(home), cwd=str(cwd)) as c:
        collect(c, "fs", FIX / "lang/javascript/npm-v3")
        c.request("docker.contexts", {})
        c.request("k8s.kubeconfigs", {})
    assert list(cwd.iterdir()) == []
    assert not (home / "python-home" / "forbidden.db").exists()
    assert not any(p.suffix == ".db" for p in home.rglob("*"))
    assert not (home / "home" / ".kube").exists() and not (home / "home" / ".ssh").exists()


def test_process_snapshot_of_a_snapshot_file(probe):
    from secmonk.collectors.process import snapshot as snapfile

    r = probe.request("process.snapshot", {"collector": "process", "target": str(FIX / "collectors/process/snapshot.json"),
                                           "options": []}).ok()
    contracts.check("process/snapshot-1.schema.json", r.result)
    assert r.result["schema"] == snapfile.SCHEMA


def test_expand_targets_of_a_selector(probe):
    r = probe.request("collector.expand_targets", {"collector": "fs", "target": str(FIX), "options": []}).ok()
    assert r.result == {"targets": [str(FIX)]}


@pytest.mark.skipif(sys.platform == "win32", reason="posix signals")
def test_a_killed_module_leaves_no_child_behind(tmp_path):
    """The host kills a module that ignores `cancel`; its own children (ssh, docker) must not outlive it."""
    c = ModuleClient("py-probe", env=isolated_env(tmp_path)).start()
    pid = c.proc.pid
    c.proc.kill()
    c.proc.wait()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
