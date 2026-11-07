"""CLI tests (typer CliRunner) against a temporary database and the fixture trees."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk import cli
from secmonk.cli import app

ROOT = Path(__file__).parent / "fixtures"
KEV = ROOT / "sources" / "kev" / "known_exploited_vulnerabilities.json"
OSV_ZIP = ROOT / "sources" / "osv" / "sample-all.zip"
ALPINE = ROOT / "collectors" / "docker" / "alpine-3.20" / "rootfs"
JS = ROOT / "lang" / "javascript"

runner = CliRunner()


@pytest.fixture
def db(tmp_path, monkeypatch) -> Path:
    p = tmp_path / "t.db"
    monkeypatch.setenv("SECMONK_DB", str(p))
    return p


def run(*args: str, code: int = 0):
    res = runner.invoke(app, [str(a) for a in args])
    assert res.exit_code == code, f"exit {res.exit_code} != {code}\n{res.output}\n{res.exception!r}"
    return res


@pytest.fixture
def scanned(db) -> Path:
    run("sync", "kev", "--path", KEV)
    run("collect", "rootfs", ALPINE, "--quiet")
    return db


def _asset_id(db: Path) -> str:
    c = sqlite3.connect(db)
    try:
        return c.execute("SELECT id FROM asset").fetchone()[0]
    finally:
        c.close()


@pytest.fixture
def seeded(scanned) -> tuple[Path, str]:
    """Alpine asset with hand-made findings covering every filter."""
    aid = _asset_id(scanned)
    c = sqlite3.connect(scanned)
    cid = [r[0] for r in c.execute("SELECT id FROM component LIMIT 5")]
    rows = [  # vuln, priority, fixed, triage, status
        ("CVE-1", "P1", "2.0", None, "open"),
        ("CVE-2", "P2", None, None, "open"),
        ("CVE-3", "P3", "1.1", "unimportant", "open"),
        ("CVE-4", "P3", None, "no-dsa", "open"),
        ("CVE-5", "P4", "1.2", None, "fixed"),
    ]
    for i, (v, p, fx, tr, st) in enumerate(rows):
        c.execute("INSERT OR REPLACE INTO finding(asset_id, component_id, vuln_id, matched_by, confidence, "
                  "fixed_version, priority, status, triage, kev, cvss_score) VALUES (?,?,?,?,?,?,?,?,?,0,5.0)",
                  (aid, cid[i], v, "osv-purl", 1.0, fx, p, st, tr))
    c.commit()
    c.close()
    return scanned, aid


# --------------------------------------------------------------------------- basics

def test_help_and_listings():
    assert "scan" in run("--help").output
    assert "kev" in run("sources").output
    out = run("collectors").output
    assert "rootfs" in out and "docker-image" in out


def test_read_only_commands_need_a_database(db):
    for args in (["status"], ["findings"], ["inventory", "assets"], ["vuln", "show", "CVE-1"], ["match", "x"]):
        res = run(*args, code=1)
        assert "no database at" in res.output and "secmonk sync" in res.output
    assert not db.exists()


def test_default_db_location_is_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run("sync", "kev", "--path", KEV)
    assert not (tmp_path / "secmonk.db").exists()
    from secmonk import paths
    assert paths.default_db_path().exists()


def test_unknown_names_exit_2(db):
    assert "unknown source" in run("sync", "nope", code=2).output
    assert "unknown collector" in run("collect", "nope", code=2).output
    run("scan", "nope", code=2)
    assert not db.exists()


# --------------------------------------------------------------------------- sync

def test_sync_kev_and_osv_then_status(db):
    run("sync", "kev", "--path", KEV)
    run("sync", "osv", "--path", OSV_ZIP)
    out = run("status").output
    assert "kev" in out and "osv" in out and "vulnerability" in out
    data = json.loads(run("status", "--format", "json").stdout)
    assert {s["source"] for s in data["sources"]} >= {"kev", "osv"}
    assert data["tables"]["vulnerability"] > 0


def test_sync_error_exit_code_and_partial(db, monkeypatch):
    from secmonk.sources.base import REGISTRY, SyncResult

    class Bad:
        name = "bad"

        def sync(self, conn, opts):
            return SyncResult("bad", status="error", message="boom")

    class Half:
        name = "half"

        def sync(self, conn, opts):
            return SyncResult("half", status="partial", records=1)

    monkeypatch.setitem(REGISTRY, "bad", Bad)
    monkeypatch.setitem(REGISTRY, "half", Half)
    assert "partial" in run("sync", "half").output
    assert "boom" in run("sync", "bad", code=1).output
    run("sync", "half", "bad", code=1)


def test_sync_exception_is_contained(db, monkeypatch):
    from secmonk.sources.base import REGISTRY

    class Crash:
        name = "crash"

        def sync(self, conn, opts):
            raise RuntimeError("kaput")

    monkeypatch.setitem(REGISTRY, "crash", Crash)
    res = run("sync", "crash", code=1)
    assert "kaput" in res.output and "Traceback" not in res.output


def test_sync_all_expands_registry():
    names = cli._expand_sources(["all"], cli._sources())
    assert names[:3] == ["kev", "epss", "osv"]
    assert set(names) == set(cli._sources())


# --------------------------------------------------------------------------- collect / scan

def test_collect_rootfs_and_output_file(db, tmp_path):
    out = tmp_path / "inv.json"
    res = run("collect", "rootfs", ALPINE, "-O", out)
    assert "saved asset" in res.output
    assert json.loads(out.read_text())["components"]
    run("collect", "rootfs", ALPINE, "--no-save", "--json", tmp_path / "old.json")
    assert (tmp_path / "old.json").exists()


def test_collect_fs_no_save(db):
    res = run("collect", "fs", JS, "--no-save")
    assert "components" in res.output
    assert not db.exists()


def test_scan_table_json_csv(scanned):
    res = run("scan", "rootfs", ALPINE)
    assert "Findings" in res.stdout
    res = run("scan", "rootfs", ALPINE, "--format", "json")
    doc = json.loads(res.stdout)
    assert {"asset", "stats", "findings", "warnings"} <= set(doc)
    res = run("scan", "rootfs", ALPINE, "--format", "csv", "--quiet")
    assert next(csv.reader(io.StringIO(res.stdout)))[0] == "priority"


def test_scan_no_save_leaves_db_untouched(db):
    run("sync", "kev", "--path", KEV)
    run("scan", "rootfs", ALPINE, "--no-save", "--quiet")
    assert json.loads(run("inventory", "assets", "-f", "json").stdout) == []


def test_scan_no_save_requires_mirror(db):
    run("scan", "rootfs", ALPINE, "--no-save", code=1)


def test_scan_fail_on(db, monkeypatch):
    run("sync", "kev", "--path", KEV)
    monkeypatch.setattr("secmonk.engine.match.match_asset", lambda conn, aid, min_confidence=0: (
        conn.execute("INSERT INTO finding(asset_id, component_id, vuln_id, priority, status) "
                     "SELECT ?, id, 'CVE-X', 'P2', 'open' FROM component LIMIT 1", (aid,)),
        {"components": 1, "matches": 1, "findings": 1})[1])
    run("scan", "rootfs", ALPINE, "--fail-on", "P3", code=3)
    run("scan", "rootfs", ALPINE, "--fail-on", "P1")
    run("scan", "rootfs", ALPINE, "--fail-on", "P9", code=2)


def test_collector_warnings_are_always_printed(db, monkeypatch):
    from secmonk.collectors.base import REGISTRY
    from secmonk.models import Asset, Inventory

    class W:
        name = "w"

        def collect(self, target=None, **o):
            return Inventory(Asset("a:1", "server", "a"), "w", warnings=["careful [b]"])

    monkeypatch.setitem(REGISTRY, "w", W)
    assert "careful [b]" in run("collect", "w", "--quiet", "--no-save").output
    run("sync", "kev", "--path", KEV)
    assert "careful" in run("scan", "w", "--quiet").output
    assert json.loads(run("scan", "w", "-f", "json").stdout)["warnings"] == ["careful [b]"]


def test_collector_errors_are_clean(db, tmp_path):
    bad = tmp_path / "bad.tar"
    bad.write_bytes(b"not a tar")
    res = run("collect", "docker-image", bad, "--no-save", code=1)
    assert "Traceback" not in res.output


def test_parse_opts():
    p = cli._parse_opts
    assert p(["sudo=yes", "password=1", "tag=yes", "hostname=0"]) == {
        "sudo": True, "password": "1", "tag": "yes", "hostname": "0"}
    assert p(["ssh_option=KexAlgorithms=a,b"]) == {"ssh_option": "KexAlgorithms=a,b"}
    assert p(["ssh_option=A=1", "ssh_option=B=2"]) == {"ssh_option": ["A=1", "B=2"]}
    assert p(["exclude=a,b"]) == {"exclude": ["a", "b"]}
    assert p(["exclude=a", "exclude=b,c"]) == {"exclude": ["a", "b", "c"]}
    assert p(["max_files=10"]) == {"max_files": "10"}
    with pytest.raises(Exception):  # noqa: B017
        p(["novalue"])


# --------------------------------------------------------------------------- match / findings / inventory

def test_match_and_unknown_asset(scanned):
    aid = _asset_id(scanned)
    assert "components" in run("match", aid).output
    res = run("match", "ghost", code=1)
    assert "unknown asset" in res.output and "Traceback" not in res.output
    run("inventory", "show", "ghost", code=1)
    run("findings", "ghost", code=1)


def ids(res) -> list[str]:
    return [r["vuln_id"] for r in json.loads(res.stdout)]


def test_findings_filters(seeded):
    _, aid = seeded
    assert ids(run("findings", "-f", "json")) == ["CVE-1", "CVE-2", "CVE-3", "CVE-4"]
    assert ids(run("findings", aid, "--all", "-f", "json")) == ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"]
    assert ids(run("findings", "--fixable", "-f", "json")) == ["CVE-1", "CVE-3"]
    assert ids(run("findings", "--hide-minor", "-f", "json")) == ["CVE-1", "CVE-2", "CVE-4"]
    assert ids(run("findings", "--hide-deferred", "-f", "json")) == ["CVE-1", "CVE-2"]
    assert ids(run("findings", "--priority", "p3", "-f", "json")) == ["CVE-3", "CVE-4"]
    assert ids(run("findings", "-n", "1", "-f", "json")) == ["CVE-1"]
    run("findings", "--priority", "P7", code=2)
    assert next(csv.DictReader(io.StringIO(run("findings", "-f", "csv").stdout)))["vuln_id"] == "CVE-1"
    assert "CVE-1" in run("findings").output


def test_inventory_commands(scanned):
    aid = _asset_id(scanned)
    rows = json.loads(run("inventory", "assets", "--format", "json").stdout)
    assert rows[0]["id"] == aid and rows[0]["components"] > 0
    comps = json.loads(run("inventory", "show", aid, "-f", "json").stdout)
    assert comps and {"name", "version", "purl"} <= set(comps[0])
    cat = comps[0]["category"]
    only = json.loads(run("inventory", "show", aid, "--category", cat, "-f", "json").stdout)
    assert all(c["category"] == cat for c in only)
    run("inventory", "unmatched")
    assert "id" in run("inventory", "assets").output


def test_vuln_show_and_search(db):
    run("sync", "kev", "--path", KEV)
    run("sync", "osv", "--path", OSV_ZIP)
    c = sqlite3.connect(db)
    vid, pkg, eco = c.execute("SELECT vuln_id, package, ecosystem FROM affected "
                              "WHERE package IS NOT NULL LIMIT 1").fetchone()
    c.close()
    assert vid in run("vuln", "show", vid).output
    assert "unknown vulnerability" in run("vuln", "show", "CVE-0000-0000", code=1).output
    assert vid in run("vuln", "search", "--package", pkg, "--ecosystem", eco, "-n", "5").output
    run("vuln", "search", code=2)
    run("vuln", "search", "--product", "nonexistent")      # NULL package/product rows must not crash


# --------------------------------------------------------------------------- misc commands

def test_windows_script():
    out = run("windows-script", "--compact").output
    assert out.strip() and "secmonk-inventory.ps1" in run("windows-script", "--help").output


def test_containers_without_engine(tmp_path):
    res = run("containers", "--socket", tmp_path / "nope.sock", code=1)
    assert "Traceback" not in res.output


def test_containers_table(monkeypatch):
    from secmonk.collectors import docker_engine
    monkeypatch.setattr(docker_engine, "list_containers", lambda **k: [
        {"Id": "abcdef0123456789", "Names": ["/web"], "Image": "nginx", "State": "running", "Status": "Up"}])
    out = run("containers").output
    assert "web" in out and "nginx" in out and "abcdef012345" in out
    assert json.loads(run("containers", "-f", "json").stdout)[0]["name"] == "web"


def test_verbose_flag_runs(db):
    run("-v", "sync", "kev", "--path", KEV)


# --------------------------------------------------------------------------- rich markup injection

def test_markup_in_untrusted_strings_is_not_interpreted(db, monkeypatch):
    from secmonk.collectors.base import REGISTRY
    from secmonk.models import Asset, Component, Inventory

    evil = ["[/x]", "[link=https://evil]x[/link]", "[bold red]y[/]"]

    class Evil:
        name = "evil"

        def collect(self, target=None, **o):
            comps = [Component(n, "1.0", "library", purl=f"pkg:npm/e{i}@1.0", ecosystem="npm",
                               source_path="/p/[/x]") for i, n in enumerate(evil)]
            return Inventory(Asset("evil:[/x]", "server", "n"), "evil", comps, warnings=["w [/x]"])

    monkeypatch.setitem(REGISTRY, "evil", Evil)
    res = run("collect", "evil")                  # must not raise MarkupError
    for s in evil:
        assert s in res.output
    run("inventory", "show", "evil:[/x]")
    out = run("inventory", "show", "evil:[/x]").output
    assert "[link=https://evil]x[/link]" in out
    assert "[/x]" in run("inventory", "assets").output
    assert "w [/x]" in res.output
