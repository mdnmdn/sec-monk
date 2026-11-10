"""Engine images are identified by their Id: an image already inventoried (saved, complete, current inventory
format) is not collected again, only re-matched (ops._reuse_image). docker-engine is replaced by a fake collector and
agent A's helpers (`image_identity`, `IMAGE_INVENTORY_VERSION`, `image_meta`) by fakes; no engine is needed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from secmonk import db as dbm
from secmonk import ops
from secmonk.cli import app
from secmonk.collectors import docker_engine
from secmonk.collectors.base import REGISTRY, Collector
from secmonk.db import connect
from secmonk.engine.inventory import current_components
from secmonk.models import Asset, Component, Inventory
from secmonk.sources.base import add_affected, upsert_vulnerability

IID = "sha256:" + "ab" * 32
IMG = "image:" + IID
AID = "image:@" + IID
ENGINE = "unix:///var/run/docker.sock"
runner = CliRunner()


class FakeEngine(Collector):
    name = "docker-engine"
    calls: ClassVar[list] = []
    version = 2
    partial = False
    verified = True

    def expand_targets(self, target, **opts):
        return list(dict.fromkeys(t for t in (target or "").split(",") if t)) or [target]

    def collect(self, target=None, **opts):
        FakeEngine.calls.append((target, dict(opts)))
        inv = Inventory(Asset(AID, "container-image", "app:1", platform="linux/arm64",
                              meta={"inventory_version": FakeEngine.version, "tags": ["app:1"], "engine": ENGINE,
                                    "requested_ref": "app:1", "platform": "linux/arm64",
                                    "id_verified": FakeEngine.verified}), "docker-engine",
                        [Component("left-pad", "1.0.0", "library", purl="pkg:npm/left-pad@1.0.0", ecosystem="npm"),
                         Component("is-odd", "3.0.0", "library", purl="pkg:npm/is-odd@3.0.0", ecosystem="npm")])
        if FakeEngine.partial:
            inv.mark_partial("test")
        return inv


@pytest.fixture
def engine(monkeypatch):
    FakeEngine.calls, FakeEngine.version, FakeEngine.partial, FakeEngine.verified = [], 2, False, True
    monkeypatch.setitem(REGISTRY, "docker-engine", FakeEngine)
    monkeypatch.setattr(docker_engine, "IMAGE_INVENTORY_VERSION", 2, raising=False)
    monkeypatch.setattr(docker_engine, "image_identity",
                        lambda t: "image:@" + t.removeprefix("image:") if t.startswith("image:sha256:") else None,
                        raising=False)
    monkeypatch.setattr(docker_engine, "image_meta", lambda ref, **o: {
        "image_id": ref.removeprefix("image:"), "tags": ["app:2", "app:latest"], "requested_ref": IID,
        "inventory_version": 2}, raising=False)
    monkeypatch.setattr(docker_engine, "find_endpoint", lambda opts=None: ENGINE)
    return FakeEngine


@pytest.fixture
def mirror(tmp_path, monkeypatch) -> Path:
    db = tmp_path / "m.db"
    c = connect(db)
    upsert_vulnerability(c, "osv", "GHSA-left-pad", severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GHSA-left-pad", ecosystem="npm", package="left-pad", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "1.0.1"}])
    c.commit()
    c.close()
    monkeypatch.setenv("SECMONK_DB", str(db))
    return db


def _scan(db, target=IMG, opts=None, save=True):
    conn = connect(db)
    try:
        if not save:
            dbm.ephemeral_overlay(conn)
        return ops.scan_target(conn, "docker-engine", target, opts or {}, save=save)[0]
    finally:
        conn.close()


def _current(db):
    conn = connect(db)
    try:
        return sorted(r["name"] for r in current_components(conn, AID))
    finally:
        conn.close()


def test_second_scan_reuses_and_rematches(engine, mirror):
    first = _scan(mirror)
    assert not first["reused"] and first["counts"]["total"] == 1 and len(engine.calls) == 1
    assert first["tags"] == ["app:1"] and "requested_refs" not in first
    # a new advisory arrives in the mirror: the reused inventory is matched against it
    c = connect(mirror)
    upsert_vulnerability(c, "osv", "GHSA-is-odd", severity="LOW", cvss_score=3.1)
    add_affected(c, "osv", "GHSA-is-odd", ecosystem="npm", package="is-odd", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "3.0.1"}])
    c.commit()
    scans_before = c.execute("SELECT COUNT(*) FROM scan").fetchone()[0]
    c.close()
    again = _scan(mirror)
    assert len(engine.calls) == 1                                       # not collected again
    assert again["reused"] is True and again["reused_scan_id"] == first["scan_id"] == again["scan_id"]
    assert again["asset"] == AID and again["counts"]["total"] == 2 and again["error"] is None
    assert {f["vuln_id"] for f in again["findings"]} == {"GHSA-left-pad", "GHSA-is-odd"}
    assert again["tags"] == ["app:2", "app:latest"]                     # the refreshed tags
    c = connect(mirror)
    try:
        assert c.execute("SELECT COUNT(*) FROM scan").fetchone()[0] == scans_before   # no new scan row
        meta = json.loads(c.execute("SELECT meta FROM asset WHERE id=?", (AID,)).fetchone()[0])
    finally:
        c.close()
    assert meta["tags"] == ["app:2", "app:latest"] and meta["inventory_version"] == 2   # tags refreshed
    assert meta["requested_ref"] == "app:1" and meta["engine"] == ENGINE      # the user's ref, not the bare Id
    c = connect(mirror)
    try:
        assert c.execute("SELECT name FROM asset WHERE id=?", (AID,)).fetchone()[0] == "app:2"   # current tag
    finally:
        c.close()
    assert _current(mirror) == ["is-odd", "left-pad"]                   # current components unchanged


@pytest.mark.parametrize("why", ["unreachable", "other-id", "other-engine", "other-platform", "endpoint-error"])
def test_reuse_needs_the_engine_to_confirm(engine, mirror, monkeypatch, why):
    """Never a 'reused' success the engine did not confirm: fall through to collect (which reports errors)."""
    _scan(mirror)
    good = docker_engine.image_meta
    if why == "unreachable":
        monkeypatch.setattr(docker_engine, "image_meta", lambda ref, **o: (_ for _ in ()).throw(OSError("down")))
    elif why == "other-id":
        monkeypatch.setattr(docker_engine, "image_meta", lambda ref, **o: {**good(ref), "image_id": "sha256:" + "cd" * 32})
    elif why == "other-engine":
        monkeypatch.setattr(docker_engine, "find_endpoint", lambda opts=None: "ssh://other.example")
    elif why == "other-platform":
        monkeypatch.setattr(docker_engine, "image_meta", lambda ref, **o: {**good(ref), "platform": "linux/amd64"})
    else:
        monkeypatch.setattr(docker_engine, "find_endpoint",
                            lambda opts=None: (_ for _ in ()).throw(RuntimeError("no engine")))
    again = _scan(mirror)
    assert len(engine.calls) == 2 and not again["reused"], why


@pytest.mark.parametrize("why", ["rescan", "version", "partial", "no-save", "not-an-image", "unverified"])
def test_collect_again(engine, mirror, why):
    FakeEngine.verified = why != "unverified"               # the stored export was not checked against the Id
    FakeEngine.partial = why == "partial"
    FakeEngine.version = 1 if why == "version" else 2      # stored by an older inventory format
    _scan(mirror)
    FakeEngine.partial, FakeEngine.version, FakeEngine.verified = False, 2, True
    n = len(engine.calls)
    target = "web" if why == "not-an-image" else IMG
    e = _scan(mirror, target=target, opts={"rescan": True} if why == "rescan" else None, save=why != "no-save")
    assert len(engine.calls) == n + 1 and not e["reused"], why
    assert "rescan" not in engine.calls[-1][1]                           # never passed to the collector
    assert _current(mirror) == ["is-odd", "left-pad"]


def test_cli_table_with_a_reused_image(engine, mirror):
    """Table / csv output of a reused entry (no inventory object) must not crash, nor lose later items."""
    runner.invoke(app, ["scan", "docker-engine", IMG, "-q"])
    for fmt in ("table", "csv"):
        res = runner.invoke(app, ["scan", "docker-engine", f"{IMG},web", "-f", fmt])
        assert res.exit_code == 0, res.output
        assert "GHSA-left-pad" in res.stdout
    assert "already inventoried" in runner.invoke(app, ["scan", "docker-engine", IMG]).output
    rows = json.loads(runner.invoke(app, ["history", "-f", "json"]).stdout)
    assert {r["status"] for r in rows} == {"ok"}


def test_folded_aliases_on_the_entry(engine, mirror, monkeypatch):
    _scan(mirror)
    good = docker_engine.image_meta
    monkeypatch.setattr(docker_engine, "image_meta",
                        lambda ref, **o: {**good(ref), "requested_refs": ["app:2", "app:latest"]})
    again = _scan(mirror)
    assert again["reused"] and again["requested_refs"] == ["app:2", "app:latest"]


def test_callback_failure_keeps_the_other_items(engine, mirror):
    items = [ops.scan_item("docker-engine", "one"), ops.scan_item("docker-engine", "two")]
    seen, errors = [], []

    def on_entry(entry, inv):
        seen.append(entry["target"])
        if entry["target"] == "one":
            raise RuntimeError("printing failed")

    conn = connect(mirror)
    try:
        entries = ops.scan_items(conn, items, save=True, on_entry=on_entry, on_exception=errors.append)
    finally:
        conn.close()
    assert seen == ["one", "two"] and len(entries) == 2 and all(e["error"] is None for e in entries)
    assert [type(e).__name__ for e in errors] == ["RuntimeError"]


def test_cli_and_history_show_reuse(engine, mirror):
    runner.invoke(app, ["scan", "docker-engine", IMG, "-q"])
    res = runner.invoke(app, ["scan", "docker-engine", f"{IMG},web", "-f", "json"])
    doc = json.loads(res.stdout)
    assert [t["reused"] for t in doc["targets"]] == [True, False] and len(engine.calls) == 2
    assert ops.parse_opts(["rescan=yes"]) == {"rescan": True}
    rows = json.loads(runner.invoke(app, ["history", "-f", "json"]).stdout)
    assert rows[0]["result"]["targets"][0]["reused_scan_id"] == doc["targets"][0]["scan_id"]
