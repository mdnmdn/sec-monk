"""Regression tests for the collector / security review findings (C1..C18, SEC2..SEC17)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import plistlib
import sqlite3
import tarfile
import time
from pathlib import Path

import httpx
import pytest

from secmonk import db as dbm
from secmonk.collectors import base, fs, homebrew, windows
from secmonk.collectors import docker_engine as de
from secmonk.collectors import docker_image as di
from secmonk.collectors import rootfs as rf
from secmonk.collectors.base import REGISTRY
from secmonk.collectors.macos import MacOSCollector
from secmonk.engine.inventory import current_components, save_inventory
from secmonk.models import Asset, Component, Inventory

from .test_docker import APK, OSR, make_tar

D = "sha256:"


def pkg(i: int) -> Component:
    return Component(f"p{i}", "1", "os-package", purl=f"pkg:deb/debian/p{i}@1")


def conn(tmp_path: Path):
    return dbm.connect(tmp_path / "t.db")


# --------------------------------------------------------------------------- C1 partial scans

def test_partial_scan_does_not_remove_components(tmp_path):
    c = conn(tmp_path)
    save_inventory(c, Inventory(Asset("h", "server", "h"), "ssh", [pkg(i) for i in range(5)]))
    inv = Inventory(Asset("h", "server", "h"), "ssh", [pkg(0)], warnings=["x"])
    inv.mark_partial("stream aborted")
    save_inventory(c, inv)
    assert len(current_components(c, "h")) == 5
    meta = json.loads(c.execute("select meta from scan order by id desc limit 1").fetchone()[0])
    assert meta["partial"] is True and meta["partial_reason"] == "stream aborted"
    # a later complete scan is authoritative again: removed packages disappear
    save_inventory(c, Inventory(Asset("h", "server", "h"), "ssh", [pkg(0), pkg(1)]))
    assert {r["name"] for r in current_components(c, "h")} == {"p0", "p1"}


def test_partial_only_asset_shows_everything_seen(tmp_path):
    c = conn(tmp_path)
    inv = Inventory(Asset("h", "server", "h"), "ssh", [pkg(1)])
    inv.mark_partial("r")
    save_inventory(c, inv)
    assert len(current_components(c, "h")) == 1


def test_docker_image_skipped_layer_is_partial(tmp_path):
    bad = b"not a tar at all" * 50
    layer = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)])
    cfg = b'{"os":"linux","architecture":"amd64"}'
    members = [("cfg.json", cfg), ("a/layer.tar", layer), ("b/layer.tar", bad),
               ("manifest.json", json.dumps([{"Config": "cfg.json", "RepoTags": ["x:1"],
                                              "Layers": ["a/layer.tar", "b/layer.tar"]}]).encode())]
    (tmp_path / "i.tar").write_bytes(_tar_of(members))
    inv = REGISTRY["docker-image"]().collect(str(tmp_path / "i.tar"))
    assert inv.partial and "layer 1" in inv.partial_reason


def test_engine_incomplete_export_is_partial(monkeypatch):
    class Resp(io.BytesIO):
        pass

    full = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)])

    class Client:
        endpoint = "unix:///x"

        def get_json(self, path):
            return {"Id": "c" * 64, "Name": "/web", "Config": {"Image": "x", "Labels": {"api_token": "s3"}},
                    "State": {}, "HostConfig": {}}

        def open(self, path):
            class Conn:
                def close(self):
                    pass
            return Conn(), Resp(full[:700])          # cut in the middle of a member

    inv = de.DockerEngineCollector()._collect_container(Client(), "web")
    assert inv.partial and "export incomplete" in inv.partial_reason
    assert inv.asset.meta["labels"]["api_token"] == "<redacted>"


def _tar_of(members, links=()):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for n, d in members:
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
        for n, target in links:
            ti = tarfile.TarInfo(n)
            ti.type, ti.linkname = tarfile.SYMTYPE, target
            tf.addfile(ti)
    return buf.getvalue()


# --------------------------------------------------------------------------- C3 / C11 / C16 / C17 archives

def _image(path: Path, repo_tags, symlink_layer=False, cfg_extra=None):
    layer = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)])
    cfg = json.dumps({"architecture": "amd64", "os": "linux", **(cfg_extra or {})}).encode()
    members, links = [("cfg.json", cfg), ("a/layer.tar", layer)], []
    layers = ["a/layer.tar"]
    if symlink_layer:
        links, layers = [("b/layer.tar", "../a/layer.tar")], ["b/layer.tar"]
    mf = json.dumps([{"Config": "cfg.json", "RepoTags": repo_tags, "Layers": layers}]).encode()
    path.write_bytes(_tar_of([*members, ("manifest.json", mf)], links))


def test_legacy_save_symlinked_layer_tar(tmp_path):
    _image(tmp_path / "l.tar", ["x:1"], symlink_layer=True)
    inv = di.inventory_from_archive(tmp_path / "l.tar")
    assert any(c.name == "musl" for c in inv.components) and not inv.partial


def test_archive_asset_ids(tmp_path):
    _image(tmp_path / "p.tar", ["localhost:5000/team/app:1.0"])
    assert di.inventory_from_archive(tmp_path / "p.tar").asset.id.startswith("image:localhost:5000/team/app@sha256:")
    _image(tmp_path / "one.tar", [])
    _image(tmp_path / "two.tar", [])
    a, b = (di.inventory_from_archive(tmp_path / n).asset.id for n in ("one.tar", "two.tar"))
    assert a == b and a.startswith("image:@sha256:") and "one" not in a
    _image(tmp_path / "n.tar", ["<none>:<none>"])
    assert di.inventory_from_archive(tmp_path / "n.tar").asset.id.startswith("image:@sha256:")


def test_not_a_tar_is_a_value_error(tmp_path):
    (tmp_path / "junk.tar").write_bytes(b"this is not a tar" * 100)
    with pytest.raises(ValueError):
        di.inventory_from_archive(tmp_path / "junk.tar")


def test_tag_option_selects_image_in_multi_image_archive(tmp_path):
    layer = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)])
    cfg1, cfg2 = b'{"os":"linux","architecture":"amd64"}', b'{"os":"linux","architecture":"amd64","x":1}'
    mf = json.dumps([{"Config": "a.json", "RepoTags": ["app:a"], "Layers": ["l/layer.tar"]},
                     {"Config": "b.json", "RepoTags": ["app:b"], "Layers": ["l/layer.tar"]}]).encode()
    (tmp_path / "m.tar").write_bytes(_tar_of([("a.json", cfg1), ("b.json", cfg2), ("l/layer.tar", layer),
                                               ("manifest.json", mf)]))
    inv = REGISTRY["docker-image"]().collect(str(tmp_path / "m.tar"), tag="app:b")
    assert inv.asset.meta["ref"] == "app:b"
    inv = REGISTRY["docker-image"]().collect(str(tmp_path / "m.tar"), tag="app:zzz")
    assert any("not found" in w for w in inv.warnings)


def test_local_dir_named_like_image_falls_back_to_registry(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "nginx").mkdir()
    seen = []

    def handler(req):
        seen.append(req.url.path)
        return httpx.Response(404)

    c = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(di.RegistryError):
        REGISTRY["docker-image"]().collect("nginx", client=c)
    assert any("library/nginx" in p for p in seen)                   # went to the registry
    with pytest.raises(ValueError, match="not an OCI image layout"):
        REGISTRY["docker-image"]().collect("./nginx")                # ./name forces the local dir


# --------------------------------------------------------------------------- SEC2 / SEC5 / SEC9 / SEC10 registry

def _registry(manifest_layers, cfg=b'{"os":"linux","architecture":"amd64","config":{}}', blobs=None):
    cd = D + hashlib.sha256(cfg).hexdigest()
    mani = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "config": {"digest": cd, "size": len(cfg)}, "layers": manifest_layers}).encode()
    seen: list[str] = []

    def h(req):
        p = req.url.path
        seen.append(p)
        if "/manifests/" in p:
            return httpx.Response(200, content=mani)
        if p.endswith(cd):
            return httpx.Response(200, content=cfg)
        if blobs and p.rsplit("/", 1)[-1] in blobs:
            return httpx.Response(200, content=blobs[p.rsplit("/", 1)[-1]])
        return httpx.Response(200, content=b"attacker bytes")

    return httpx.Client(transport=httpx.MockTransport(h)), seen


def test_hostile_digest_never_touches_paths(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    evil = D + "../" * 30 + str(victim).lstrip("/")
    client, seen = _registry([{"digest": evil, "size": 10, "mediaType": "application/vnd.oci.image.layer.v1.tar"}])
    for kw in ({"no_cache": True}, {"cache_dir": str(tmp_path / "cache")}):
        with pytest.raises(ValueError, match="invalid digest"):
            REGISTRY["docker-image"]().collect("evil.example/x/y:1", client=client, **kw)
    assert victim.read_text() == "precious" and not any("victim" in p for p in seen)


def test_oci_layout_rejects_hostile_digest(tmp_path):
    (tmp_path / "index.json").write_text(json.dumps({"manifests": [{"digest": D + "../../x"}]}))
    with pytest.raises(ValueError):
        di.inventory_from_archive(tmp_path)


def test_cache_hit_is_reverified_and_corrupt_blob_replaced(tmp_path):
    layer = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)], gz=True)
    ld = D + hashlib.sha256(layer).hexdigest()
    client, _seen = _registry([{"digest": ld, "size": len(layer), "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}],
                             blobs={ld: layer})
    cache = tmp_path / "cache"
    REGISTRY["docker-image"]().collect("ghcr.io/o/i:1", client=client, cache_dir=str(cache))
    blob = cache / "blobs" / "sha256" / ld.split(":")[1]
    assert blob.is_file()
    blob.write_bytes(b"poisoned")                                    # planted / corrupted cache entry
    inv = REGISTRY["docker-image"]().collect("ghcr.io/o/i:1", client=client, cache_dir=str(cache))
    assert any(c.name == "musl" for c in inv.components) and blob.read_bytes() == layer


def test_registry_response_caps():
    big = b"{" + b" " * (di.MAX_MANIFEST_BYTES + 10) + b"}"
    c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=big)))
    reg = di.RegistryClient(di.parse_reference("ghcr.io/o/i:1"), c)
    with pytest.raises(di.RegistryError, match="larger than limit"):
        reg.manifest("1")
    c2 = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500, content=b"x" * 10_000_000)))
    reg2 = di.RegistryClient(di.parse_reference("ghcr.io/o/i:1"), c2, sleep=lambda s: None)
    with pytest.raises(di.RegistryError) as e:
        reg2.manifest("1")
    assert len(str(e.value)) < 1000


def test_archive_member_size_checked_before_reading(tmp_path):
    cfg = b"{" + b" " * (di.MAX_CONFIG_BYTES + 10) + b"}"
    mf = json.dumps([{"Config": "cfg.json", "RepoTags": ["x:1"], "Layers": []}]).encode()
    (tmp_path / "big.tar").write_bytes(_tar_of([("cfg.json", cfg), ("manifest.json", mf)]))
    with pytest.raises(ValueError, match="exceeds"):
        di.inventory_from_archive(tmp_path / "big.tar")


def test_token_realm_must_be_https():
    def h(req):
        if req.url.host == "reg.example":
            return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="http://evil.example/token",service="s"'})
        return httpx.Response(200, json={"token": "t"})

    reg = di.RegistryClient(di.parse_reference("reg.example/a/b:1"), httpx.Client(transport=httpx.MockTransport(h)),
                            credentials=("u", "p"))
    with pytest.raises(di.RegistryError, match="https is required"):
        reg.manifest("1")


def test_redirect_downgrade_refused():
    def h(req):
        if req.url.host == "reg.example":
            return httpx.Response(307, headers={"location": "http://cdn.example/blob"})
        return httpx.Response(200, content=b"x")

    reg = di.RegistryClient(di.parse_reference("reg.example/a/b:1"), httpx.Client(transport=httpx.MockTransport(h)))
    with pytest.raises(di.RegistryError, match="refusing redirect"):
        reg.blob_bytes(D + "a" * 64)


def test_localhost_registry_hosts():
    assert di.RegistryClient(di.parse_reference("[::1]:5000/x"), httpx.Client()).base == "http://[::1]:5000"
    assert di.RegistryClient(di.parse_reference("example.com/x"), httpx.Client()).base == "https://example.com"


# --------------------------------------------------------------------------- C10 docker engine endpoint

def test_explicit_missing_socket_is_an_error(monkeypatch):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    real = os.path.exists
    monkeypatch.setattr(de.os.path, "exists", lambda p: True if p == "/var/run/docker.sock" else real(p))
    with pytest.raises(RuntimeError, match="does not exist"):
        de.find_endpoint({"socket": "/nonexistent/my.sock"})
    monkeypatch.setenv("DOCKER_HOST", "unix:///typo/docker.sock")
    with pytest.raises(RuntimeError, match="DOCKER_HOST"):
        de.find_endpoint({})


def test_rootless_docker_socket_candidate(monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert "/run/user/1000/docker.sock" in de.candidate_sockets()


# --------------------------------------------------------------------------- C6 / SEC15 / C18 macOS

def _app(root: Path, base: str, name: str, info: dict, wrapper=False) -> Path:
    p = root / base / f"{name}.app"
    d = p / "Wrapper" / f"{name}.app" if wrapper else p / "Contents"
    d.mkdir(parents=True)
    (d / "Info.plist").write_bytes(plistlib.dumps(info))
    return p


def test_macos_home_option_accepts_a_string(tmp_path):
    root = tmp_path / "root"
    (root / "System/Library/CoreServices").mkdir(parents=True)
    (root / "System/Library/CoreServices/SystemVersion.plist").write_bytes(plistlib.dumps({"ProductVersion": "14.5"}))
    home = tmp_path / "Users-bob"
    _app(home, "Applications", "Mine", {"CFBundleIdentifier": "com.acme.mine", "CFBundleShortVersionString": "1.0"})
    inv = MacOSCollector().collect(str(root), home=str(home))
    assert [c.name for c in inv.components if c.category == "application"] == ["Mine"]


def test_macos_ios_wrapper_app_and_feed_url_stripped(tmp_path):
    root = tmp_path
    _app(root, "Applications", "Game", {"CFBundleIdentifier": "com.acme.game", "CFBundleShortVersionString": "1.2"},
         wrapper=True)
    _app(root, "Applications", "Upd", {"CFBundleIdentifier": "com.acme.upd", "CFBundleShortVersionString": "2",
                                        "SUFeedURL": "https://u:pw@acme.example/feed.xml?token=abc"})
    inv = MacOSCollector().collect(str(root), home=[])
    apps = {c.name: c for c in inv.components if c.category == "application"}
    assert apps["Game"].version == "1.2" and apps["Game"].meta["ios_app_on_mac"]
    assert apps["Upd"].meta["sparkle_feed"] == "https://acme.example/feed.xml"


def test_macos_symlink_escape_and_loop_contained(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    _app(outside, "", "Evil", {"CFBundleIdentifier": "com.evil", "CFBundleShortVersionString": "9"})
    (root / "Applications").mkdir(parents=True)
    (root / "Applications" / "Evil.app").symlink_to(outside / "Evil.app")
    (root / "Applications" / "Loop.app").symlink_to(root / "Applications" / "Loop.app")
    _app(root, "Applications", "Big", {"CFBundleIdentifier": "com.big"})
    big = root / "Applications/Big.app/Contents/Info.plist"
    big.write_bytes(b"0" * (9 * 1024 * 1024))
    inv = MacOSCollector().collect(str(root), home=[])
    assert not [c for c in inv.components if c.name == "Evil"]
    assert any("Big.app" in w for w in inv.warnings)


# --------------------------------------------------------------------------- SEC8 homebrew

def test_formula_parser_is_linear_on_hostile_input():
    text = ("  license\n" * 20000) + ("  stable do\n    url x\n" * 20000)
    t = time.monotonic()
    homebrew.parse_formula_rb(text)
    homebrew._cask_text_fields("quit: [\n" * 20000)
    assert time.monotonic() - t < 3


def test_formula_parser_still_extracts_fields():
    f = homebrew.parse_formula_rb('class X < Formula\n  desc "d"\n  homepage "https://h"\n'
                                  '  stable do\n    url "https://x/a.tgz"\n  end\n  head "https://x/h.git"\n'
                                  '  license any_of: [\n    "MIT",\n    "Apache-2.0",\n  ]\n  deprecate! date: "2024-01-01"\nend\n')
    assert (f["desc"], f["url"], f["head"], f["license"], f["deprecated"]) == (
        "d", "https://x/a.tgz", "https://x/h.git", "MIT OR Apache-2.0", True)


def test_homebrew_symlinked_receipt_outside_root_is_ignored(tmp_path):
    prefix = tmp_path / "root/opt/homebrew"
    keg = prefix / "Cellar/foo/1.0"
    keg.mkdir(parents=True)
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"homebrew_version": "LEAK"}))
    (keg / "INSTALL_RECEIPT.json").symlink_to(secret)
    comps, warns = homebrew.collect_prefixes(tmp_path / "root")
    assert comps and "homebrew_version" not in comps[0].meta and any("INSTALL_RECEIPT" in w for w in warns)


# --------------------------------------------------------------------------- C9 / C18 / SEC4 / SEC6 rootfs

def test_derivative_release_from_codename_or_bare_with_warning():
    assert rf.distro_ecosystem({"ID": "kali", "ID_LIKE": "debian", "VERSION_ID": "2024.1",
                                "DEBIAN_CODENAME": "bookworm"}) == "Debian:12"
    assert rf.distro_ecosystem({"ID": "kali", "ID_LIKE": "debian", "VERSION_ID": "2024.1"}, debian_version="13.0") == "Debian:13"
    w: list[str] = []
    assert rf.distro_ecosystem({"ID": "kali", "ID_LIKE": "debian", "VERSION_ID": "2024.1"}, warnings=w) == "Debian"
    assert w and "release could not be determined" in w[0]
    assert rf.distro_ecosystem({"ID": "ubuntu", "VERSION_ID": "22.04"}) == "Ubuntu:22.04"


def test_dpkg_transitional_states_listed():
    t = "".join(f"Package: p{i}\nStatus: {s}\nVersion: 1\nArchitecture: amd64\n\n" for i, s in enumerate(
        ["install ok installed", "install ok unpacked", "install ok half-configured", "install ok triggers-pending",
         "install ok half-installed", "deinstall ok config-files"]))
    got = {p["name"]: p["state"] for p in rf.parse_dpkg_status(t)}
    assert got == {"p0": "installed", "p1": "unpacked", "p2": "half-configured", "p3": "triggers-pending"}


def test_status_d_budget_and_whiteout_index():
    v = rf.LayeredTarView()
    big = b"Package: a\nVersion: 1\nStatus: install ok installed\n\n"
    members = [(f"var/lib/dpkg/status.d/p{i}", big) for i in range(50)]
    v.add_layer(io.BytesIO(_tar_of(members)))
    assert len(v._dirs["var/lib/dpkg/status.d"]) == 50
    v.add_layer(io.BytesIO(_tar_of([("var/lib/dpkg/.wh.status.d", b"")])))
    assert not v.files and "var/lib/dpkg/status.d" not in v._dirs and "var" not in v._dirs
    # file-count cap
    v2 = rf.LayeredTarView()
    old = rf.MAX_STATUS_D_FILES
    rf.MAX_STATUS_D_FILES = 5
    try:
        v2.add_layer(io.BytesIO(_tar_of(members)))
    finally:
        rf.MAX_STATUS_D_FILES = old
    assert len(v2.files) == 5 and v2.truncated


def test_many_whiteouts_are_fast():
    v = rf.LayeredTarView()
    links = [(f"d{i}/l", "x") for i in range(20000)]
    v.add_layer(io.BytesIO(_tar_of([], links)))
    t = time.monotonic()
    v.add_layer(io.BytesIO(_tar_of([(f".wh.d{i}", b"") for i in range(20000)])))
    assert not v.links and time.monotonic() - t < 5


def test_same_layer_opaque_marker_keeps_lang_package():
    pkgj = json.dumps({"name": "left-pad", "version": "1.3.0"}).encode()
    v = rf.LayeredTarView()
    v.add_layer(io.BytesIO(_tar_of([("app/node_modules/.hidden/package.json", pkgj),
                                    ("app/node_modules/.wh..wh..opq", b"")])))
    assert [c.name for c in v.lang.components()] == ["left-pad"]


def test_hostile_rpmdb_view_is_refused_quickly(tmp_path):
    p = tmp_path / "db.sqlite"
    c = sqlite3.connect(p)
    c.execute("CREATE VIEW Packages AS WITH RECURSIVE r(hnum) AS (SELECT 1 UNION ALL SELECT hnum+1 FROM r) "
              "SELECT hnum, x'00' AS blob FROM r")
    c.commit()
    c.close()
    t = time.monotonic()
    with pytest.raises(sqlite3.Error):
        rf._rpm_rows_from_bytes(p.read_bytes(), None)
    assert time.monotonic() - t < 5


def test_rpmdb_vm_budget_aborts_runaway_query(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "RPM_VM_BUDGET", 5000)
    p = tmp_path / "db.sqlite"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB)")
    c.executemany("INSERT INTO Packages VALUES (?, x'00')", [(i,) for i in range(1, 20000)])
    c.commit()
    c.close()
    with pytest.raises(sqlite3.Error):
        rf.parse_rpmdb_sqlite(p)


# --------------------------------------------------------------------------- C12 / SEC3 / SEC17 fs git

def _repo(tmp_path: Path, cfg="", head="ref: refs/heads/feature/login-fix\n", loose=True) -> Path:
    g = tmp_path / ".git"
    (g / "refs/heads/feature").mkdir(parents=True)
    (g / "HEAD").write_text(head)
    (g / "config").write_text(cfg)
    if loose:
        (g / "refs/heads/feature/login-fix").write_text("a" * 40 + "\n")
    else:
        (g / "packed-refs").write_text("# pack-refs\n" + "a" * 40 + " refs/heads/feature/login-fix\n")
    return tmp_path


def test_git_info_branch_credentials_and_percent(tmp_path):
    d = _repo(tmp_path, '[remote "origin"]\n\turl = https://bob:p%40ss@github.com/o/r.git?x=1#f\n')
    assert fs._git_info(d) == {"branch": "feature/login-fix", "commit": "a" * 40,
                              "remote": "https://github.com/o/r.git"}
    assert fs.FsCollector().collect(str(d)).asset.meta["git"]["remote"] == "https://github.com/o/r.git"


def test_git_packed_refs_and_scp_url(tmp_path):
    d = _repo(tmp_path, '[remote "origin"]\n\turl = git@github.com:o/r.git\n', loose=False)
    assert fs._git_info(d)["commit"] == "a" * 40 and fs._git_info(d)["remote"] == "git@github.com:o/r.git"


def test_git_broken_config_does_not_crash(tmp_path):
    d = _repo(tmp_path, "garbage without section\n[remote\n")
    assert fs._git_info(d)["branch"] == "feature/login-fix"


def test_git_head_traversal_and_symlinked_head_ignored(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("a" * 40)
    repo = tmp_path / "r"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git/HEAD").write_text("ref: " + "../" * 20 + str(secret).lstrip("/") + "\n")
    assert fs._git_info(repo) == {}
    repo2 = tmp_path / "r2"
    (repo2 / ".git").mkdir(parents=True)
    (repo2 / ".git/HEAD").symlink_to(secret)
    assert fs._git_info(repo2) == {}
    (tmp_path / "r3").mkdir()
    repo3 = _repo(tmp_path / "r3")
    (repo3 / ".git/refs/heads/feature/login-fix").unlink()
    (repo3 / ".git/refs/heads/feature/login-fix").symlink_to(secret)
    assert "commit" not in fs._git_info(repo3)


def test_git_file_gitdir_pointer(tmp_path):
    real = tmp_path / "main/.git/worktrees/wt"
    real.mkdir(parents=True)
    (real / "HEAD").write_text("a" * 40 + "\n")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {real}\n")
    assert fs._git_info(wt) == {"commit": "a" * 40}
    assert fs.FsCollector().collect(str(wt)).asset.type == "repo"
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / ".git").write_text("gitdir: /etc\n")                  # a directory, but no HEAD
    assert fs._git_info(bad) == {}


# --------------------------------------------------------------------------- SEC17 redaction helpers

def test_redaction_helpers():
    assert base.redact_command(["app", "--password", "x", "--token=abc", "DB_PASSWORD=1", "https://u:p@h/x?k=1"]) == [
        "app", "--password", base.REDACTED, "--token=" + base.REDACTED, "DB_PASSWORD=" + base.REDACTED, "https://h/x"]
    assert base.redact_labels({"org.opencontainers.image.authors": "me", "api_key": "k"}) == {
        "org.opencontainers.image.authors": "me", "api_key": base.REDACTED}
    assert base.strip_url_secrets("https://bob:pw@h:8443/p?q=1#f") == "https://h:8443/p"
    assert base.strip_url_secrets("git@github.com:o/r.git") == "git@github.com:o/r.git"


def test_image_config_meta_redacts_secrets(tmp_path):
    _image(tmp_path / "s.tar", ["x:1"], cfg_extra={"config": {
        "Cmd": ["run", "--password", "hunter2"], "Entrypoint": ["/e", "TOKEN=abc"],
        "Labels": {"db.password": "p", "ok": "v"}}})
    m = di.inventory_from_archive(tmp_path / "s.tar").asset.meta
    assert m["cmd"] == ["run", "--password", "<redacted>"] and m["entrypoint"] == ["/e", "TOKEN=<redacted>"]
    assert m["labels"] == {"db.password": "<redacted>", "ok": "v"}


# --------------------------------------------------------------------------- C13 windows

def test_windows_missing_hostname_and_ubr():
    doc = {"schema": "secmonk-windows-inventory/1", "hostname": None,
           "os": {"product_name": "Windows 10 Pro", "display_version": "23H2", "current_build": "22631",
                  "major": 10, "minor": 0, "installation_type": "Client"}, "uninstall": [], "appx": [], "hotfixes": []}
    inv = windows.parse_inventory_json(doc)
    assert inv.asset.os_version == "23H2 (build 22631)" and "None" not in inv.asset.os_version
    assert inv.asset.id == "windows:unknown" and any("no hostname" in w for w in inv.warnings)
    inv = windows.parse_inventory_json(doc, hostname_hint="web01")
    assert inv.asset.id == "windows:web01" and any("web01" in w for w in inv.warnings)


def test_windows_hostname_from_file_name(tmp_path):
    doc = {"schema": "secmonk-windows-inventory/1", "os": {"current_build": "22631", "ubr": 1}, "uninstall": []}
    (tmp_path / "web01.json").write_text(json.dumps(doc))
    inv = REGISTRY["windows"]().collect(str(tmp_path / "web01.json"))
    assert inv.asset.id == "windows:web01"


def test_windows_script_loaded_from_package_data():
    s = windows.inventory_script(compact=False)
    assert "secmonk-windows-inventory" in s
