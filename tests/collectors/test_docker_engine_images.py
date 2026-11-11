"""docker-engine local images: identity by engine Id (aliases scanned once, a moved tag is a new asset), image
selectors over RepoTags. A fake engine client serves synthetic /images/* answers and `docker save` tars."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile

import pytest

from secmonk.collectors import docker_engine as de
from secmonk.collectors.base import REGISTRY

OSR = b"ID=alpine\nVERSION_ID=3.20.1\n"
APK = b"P:musl\nV:1.2.5-r0\nA:x86_64\no:musl\n\n"


def cfg(marker: str) -> bytes:
    return json.dumps({"architecture": "amd64", "os": "linux", "config": {"Labels": {"m": marker}}}).encode()


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


# classic image store: Id = sha256 of the config blob
ID_A = sha(cfg("A"))                 # nginx:1.25 == nginx:latest == myreg/nginx:prod
ID_B = sha(cfg("B"))                 # postgres:16
ID_C = sha(cfg("C"))                 # dangling
ID_N = sha(cfg("N"))                 # nginx:latest after a re-pull


def _tar(members) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for n, d in members:
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


def save_tar(marker: str, extra=()) -> bytes:
    """`docker save` of an image exported by Id: no RepoTags in the manifest."""
    layer = _tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)])
    mf = json.dumps([{"Config": "cfg.json", "RepoTags": None, "Layers": ["l/layer.tar"]}]).encode()
    return _tar([("cfg.json", cfg(marker)), ("l/layer.tar", layer), ("manifest.json", mf), *extra])


class Engine:
    """Fake EngineClient: images keyed by Id; refs resolve through tags and Id prefixes like the engine."""

    def __init__(self, images: list[dict]):
        self.images = images
        self.paths: list[str] = []
        self.endpoint = de.Endpoint(unix="/x.sock")

    def _resolve(self, ref: str) -> dict:
        for im in self.images:
            tags = im.get("RepoTags") or []
            if ref in tags or f"{ref}:latest" in tags or im["Id"] == ref or (
                    len(ref) >= 4 and im["Id"].removeprefix("sha256:").startswith(ref.removeprefix("sha256:"))):
                return im
        raise RuntimeError(f"Docker API GET /images/{ref}/json -> HTTP 404: No such image: {ref}")

    def get_json(self, path: str):
        self.paths.append(path)
        if path == "/images/json":
            return self.images
        if path == "/version":
            return {"Arch": "x86_64"}
        if path.startswith("/images/") and path.endswith("/json"):
            return self._resolve(path[len("/images/"):-len("/json")])
        if path.startswith("/containers/json"):
            return []
        raise RuntimeError(f"HTTP 404 {path}")

    def open(self, path: str):
        self.paths.append(path)
        im = self._resolve(path[len("/images/"):-len("/get")])

        class Conn:
            def close(self):
                pass
        return Conn(), io.BytesIO(im.get("archive") or save_tar(im["m"]))


IMAGES = [
    {"Id": ID_A, "m": "A", "RepoTags": ["nginx:1.25", "nginx:latest", "myreg.example.test/nginx:prod"],
     "RepoDigests": ["nginx@sha256:" + "1" * 64]},
    {"Id": ID_B, "m": "B", "RepoTags": ["postgres:16"], "RepoDigests": []},
    {"Id": ID_C, "m": "C", "RepoTags": ["<none>:<none>"], "RepoDigests": []},
]


@pytest.fixture(autouse=True)
def _clear_folded():
    de._FOLDED.clear()
    yield
    de._FOLDED.clear()


def test_aliases_fold_into_one_target_and_asset():
    eng = Engine(IMAGES)
    c = REGISTRY["docker-engine"]()
    targets = c.expand_targets("image:nginx:1.25,web,image:myreg.example.test/nginx:prod,image:nginx", client=eng)
    assert targets == [f"image:{ID_A}", "web"]
    inv = c.collect(targets[0], client=eng)
    a = inv.asset
    assert a.id == f"image:@{ID_A}" and a.name == "myreg.example.test/nginx:prod"     # min tag (requested Id)
    assert a.meta["image_id"] == ID_A and a.meta["tags"] == IMAGES[0]["RepoTags"]
    assert a.meta["repo_digests"] == IMAGES[0]["RepoDigests"] and a.meta["requested_ref"] == ID_A
    assert a.meta["requested_refs"] == ["nginx:1.25", "myreg.example.test/nginx:prod", "nginx"]
    assert any("scanned once: nginx:1.25, myreg.example.test/nginx:prod, nginx" in w for w in inv.warnings)
    assert f"/images/{ID_A}/get" in eng.paths                                        # exported by Id
    assert {x.name for x in inv.components if x.category == "os-package"} == {"musl"}


def test_requested_tag_names_the_asset_and_moved_tag_is_a_new_asset():
    c = REGISTRY["docker-engine"]()
    first = c.collect("image:nginx:latest", client=Engine(IMAGES))
    assert first.asset.id == f"image:@{ID_A}" and first.asset.name == "nginx:latest"
    moved = [{"Id": ID_N, "m": "N", "RepoTags": ["nginx:latest"], "RepoDigests": []},
             {**IMAGES[0], "RepoTags": ["nginx:1.25", "myreg.example.test/nginx:prod"]}]
    second = c.collect("image:nginx:latest", client=Engine(moved))
    assert second.asset.id == f"image:@{ID_N}" != first.asset.id
    assert c.collect("image:nginx:1.25", client=Engine(moved)).asset.id == first.asset.id   # alias keeps it


def test_image_patterns_over_repo_tags():
    eng = Engine(IMAGES)
    c = REGISTRY["docker-engine"]()
    assert c.expand_targets("image:*", client=eng) == [f"image:{ID_A}", f"image:{ID_B}"]      # dangling ignored
    assert c.expand_targets("image:nginx:*,image:re:^myreg\\.", client=eng) == [f"image:{ID_A}"]
    assert de._FOLDED[("unix:///x.sock", ID_A)] == ["nginx:1.25", "myreg.example.test/nginx:prod"]
    assert c.expand_targets("image:re:^postgres:1[0-9]$", client=eng) == [f"image:{ID_B}"]
    with pytest.raises(ValueError, match="no image matches 'image:redis:\\*'; tagged images: nginx:1.25"):
        c.expand_targets("image:redis:*", client=eng)
    with pytest.raises(ValueError, match="catastrophic"):
        c.expand_targets("image:re:^(a+)+$", client=eng)
    assert eng.paths.count("/images/json") == 5                          # one listing per expansion


def test_id_prefix_and_unknown_image():
    eng = Engine(IMAGES)
    c = REGISTRY["docker-engine"]()
    assert c.expand_targets(f"image:{ID_B[7:19]}", client=eng) == [f"image:{ID_B}"]
    inv = c.collect(f"image:{ID_B[7:19]}", client=eng)
    assert inv.asset.id == f"image:@{ID_B}" and inv.asset.name == "postgres:16"
    assert "requested_refs" not in inv.asset.meta or inv.asset.meta["requested_refs"] == [ID_B[7:19]]
    assert c.expand_targets("image:nosuch:1", client=eng) == ["image:nosuch:1"]       # collect reports it
    with pytest.raises(RuntimeError, match="No such image: nosuch:1"):
        c.collect("image:nosuch:1", client=eng)


def test_select_images_pure():
    rows = [*IMAGES, {"Id": "e" * 64, "RepoTags": ["x" * 300 + ":1", "short:1"]}, {"Id": "bad", "RepoTags": ["z:1"]}]
    assert de.select_images("*:1", rows) == [("sha256:" + "e" * 64, "short:1")]    # podman bare id; long tag skipped
    assert de.select_images("nginx*", rows) == [(ID_A, "nginx:1.25")]


def test_containers_are_not_deduped_by_image():
    rows = [{"Id": "1" * 64, "Names": ["/web-1"], "Image": "nginx:1.25"},
            {"Id": "2" * 64, "Names": ["/web-2"], "Image": "nginx:1.25"}]
    assert de.select_containers("web-*", rows) == ["web-1", "web-2"]


def test_image_identity_is_pure():
    assert de.image_identity(f"image:{ID_A}") == f"image:@{ID_A}"
    for t in ("image:nginx:1.25", "image:aaaaaaaaaaaa", "image:sha256:abc", "web", None, "", ID_A):
        assert de.image_identity(t) is None
    c = REGISTRY["docker-engine"]()
    for t in c.expand_targets("image:*", client=Engine(IMAGES)):
        assert c.collect(t, client=Engine(IMAGES)).asset.id == de.image_identity(t)


def test_image_meta_refreshes_without_export():
    eng = Engine(IMAGES)
    c = REGISTRY["docker-engine"]()
    (t,) = c.expand_targets("image:nginx:1.25,image:nginx:latest", client=eng)
    eng.paths.clear()
    m = de.image_meta(t, client=eng)
    assert eng.paths == [f"/images/{ID_A}/json"]                                  # one GET, no /get
    assert m == {"source": "docker-engine", "image_id": ID_A, "tags": IMAGES[0]["RepoTags"],
                 "repo_digests": IMAGES[0]["RepoDigests"], "requested_ref": ID_A,
                 "inventory_version": de.IMAGE_INVENTORY_VERSION, "requested_refs": ["nginx:1.25", "nginx:latest"],
                 "engine": "unix:///x.sock"}
    inv = c.collect(t, client=eng)                                       # same keys as a full collect
    assert {k: inv.asset.meta[k] for k in m if k != "requested_refs"} == {k: v for k, v in m.items()
                                                                         if k != "requested_refs"}
    assert inv.asset.meta["inventory_version"] == 1
    with pytest.raises(RuntimeError, match="No such image"):
        de.image_meta("image:nosuch", client=eng)


# --------------------------------------------------------------------------- review fixes (2026-11-11)

def test_image_id_is_verified_against_the_export():
    c = REGISTRY["docker-engine"]()
    inv = c.collect("image:postgres:16", client=Engine(IMAGES))
    m = inv.asset.meta
    assert m["id_verified"] is True and not inv.partial
    assert m["engine"] == "unix:///x.sock" and m["platform"] == inv.asset.platform == "linux/amd64"
    # a lying engine: claims postgres' Id but exports another image's config
    liar = [{**IMAGES[1], "archive": save_tar("EVIL")}]
    inv = c.collect("image:postgres:16", client=Engine(liar))
    assert inv.asset.meta["id_verified"] is False and inv.partial
    assert any("not verified" in w and "does not belong" in w for w in inv.warnings)


def test_containerd_store_id_is_a_manifest_digest(tmp_path):
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": sha(cfg("M"))}, "layers": []}).encode()
    index = json.dumps({"schemaVersion": 2, "manifests": [{"digest": sha(manifest)}]}).encode()
    iid = sha(index)
    blobs = [(f"blobs/sha256/{sha(b)[7:]}", b) for b in (manifest, index)]
    (tmp_path / "ok.tar").write_bytes(save_tar("M", blobs))
    assert de.verify_image_archive(tmp_path / "ok.tar", iid) == (True, "manifest digest")
    assert de.verify_image_archive(tmp_path / "ok.tar", sha(manifest))[0]
    (tmp_path / "bad.tar").write_bytes(save_tar("OTHER", blobs))      # index fine, config swapped
    ok, why = de.verify_image_archive(tmp_path / "bad.tar", iid)
    assert not ok and "does not belong" in why
    forged = [(f"blobs/sha256/{iid[7:]}", index + b" ")]                # blob name does not match its hash
    (tmp_path / "forged.tar").write_bytes(save_tar("M", forged))
    assert not de.verify_image_archive(tmp_path / "forged.tar", iid)[0]
    (tmp_path / "junk.tar").write_bytes(b"not a tar")
    assert de.verify_image_archive(tmp_path / "junk.tar", iid)[0] is False


def test_folded_groups_are_per_engine_and_never_leak():
    c = REGISTRY["docker-engine"]()
    eng = Engine(IMAGES)
    c.expand_targets("image:nginx:1.25,image:nginx:latest", client=eng)
    assert list(de._FOLDED) == [("unix:///x.sock", ID_A)]
    other = Engine(IMAGES)
    other.endpoint = de.Endpoint(host="engine.example.test", port=2375)
    assert "requested_refs" not in c.collect(f"image:{ID_A}", client=other).asset.meta   # other engine
    assert ("unix:///x.sock", ID_A) in de._FOLDED
    c.expand_targets("image:postgres:16", client=eng)                      # a new expansion clears old groups
    assert list(de._FOLDED) == [("unix:///x.sock", ID_B)]
    broken = Engine([{**IMAGES[1], "archive": b"not a tar"}])
    with pytest.raises(ValueError):
        c.collect(f"image:{ID_B}", client=broken)
    assert de._FOLDED == {}                                                # popped although collect failed
    c.expand_targets("image:postgres:16", client=eng)
    with pytest.raises(RuntimeError):
        c.collect(f"image:{ID_B}", client=Engine([]))                     # inspect fails: still popped
    assert de._FOLDED == {}


# --------------------------------------------------------------------------- missing permissions (2026-11-11)

class Restricted(Engine):
    """Engine behind an authorization plugin: some endpoints answer 403."""

    def __init__(self, images, denied=()):
        super().__init__(images)
        self.denied = denied
        self.container = {"Id": "f" * 64, "Name": "/web", "Image": ID_A, "Config": {"Image": "nginx:1.25"},
                          "State": {"Status": "running"}, "HostConfig": {}}

    def _deny(self, path):
        if any(path.startswith(d) for d in self.denied):
            raise RuntimeError(f"Docker API GET {path} -> HTTP 403: authorization denied by plugin authz")

    def get_json(self, path):
        self._deny(path)
        if path == "/containers/web/json":
            return self.container
        return super().get_json(path)

    def open(self, path):
        self._deny(path)
        return super().open(path)


def test_container_export_denied_falls_back_to_its_image():
    eng = Restricted(IMAGES, denied=("/containers/" + "f" * 64 + "/export",))
    inv = REGISTRY["docker-engine"]().collect("web", client=eng)
    a = inv.asset
    assert a.id == "container:web" and a.type == "container"
    assert a.meta["scanned_image"] == ID_A and a.meta["filesystem"] == "image-only" and a.meta["image_id_verified"]
    assert {c.name for c in inv.components if c.category == "os-package"} == {"musl"}
    assert inv.partial and "container filesystem not readable" in inv.partial_reason
    assert inv.warnings[0].startswith("container filesystem not readable (Docker API GET")
    assert f"scanned its image {ID_A[7:19]} instead" in inv.warnings[0]


def test_container_and_image_denied_are_target_errors():
    eng = Restricted(IMAGES, denied=("/containers/web/json",))
    with pytest.raises(RuntimeError, match="HTTP 403"):
        REGISTRY["docker-engine"]().collect("web", client=eng)
    eng = Restricted(IMAGES, denied=("/containers/" + "f" * 64 + "/export", f"/images/{ID_A}/get"))
    with pytest.raises(RuntimeError, match="container filesystem not readable .*its image .* neither: .*HTTP 403"):
        REGISTRY["docker-engine"]().collect("web", client=eng)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        REGISTRY["docker-engine"]().collect("image:nginx:1.25", client=Restricted(IMAGES, denied=("/images/",)))


def test_listing_denied_names_the_selector():
    c = REGISTRY["docker-engine"]()
    with pytest.raises(RuntimeError, match="cannot list images for selector 'image:nginx:\\*'.*HTTP 403"):
        c.expand_targets("image:nginx:*", client=Restricted(IMAGES, denied=("/images/json",)))

    class NoList(Restricted):
        def get_json(self, path):
            if path.startswith("/containers/json"):
                raise RuntimeError("Docker API GET /containers/json -> HTTP 403: denied")
            return super().get_json(path)

    with pytest.raises(RuntimeError, match="cannot list containers for selector 'web-\\*'"):
        c.expand_targets("web-*", client=NoList(IMAGES))
    assert c.expand_targets("web", client=NoList(IMAGES)) == ["web"]         # exact names need no listing


def test_hostile_container_json_is_tolerated():
    eng = Restricted(IMAGES)
    eng.container = {**eng.container, "NetworkSettings": ["not", "a", "dict"], "Config": {"Labels": ["x"]},
                     "State": "weird", "HostConfig": None}
    inv = REGISTRY["docker-engine"]().collect("web", client=eng)
    assert inv.asset.meta["published_ports"] is False and inv.asset.meta["labels"] == {}
