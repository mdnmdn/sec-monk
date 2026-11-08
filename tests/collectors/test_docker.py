"""docker-image + docker-engine collectors (no network, no daemon)."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import socketserver
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import ClassVar

import httpx
import pytest

from secmonk.collectors import docker_engine as de
from secmonk.collectors import docker_image as di
from secmonk.collectors.base import REGISTRY
from secmonk.collectors.rootfs import LayeredTarView

FX = Path(__file__).parent.parent / "fixtures" / "collectors" / "docker"


def make_tar(members: list[tuple[str, bytes | str | None]], gz: bool = False) -> bytes:
    """(name, bytes) = file, (name, str) = symlink target, (name, None) = directory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            if data is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif isinstance(data, str):
                ti.type, ti.linkname = tarfile.SYMTYPE, data
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw) if gz else raw


APK = (b"C:Q1x\nP:musl\nV:1.2.5-r0\nA:x86_64\no:musl\nL:MIT\n\n"
       b"P:xz-libs\nV:5.6.0-r0\nA:x86_64\no:xz\n\n")
OSR = b'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.20.1\n'


# --------------------------------------------------------------------------- tarball / layers

def test_alpine_mini_tar():
    inv = REGISTRY["docker-image"]().collect(str(FX / "alpine-mini.tar"))
    a = inv.asset
    assert a.type == "container-image" and a.name == "alpine:3.20" and a.platform == "linux/amd64"
    assert a.id == "image:docker.io/library/alpine@sha256:ed121134e825270d8e5208f8dc97e11da3f678222594e0c4ea5a9a547116db9c"
    assert a.os_name == "Alpine Linux"
    pk = [c for c in inv.components if c.category == "os-package"]
    assert len(pk) == 5 and all(c.ecosystem == "Alpine:v3.20" for c in pk)
    assert any(c.name == "alpine-baselayout" for c in pk)


def test_oci_layout_dir(tmp_path: Path):
    with tarfile.open(FX / "alpine-mini.tar") as tf:
        tf.extractall(tmp_path, filter="data")
    (tmp_path / "manifest.json").unlink()                         # force the index.json path
    inv = REGISTRY["docker-image"]().collect(str(tmp_path))
    assert len([c for c in inv.components if c.category == "os-package"]) == 5
    assert inv.asset.meta["ref"] is None          # a bare OCI tag annotation is not a repository ref


def test_dir_that_is_not_a_layout(tmp_path: Path):
    with pytest.raises(ValueError, match="rootfs"):
        REGISTRY["docker-image"]().collect(str(tmp_path))


def test_whiteouts_and_opaque_dirs():
    v = LayeredTarView()
    v.add_layer(io.BytesIO(make_tar([
        ("etc/os-release", b"ID=alpine\n"), ("lib/apk/db/installed", APK),
        ("var/lib/dpkg/status.d/a", b"Package: a\n"), ("var/lib/dpkg/status.d/b", b"Package: b\n"),
        ("usr/lib/os-release", b"ID=old\n"),
    ])))
    v.add_layer(io.BytesIO(make_tar([
        ("etc/.wh.os-release", b""),                        # delete
        ("var/lib/dpkg/status.d/.wh..wh..opq", b""),        # opaque: drop a, b ...
        ("var/lib/dpkg/status.d/c", b"Package: c\n"),       # ... but keep what this layer adds
        ("lib/apk/db/installed", APK + b"P:new\nV:1\n\n"),  # replaced
    ], gz=True)))
    assert v.read("etc/os-release") is None
    assert v.listdir("var/lib/dpkg/status.d") == ["c"]
    assert b"P:new" in v.read("lib/apk/db/installed")
    assert v.read("usr/lib/os-release") == b"ID=old\n"
    # whiteout of a whole directory
    v.add_layer(io.BytesIO(make_tar([("usr/lib/.wh.os-release", b"")])))
    assert v.read("usr/lib/os-release") is None


def test_symlink_resolution_in_layers():
    v = LayeredTarView()
    v.add_layer(io.BytesIO(make_tar([
        ("etc/os-release", "../usr/lib/os-release"), ("usr/lib/os-release", OSR),
        ("var/lib/rpm", "../../usr/lib/sysimage/rpm"), ("usr/lib/sysimage/rpm/Packages", b"x"),
        ("etc/abs", "/usr/lib/os-release"), ("etc/evil", "../../../../../etc/passwd"),
    ])))
    assert v.read("etc/os-release") == OSR and v.read("etc/abs") == OSR
    assert v.read("var/lib/rpm/Packages") == b"x"
    assert v.read("etc/evil") is None


def test_collect_two_layer_image(tmp_path: Path):
    l1 = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)])
    l2 = make_tar([("lib/apk/db/installed", APK + b"P:curl\nV:8.0-r0\nA:x86_64\no:curl\n\n")], gz=True)
    cfg = json.dumps({"os": "linux", "architecture": "arm64", "variant": "v8", "created": "2024-01-01T00:00:00Z",
                      "config": {"Labels": {"a": "b"}, "Env": ["SECRET=1", "PATH=/bin"], "User": "root"}}).encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tf:
        for n, d in (("c.json", cfg), ("l1/layer.tar", l1), ("l2/layer.tar", l2),
                     ("manifest.json", json.dumps([{"Config": "c.json", "RepoTags": ["x/y:1"],
                                                    "Layers": ["l1/layer.tar", "l2/layer.tar"]}]).encode())):
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
    p = tmp_path / "img.tar"
    p.write_bytes(out.getvalue())
    inv = REGISTRY["docker-image"]().collect(str(p))
    names = {c.name for c in inv.components if c.category == "os-package"}
    assert names == {"musl", "xz-libs", "curl"}
    assert inv.asset.platform == "linux/arm64/v8" and inv.asset.meta["labels"] == {"a": "b"}
    assert inv.asset.meta["env_names"] == ["PATH", "SECRET"] and inv.asset.id.startswith("image:docker.io/x/y@sha256:")


# --------------------------------------------------------------------------- references

@pytest.mark.parametrize("ref,reg,repo,tag,digest", [
    ("alpine", "docker.io", "library/alpine", "latest", None),
    ("alpine:3.20", "docker.io", "library/alpine", "3.20", None),
    ("debian:12-slim", "docker.io", "library/debian", "12-slim", None),
    ("grafana/grafana:10", "docker.io", "grafana/grafana", "10", None),
    ("ghcr.io/org/img:tag", "ghcr.io", "org/img", "tag", None),
    ("mirror.gcr.io/library/rockylinux:9-minimal", "mirror.gcr.io", "library/rockylinux", "9-minimal", None),
    ("localhost:5000/a/b", "localhost:5000", "a/b", "latest", None),
    ("alpine@sha256:" + "a" * 64, "docker.io", "library/alpine", None, "sha256:" + "a" * 64),
    ("ghcr.io/o/i:1@sha256:" + "b" * 64, "ghcr.io", "o/i", "1", "sha256:" + "b" * 64),
])
def test_parse_reference(ref, reg, repo, tag, digest):
    r = di.parse_reference(ref)
    assert (r.registry, r.repository, r.tag, r.digest) == (reg, repo, tag, digest)


def test_parse_reference_hosts():
    assert di.parse_reference("alpine").host == "registry-1.docker.io"
    with pytest.raises(ValueError):
        di.parse_reference("a@sha256:xyz")


def test_select_manifest_skips_attestations():
    idx = json.loads((FX / "registry/alpine-3.20.index.json").read_text())["manifests"]
    pick = di.select_manifest(idx, "linux/amd64")
    assert pick["platform"] == {"architecture": "amd64", "os": "linux"}
    assert di.select_manifest(idx, "linux/arm/v6")["platform"]["variant"] == "v6"
    assert di.select_manifest(idx, "windows/amd64") is None


# --------------------------------------------------------------------------- registry (mock)

def test_registry_pull_with_token_redirect_and_retry():
    reg = FX / "registry"
    index = (reg / "alpine-3.20.index.json").read_bytes()
    config = (reg / "alpine-3.20.config.json").read_bytes()
    layer = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)], gz=True)
    cfg_d = "sha256:" + hashlib.sha256(config).hexdigest()
    lay_d = "sha256:" + hashlib.sha256(layer).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"digest": cfg_d, "size": len(config),
                                      "mediaType": "application/vnd.oci.image.config.v1+json"},
                           "layers": [{"digest": lay_d, "size": len(layer),
                                       "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]}).encode()
    idx = json.loads(index)
    amd64 = "sha256:" + hashlib.sha256(manifest).hexdigest()          # fetched by digest => verified
    di.select_manifest(idx["manifests"], "linux/amd64")["digest"] = amd64
    index = json.dumps(idx).encode()
    seen: list[httpx.Request] = []
    state = {"429": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        u = req.url
        if u.host == "auth.docker.io":
            assert u.params["service"] == "registry.docker.io"
            assert u.params["scope"] == "repository:library/alpine:pull"
            return httpx.Response(200, json={"token": "T0K"})
        if u.host == "cdn.example.net":
            assert "authorization" not in req.headers          # dropped on the cross-host redirect
            return httpx.Response(200, content=layer)
        assert u.host == "registry-1.docker.io"
        if req.headers.get("authorization") != "Bearer T0K":
            return httpx.Response(401, headers={"www-authenticate":
                                  'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'})
        if "manifests" in u.path:
            for a in ("application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
                      "application/vnd.docker.distribution.manifest.v2+json"):
                assert a in req.headers["accept"]
        if u.path == "/v2/library/alpine/manifests/3.20":
            if state["429"] == 0:
                state["429"] = 1
                return httpx.Response(429, headers={"retry-after": "0"},
                                      json={"errors": [{"code": "TOOMANYREQUESTS", "message": "slow down"}]})
            return httpx.Response(200, content=index, headers={"content-type": "application/vnd.oci.image.index.v1+json"})
        if u.path == f"/v2/library/alpine/manifests/{amd64}":
            return httpx.Response(200, content=manifest)
        if u.path == f"/v2/library/alpine/blobs/{cfg_d}":
            return httpx.Response(200, content=config)
        if u.path == f"/v2/library/alpine/blobs/{lay_d}":
            return httpx.Response(307, headers={"location": "https://cdn.example.net/blob/xyz"})
        return httpx.Response(404, json={"errors": [{"code": "NAME_UNKNOWN", "message": u.path}]})

    with tempfile.TemporaryDirectory() as cache:
        client = httpx.Client(transport=httpx.MockTransport(handler))
        kw = {"client": client, "cache_dir": cache, "sleep": lambda s: None}
        inv = REGISTRY["docker-image"]().collect("alpine:3.20", **kw)
        assert inv.asset.id == "image:docker.io/library/alpine@sha256:" + hashlib.sha256(manifest).hexdigest()
        assert inv.asset.name == "alpine:3.20" and inv.asset.platform == "linux/amd64"
        assert inv.asset.os_version == "3.20.1"
        assert {c.name for c in inv.components if c.category == "os-package"} == {"musl", "xz-libs"}
        assert (Path(cache) / "blobs/sha256" / lay_d.split(":")[1]).exists()        # cached
        n = len(seen)
        REGISTRY["docker-image"]().collect("alpine:3.20", **kw)
        assert not any("blobs" in r.url.path and r.url.path.endswith(lay_d) for r in seen[n:])  # cache hit
        REGISTRY["docker-image"]().collect("alpine:3.20", **{**kw, "no_cache": True})


def test_registry_digest_mismatch_and_errors():
    config = b"{}"
    layer = make_tar([("etc/os-release", OSR)])
    cfg_d = "sha256:" + hashlib.sha256(config).hexdigest()
    lay_d = "sha256:" + "0" * 64
    manifest = json.dumps({"config": {"digest": cfg_d}, "layers": [{"digest": lay_d}]}).encode()

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if "manifests" in p:
            return httpx.Response(200, content=manifest)
        if cfg_d in p:
            return httpx.Response(200, content=config)
        if lay_d in p:
            return httpx.Response(200, content=layer)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with tempfile.TemporaryDirectory() as cache, pytest.raises(di.RegistryError, match="digest mismatch"):
        REGISTRY["docker-image"]().collect("ghcr.io/o/i:1", client=client, cache_dir=cache)

    def always429(req: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"errors": [{"code": "TOOMANYREQUESTS", "message": "limit"}]})

    c2 = httpx.Client(transport=httpx.MockTransport(always429))
    with pytest.raises(di.RegistryError, match="rate limited"):
        REGISTRY["docker-image"]().collect("alpine", client=c2, sleep=lambda s: None)


def test_zstd_layer_without_module_warns(tmp_path: Path):
    from secmonk.collectors.rootfs import UnsupportedLayer, open_maybe_compressed

    try:
        open_maybe_compressed(io.BytesIO(b"\x28\xb5\x2f\xfd" + b"\0" * 16))
    except UnsupportedLayer:
        w: list[str] = []
        di._apply_layer(LayeredTarView(), 3, io.BytesIO(b"\x28\xb5\x2f\xfd" + b"\0" * 16), w)
        assert "layer 3" in w[0] and "zstd" in w[0]


# --------------------------------------------------------------------------- engine (fake socket)

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    routes: ClassVar[dict[str, tuple[int, bytes]]] = {}
    requests: ClassVar[list[str]] = []

    def address_string(self) -> str:
        return "unix"

    def log_message(self, *a) -> None:
        pass

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        code, body = self.routes.get(self.path.split("?")[0], (404, b'{"message":"nope"}'))
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def engine():
    d = tempfile.mkdtemp(prefix="sm")
    sock = f"{d}/d.sock"
    eng = FX / "engine"
    export = make_tar([("etc/os-release", OSR), ("lib/apk/db/installed", APK)])
    handler = type("H", (_Handler,), {"routes": {
        "/_ping": (200, b"OK"),
        "/version": (200, (eng / "version.json").read_bytes()),
        "/containers/json": (200, (eng / "containers-json.json").read_bytes()),
        "/containers/web/json": (200, (eng / "container-inspect.json").read_bytes()),
        "/containers/8dfafdbc3a40a1f7c0a2a8e5d4a0b4a3c2f1e0d9c8b7a69584736251403f2e1d/export": (200, export),
    }, "requests": []})
    srv = socketserver.ThreadingUnixStreamServer(sock, handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield sock, handler
    srv.shutdown()
    srv.server_close()


def test_engine_list_version_and_container(engine):
    sock, handler = engine
    assert de.EngineClient(de.Endpoint(unix=sock)).ping()
    assert de.EngineClient(de.Endpoint(unix=sock)).version()["Version"] == "27.0.3"
    running = de.list_containers(socket=sock)
    assert [c["Names"][0] for c in running] == ["/web", "/db", "/old-job"]
    assert "/containers/json?all=0" in handler.requests and de.list_containers(all=True, socket=f"unix://{sock}")

    inv = REGISTRY["docker-engine"]().collect("web", socket=sock)
    a = inv.asset
    assert a.id == "container:web" and a.type == "container"
    assert a.meta["image"] == "nginx:1.25.3" and a.meta["state"] == "running"
    assert a.meta["image_id"].startswith("sha256:a6bd")
    assert {c.name for c in inv.components if c.category == "os-package"} == {"musl", "xz-libs"}
    assert all(r.startswith("/") for r in handler.requests)


def test_engine_errors(engine, monkeypatch, tmp_path):
    sock, _ = engine
    with pytest.raises(RuntimeError, match="HTTP 404"):
        REGISTRY["docker-engine"]().collect("nosuch", socket=sock)
    with pytest.raises(ValueError, match="web \\(nginx"):
        REGISTRY["docker-engine"]().collect(None, socket=sock)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setattr(de, "candidate_sockets", lambda opts=None: [str(tmp_path / "nope.sock")])
    with pytest.raises(RuntimeError, match="Docker engine socket not found: tried .*nope.sock"):
        de.find_endpoint({})
    monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.1:2376")
    assert str(de.find_endpoint({})) == "tcp://10.0.0.1:2376"


def test_stale_socket_is_skipped_in_auto_discovery(engine, monkeypatch):
    # macOS 2026-11-08: Docker Desktop not running but ~/.docker/run/docker.sock left behind (ECONNREFUSED)
    import socket as so

    live, _ = engine
    stale = str(Path(live).with_name("stale.sock"))        # same short temp dir (AF_UNIX path limit on macOS)
    s = so.socket(so.AF_UNIX, so.SOCK_STREAM)
    s.bind(stale)                                          # bound, never listening -> connect is refused
    try:
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        monkeypatch.setattr(de, "candidate_sockets", lambda opts=None: [stale, live])
        assert de.find_endpoint({}).unix == live
        monkeypatch.setattr(de, "candidate_sockets", lambda opts=None: [stale])
        with pytest.raises(RuntimeError, match="refusing connections .*stale.sock"):
            de.find_endpoint({})
        assert de.find_endpoint({"socket": stale}).unix == stale   # explicit: never second-guessed
    finally:
        s.close()
        Path(stale).unlink(missing_ok=True)
