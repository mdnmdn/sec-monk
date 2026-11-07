"""Container image inventory: `docker save` tarballs, OCI layout dirs, and registry pulls.

No Docker daemon, nothing is executed or extracted to disk: layers are streamed through
`LayeredTarView`, which keeps only the whitelisted files (package DBs, os-release, language
metadata) and applies whiteouts. See _docs/tech/collectors/docker-image.md.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urljoin, urlsplit

import httpx

from ..models import Asset, Inventory
from ..sources.base import CACHE_DIR, http_client
from .base import Collector, register
from .rootfs import LayeredTarView, UnsupportedLayer, collect_from_view, norm_path

MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}
DOCKER_HUB = "docker.io"
DOCKER_HUB_HOST = "registry-1.docker.io"
DEFAULT_PLATFORM = "linux/amd64"
MAX_LAYER_BYTES = 4 * 1024**3
MAX_RETRIES = 4


# --------------------------------------------------------------------------- references

@dataclass
class ImageRef:
    registry: str            # display name: 'docker.io', 'ghcr.io', 'mirror.gcr.io'
    repository: str          # 'library/alpine'
    tag: str | None = None
    digest: str | None = None

    @property
    def host(self) -> str:
        return DOCKER_HUB_HOST if self.registry == DOCKER_HUB else self.registry

    @property
    def reference(self) -> str:
        return self.digest or self.tag or "latest"

    @property
    def canonical_repo(self) -> str:
        return f"{self.registry}/{self.repository}"

    def __str__(self) -> str:
        s = self.canonical_repo
        if self.tag:
            s += f":{self.tag}"
        if self.digest:
            s += f"@{self.digest}"
        return s


def parse_reference(ref: str) -> ImageRef:
    """'alpine:3.20' -> docker.io/library/alpine:3.20; 'ghcr.io/o/i:t'; 'img@sha256:...'."""
    ref = ref.strip()
    if not ref:
        raise ValueError("empty image reference")
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not re.fullmatch(r"[A-Za-z0-9_+.-]+:[A-Fa-f0-9]{32,}", digest):
            raise ValueError(f"invalid digest in image reference: {digest}")
    first, sep, rest = ref.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = DOCKER_HUB, ref
    if registry in ("index.docker.io", DOCKER_HUB_HOST):
        registry = DOCKER_HUB
    tag = None
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path, tag = path.rsplit(":", 1)
    if not path:
        raise ValueError(f"invalid image reference: {ref}")
    if registry == DOCKER_HUB and "/" not in path:
        path = f"library/{path}"
    if tag is None and digest is None:
        tag = "latest"
    return ImageRef(registry, path, tag, digest)


# --------------------------------------------------------------------------- platform selection

def parse_platform(p: str) -> tuple[str, str, str | None]:
    parts = p.split("/")
    if len(parts) < 2:
        raise ValueError(f"platform must look like os/arch[/variant]: {p}")
    return parts[0], parts[1], parts[2] if len(parts) > 2 else None


def select_manifest(entries: list[dict], platform: str) -> dict | None:
    """Pick the manifest descriptor for `platform`; skips unknown/unknown attestation entries."""
    want_os, want_arch, want_var = parse_platform(platform)
    real = [e for e in entries
            if (e.get("platform") or {}).get("os") not in ("unknown", None)
            and (e.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest"]
    cands = [e for e in real if e["platform"].get("os") == want_os and e["platform"].get("architecture") == want_arch]
    if want_var:
        exact = [e for e in cands if e["platform"].get("variant") == want_var]
        cands = exact or [e for e in cands if not e["platform"].get("variant")]
    elif len(cands) > 1:
        nov = [e for e in cands if not e["platform"].get("variant")]
        cands = nov or cands
    return cands[0] if cands else None


def _describe_platforms(entries: list[dict]) -> str:
    out = []
    for e in entries:
        p = e.get("platform") or {}
        if p.get("os") != "unknown":
            out.append("/".join(x for x in (p.get("os"), p.get("architecture"), p.get("variant")) if x))
    return ", ".join(out) or "none"


# --------------------------------------------------------------------------- registry client

class RegistryError(RuntimeError):
    pass


def _parse_challenge(header: str) -> tuple[str, dict[str, str]]:
    scheme, _, rest = header.strip().partition(" ")
    return scheme.lower(), dict(re.findall(r'(\w+)="([^"]*)"', rest))


def docker_config_auth(host: str) -> tuple[str, str] | None:
    """Inline `auths.<host>.auth` from ~/.docker/config.json (credential helpers are not supported)."""
    try:
        cfg = json.loads((Path.home() / ".docker" / "config.json").read_text())
    except (OSError, ValueError):
        return None
    keys = [host, f"https://{host}", f"https://{host}/v1/"]
    if host == DOCKER_HUB_HOST:
        keys.append("https://index.docker.io/v1/")
    for key in keys:
        a = (cfg.get("auths") or {}).get(key, {}).get("auth")
        if a:
            with contextlib.suppress(Exception):
                user, _, pw = base64.b64decode(a).decode().partition(":")
                return user, pw
    return None


class RegistryClient:
    """Minimal read-only Registry HTTP API v2 client with anonymous/basic token auth."""

    def __init__(self, ref: ImageRef, client: httpx.Client, credentials: tuple[str, str] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.ref, self.http, self.credentials, self.sleep = ref, client, credentials, sleep
        self._token: str | None = None
        self._basic: str | None = None
        host = ref.host
        local = host.split(":")[0] in ("localhost", "127.0.0.1")
        self.base = f"{'http' if local else 'https'}://{host}"

    # ---- auth
    def _fetch_token(self, params: dict[str, str]) -> str:
        realm = params.get("realm")
        if not realm:
            raise RegistryError("registry sent a Bearer challenge without realm")
        q = {k: v for k, v in params.items() if k in ("service", "scope")}
        q.setdefault("scope", f"repository:{self.ref.repository}:pull")
        auth = httpx.BasicAuth(*self.credentials) if self.credentials else None
        r = self.http.get(realm, params=q, auth=auth)
        if r.status_code != 200:
            raise RegistryError(f"token endpoint {realm} answered {r.status_code}: {r.text[:200]}")
        d = r.json()
        tok = d.get("token") or d.get("access_token")
        if not tok:
            raise RegistryError("token endpoint returned no token")
        return tok

    # ---- requests
    def _error(self, r: httpx.Response, body: bytes) -> RegistryError:
        msg = ""
        with contextlib.suppress(Exception):
            errs = json.loads(body).get("errors") or []
            msg = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errs)
        return RegistryError(f"{r.request.url} -> HTTP {r.status_code} {msg or body[:200].decode('utf-8', 'replace')}")

    def get(self, path_or_url: str, accept: str | None = None, dest: BinaryIO | None = None,
            max_bytes: int | None = None) -> tuple[httpx.Headers, bytes | None]:
        """GET with token auth, 429/5xx backoff and manual redirects (Authorization is dropped on
        any redirect to another host: blob URLs point to CDNs, and httpx would also strip it, but
        we do not rely on the version of httpx or on an injected client's settings).
        Body is returned, or streamed into `dest` (then None is returned)."""
        url = path_or_url if path_or_url.startswith("http") else self.base + path_or_url
        attempts = 0
        authed_retry = False
        while True:
            hops, cur = 0, url
            while True:
                headers = {"Accept": accept} if accept else {}
                if self._token and urlsplit(cur).netloc == urlsplit(url).netloc:
                    headers["Authorization"] = f"Bearer {self._token}"
                elif self._basic and urlsplit(cur).netloc == urlsplit(url).netloc:
                    headers["Authorization"] = f"Basic {self._basic}"
                with self.http.stream("GET", cur, headers=headers, follow_redirects=False) as r:
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        hops += 1
                        if hops > 6:
                            raise RegistryError("too many redirects")
                        cur = urljoin(cur, r.headers["location"])
                        continue
                    if r.status_code == 200:
                        if dest is None:
                            body = r.read()
                            return r.headers, body
                        n = 0
                        for chunk in r.iter_bytes(1 << 20):
                            n += len(chunk)
                            if max_bytes and n > max_bytes:
                                raise RegistryError(f"blob larger than limit ({max_bytes} bytes)")
                            dest.write(chunk)
                        return r.headers, None
                    body = r.read()
                    status, resp_headers = r.status_code, r.headers
                    err = self._error(r, body)
                break
            if status == 401 and not authed_retry and urlsplit(cur).netloc == urlsplit(url).netloc:
                scheme, params = _parse_challenge(resp_headers.get("www-authenticate", ""))
                if scheme == "bearer":
                    self._token = self._fetch_token(params)
                    authed_retry = True
                    continue
                if scheme == "basic" and self.credentials:
                    self._basic = base64.b64encode(":".join(self.credentials).encode()).decode()
                    authed_retry = True
                    continue
            if status in (429, 500, 502, 503, 504) and attempts < MAX_RETRIES:
                attempts += 1
                try:
                    wait = min(float(resp_headers.get("retry-after", 2 ** attempts)), 20.0)
                except ValueError:
                    wait = 2.0 ** attempts
                self.sleep(wait)
                if dest is not None:
                    dest.seek(0)
                    dest.truncate()
                continue
            if status == 429:
                raise RegistryError(f"rate limited by {self.ref.host} (HTTP 429): {err}. "
                                    "Try a mirror such as mirror.gcr.io/library/<image>.")
            raise err

    def manifest(self, reference: str) -> tuple[dict, str, bytes]:
        _, body = self.get(f"/v2/{self.ref.repository}/manifests/{reference}", accept=MANIFEST_ACCEPT)
        assert body is not None
        return json.loads(body), "sha256:" + hashlib.sha256(body).hexdigest(), body

    def blob_bytes(self, digest: str) -> bytes:
        _, body = self.get(f"/v2/{self.ref.repository}/blobs/{digest}")
        assert body is not None
        _verify(digest, hashlib.new(digest.split(":")[0], body).hexdigest())
        return body

    def blob_to_file(self, digest: str, path: Path, max_bytes: int | None = None) -> None:
        alg = digest.partition(":")[0]
        h = hashlib.new(alg)
        tmp = path.with_suffix(".part")
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(tmp, "w+b") as f:
                self.get(f"/v2/{self.ref.repository}/blobs/{digest}", dest=f, max_bytes=max_bytes)
                f.seek(0)
                while chunk := f.read(1 << 20):
                    h.update(chunk)
            _verify(digest, h.hexdigest())
            os.replace(tmp, path)
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink()


def _verify(digest: str, actual_hex: str) -> None:
    if digest.partition(":")[2].lower() != actual_hex.lower():
        raise RegistryError(f"digest mismatch for {digest}: got {actual_hex}")


# --------------------------------------------------------------------------- local layouts

class _TarStore:
    """Random access to the members of a `docker save` tarball."""

    def __init__(self, path: Path):
        self.tf = tarfile.open(path, "r:*")  # noqa: SIM115  closed in close()
        self.members = {norm_path(m.name): m for m in self.tf.getmembers() if m.isfile()}

    def has(self, name: str) -> bool:
        return norm_path(name) in self.members

    def open(self, name: str) -> BinaryIO:
        f = self.tf.extractfile(self.members[norm_path(name)])
        assert f is not None
        return f  # type: ignore[return-value]

    def read(self, name: str) -> bytes:
        with self.open(name) as f:
            return f.read()

    def close(self) -> None:
        self.tf.close()


class _DirStore:
    """Files of an OCI layout directory (never following symlinks out of it)."""

    def __init__(self, root: Path):
        self.root = root.resolve()

    def _p(self, name: str) -> Path:
        p = (self.root / norm_path(name)).resolve()
        if self.root != p and self.root not in p.parents:
            raise ValueError(f"path escapes layout dir: {name}")
        return p

    def has(self, name: str) -> bool:
        return self._p(name).is_file()

    def open(self, name: str) -> BinaryIO:
        return open(self._p(name), "rb")

    def read(self, name: str) -> bytes:
        return self._p(name).read_bytes()

    def close(self) -> None:
        pass


def _blob_name(digest: str) -> str:
    alg, _, hexd = digest.partition(":")
    return f"blobs/{alg}/{hexd}"


@dataclass
class _Image:
    config: dict
    layers: list[dict]            # descriptors {digest|name, mediaType, size}
    manifest_digest: str | None
    ref_name: str | None


def _resolve_layout(store: Any, platform: str, tag: str | None, warnings: list[str]) -> tuple[_Image, Callable[[dict], BinaryIO]]:
    """Find the image to scan inside a docker-save tar / OCI layout."""
    index = json.loads(store.read("index.json")) if store.has("index.json") else None

    def single_manifest_digest() -> str | None:
        if index and len(index.get("manifests", [])) == 1:
            return index["manifests"][0].get("digest")
        return None

    if store.has("manifest.json"):
        entries = json.loads(store.read("manifest.json"))
        entry = entries[0]
        if tag:
            entry = next((e for e in entries if tag in (e.get("RepoTags") or [])), entry)
        if len(entries) > 1:
            warnings.append(f"archive holds {len(entries)} images; scanning {(entry.get('RepoTags') or ['first'])[0]}")
        config = json.loads(store.read(entry["Config"]))
        layers = [{"name": n} for n in entry["Layers"]]
        tags = entry.get("RepoTags") or []
        return (_Image(config, layers, single_manifest_digest(), tags[0] if tags else None),
                lambda d: store.open(d["name"]))
    if index is None:
        raise ValueError("not an image archive: neither manifest.json nor index.json found")
    desc = {"digest": None, "mediaType": "application/vnd.oci.image.index.v1+json", "_inline": index}
    ref_name = None
    manifest: dict | None = None
    digest = None
    for _ in range(4):
        doc = desc.pop("_inline", None) or json.loads(store.read(_blob_name(desc["digest"])))
        if "manifests" in doc:
            ents = doc["manifests"]
            if tag:
                m = [e for e in ents if (e.get("annotations") or {}).get("org.opencontainers.image.ref.name") == tag]
                ents = m or ents
            pick = select_manifest(ents, platform)
            if pick is None:
                real = [e for e in ents if (e.get("platform") or {}).get("os") != "unknown"]
                if len(real) == 1 or (real and not any("platform" in e for e in real)):
                    pick = real[0]
                    if "platform" in pick:
                        warnings.append(f"platform {platform} not in layout; scanning {_describe_platforms([pick])}")
                else:
                    raise ValueError(f"no manifest for {platform} (have: {_describe_platforms(ents)})")
            ref_name = ref_name or (pick.get("annotations") or {}).get("org.opencontainers.image.ref.name")
            desc = pick
            digest = pick["digest"]
        else:
            manifest = doc
            break
    if manifest is None:
        raise ValueError("could not resolve an image manifest in the layout")
    config = json.loads(store.read(_blob_name(manifest["config"]["digest"])))
    return (_Image(config, manifest["layers"], digest, ref_name),
            lambda d: store.open(_blob_name(d["digest"])))


# --------------------------------------------------------------------------- collector

def _apply_layer(view: LayeredTarView, idx: int, src: Any, warnings: list[str]) -> None:
    try:
        view.add_layer(src)
    except UnsupportedLayer as e:
        warnings.append(f"layer {idx}: {e}; layer skipped (results may be incomplete)")
    except (tarfile.TarError, EOFError, OSError) as e:
        warnings.append(f"layer {idx}: unreadable ({e}); layer skipped")


def _config_meta(config: dict) -> dict[str, Any]:
    c = config.get("config") or config.get("container_config") or {}
    return {k: v for k, v in {
        "labels": c.get("Labels") or {},
        "created": config.get("created"),
        "user": c.get("User") or None,
        "exposed_ports": sorted((c.get("ExposedPorts") or {}).keys()),
        # Env values may hold secrets; keep only the variable names.
        "env_names": sorted(e.split("=", 1)[0] for e in (c.get("Env") or [])),
        "entrypoint": c.get("Entrypoint"), "cmd": c.get("Cmd"),
    }.items() if v not in (None, [], {})}


def _platform_of(config: dict) -> str | None:
    if not config.get("os") and not config.get("architecture"):
        return None
    s = f"{config.get('os', '?')}/{config.get('architecture', '?')}"
    return s + (f"/{config['variant']}" if config.get("variant") else "")


def inventory_from_archive(path: str | Path, platform: str = DEFAULT_PLATFORM, name: str | None = None,
                           asset_id: str | None = None, collector: str = "docker-image",
                           tag: str | None = None) -> Inventory:
    """Inventory of a `docker save` tarball or an OCI layout directory."""
    p = Path(path)
    store: Any = _DirStore(p) if p.is_dir() else _TarStore(p)
    warnings: list[str] = []
    try:
        img, opener = _resolve_layout(store, platform, tag, warnings)
        view = LayeredTarView()
        for i, d in enumerate(img.layers):
            with contextlib.closing(opener(d)) as f:
                _apply_layer(view, i, f, warnings)
    finally:
        store.close()
    config_sha = hashlib.sha256(json.dumps(img.config, sort_keys=True).encode()).hexdigest()
    ident = img.manifest_digest or f"sha256:{config_sha}"
    repo = (img.ref_name or p.stem).split(":")[0]
    asset = Asset(
        id=asset_id or f"image:{repo}@{ident}", type="container-image", name=name or img.ref_name or p.name,
        platform=_platform_of(img.config),
        meta={"ref": img.ref_name, "archive": str(p), "digest": img.manifest_digest,
              "layers": len(img.layers), **_config_meta(img.config)})
    comps = collect_from_view(view, asset, warnings)
    return Inventory(asset=asset, collector=collector, components=comps, warnings=warnings)


@register
class DockerImageCollector(Collector):
    name = "docker-image"
    description = "Container image: registry reference, docker-save tarball or OCI layout dir (no daemon)"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        if not target:
            raise ValueError("docker-image needs a target: image reference, tarball or OCI layout dir")
        platform = opts.get("platform") or DEFAULT_PLATFORM
        p = Path(target)
        if p.is_dir() or p.is_file():
            if p.is_dir() and not (p / "index.json").exists() and not (p / "manifest.json").exists():
                raise ValueError(f"{target} is a directory but not an OCI image layout; "
                                 "use the `rootfs` collector for a filesystem tree")
            return inventory_from_archive(p, platform, collector=self.name)
        return self._collect_registry(target, platform, opts)

    # ---- registry pull
    def _collect_registry(self, target: str, platform: str, opts: dict[str, Any]) -> Inventory:
        ref = parse_reference(target)
        own_client = opts.get("client") is None
        client = opts.get("client") or http_client(timeout=120.0)
        creds = None
        if opts.get("username"):
            creds = (opts["username"], opts.get("password") or os.environ.get("SECMONK_REGISTRY_PASSWORD", ""))
        else:
            creds = docker_config_auth(ref.host)
        reg = RegistryClient(ref, client, creds, sleep=opts.get("sleep", time.sleep))
        warnings: list[str] = []
        try:
            manifest, mdigest, _ = reg.manifest(ref.reference)
            if manifest.get("mediaType") in INDEX_TYPES or "manifests" in manifest:
                pick = select_manifest(manifest["manifests"], platform)
                if pick is None:
                    raise RegistryError(f"no manifest for {platform} in {ref} "
                                        f"(available: {_describe_platforms(manifest['manifests'])})")
                manifest, mdigest, _ = reg.manifest(pick["digest"])
            config = json.loads(reg.blob_bytes(manifest["config"]["digest"]))

            no_cache = bool(opts.get("no_cache"))
            cache = Path(opts.get("cache_dir") or CACHE_DIR) / "blobs"
            tmpdir = Path(tempfile.mkdtemp(prefix="secmonk-blobs-")) if no_cache else None
            view = LayeredTarView()
            max_bytes = int(opts.get("max_layer_bytes") or MAX_LAYER_BYTES)
            try:
                for i, layer in enumerate(manifest["layers"]):
                    mt = layer.get("mediaType", "")
                    if "foreign" in mt or "nondistributable" in mt:
                        warnings.append(f"layer {i}: foreign layer skipped")
                        continue
                    if layer.get("size", 0) > max_bytes:
                        warnings.append(f"layer {i}: {layer['size']} bytes exceeds limit; skipped")
                        continue
                    alg, _, hexd = layer["digest"].partition(":")
                    dest = (tmpdir or cache) / alg / hexd
                    if not dest.exists():
                        reg.blob_to_file(layer["digest"], dest, max_bytes)
                    _apply_layer(view, i, dest, warnings)
                    if tmpdir:
                        dest.unlink(missing_ok=True)
            finally:
                if tmpdir:
                    shutil.rmtree(tmpdir, ignore_errors=True)
        finally:
            if own_client:
                client.close()

        asset = Asset(
            id=f"image:{ref.canonical_repo}@{mdigest}", type="container-image", name=target,
            platform=_platform_of(config),
            meta={"ref": str(ref), "repository": ref.canonical_repo, "tag": ref.tag, "digest": mdigest,
                  "config_digest": manifest["config"]["digest"], "layers": len(manifest["layers"]),
                  **_config_meta(config)})
        comps = collect_from_view(view, asset, warnings)
        return Inventory(asset=asset, collector=self.name, components=comps, warnings=warnings)
