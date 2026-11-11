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
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urljoin, urlsplit

import httpx

from .. import paths
from ..models import Asset, Inventory
from ..sources.base import http_client
from .base import Collector, redact_command, redact_labels, register
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
MAX_MANIFEST_BYTES = 4 * 1024 * 1024     # manifest / index documents
MAX_CONFIG_BYTES = 32 * 1024 * 1024      # image config blob
MAX_ERROR_BYTES = 64 * 1024              # error / token response bodies
MAX_LINK_HOPS = 20

_DIGEST_RE = re.compile(r"^(?:sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


def valid_digest(digest: Any) -> str:
    """Return `digest` if it is a well-formed sha256/sha512 digest, else raise ValueError.

    Every digest that comes from a registry or an archive is checked with this before it is used
    in a URL or a file path (a hostile registry could otherwise answer `sha256:../../x`)."""
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ValueError(f"invalid digest {str(digest)[:80]!r}")
    return digest


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


# Strict image reference grammar (distribution/reference): [domain[:port]/]path[:tag][@digest]. Used for references
# that come from an untrusted source (a cluster's pod specs) and for `source=registry`.
_REF_DOMAIN = r"(?:(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])(?:\.(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]))*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?"
_REF_PATH = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_STRICT_REF = re.compile(rf"^(?:{_REF_DOMAIN}/)?{_REF_PATH}(?:/{_REF_PATH})*(?::[\w][\w.-]{{0,127}})?"
                         r"(?:@[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,})?$")


def valid_image_ref(ref: Any) -> bool:
    """True for a registry image reference only: never a path (`/x`, `./x`, `~x`), an option (`-x`), a list
    (`,`), whitespace or control characters; it must match the reference grammar and `parse_reference`."""
    if not isinstance(ref, str) or not ref or len(ref) > 512 or ref[0] in "/.~-":
        return False
    if any(c in ref for c in ", \t\r\n") or any(ord(c) < 32 or ord(c) == 127 for c in ref):
        return False
    if not _STRICT_REF.match(ref):
        return False
    try:
        parse_reference(ref)
    except ValueError:
        return False
    return True


def registry_is_private(ref: str) -> bool:
    """The reference's registry is localhost or a loopback / link-local / private IP literal (a pull would reach
    a service on the scanning machine or its network)."""
    import ipaddress

    try:
        host = parse_reference(ref).host
    except ValueError:
        return True
    h = host.rsplit(":", 1)[0] if not host.startswith("[") else host[1:host.find("]")]
    if h.lower() in ("localhost", "localhost.localdomain") or h.lower().endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved


def parse_reference(ref: str) -> ImageRef:
    """'alpine:3.20' -> docker.io/library/alpine:3.20; 'ghcr.io/o/i:t'; 'img@sha256:...'."""
    ref = ref.strip()
    if not ref:
        raise ValueError("empty image reference")
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not _DIGEST_RE.fullmatch(digest):
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
    if tag is not None and not _TAG_RE.fullmatch(tag):
        raise ValueError(f"invalid tag in image reference: {tag!r}")
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


def _is_local_host(host: str) -> bool:
    name = urlsplit(f"//{host}").hostname or ""
    return name in ("localhost", "127.0.0.1", "::1") or name.endswith(".localhost")


def _read_capped(r: httpx.Response, limit: int) -> bytes:
    """Read a response body but never more than `limit` bytes (error pages, tokens)."""
    out = bytearray()
    for chunk in r.iter_bytes(8192):
        out += chunk
        if len(out) >= limit:
            break
    return bytes(out[:limit])


class RegistryClient:
    """Minimal read-only Registry HTTP API v2 client with anonymous/basic token auth."""

    def __init__(self, ref: ImageRef, client: httpx.Client, credentials: tuple[str, str] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.ref, self.http, self.credentials, self.sleep = ref, client, credentials, sleep
        self._token: str | None = None
        self._basic: str | None = None
        host = ref.host
        self.base = f"{'http' if _is_local_host(host) else 'https'}://{host}"

    # ---- auth
    def _fetch_token(self, params: dict[str, str]) -> str:
        realm = params.get("realm")
        if not realm:
            raise RegistryError("registry sent a Bearer challenge without realm")
        ru = urlsplit(realm)
        if ru.scheme != "https" and not (ru.scheme == "http" and _is_local_host(ru.netloc)):
            # never send credentials (or accept tokens) over a plaintext channel
            raise RegistryError(f"refusing token realm {realm!r}: https is required")
        q = {k: v for k, v in params.items() if k in ("service", "scope")}
        q.setdefault("scope", f"repository:{self.ref.repository}:pull")
        auth = httpx.BasicAuth(*self.credentials) if self.credentials else None
        with self.http.stream("GET", realm, params=q, auth=auth, follow_redirects=False) as r:
            body = _read_capped(r, MAX_ERROR_BYTES if r.status_code != 200 else MAX_MANIFEST_BYTES)
            status = r.status_code
        if status != 200:
            raise RegistryError(f"token endpoint {realm} answered {status}: "
                                f"{body[:200].decode('utf-8', 'replace')}")
        d = json.loads(body)
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
        """GET with token auth, 429/5xx backoff and manual redirects.

        Authorization is only sent to the original (scheme, host:port); a redirect that downgrades
        https to http is refused. Bodies are read in streamed chunks and never exceed `max_bytes`
        (default 4 MB when returned in memory; unlimited only for an explicit `dest`).
        The body is returned, or streamed into `dest` (then None is returned)."""
        url = path_or_url if path_or_url.startswith("http") else self.base + path_or_url
        origin = urlsplit(url)[:2]
        if dest is None and max_bytes is None:
            max_bytes = MAX_MANIFEST_BYTES
        attempts = 0
        authed_retry = False
        while True:
            hops, cur = 0, url
            while True:
                headers = {"Accept": accept} if accept else {}
                same_origin = urlsplit(cur)[:2] == origin
                if self._token and same_origin:
                    headers["Authorization"] = f"Bearer {self._token}"
                elif self._basic and same_origin:
                    headers["Authorization"] = f"Basic {self._basic}"
                with self.http.stream("GET", cur, headers=headers, follow_redirects=False) as r:
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        hops += 1
                        if hops > 6:
                            raise RegistryError("too many redirects")
                        nxt = urljoin(cur, r.headers["location"])
                        if urlsplit(cur).scheme == "https" and urlsplit(nxt).scheme != "https":
                            raise RegistryError(f"refusing redirect from https to {urlsplit(nxt).scheme}: {nxt[:120]}")
                        cur = nxt
                        continue
                    if r.status_code == 200:
                        clen = r.headers.get("content-length")
                        if max_bytes and clen and clen.isdigit() and int(clen) > max_bytes:
                            raise RegistryError(f"response larger than limit ({max_bytes} bytes)")
                        n = 0
                        buf = bytearray()
                        for chunk in r.iter_bytes(1 << 20):
                            n += len(chunk)
                            if max_bytes and n > max_bytes:
                                raise RegistryError(f"response larger than limit ({max_bytes} bytes)")
                            if dest is None:
                                buf += chunk
                            else:
                                dest.write(chunk)
                        return r.headers, (bytes(buf) if dest is None else None)
                    body = _read_capped(r, MAX_ERROR_BYTES)
                    status, resp_headers = r.status_code, r.headers
                    err = self._error(r, body)
                break
            if status == 401 and not authed_retry and urlsplit(cur)[:2] == origin:
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
        if ":" in reference:
            valid_digest(reference)
        elif not _TAG_RE.fullmatch(reference):
            raise ValueError(f"invalid reference {reference!r}")
        _, body = self.get(f"/v2/{self.ref.repository}/manifests/{reference}", accept=MANIFEST_ACCEPT,
                           max_bytes=MAX_MANIFEST_BYTES)
        assert body is not None
        if ":" in reference:
            _verify(reference, hashlib.new(reference.split(":")[0], body).hexdigest())
        doc = json.loads(body)
        if not isinstance(doc, dict):
            raise RegistryError("manifest is not a JSON object")
        return doc, "sha256:" + hashlib.sha256(body).hexdigest(), body

    def blob_bytes(self, digest: str, max_bytes: int = MAX_CONFIG_BYTES) -> bytes:
        valid_digest(digest)
        _, body = self.get(f"/v2/{self.ref.repository}/blobs/{digest}", max_bytes=max_bytes)
        assert body is not None
        _verify(digest, hashlib.new(digest.split(":")[0], body).hexdigest())
        return body

    def blob_to_file(self, digest: str, path: Path, max_bytes: int | None = None) -> None:
        """Download a blob into `path` (atomically, digest-verified). `path` must be fresh or ours."""
        valid_digest(digest)
        alg = digest.partition(":")[0]
        h = hashlib.new(alg)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmpname = tempfile.mkstemp(dir=path.parent, prefix=".part-")
        tmp = Path(tmpname)
        try:
            with os.fdopen(fd, "w+b") as f:
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


def _file_digest_ok(path: Path, digest: str) -> bool:
    """True when `path` is a regular file (not a symlink) whose content hashes to `digest`."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return False
        h = hashlib.new(digest.partition(":")[0])
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
    except OSError:
        return False
    return h.hexdigest() == digest.partition(":")[2]


def _blob_cache_path(root: Path, digest: str) -> Path:
    """`<root>/<alg>/<hex>` for a validated digest, guaranteed to stay below `root`."""
    valid_digest(digest)
    alg, _, hexd = digest.partition(":")
    dest = root / alg / hexd
    base = root.resolve()
    if base not in dest.resolve().parents:
        raise ValueError(f"blob path escapes the cache: {digest}")
    return dest


# --------------------------------------------------------------------------- local layouts

class _TarStore:
    """Random access to the members of a `docker save` tarball.

    Symlinks and hardlinks are indexed too (legacy `docker save` dedups identical layers as
    `<id>/layer.tar -> ../<other>/layer.tar`) and are resolved inside the archive only.
    """

    def __init__(self, path: Path):
        self.tf = tarfile.open(path, "r:*")  # noqa: SIM115  closed in close()
        self.members: dict[str, tarfile.TarInfo] = {}
        self.links: dict[str, str] = {}
        for m in self.tf.getmembers():
            name = norm_path(m.name)
            if m.isfile():
                self.members[name] = m
            elif m.issym():
                self.links[name] = norm_path(posixpath.join(posixpath.dirname(name), m.linkname)
                                             if not m.linkname.startswith("/") else m.linkname)
            elif m.islnk():
                self.links[name] = norm_path(m.linkname)

    def _resolve(self, name: str) -> str | None:
        cur = norm_path(name)
        for _ in range(MAX_LINK_HOPS):
            if cur in self.members:
                return cur
            if cur not in self.links:
                return None
            cur = self.links[cur]
        return None

    def has(self, name: str) -> bool:
        return self._resolve(name) is not None

    def _member(self, name: str) -> tarfile.TarInfo:
        real = self._resolve(name)
        if real is None:
            raise KeyError(name)
        return self.members[real]

    def open(self, name: str) -> BinaryIO:
        f = self.tf.extractfile(self._member(name))
        assert f is not None
        return f  # type: ignore[return-value]

    def read(self, name: str, limit: int = MAX_MANIFEST_BYTES) -> bytes:
        m = self._member(name)
        if m.size > limit:
            raise ValueError(f"{name}: {m.size} bytes exceeds the {limit} byte limit")
        with self.open(name) as f:
            return f.read(limit + 1)

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

    def read(self, name: str, limit: int = MAX_MANIFEST_BYTES) -> bytes:
        p = self._p(name)
        if p.stat().st_size > limit:
            raise ValueError(f"{name}: {p.stat().st_size} bytes exceeds the {limit} byte limit")
        with open(p, "rb") as f:
            return f.read(limit + 1)

    def close(self) -> None:
        pass


def _blob_name(digest: str) -> str:
    alg, _, hexd = valid_digest(digest).partition(":")
    return f"blobs/{alg}/{hexd}"


@dataclass
class _Image:
    config: dict
    layers: list[dict]            # descriptors {digest|name, mediaType, size}
    manifest_digest: str | None
    ref_name: str | None          # a repository reference ('app:1.0', 'ghcr.io/o/i:t'); never a bare tag


def _tag_matches(wanted: str, candidate: str) -> bool:
    if wanted == candidate:
        return True
    try:
        return str(parse_reference(wanted)) == str(parse_reference(candidate))
    except ValueError:
        return False


def _usable_ref(name: str | None) -> str | None:
    """A RepoTag / ref-name annotation as a repository reference, or None for `<none>:<none>`
    and bare OCI tags like `latest` (those carry no repository)."""
    if not name or name.startswith("<none>") or not ("/" in name or ":" in name):
        return None
    try:
        parse_reference(name)
    except ValueError:
        return None
    return name


def _json_obj(raw: bytes, what: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError as e:
        raise ValueError(f"{what} is not valid JSON: {e}") from e


def _resolve_layout(store: Any, platform: str, tag: str | None, warnings: list[str]) -> tuple[_Image, Callable[[dict], BinaryIO]]:
    """Find the image to scan inside a docker-save tar / OCI layout."""
    index = _json_obj(store.read("index.json"), "index.json") if store.has("index.json") else None

    def single_manifest_digest() -> str | None:
        if index and len(index.get("manifests", [])) == 1:
            return valid_digest(index["manifests"][0].get("digest"))
        return None

    if store.has("manifest.json"):
        entries = _json_obj(store.read("manifest.json"), "manifest.json")
        entry = entries[0]
        if tag:
            found = next((e for e in entries if any(_tag_matches(tag, t) for t in (e.get("RepoTags") or []))), None)
            if found is None:
                warnings.append(f"tag {tag!r} not found in the archive; scanning the first image")
            else:
                entry = found
        if len(entries) > 1:
            warnings.append(f"archive holds {len(entries)} images; scanning {(entry.get('RepoTags') or ['first'])[0]}")
        config = _json_obj(store.read(entry["Config"], MAX_CONFIG_BYTES), "image config")
        layers = [{"name": n} for n in entry["Layers"]]
        tags = [t for t in (entry.get("RepoTags") or []) if _usable_ref(t)]
        want = next((t for t in tags if tag and _tag_matches(tag, t)), None)
        return (_Image(config, layers, single_manifest_digest(), want or (tags[0] if tags else None)),
                lambda d: store.open(d["name"]))
    if index is None:
        raise ValueError("not an image archive: neither manifest.json nor index.json found")
    desc: dict[str, Any] = {"digest": None, "mediaType": "application/vnd.oci.image.index.v1+json", "_inline": index}
    ref_name = None
    manifest: dict | None = None
    digest = None
    for _ in range(4):
        doc = desc.pop("_inline", None) or _json_obj(store.read(_blob_name(desc["digest"])), "manifest")
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
            digest = valid_digest(pick["digest"])
        else:
            manifest = doc
            break
    if manifest is None:
        raise ValueError("could not resolve an image manifest in the layout")
    config = _json_obj(store.read(_blob_name(manifest["config"]["digest"]), MAX_CONFIG_BYTES), "image config")
    layers = manifest["layers"]
    for d in layers:
        valid_digest(d.get("digest"))
    return (_Image(config, layers, digest, _usable_ref(ref_name)),
            lambda d: store.open(_blob_name(d["digest"])))


# --------------------------------------------------------------------------- collector

def _apply_layer(view: LayeredTarView, idx: int, src: Any, warnings: list[str]) -> str | None:
    """Apply one layer; returns a reason when the layer could not be (fully) applied."""
    try:
        view.add_layer(src)
    except UnsupportedLayer as e:
        reason = f"layer {idx}: {e}; layer skipped (results may be incomplete)"
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        reason = f"layer {idx}: unreadable ({e}); layer skipped"
    else:
        return None
    warnings.append(reason)
    return reason


def _config_meta(config: dict) -> dict[str, Any]:
    c = config.get("config") or config.get("container_config") or {}
    return {k: v for k, v in {
        "labels": redact_labels(c.get("Labels")),
        "created": config.get("created"),
        "user": c.get("User") or None,
        "exposed_ports": sorted((c.get("ExposedPorts") or {}).keys()),
        # Env values may hold secrets; keep only the variable names.
        "env_names": sorted(e.split("=", 1)[0] for e in (c.get("Env") or [])),
        # Cmd/Entrypoint are kept (they matter for exposure) with secret-looking arguments redacted.
        "entrypoint": redact_command(c.get("Entrypoint")), "cmd": redact_command(c.get("Cmd")),
    }.items() if v not in (None, [], {})}


def _platform_of(config: dict) -> str | None:
    if not config.get("os") and not config.get("architecture"):
        return None
    s = f"{config.get('os', '?')}/{config.get('architecture', '?')}"
    return s + (f"/{config['variant']}" if config.get("variant") else "")


def inventory_from_archive(path: str | Path, platform: str = DEFAULT_PLATFORM, name: str | None = None,
                           asset_id: str | None = None, collector: str = "docker-image",
                           tag: str | None = None) -> Inventory:
    """Inventory of a `docker save` tarball or an OCI layout directory.

    Asset id: `image:<registry>/<repo>@<digest>` (the same id a registry pull of that image gets),
    or `image:@<digest>` when the archive carries no repository reference. The archive's own file
    name is never part of the id (docker-engine exports use temp names).
    """
    p = Path(path)
    warnings: list[str] = []
    partial: list[str] = []
    try:
        store: Any = _DirStore(p) if p.is_dir() else _TarStore(p)
    except (tarfile.TarError, EOFError) as e:
        raise ValueError(f"{p} is not a readable image archive: {e}") from e
    try:
        img, opener = _resolve_layout(store, platform, tag, warnings)
        view = LayeredTarView()
        for i, d in enumerate(img.layers):
            with contextlib.closing(opener(d)) as f:
                reason = _apply_layer(view, i, f, warnings)
            if reason:
                partial.append(reason)
    except (KeyError, TypeError, IndexError, AttributeError, tarfile.TarError) as e:
        raise ValueError(f"malformed image archive ({type(e).__name__}: {e})") from e
    finally:
        store.close()
    config_sha = hashlib.sha256(json.dumps(img.config, sort_keys=True).encode()).hexdigest()
    ident = img.manifest_digest or f"sha256:{config_sha}"
    repo = parse_reference(img.ref_name).canonical_repo if img.ref_name else ""
    asset = Asset(
        id=asset_id or f"image:{repo}@{ident}", type="container-image",
        name=name or img.ref_name or p.name,
        platform=_platform_of(img.config),
        meta={"ref": img.ref_name, "archive": str(p), "digest": img.manifest_digest,
              "layers": len(img.layers), **_config_meta(img.config)})
    comps = collect_from_view(view, asset, warnings)
    if view.truncated:
        partial.append("file/count limits reached while reading layers")
    inv = Inventory(asset=asset, collector=collector, components=comps, warnings=warnings)
    if partial:
        inv.mark_partial("; ".join(partial))
    return inv


def _registry_only(opts: dict[str, Any]) -> bool:
    src = str(opts.get("source") or "auto").lower()
    if src not in ("auto", "registry"):
        raise ValueError(f"source must be auto or registry, got {src!r}")
    return src == "registry"


@register
class DockerImageCollector(Collector):
    name = "docker-image"
    description = "Container image: registry reference, docker-save tarball or OCI layout dir (no daemon)"

    def expand_targets(self, target: str | None, **opts: Any) -> list[str | None]:
        """A comma-separated list of references / paths -> one target each (stripped, empties and duplicates
        dropped, order kept; no patterns). Lets a list of images (e.g. a cluster's, pinned by digest) be one item.
        With `source=registry` every item must be a valid registry reference (ValueError naming the others)."""
        items: list[str | None] = []
        for t in (target or "").split(","):
            t = t.strip()
            if t and t not in items:
                items.append(t)
        if _registry_only(opts):
            bad = [str(t)[:80] for t in items if not valid_image_ref(t)]
            if bad:
                raise ValueError("source=registry: not image references: " + ", ".join(repr(b) for b in bad[:10]))
        return items or [target]

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        if not target:
            raise ValueError("docker-image needs a target: image reference, tarball or OCI layout dir")
        platform = opts.get("platform") or DEFAULT_PLATFORM
        if _registry_only(opts):         # never a local path, whatever exists on disk
            if not valid_image_ref(target):
                raise ValueError(f"source=registry: {target[:120]!r} is not an image reference")
            return self._collect_registry(target, platform, opts)
        p = Path(target)
        note: str | None = None
        if p.is_file():
            return inventory_from_archive(p, platform, collector=self.name, tag=opts.get("tag"))
        if p.is_dir():
            if (p / "index.json").exists() or (p / "manifest.json").exists():
                return inventory_from_archive(p, platform, collector=self.name, tag=opts.get("tag"))
            if os.sep in target or "/" in target:
                raise ValueError(f"{target} is a directory but not an OCI image layout; "
                                 "use the `rootfs` collector for a filesystem tree")
            # `nginx` while ./nginx happens to be a plain directory: the user means the registry
            # image (write ./nginx to force the local directory).
            note = (f"local directory {target!r} is not an OCI layout; treating {target!r} as a "
                    f"registry reference (use ./{target} for the directory)")
        inv = self._collect_registry(target, platform, opts)
        if note:
            inv.warnings.insert(0, note)
        return inv

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
        partial: list[str] = []
        try:
            manifest, mdigest, _ = reg.manifest(ref.reference)
            if manifest.get("mediaType") in INDEX_TYPES or "manifests" in manifest:
                pick = select_manifest(manifest["manifests"], platform)
                if pick is None:
                    raise RegistryError(f"no manifest for {platform} in {ref} "
                                        f"(available: {_describe_platforms(manifest['manifests'])})")
                manifest, mdigest, _ = reg.manifest(valid_digest(pick["digest"]))
            config_digest = valid_digest(manifest["config"]["digest"])
            layer_digests = [valid_digest(layer.get("digest")) for layer in manifest["layers"]]
            config = json.loads(reg.blob_bytes(config_digest))

            no_cache = bool(opts.get("no_cache"))
            tmpdir = Path(tempfile.mkdtemp(prefix="secmonk-blobs-")) if no_cache else None
            if no_cache:
                cache = tmpdir
            elif opts.get("cache_dir"):
                cache = paths.ensure_private_dir(Path(opts["cache_dir"]) / "blobs")
            else:
                cache = paths.cache_subdir("blobs")
            view = LayeredTarView()
            max_bytes = int(opts.get("max_layer_bytes") or MAX_LAYER_BYTES)
            try:
                for i, layer in enumerate(manifest["layers"]):
                    mt = layer.get("mediaType", "")
                    if "foreign" in mt or "nondistributable" in mt:
                        msg = f"layer {i}: foreign layer skipped"
                        warnings.append(msg)
                        partial.append(msg)
                        continue
                    if layer.get("size", 0) > max_bytes:
                        msg = f"layer {i}: {layer['size']} bytes exceeds limit; skipped"
                        warnings.append(msg)
                        partial.append(msg)
                        continue
                    digest = layer_digests[i]
                    dest = _blob_cache_path(cache, digest)
                    # A cached blob is trusted only after its digest is re-verified; a corrupt or
                    # planted file is replaced (the download goes to a fresh temp file first).
                    if not _file_digest_ok(dest, digest):
                        reg.blob_to_file(digest, dest, max_bytes)
                    reason = _apply_layer(view, i, dest, warnings)
                    if reason:
                        partial.append(reason)
                    if tmpdir:
                        dest.unlink(missing_ok=True)   # only ever our own fresh temp dir
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
                  "config_digest": config_digest, "layers": len(manifest["layers"]),
                  **_config_meta(config)})
        comps = collect_from_view(view, asset, warnings)
        if view.truncated:
            partial.append("file/count limits reached while reading layers")
        inv = Inventory(asset=asset, collector=self.name, components=comps, warnings=warnings)
        if partial:
            inv.mark_partial("; ".join(partial))
        return inv
