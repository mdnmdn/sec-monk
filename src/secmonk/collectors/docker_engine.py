"""Docker Engine (and Podman Docker-compatible API) collector, stdlib only.

The engine is reached over a local unix socket, tcp (optionally TLS), or `ssh://` (`docker system dial-stdio`),
chosen explicitly, through a Docker CLI context, or discovered (see `find_endpoint`). Read-only: only GET requests
are ever sent. See _docs/tech/collectors/docker-engine.md.
"""

from __future__ import annotations

import fnmatch
import http.client
import json
import os
import re
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..models import Asset, Inventory
from .base import Collector, redact_labels, register, strip_url_secrets
from .docker_image import inventory_from_archive
from .docker_transport import (
    REMOTE_DOCKER_PATHS,
    ContextInfo,
    Endpoint,
    SSHHTTPConnection,
    TLSConfig,
    UnixHTTPConnection,
    as_bool,
    config_dir,
    current_context,
    iter_contexts,
    load_context,
    parse_host,
    tls_files,
)
from .rootfs import LayeredTarView, collect_from_view
from .ssh import _as_list

TLS_OPTS = ("tls_ca", "tls_cert", "tls_key")


def candidate_sockets(opts: dict[str, Any] | None = None) -> list[str]:
    opts = opts or {}
    home = Path.home()
    out: list[str] = []
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    out += ["/var/run/docker.sock", str(home / ".docker/run/docker.sock"),
            str(home / ".colima/default/docker.sock"), str(home / ".rd/docker.sock"),
            str(home / ".orbstack/run/docker.sock")]
    if xdg:
        out.append(f"{xdg}/docker.sock")          # rootless Docker
        out.append(f"{xdg}/podman/podman.sock")
    out.append("/run/podman/podman.sock")
    return out


# --------------------------------------------------------------------------- endpoint resolution

def find_endpoint(opts: dict[str, Any] | None = None) -> Endpoint:
    """Which engine to talk to. First match wins:

    opts['socket'] > opts['host'] > opts['context'] > $DOCKER_HOST > $DOCKER_CONTEXT > `currentContext` of
    `$DOCKER_CONFIG/config.json` (unless "default") > well-known local sockets.

    Anything requested (an option, an env variable, the configured current context) that cannot be resolved is a
    RuntimeError: it is never silently replaced by another engine. The context name "default" means the local
    engine (well-known sockets)."""
    opts = opts or {}
    if opts.get("socket"):
        return _explicit(str(opts["socket"]), "--socket", opts)
    if opts.get("host"):
        return _explicit(str(opts["host"]), "--host", opts, env_tls=True)
    if opts.get("context"):
        return _from_context(str(opts["context"]), "--context", opts)
    if env := os.environ.get("DOCKER_HOST"):
        return _explicit(env, "DOCKER_HOST", opts, env_tls=True)
    if env := os.environ.get("DOCKER_CONTEXT"):
        return _from_context(env, "DOCKER_CONTEXT", opts)
    cur = current_context()
    if cur and cur != "default":
        return _from_context(cur, f"currentContext in {config_dir() / 'config.json'}", opts)
    return _discover(opts)


def _explicit(value: str, src: str, opts: dict[str, Any], *, env_tls: bool = False,
              ctx: ContextInfo | None = None) -> Endpoint:
    try:
        ep = parse_host(value)
    except ValueError as e:
        raise RuntimeError(f"{e} (from {src})") from e
    if ep is None:
        raise RuntimeError(f"Unsupported Docker host {strip_url_secrets(value)!r} (from {src}; use unix:///path, "
                           "tcp://host:port or ssh://[user@]host[:port])")
    ep.source = src
    if ep.scheme == "unix":
        # An explicitly requested endpoint is never silently replaced by another one.
        if not os.path.exists(ep.unix or ""):
            raise RuntimeError(f"Docker socket {ep.unix} (from {src}) does not exist")
    elif ep.scheme == "tcp":
        ep.tls = _tls_config(opts, env_tls=env_tls, ctx=ctx)
        if ep.port is None:
            ep.port = 2376 if ep.tls else 2375
    else:
        _ssh_options(ep, opts)
    return ep


# ssh collector options that only its paramiko transport understands: refused rather than silently ignored
_PARAMIKO_ONLY = ("allow_agent", "look_for_keys", "ssh_config")


def _ssh_options(ep: Endpoint, opts: dict[str, Any]) -> None:
    """Options of the SSH collector that apply to `ssh://` engines (the system ssh only): identity, ssh_bin,
    connect_timeout, ssh_option (repeatable `-o`), insecure_host_key, known_hosts (-> UserKnownHostsFile)."""
    transport = str(opts.get("transport") or "auto").lower()
    if transport not in ("auto", "openssh"):
        raise ValueError(f"transport={transport} is not supported for ssh:// Docker engines (system ssh only)")
    bad = [k for k in _PARAMIKO_ONLY if opts.get(k) not in (None, "")]
    if bad:
        raise ValueError(f"option(s) {', '.join(bad)} apply to the paramiko ssh transport only; ssh:// Docker "
                         "engines use the system ssh (configure it in ~/.ssh/config or with ssh_option)")
    ep.ssh_bin = opts.get("ssh_bin") or None
    ep.identity = opts.get("identity") or None
    ep.connect_timeout = int(_seconds(opts, "connect_timeout", 15))
    ep.insecure_host_key = bool(as_bool(opts.get("insecure_host_key"), False))
    options = _as_list(opts.get("ssh_option"))
    if kh := opts.get("known_hosts"):
        if any(c in str(kh) for c in '"\r\n'):
            raise ValueError("known_hosts path must not contain quotes or newlines")
        options.append(f'UserKnownHostsFile="{kh}"')
    if any("\n" in o or "\r" in o for o in options):
        raise ValueError("ssh_option values must not contain newlines")
    ep.ssh_options = options
    if rd := opts.get("remote_docker"):
        if rd not in REMOTE_DOCKER_PATHS:
            raise ValueError(f"remote_docker must be one of {', '.join(REMOTE_DOCKER_PATHS)}")
        ep.remote_docker = rd


def _seconds(opts: dict[str, Any], key: str, default: float) -> float:
    """A positive number of seconds from an option (CLI values arrive as strings)."""
    v = opts.get(key)
    if v is None or v == "":
        return default
    try:
        f = float(v)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{key} must be a number of seconds, got {v!r}") from e
    if not f > 0 or f == float("inf"):
        raise ValueError(f"{key} must be a positive number of seconds, got {v!r}")
    return f


def _tls_config(opts: dict[str, Any], *, env_tls: bool, ctx: ContextInfo | None) -> TLSConfig | None:
    """TLS for a tcp endpoint, or None for plain http. Material comes from the context's TLS directory, or (for
    --host / DOCKER_HOST) from $DOCKER_CERT_PATH when $DOCKER_TLS_VERIFY is set (any non-empty value, as the Docker
    CLI does); tls_ca / tls_cert / tls_key / tls_verify options override both."""
    files: dict[str, str] = {}
    verify: bool | None = None
    use = False
    if ctx is not None:
        files = dict(ctx.tls)
        use = bool(files) or ctx.skip_tls_verify
        verify = not ctx.skip_tls_verify
    elif env_tls and os.environ.get("DOCKER_TLS_VERIFY"):
        use, verify = True, True
        files = tls_files(os.environ.get("DOCKER_CERT_PATH") or config_dir())
    for k in TLS_OPTS:
        if opts.get(k):
            files[k.removeprefix("tls_")] = str(opts[k])
            use = True
    try:
        v = as_bool(opts.get("tls_verify"))
    except ValueError as e:
        raise ValueError(f"tls_verify: {e}") from e
    if v is not None:
        use, verify = True, v
    if not use:
        return None
    return TLSConfig(ca=files.get("ca"), cert=files.get("cert"), key=files.get("key"),
                     verify=True if verify is None else verify)


def _from_context(name: str, src: str, opts: dict[str, Any]) -> Endpoint:
    if name == "default":
        return _discover(opts)
    try:
        ctx = load_context(name)
    except RuntimeError as e:
        raise RuntimeError(f"{e} (from {src})") from e
    if not ctx.host:
        raise RuntimeError(f"Docker context {name!r} (from {src}) has no docker endpoint host")
    ep = _explicit(ctx.host, f"context {name!r}", opts, ctx=ctx)
    ep.context = name
    return ep


def _discover(opts: dict[str, Any]) -> Endpoint:
    """First well-known socket that exists and does not refuse connections."""
    tried: list[str] = []
    stale: list[str] = []
    for path in candidate_sockets(opts):
        if path in tried:
            continue
        tried.append(path)
        if os.path.exists(path):
            if _refuses(path):
                stale.append(path)
                continue
            return Endpoint(unix=path, source="auto")
    msg = "Docker engine socket not found: tried " + ", ".join(tried)
    if stale:
        msg += "; refusing connections (engine not running, stale socket file): " + ", ".join(stale)
    raise RuntimeError(msg)


def list_contexts(**opts: Any) -> list[dict]:
    """Docker CLI contexts as {name, host, description, current}, starting with the implicit "default" (the local
    engine: the first well-known socket that exists). `current` marks the context `find_endpoint` would use
    (opts['context'] > $DOCKER_CONTEXT > currentContext > default); with --host / $DOCKER_HOST set none is
    current. Hosts never carry credentials (userinfo dropped); unreadable entries are listed with host None and
    the error as description."""
    cur = opts.get("context") or os.environ.get("DOCKER_CONTEXT") or current_context() or "default"
    if opts.get("socket") or opts.get("host") or (not opts.get("context") and os.environ.get("DOCKER_HOST")):
        cur = None
    local = next((p for p in candidate_sockets(opts) if os.path.exists(p)), "/var/run/docker.sock")
    out = [{"name": "default", "host": f"unix://{local}", "description": "Local engine (well-known socket)",
            "current": cur == "default"}]
    for cid, info, err in iter_contexts():
        if info is None:
            out.append({"name": cid, "host": None, "description": err, "current": False})
        elif info.name != "default":
            out.append({"name": info.name, "host": strip_url_secrets(info.host), "description": info.description,
                        "current": info.name == cur})
    return out


def _refuses(path: str) -> bool:
    """True only when nothing listens on the socket file (ECONNREFUSED): Docker Desktop leaves
    ~/.docker/run/docker.sock behind when it quits, while another runtime may be the one running.
    Any other outcome (accepted, permission denied, path too long) leaves the decision to the real request."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(path)
    except ConnectionRefusedError:
        return True
    except OSError:
        return False
    finally:
        s.close()
    return False


class EngineClient:
    def __init__(self, endpoint: Endpoint, timeout: float | None = 30):
        self.endpoint, self.timeout = endpoint, timeout
        self._ssl: Any = None

    def _conn(self) -> http.client.HTTPConnection:
        ep = self.endpoint
        if ep.scheme == "unix":
            return UnixHTTPConnection(ep.unix or "", self.timeout)
        if ep.scheme == "ssh":
            return SSHHTTPConnection(ep, self.timeout)
        if ep.tls is not None:
            if self._ssl is None:
                self._ssl = ep.tls.ssl_context()
            return http.client.HTTPSConnection(ep.host or "", ep.port, timeout=self.timeout, context=self._ssl)
        return http.client.HTTPConnection(ep.host or "", ep.port, timeout=self.timeout)

    def open(self, path: str) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
        """GET `path`; caller reads the response and closes the connection. Raises on HTTP errors."""
        conn = self._conn()
        try:
            conn.request("GET", path, headers={"Host": "docker", "User-Agent": "secmonk"})
            resp = conn.getresponse()
        except PermissionError as e:
            conn.close()
            raise RuntimeError(f"permission denied on Docker socket {self.endpoint} "
                               "(is your user in the `docker` group?)") from e
        except (OSError, http.client.HTTPException) as e:
            conn.close()                       # first: ends ssh, so its stderr is complete and nothing waits
            detail = conn.diagnostics() if isinstance(conn, SSHHTTPConnection) else ""
            msg = f"cannot talk to Docker engine at {self.endpoint}: {e or type(e).__name__}"
            raise RuntimeError(msg + (f" (ssh: {detail})" if detail else "")) from e
        if resp.status != 200:
            body = resp.read()[:400].decode("utf-8", "replace")
            conn.close()
            try:
                body = json.loads(body).get("message", body)
            except (ValueError, AttributeError):
                pass
            raise RuntimeError(f"Docker API GET {path} -> HTTP {resp.status}: {body}")
        return conn, resp

    def get_json(self, path: str) -> Any:
        conn, resp = self.open(path)
        try:
            data = resp.read()
        except (OSError, http.client.HTTPException) as e:
            raise RuntimeError(f"Docker API GET {path} at {self.endpoint}: reading the response failed: "
                               f"{e or type(e).__name__}") from e
        finally:
            conn.close()
        try:
            return json.loads(data)
        except ValueError as e:
            raise RuntimeError(f"Docker API GET {path}: invalid JSON ({e})") from e

    def ping(self) -> bool:
        conn, resp = self.open("/_ping")
        try:
            return resp.read().strip() == b"OK"
        finally:
            conn.close()

    def version(self) -> dict:
        return self.get_json("/version")


def _client(opts: dict[str, Any]) -> EngineClient:
    """`timeout`: seconds any single wait for engine data may take (socket, TLS and ssh alike; default 30)."""
    return opts.get("client") or EngineClient(find_endpoint(opts), _seconds(opts, "timeout", 30))


def list_containers(all: bool = False, **opts: Any) -> list[dict]:
    """Containers as returned by GET /containers/json (running only unless all=True). `opts` select the engine
    (socket, host, context, tls_*, identity, ssh_bin: see `find_endpoint`)."""
    rows = _client(opts).get_json(f"/containers/json?all={1 if all else 0}")
    if isinstance(rows, list):
        return [r for r in rows if isinstance(r, dict)]
    raise RuntimeError("Docker API GET /containers/json did not return a list")


# --------------------------------------------------------------------------- container selectors

MAX_PATTERN = 256
MAX_NAME = 128          # names / ids longer than this (hostile engine) are never tested against a pattern
MAX_REGEX_REPEATS = 3   # quantifiers that can repeat more than once, per regex (bounds polynomial backtracking)
_GLOB_CHARS = "*?["


def split_selector(selector: str | None) -> list[str]:
    """Comma-separated items, stripped, empties dropped, duplicates removed (first occurrence kept)."""
    out: list[str] = []
    for item in (selector or "").split(","):
        item = item.strip()
        if item and item not in out:
            out.append(item)
    return out


def is_pattern(item: str) -> bool:
    """`re:<regex>` or a glob (`*`, `?`, `[`); `image:` items are never patterns."""
    return not item.startswith("image:") and (item.startswith("re:") or any(c in item for c in _GLOB_CHARS))


def _check_regex(pat: str) -> None:
    """Refuse regexes that can backtrack catastrophically on a hostile container name: a quantified group that
    contains another quantifier or an alternation (`(a+)+`, `(a|aa)*`), or more than MAX_REGEX_REPEATS repeating
    quantifiers. Names come from the engine, which may be remote and untrusted."""
    from re import _constants as c
    from re import _parser

    repeats = (c.MAX_REPEAT, c.MIN_REPEAT, getattr(c, "POSSESSIVE_REPEAT", c.MAX_REPEAT))
    count = 0

    def walk(sub: Any, inside: bool) -> None:
        nonlocal count
        for op, av in sub:
            if op in repeats:
                _lo, hi, item = av
                if inside:
                    raise ValueError(f"regular expression {pat!r} nests a quantifier inside a repeated group "
                                     "(catastrophic backtracking); simplify it")
                if hi > 1:
                    count += 1
                walk(item, hi > 1)
            elif op is c.BRANCH:
                if inside:
                    raise ValueError(f"regular expression {pat!r} repeats an alternation (catastrophic "
                                     "backtracking); use a character class or separate selector items")
                for b in av[1]:
                    walk(b, inside)
            elif op is c.SUBPATTERN:
                walk(av[3], inside)
            elif op is getattr(c, "ATOMIC_GROUP", None):
                walk(av, inside)
            elif op in (c.ASSERT, c.ASSERT_NOT):
                walk(av[1], inside)
            elif op is c.GROUPREF_EXISTS:
                walk(av[1], inside)
                if av[2] is not None:
                    walk(av[2], inside)

    walk(_parser.parse(pat), False)
    if count > MAX_REGEX_REPEATS:
        raise ValueError(f"regular expression {pat!r} has {count} repeating quantifiers (at most "
                         f"{MAX_REGEX_REPEATS}); use several selector items instead")


def _row_keys(row: dict) -> tuple[str, list[str]]:
    """(display name, keys a pattern is tested on: every name without the leading / and the 12-char id)."""
    cid = str(row.get("Id") or "")[:12]
    names = [str(n).lstrip("/") for n in row.get("Names") or [] if isinstance(n, str) and n.strip("/")]
    keys = [k for k in (*names, *([cid] if cid else [])) if len(k) <= MAX_NAME]
    return (names[0] if names else cid), keys


def _matcher(item: str) -> Any:
    if item.startswith("re:"):
        pat = item[3:]
        if not pat:
            raise ValueError("empty regular expression in selector 're:'")
        if len(pat) > MAX_PATTERN:
            raise ValueError(f"regular expression longer than {MAX_PATTERN} characters: {pat[:40]!r}...")
        try:
            rx = re.compile(pat)
        except re.error as e:
            raise ValueError(f"invalid regular expression {pat!r}: {e}") from e
        _check_regex(pat)
        return rx.search
    if len(item) > MAX_PATTERN:
        raise ValueError(f"pattern longer than {MAX_PATTERN} characters: {item[:40]!r}...")
    return lambda key: fnmatch.fnmatchcase(key, item)


def select_containers(selector: str, containers: list[dict]) -> list[str]:
    """Expand a selector against /containers/json rows into target names, in order, without duplicates.

    Items are comma-separated: `image:<ref>` and exact names/ids pass through unchanged (not checked against
    `containers`); `re:<regex>` (re.search) and globs (`*?[`, fnmatch, case-sensitive) are tested on each
    container's names (no leading /) and 12-char id and yield the container's first name. A pattern matching
    nothing, a bad or over-long regex raise ValueError (the message lists the available containers)."""
    rows = [_row_keys(c) for c in containers if isinstance(c, dict)]
    out: list[str] = []
    for item in split_selector(selector):
        if not is_pattern(item):
            found = [item]
        else:
            match = _matcher(item)
            found = [name for name, keys in rows if any(match(k) for k in keys)]
            if not found:
                avail = ", ".join(name[:64] for name, _ in rows[:50]) or "none"
                more = f" (+{len(rows) - 50} more)" if len(rows) > 50 else ""
                raise ValueError(f"no container matches {item!r}; available: {avail}{more}")
        out += [n for n in found if n not in out]
    return out


# --------------------------------------------------------------------------- local images (identified by Id)

# Version of what an engine image inventory contains. Bump it whenever a change to the collector, the image/rootfs
# parsers or the asset meta makes an earlier inventory of the same image Id incomplete or different: callers reuse a
# stored `image:@<Id>` inventory only when its meta "inventory_version" equals this.
IMAGE_INVENTORY_VERSION = 1
MAX_TAG = 255           # RepoTags longer than this are never tested against a pattern
MAX_FOLDED = 1000       # remembered alias groups (see _FOLDED)
# (engine, image Id) -> the refs that expand_targets folded into one `image:<Id>` target; read by collect() to record
# them on the asset (expansion and collection run in one process, on different collector instances). Cleared by
# every expand_targets, popped by every collect / image_meta of that Id, whatever the outcome.
_FOLDED: dict[tuple[str, str], list[str]] = {}


def _norm_id(v: Any) -> str | None:
    """`sha256:<hex>` (Podman may omit the algorithm); None when not an image id."""
    if not isinstance(v, str):
        return None
    v = v if ":" in v else f"sha256:{v}"
    return v if re.fullmatch(r"sha256:[0-9a-f]{64}", v) else None


def image_tags(row: dict) -> list[str]:
    """Real RepoTags of an /images/json or /images/{ref}/json row (`<none>:<none>` dropped)."""
    return [t for t in row.get("RepoTags") or [] if isinstance(t, str) and t and t != "<none>:<none>"]


def list_images(**opts: Any) -> list[dict]:
    """Local images as returned by GET /images/json (engine options as for list_containers)."""
    rows = _client(opts).get_json("/images/json")
    if isinstance(rows, list):
        return [r for r in rows if isinstance(r, dict)]
    raise RuntimeError("Docker API GET /images/json did not return a list")


def is_image_pattern(ref: str) -> bool:
    """The part after `image:` is a pattern: `re:<regex>` or a glob."""
    return ref.startswith("re:") or any(c in ref for c in _GLOB_CHARS)


def select_images(pattern: str, images: list[dict]) -> list[tuple[str, str]]:
    """(image Id, matching tag) for every tagged image with a RepoTag matched by `pattern` (glob, or `re:<regex>`
    with the container selector's guards); untagged / dangling images never match. One pair per Id (its first
    matching tag), in listing order. ValueError when nothing matches."""
    match = _matcher(pattern)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in images:
        iid = _norm_id(row.get("Id"))
        if not iid or iid in seen:
            continue
        hit = next((t for t in image_tags(row) if len(t) <= MAX_TAG and match(t)), None)
        if hit:
            seen.add(iid)
            out.append((iid, hit))
    if not out:
        tags = [t[:64] for r in images for t in image_tags(r)]
        more = f" (+{len(tags) - 50} more)" if len(tags) > 50 else ""
        raise ValueError(f"no image matches 'image:{pattern}'; tagged images: {', '.join(tags[:50]) or 'none'}{more}")
    return out


def inspect_image(client: EngineClient, ref: str) -> dict:
    """GET /images/{ref}/json (`ref`: name[:tag], name@digest, Id or Id prefix, resolved by the engine)."""
    info = client.get_json(f"/images/{quote(ref, safe=':/@')}/json")
    if isinstance(info, dict) and _norm_id(info.get("Id")):
        return info
    raise RuntimeError(f"Docker API GET /images/{ref}/json: no image Id in the answer")


def image_identity(target: str | None) -> str | None:
    """Asset id of an expanded image target, without I/O: `image:<full sha256 Id>` (as emitted by expand_targets)
    -> `image:@<Id>`; anything else (a tag, an Id prefix, a container) -> None."""
    if not target or not target.startswith("image:"):
        return None
    ref = target[len("image:"):]
    return f"image:@{ref}" if re.fullmatch(r"sha256:[0-9a-f]{64}", ref) else None


def _engine_key(client: Any) -> str:
    return strip_url_secrets(str(getattr(client, "endpoint", ""))) or ""


def _pop_folded(client: Any, *refs: str | None) -> list[str] | None:
    """Remove (and return the first of) the alias groups recorded for these refs' Ids on this engine."""
    found = None
    for r in refs:
        iid = _norm_id(r) if r else None
        if iid:
            got = _FOLDED.pop((_engine_key(client), iid), None)
            found = found or got
    return found


def _image_meta(info: dict, ref: str, client: Any) -> dict:
    iid = _norm_id(info.get("Id")) or ""
    meta: dict[str, Any] = {
        "source": "docker-engine", "image_id": iid, "tags": image_tags(info),
        "repo_digests": [d for d in info.get("RepoDigests") or [] if isinstance(d, str)],
        "requested_ref": ref, "inventory_version": IMAGE_INVENTORY_VERSION, "engine": _engine_key(client)}
    folded = _FOLDED.get((_engine_key(client), iid))
    if folded:
        meta["requested_refs"] = list(folded)
    return meta


def image_meta(ref_or_id: str, **opts: Any) -> dict:
    """The engine-side meta of a local image (one GET /images/{ref}/json, no layer export): `source`, `image_id`,
    `tags`, `repo_digests`, `requested_ref`, `inventory_version` and, when expand_targets folded aliases into this
    Id, `requested_refs`. Lets a caller refresh a reused `image:@<Id>` asset. `ref_or_id` may carry `image:`."""
    ref = ref_or_id.removeprefix("image:")
    client = _client(opts)
    iid = None
    try:
        info = inspect_image(client, ref)
        iid = info.get("Id")
        return _image_meta(info, ref, client)
    finally:
        _pop_folded(client, ref, iid)


def _remember_folded(client: Any, groups: dict[str, list[str]]) -> None:
    for iid, refs in groups.items():
        if len(refs) > 1 or refs[0] != iid:
            if len(_FOLDED) >= MAX_FOLDED:
                _FOLDED.pop(next(iter(_FOLDED)))
            _FOLDED[(_engine_key(client), iid)] = refs


def verify_image_archive(path: str | Path, iid: str) -> tuple[bool, str]:
    """Does the `docker save` archive at `path` really hold image `iid`? (an engine, possibly remote and
    untrusted, could answer with another image). True when the config blob that manifest.json names hashes to the
    Id (classic image store), or when the Id is the digest of a manifest / index blob in the archive (containerd
    image store) whose hash matches and which leads to that config blob. Layers are not re-hashed."""
    import hashlib
    import tarfile

    from .docker_image import MAX_CONFIG_BYTES

    def norm(n: str) -> str:
        return n[2:] if n.startswith("./") else n.lstrip("/")

    def sha(b: bytes) -> str:
        return "sha256:" + hashlib.sha256(b).hexdigest()

    try:
        with tarfile.open(path, "r:") as tf:
            members = {norm(m.name): m for m in tf.getmembers() if m.isfile()}

            def read(name: str) -> bytes | None:
                m = members.get(norm(name))
                if m is None or m.size > MAX_CONFIG_BYTES:
                    return None
                f = tf.extractfile(m)
                return f.read() if f else None

            raw = read("manifest.json")
            entries = json.loads(raw) if raw else None
            if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
                return False, "no manifest.json in the export"
            cfg = read(str(entries[0].get("Config") or ""))
            if cfg is None:
                return False, "config blob missing from the export"
            cfg_digest = sha(cfg)
            if cfg_digest == iid:
                return True, "config digest"
            # containerd store: Id = manifest or index digest
            configs: set[str] = set()
            todo, seen = [iid], set()
            while todo and len(seen) < 64:
                d = todo.pop()
                if d in seen:
                    continue
                seen.add(d)
                blob = read(f"blobs/{d.replace(':', '/', 1)}")
                if blob is None or sha(blob) != d:
                    continue
                doc = json.loads(blob)
                if not isinstance(doc, dict):
                    continue
                for e in doc.get("manifests") or []:
                    if isinstance(e, dict) and isinstance(e.get("digest"), str):
                        todo.append(e["digest"])
                c = (doc.get("config") or {}).get("digest") if isinstance(doc.get("config"), dict) else None
                if isinstance(c, str):
                    configs.add(c)
            if cfg_digest in configs:
                return True, "manifest digest"
            return False, f"the exported config ({cfg_digest[:19]}) does not belong to {iid[:19]}"
    except (OSError, tarfile.TarError, ValueError, KeyError) as e:
        return False, f"cannot read the export: {e}"


def export_image(ref: str, dest: str | Path | None = None, **opts: Any) -> Path:
    """Stream `docker save` of an image (GET /images/{name}/get) into a tar file and return its path."""
    client = _client(opts)
    if dest is None:
        fd, name = tempfile.mkstemp(prefix="secmonk-image-", suffix=".tar")
        os.close(fd)
        dest = name
    conn, resp = client.open(f"/images/{quote(ref, safe=':/@')}/get")
    try:
        with open(dest, "wb") as f:
            shutil.copyfileobj(resp, f, 1 << 20)
    finally:
        conn.close()
    return Path(dest)


@register
class DockerEngineCollector(Collector):
    name = "docker-engine"
    description = "Live container (or local image) via a local or remote Docker/Podman engine"

    def expand_targets(self, target: str | None, **opts: Any) -> list[str]:
        """`web,db`, `shop-*`, `re:^api-[0-9]+$`, `image:nginx:1.25`, `image:*`, `image:re:^myreg/` (comma-separated,
        mixed) -> targets. Containers: patterns see running containers only (all with opts['all']); exact names
        pass through without listing. Images: every `image:` item is resolved to its engine Id and emitted once as
        `image:<Id>`, so aliases (one Id, several tags) are scanned once; a pattern matches RepoTags of tagged
        images. An exact image the engine cannot resolve (or an unreachable engine) passes through unchanged, so
        `collect` reports the error. A falsy target comes back as `[target]`."""
        items = split_selector(target)
        if not items:
            return [target]  # type: ignore[list-item]
        if not any(is_pattern(i) or i.startswith("image:") for i in items):
            return items
        try:
            all_ = bool(as_bool(opts.get("all"), False))
        except ValueError as e:
            raise ValueError(f"all: {e}") from e
        engine_opts = {k: v for k, v in opts.items() if k != "all"}
        _FOLDED.clear()                         # alias groups of an earlier expansion are never reused
        client: EngineClient | None = None
        rows: list[dict] | None = None
        images: list[dict] | None = None
        groups: dict[str, list[str]] = {}
        out: list[str] = []

        def add(item: str) -> None:
            if item not in out:
                out.append(item)

        for item in items:
            if item.startswith("image:"):
                ref = item[len("image:"):]
                if is_image_pattern(ref):
                    client = client or _client(engine_opts)
                    if images is None:
                        try:
                            images = list_images(client=client)
                        except RuntimeError as e:
                            raise RuntimeError(f"cannot list images for selector {item!r}: {e}") from e
                    pairs = select_images(ref, images)
                else:
                    try:
                        client = client or _client(engine_opts)
                        iid = _norm_id(inspect_image(client, ref)["Id"])
                    except (RuntimeError, OSError):
                        add(item)                      # collect() reports it
                        continue
                    pairs = [(iid or ref, ref)]
                for iid, ref_ in pairs:
                    groups.setdefault(iid, [])
                    if ref_ not in groups[iid]:
                        groups[iid].append(ref_)
                    add(f"image:{iid}")
            elif is_pattern(item):
                if rows is None:
                    try:
                        rows = list_containers(all=all_, **engine_opts)
                    except RuntimeError as e:
                        raise RuntimeError(f"cannot list containers for selector {item!r}: {e}") from e
                for name in select_containers(item, rows):
                    add(name)
            else:
                add(item)
        if client is not None:
            _remember_folded(client, groups)
        return out

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        client = _client(opts)
        if not target:
            names = []
            for c in client.get_json("/containers/json?all=0"):
                names.append(f"{(c.get('Names') or [c['Id'][:12]])[0].lstrip('/')} ({c.get('Image')})")
            raise ValueError("docker-engine needs a container id/name (or image:<ref>). Running containers: "
                             + (", ".join(names) or "none"))
        if target.startswith("image:"):
            return self._collect_image(client, target[len("image:"):])
        if "," in target or is_pattern(target):
            raise ValueError(f"{target!r} is a selector: expand it with expand_targets() and collect each name")
        return self._collect_container(client, target)

    def _collect_image(self, client: EngineClient, ref: str) -> Inventory:
        """One local image, identified by its engine Id: asset `image:@<Id>` (aliases share it; a tag moved to a
        new build is a new asset). Name: the requested tag, else the first RepoTag."""
        iid: str | None = None
        try:
            info = inspect_image(client, ref)
            extra = _image_meta(info, ref, client)
            iid, tags = extra["image_id"], extra["tags"]
            by_id = ref == iid or (re.fullmatch(r"(sha256:)?[0-9a-f]{4,64}", ref) is not None
                                   and iid.removeprefix("sha256:").startswith(ref.removeprefix("sha256:"))
                                   and ref not in tags and f"{ref}:latest" not in tags)
            name = (min(tags) if tags else iid[:19]) if by_id else ref
            fd, tmp = tempfile.mkstemp(prefix="secmonk-image-", suffix=".tar")
            os.close(fd)
            try:
                export_image(iid, tmp, client=client)
                verified, how = verify_image_archive(tmp, iid)
                inv = inventory_from_archive(tmp, name=name, collector=self.name, asset_id=f"image:@{iid}",
                                             platform=f"linux/{_arch(client)}")
            finally:
                os.unlink(tmp)
        finally:
            _pop_folded(client, ref, iid)
        inv.asset.meta.update({**extra, "platform": inv.asset.platform, "id_verified": verified})
        if not verified:
            msg = f"image Id {iid[:19]} not verified against the export: {how}"
            inv.warnings.append(msg)
            if "does not belong" in how:
                inv.mark_partial(msg)
        folded = extra.get("requested_refs")
        if folded and len(folded) > 1:
            inv.warnings.append(f"aliases of one image (Id {iid[7:19]}) scanned once: {', '.join(folded)}")
        return inv

    def _collect_container(self, client: EngineClient, target: str) -> Inventory:
        """The live filesystem of one container (`/export`). When the engine refuses the export (authorization
        plugin, 403/500, Podman limits) its image is scanned by Id instead: a warning, and the inventory is partial
        (the writable layer is missing). `/containers/{id}/json` refused is an error for this target."""
        info = client.get_json(f"/containers/{quote(target, safe='')}/json")
        cid = info.get("Id") if isinstance(info, dict) else None
        if not cid or not isinstance(cid, str):
            raise RuntimeError(f"Docker API GET /containers/{target}/json: no container Id in the answer")
        name = str(info.get("Name") or cid[:12]).lstrip("/")
        cfg, st, host = (info.get(k) if isinstance(info.get(k), dict) else {} for k in ("Config", "State",
                                                                                         "HostConfig"))
        net = info.get("NetworkSettings")
        ports = net.get("Ports") if isinstance(net, dict) else None
        published = any(v for v in ports.values()) if isinstance(ports, dict) else False
        ep = client.endpoint
        label = getattr(ep, "label", None)
        asset = Asset(
            id=f"container:{label}/{name}" if label else f"container:{name}", type="container", name=name,
            meta={"container_id": cid, "image": cfg.get("Image"), "image_id": info.get("Image"),
                  "labels": redact_labels(cfg.get("Labels") if isinstance(cfg.get("Labels"), dict) else None),
                  "state": st.get("Status") if isinstance(st.get("Status"), str) else None,
                  "privileged": bool(host.get("Privileged")), "published_ports": published,
                  "user": cfg.get("User") or None, "engine": strip_url_secrets(str(ep))})
        if getattr(ep, "context", None):
            asset.meta["engine_context"] = ep.context  # type: ignore[union-attr]
        try:
            conn, resp = client.open(f"/containers/{cid}/export")
        except RuntimeError as e:
            return self._container_from_image(client, asset, str(e))
        view = LayeredTarView()
        warnings: list[str] = []
        partial: str | None = None
        try:
            view.add_layer(resp)
        except Exception as e:  # noqa: BLE001  truncated stream, daemon error mid-export ...
            partial = f"container export incomplete: {e}"
            warnings.append(partial)
        finally:
            conn.close()
        comps = collect_from_view(view, asset, warnings)
        inv = Inventory(asset=asset, collector=self.name, components=comps, warnings=warnings)
        if partial:
            inv.mark_partial(partial)
        if view.truncated:
            inv.mark_partial("file/count limits reached while reading the export")
        return inv

    def _container_from_image(self, client: EngineClient, asset: Asset, reason: str) -> Inventory:
        iid = _norm_id(asset.meta.get("image_id"))
        if not iid:
            raise RuntimeError(f"container filesystem not readable ({reason}) and no image Id to fall back to")
        try:
            img = self._collect_image(client, iid)
        except Exception as e:
            raise RuntimeError(f"container filesystem not readable ({reason}); its image {iid[7:19]} "
                               f"neither: {e}") from e
        msg = f"container filesystem not readable ({reason[:300]}); scanned its image {iid[7:19]} instead"
        asset.platform = asset.platform or img.asset.platform
        asset.meta.update({"scanned_image": iid, "image_id_verified": img.asset.meta.get("id_verified"),
                           "filesystem": "image-only"})
        inv = Inventory(asset=asset, collector=self.name, components=img.components, warnings=[msg, *img.warnings])
        inv.mark_partial(msg + (f"; {img.partial_reason}" if img.partial else ""))
        return inv


def _arch(client: EngineClient) -> str:
    try:
        return {"x86_64": "amd64", "aarch64": "arm64"}.get(arch := client.version().get("Arch", "amd64"), arch)
    except Exception:  # noqa: BLE001
        return "amd64"
