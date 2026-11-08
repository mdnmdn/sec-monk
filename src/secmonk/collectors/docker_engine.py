"""Docker Engine (and Podman Docker-compatible API) collector over a unix socket, stdlib only.

Read-only: only GET requests are ever sent. See _docs/tech/collectors/docker-engine.md.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from ..models import Asset, Inventory
from .base import Collector, redact_labels, register
from .docker_image import inventory_from_archive
from .rootfs import LayeredTarView, collect_from_view


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 over an AF_UNIX stream socket."""

    def __init__(self, path: str, timeout: float | None = 30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


@dataclass
class Endpoint:
    unix: str | None = None
    host: str | None = None      # tcp: host:port
    port: int | None = None

    def __str__(self) -> str:
        return f"unix://{self.unix}" if self.unix else f"tcp://{self.host}:{self.port}"


def _parse_host(value: str) -> Endpoint | None:
    value = value.strip()
    if value.startswith("unix://"):
        return Endpoint(unix=value[len("unix://"):])
    if value.startswith("/"):
        return Endpoint(unix=value)
    if value.startswith(("tcp://", "http://")):
        u = urlsplit(value.replace("tcp://", "http://", 1))
        return Endpoint(host=u.hostname or "localhost", port=u.port or 2375)
    return None


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


def find_endpoint(opts: dict[str, Any] | None = None) -> Endpoint:
    """opts['socket'] > $DOCKER_HOST > well-known socket paths. An explicit but missing socket is an
    error (no fallback to the defaults)."""
    opts = opts or {}
    tried: list[str] = []
    explicit = opts.get("socket") or os.environ.get("DOCKER_HOST")
    if explicit:
        ep = _parse_host(explicit)
        if ep is None:
            raise RuntimeError(f"Unsupported Docker host {explicit!r} (use unix:///path or tcp://host:port)")
        # An explicitly requested endpoint is never silently replaced by another one.
        if ep.unix is not None and not os.path.exists(ep.unix):
            src = "--socket" if opts.get("socket") else "DOCKER_HOST"
            raise RuntimeError(f"Docker socket {ep.unix} (from {src}) does not exist")
        return ep
    stale: list[str] = []
    for path in candidate_sockets(opts):
        if path in tried:
            continue
        tried.append(path)
        if os.path.exists(path):
            if _refuses(path):
                stale.append(path)
                continue
            return Endpoint(unix=path)
    msg = "Docker engine socket not found: tried " + ", ".join(tried)
    if stale:
        msg += "; refusing connections (engine not running, stale socket file): " + ", ".join(stale)
    raise RuntimeError(msg)


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

    def _conn(self) -> http.client.HTTPConnection:
        ep = self.endpoint
        if ep.unix:
            return UnixHTTPConnection(ep.unix, self.timeout)
        return http.client.HTTPConnection(ep.host, ep.port, timeout=self.timeout)

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
        except OSError as e:
            conn.close()
            raise RuntimeError(f"cannot talk to Docker engine at {self.endpoint}: {e}") from e
        if resp.status != 200:
            body = resp.read()[:400].decode("utf-8", "replace")
            conn.close()
            try:
                body = json.loads(body).get("message", body)
            except ValueError:
                pass
            raise RuntimeError(f"Docker API GET {path} -> HTTP {resp.status}: {body}")
        return conn, resp

    def get_json(self, path: str) -> Any:
        conn, resp = self.open(path)
        try:
            return json.loads(resp.read())
        finally:
            conn.close()

    def ping(self) -> bool:
        conn, resp = self.open("/_ping")
        try:
            return resp.read().strip() == b"OK"
        finally:
            conn.close()

    def version(self) -> dict:
        return self.get_json("/version")


def _client(opts: dict[str, Any]) -> EngineClient:
    return opts.get("client") or EngineClient(find_endpoint(opts), opts.get("timeout", 30))


def list_containers(all: bool = False, **opts: Any) -> list[dict]:
    """Containers as returned by GET /containers/json (running only unless all=True)."""
    return _client(opts).get_json(f"/containers/json?all={1 if all else 0}")


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
    description = "Live container (or local image) via the Docker/Podman engine socket"

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
        return self._collect_container(client, target)

    def _collect_image(self, client: EngineClient, ref: str) -> Inventory:
        fd, tmp = tempfile.mkstemp(prefix="secmonk-image-", suffix=".tar")
        os.close(fd)
        try:
            export_image(ref, tmp, client=client)
            inv = inventory_from_archive(tmp, name=ref, collector=self.name,
                                         platform=f"linux/{_arch(client)}")
        finally:
            os.unlink(tmp)
        inv.asset.meta["source"] = "docker-engine"
        return inv

    def _collect_container(self, client: EngineClient, target: str) -> Inventory:
        info = client.get_json(f"/containers/{quote(target, safe='')}/json")
        cid = info["Id"]
        name = (info.get("Name") or cid[:12]).lstrip("/")
        cfg, st, host = info.get("Config") or {}, info.get("State") or {}, info.get("HostConfig") or {}
        view = LayeredTarView()
        conn, resp = client.open(f"/containers/{cid}/export")
        warnings: list[str] = []
        partial: str | None = None
        try:
            view.add_layer(resp)
        except Exception as e:  # noqa: BLE001  truncated stream, daemon error mid-export ...
            partial = f"container export incomplete: {e}"
            warnings.append(partial)
        finally:
            conn.close()
        ports = (info.get("NetworkSettings") or {}).get("Ports") or {}
        published = any(v for v in ports.values())
        asset = Asset(
            id=f"container:{name}", type="container", name=name,
            meta={"container_id": cid, "image": cfg.get("Image"), "image_id": info.get("Image"),
                  "labels": redact_labels(cfg.get("Labels")), "state": st.get("Status"),
                  "privileged": bool(host.get("Privileged")), "published_ports": published,
                  "user": cfg.get("User") or None, "engine": str(client.endpoint)})
        comps = collect_from_view(view, asset, warnings)
        inv = Inventory(asset=asset, collector=self.name, components=comps, warnings=warnings)
        if partial:
            inv.mark_partial(partial)
        if view.truncated:
            inv.mark_partial("file/count limits reached while reading the export")
        return inv


def _arch(client: EngineClient) -> str:
    try:
        return {"x86_64": "amd64", "aarch64": "arm64"}.get(arch := client.version().get("Arch", "amd64"), arch)
    except Exception:  # noqa: BLE001
        return "amd64"
