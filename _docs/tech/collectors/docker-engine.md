---
title: Docker engine collector
type: tech
context: tech
status: implemented
tags: [collector, docker, containers, engine-api, podman]
updated: 2026-11-07
sample: synthetic
fixtures: tests/fixtures/collectors/docker/engine/
code: src/secmonk/collectors/docker_engine.py
related: [tech/collectors/docker-image.md, features/inventory-docker.md, tech/engine/classification.md]
---

# Docker engine collector

## Summary

Enumerates **running (and stopped) containers and local images** through the Docker Engine HTTP API over a
unix socket, using only the Python stdlib (`http.client` + `socket`; no `docker` SDK). For each image/container
it hands a rootfs tarball to the [image collector](docker-image.md) to read the package DBs. Two scan depths:

- **Image scan** (`GET /images/{name}/get`): what the image *was built with*. Reusable by the image collector as a `docker save` tarball.
- **Container scan** (`GET /containers/{id}/export`): flat rootfs of the *live container filesystem*, so it also catches packages installed at runtime (`apt-get install` in a running container, written layer). Flattened: no layer info, no image config, no whiteout files (already applied).

The sandbox has no Docker daemon, so **nothing here was exercised against a real engine**. Endpoint behaviour is from the
Docker Engine API docs (v1.4x) and long-standing behaviour; fixtures are **synthetic** (realistic shapes).
Verify on a real host before marking `implemented`.

## Where the data lives

Socket discovery order (first that exists and answers `GET /_ping`):

1. `DOCKER_HOST` env: `unix:///path/to.sock` (also `tcp://host:2375`, `ssh://` - out of scope; refuse plain tcp unless `--allow-tcp`).
2. `/var/run/docker.sock` (Linux; also on macOS via symlink from Docker Desktop/OrbStack).
3. `~/.docker/run/docker.sock` (Docker Desktop macOS, newer versions).
4. `~/.colima/default/docker.sock` (Colima); `~/.rd/docker.sock` (Rancher Desktop); `~/.orbstack/run/docker.sock` (OrbStack).
5. Docker contexts: `~/.docker/contexts/meta/*/meta.json` -> `Endpoints.docker.Host` (honour `docker context use`; current context in `~/.docker/config.json` `currentContext`).
6. Podman: `$XDG_RUNTIME_DIR/podman/podman.sock` (rootless; `/run/user/<uid>/podman/podman.sock`), `/run/podman/podman.sock` (rootful). Podman exposes a Docker-compatible API at `/v1.40/...` plus its own `/libpod/...`.

Permissions: the socket is `root:docker` mode 660 - the user must be in the `docker` group (equivalent to root!). Report `PermissionError`
clearly. The collector is **read-only**: only GET requests; never `POST /containers/*/start|exec`, `create`, etc. Note: that `/export` and `/images/*/get` read big data, so the scan can load the host.

## Data format

Stdlib client (HTTP/1.1 over AF_UNIX; send `Host: docker`; handle `Transfer-Encoding: chunked` - `http.client` does it for you):

```python
class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout); self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout); self.sock.connect(self.path)
```

Use a version-pinned prefix (`/v1.41/containers/json`) for stable shape; unversioned = engine latest. Check `/version` first and
require `MinAPIVersion <= 1.41 <= ApiVersion`.

| Endpoint | Returns | Used for |
|---|---|---|
| `GET /_ping` | `OK` (text) | liveness |
| `GET /version` | JSON: `Version`, `ApiVersion`, `MinAPIVersion`, `Os`, `Arch`, `KernelVersion`, `Components[]` (Engine, containerd, runc) | host asset metadata; **engine/containerd/runc themselves are components** (`pkg:generic/docker-engine`, `cpe:2.3:a:docker:docker:27.0.3`, `cpe:2.3:a:linuxfoundation:runc:1.1.13`) |
| `GET /containers/json?all=1` | array of `{Id, Names[], Image, ImageID, Command, Created(epoch), Ports[], Labels{}, State, Status, HostConfig, Mounts[]}` | container list. `Names` start with `/`. `State`: running/exited/paused/created/restarting. `Image` is the *tag as given at create time* or a bare `sha256:` id if the tag has moved/been removed; `ImageID` is authoritative. |
| `GET /containers/{id}/json` | full inspect: `Config.{Image,Env,Labels,User,Cmd}`, `HostConfig.{Privileged,PortBindings,NetworkMode}`, `State`, `Image` (id) | context for prioritization: privileged, published ports (**exposure**), user, running state |
| `GET /images/json` | array `{Id, RepoTags[], RepoDigests[], Created, Size, Containers, Labels}` | local images; `RepoTags` may be `[]` or `["<none>:<none>"]` (older) for dangling |
| `GET /images/{name or id}/json` | inspect: `Architecture`, `Os`, `RepoDigests`, `Config.Labels`, `RootFS.Layers` | digest/provenance |
| `GET /images/{name}/get` | **tar stream** (`docker save` format; Docker >= 25 emits OCI layout style, see image doc). `name` may be `repo:tag` or `sha256:id`; `/images/get?names=a&names=b` for several | pass straight to the image collector; stream to a temp file (can be GBs) or to `tarfile.open(fileobj=resp, mode="r|")` streaming mode |
| `GET /containers/{id}/export` | tar stream of the merged container filesystem (no manifest/config) | rootfs collector (dpkg/apk/rpm + language packages), live state |
| `GET /containers/{id}/archive?path=/var/lib/dpkg` (HEAD/GET) | tar of just a path (stat in `X-Docker-Container-Path-Stat` header, base64 JSON) | **cheaper alternative to `/export`**: fetch only `/etc/os-release`, `/var/lib/dpkg/status`, `/lib/apk/db/installed`, `/var/lib/rpm/`, `/usr/lib/os-release`, python/node dirs. 404 when the path is missing - expected. Works on stopped containers too. |

Fixtures (synthetic): `version.json`, `containers-json.json` (3 containers: running nginx, running postgres, exited container whose image tag is a bare `sha256:`),
`images-json.json`, `container-inspect.json`.

Typical flow:

1. `/version` -> host asset; 2. `/containers/json?all=1` -> map container -> `ImageID`; 3. scan each **distinct ImageID once** (many containers share an image); 4. for **running** containers also do a targeted `/archive` of package DB paths and diff against the image result (extra/changed packages = runtime drift; tag them `source=container-runtime`); 5. attach per-container context (name, compose project label `com.docker.compose.project`, published ports, privileged) as asset/component properties used by prioritization.

## Classification

Components are emitted by the image collector (deb/apk/rpm/pypi/npm PURLs). This collector adds:
asset type `container` (id = `<engine host>/<container id[:12]>`, name from `Names`), asset type `container-host` for the engine host, properties
`image_ref`, `image_id`, `exposure` (`published-ports` if any `PublicPort`), `privileged`, `state`, `compose_project`, plus engine / containerd / runc components from `/version`.

## Limitations / gotchas

- Docker Desktop (macOS/Windows) engine runs in a VM: socket paths are on the host but the container FS is in the VM; the API hides this (works over the socket). Colima/Podman Machine likewise.
- `/containers/{id}/export` of a running container is not a consistent snapshot; large (GBs) - stream, set a size cap, avoid `/export` when `/archive` is enough.
- Image stores: Docker >= 25 with the containerd image store changes `/images/*/get` output to OCI layout (`index.json` + `blobs/`, still includes `manifest.json`) and `RepoDigests`/`Id` semantics (Id = manifest digest). Handle both layouts.
- `docker save` of a multi-platform image only includes the host's platform (older engines), or requires `?platform=` (API >= 1.48) with the containerd store.
- Stopped container whose image was deleted: `Image` is a bare sha256; `/images/{id}/get` fails (404) -> fall back to `/containers/{id}/export`.
- Rootless podman: `/containers/json` is the Docker-compatible endpoint, labels and `Image` semantic differ slightly; `libpod` API adds `Digest`, `Names` without slash.
- Do not follow symlinks while extracting tar streams (path traversal, `..`, absolute links); read members in memory, only the whitelisted paths.
- Security: access to the Docker socket = root on host; document that scanning requires it, and never mount the socket into a scanner container without understanding that.

## Implementation notes

Implemented in `src/secmonk/collectors/docker_engine.py` (stdlib `http.client` + `UnixHTTPConnection`). **Verified only against a fake unix-socket server** (`tests/collectors/test_docker.py`) serving the synthetic fixtures; never run against a real engine in this sandbox.

- Endpoint discovery (`find_endpoint`): `opts["socket"]` > `$DOCKER_HOST` (`unix://` or `tcp://` plain http) > `/var/run/docker.sock`, `~/.docker/run/docker.sock`, `~/.colima/default/docker.sock`, `~/.rd/docker.sock`, `~/.orbstack/run/docker.sock`, `$XDG_RUNTIME_DIR/podman/podman.sock`, `/run/podman/podman.sock`. None found -> `RuntimeError("Docker engine socket not found: tried ...")`. Docker contexts and ssh:// are not implemented.
- Only GET requests; unversioned API paths (engine latest) - `/version` is not enforced against MinAPIVersion.
- `collect("<container id|name>")`: `GET /containers/{id}/json` (metadata) + `GET /containers/{id}/export` streamed straight into `LayeredTarView` as one layer (nothing touches disk). Asset `container:<name>`, type `container`, meta `container_id, image, image_id, labels, state, privileged, published_ports, user, engine`. `collect("image:<ref>")` streams `GET /images/{ref}/get` to a temp tar and reuses the docker-image archive path. `collect(None)` raises `ValueError` listing running containers.
- Helpers for the CLI: `list_containers(all=False, **opts)`, `export_image(ref, dest)`, `EngineClient.ping()/version()`.
- Not done: `/archive` partial fetch, one-scan-per-ImageID dedupe, host asset + engine/containerd/runc components, `Privileged` as scoring input (stored in meta only).


## Review fixes (2026-11)

- An explicit endpoint (`-o socket=...` or `$DOCKER_HOST`) that does not exist is a `RuntimeError`; the well-known paths are only tried when nothing was requested.
- Rootless Docker (`$XDG_RUNTIME_DIR/docker.sock`) is a candidate socket (before the rootless podman one).
- An interrupted `/containers/<id>/export` or `/images/<ref>/get` marks the inventory **partial** (`Inventory.partial`), so removal
  detection ignores that scan (see data-model). Container labels are stored with secret-looking keys redacted (`<redacted>`).
