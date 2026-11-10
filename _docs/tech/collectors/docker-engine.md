---
title: Docker engine collector
summary: Docker Engine API collector for local and remote engines (unix socket, tcp+TLS, ssh dial-stdio, Docker contexts) - endpoint resolution, container selectors, image and container export scans, limits.
read_when: you change how sec-monk reaches a Docker daemon (socket, context, ssh, TLS), expands container selectors, or scans running containers and local images
type: tech
context: tech
status: implemented
tags: [collector, docker, containers, engine-api, podman, ssh, tls, contexts]
updated: 2026-11-10
verified: 2026-11-10
sample: synthetic
fixtures: tests/fixtures/collectors/docker/engine/
code: [src/secmonk/collectors/docker_engine.py, src/secmonk/collectors/docker_transport.py]
related: [tech/collectors/docker-image.md, features/inventory-docker.md, tech/engine/classification.md, tech/collectors/ssh.md]
---

# Docker engine collector

## Summary

Enumerates **running (and stopped) containers and local images** through the Docker Engine HTTP API of a local or
remote engine: unix socket, `tcp://` (plain or TLS), or `ssh://` (the engine's own `docker system dial-stdio`, as the
Docker CLI does), chosen explicitly, through a Docker CLI context, or discovered. Python stdlib only (`http.client`,
`socket`, `ssl`, `subprocess` for `ssh`; no `docker` SDK). For each image/container
it hands a rootfs tarball to the [image collector](docker-image.md) to read the package DBs. Two scan depths:

- **Image scan** (`GET /images/{name}/get`): what the image *was built with*. Reusable by the image collector as a `docker save` tarball.
- **Container scan** (`GET /containers/{id}/export`): flat rootfs of the *live container filesystem*, so it also catches packages installed at runtime (`apt-get install` in a running container, written layer). Flattened: no layer info, no image config, no whiteout files (already applied).

The sandbox has no Docker daemon, so **nothing here was exercised against a real engine**. Endpoint behaviour is from the
Docker Engine API docs (v1.4x) and long-standing behaviour; fixtures are **synthetic** (realistic shapes).
Verify on a real host before marking `implemented`.

## Where the data lives

Endpoint resolution (`docker_engine.find_endpoint`), first match wins:

| # | Source | Notes |
|---|---|---|
| 1 | `opts["socket"]` (`--socket`, `-o socket=`) | any host form below |
| 2 | `opts["host"]` (`-o host=`) | `$DOCKER_TLS_VERIFY`/`$DOCKER_CERT_PATH` apply |
| 3 | `opts["context"]` (`-o context=`) | a Docker CLI context name |
| 4 | `$DOCKER_HOST` | `$DOCKER_TLS_VERIFY`/`$DOCKER_CERT_PATH` apply |
| 5 | `$DOCKER_CONTEXT` | |
| 6 | `currentContext` in `$DOCKER_CONFIG/config.json` (default `~/.docker`) | ignored when `"default"`, unset, or the file cannot be opened |
| 7 | well-known sockets | the first that exists **and does not refuse a connection** |

Anything requested in 1-6 that cannot be resolved (missing context, context without a docker endpoint, missing socket
file, unsupported scheme, malformed `config.json`) is a `RuntimeError`: it is never silently replaced by another
engine. The context name `default` means step 7. Host forms (`docker_transport.parse_host`): `unix:///path`, `/path`,
`tcp://host[:port]` (`http://` accepted; default port 2376 with TLS, 2375 without), `ssh://[user@]host[:port]`
(`npipe://` is refused).

Well-known sockets (step 7). A refused one is skipped and named in the final error: Docker Desktop leaves
`~/.docker/run/docker.sock` behind when it quits, seen on macOS 26.5 on 2026-11-08 while OrbStack was the active context:

1. `/var/run/docker.sock` (Linux; also on macOS via symlink from Docker Desktop/OrbStack).
2. `~/.docker/run/docker.sock` (Docker Desktop macOS, newer versions).
3. `~/.colima/default/docker.sock` (Colima); `~/.rd/docker.sock` (Rancher Desktop); `~/.orbstack/run/docker.sock` (OrbStack).
4. `$XDG_RUNTIME_DIR/docker.sock` (rootless Docker).
5. Podman: `$XDG_RUNTIME_DIR/podman/podman.sock` (rootless; `/run/user/<uid>/podman/podman.sock`), `/run/podman/podman.sock` (rootful). Podman exposes a Docker-compatible API at `/v1.40/...` plus its own `/libpod/...`.

Docker CLI contexts (format of the Docker CLI, read by `docker_transport.load_context` / `iter_contexts`; JSON files
capped at 1 MiB, every field type-checked):

- `<config>/contexts/meta/<sha256(name)>/meta.json`: `Name`, `Metadata.Description`, `Endpoints.docker.Host`,
  `Endpoints.docker.SkipTLSVerify`. A `Name` that differs from the requested one is an error.
- `<config>/contexts/tls/<sha256(name)>/docker/{ca,cert,key}.pem`: TLS material (each file present is used).
- `<config>/config.json` `currentContext`.

TLS for `tcp://` (`docker_transport.TLSConfig`, `ssl` + `http.client.HTTPSConnection`): on when the context has TLS
files or `SkipTLSVerify`, when `$DOCKER_TLS_VERIFY` is non-empty (with `--host`/`$DOCKER_HOST`; any non-empty value,
as in the Docker CLI; files from `$DOCKER_CERT_PATH`, default the config dir), or when a `tls_ca`/`tls_cert`/`tls_key`/
`tls_verify` option is given (options override the other sources). With verification the CA file, when given, is the
only trust anchor (otherwise the system store); `tls_verify=false` / `SkipTLSVerify` disables certificate and name
checks. `$DOCKER_CERT_PATH` alone does not enable TLS (Docker CLI behaviour).

`ssh://` (`docker_transport.SSHHTTPConnection`): one system `ssh` process per HTTP connection, argv from the SSH
collector's `OpenSSHTransport.argv` (`BatchMode=yes`, `ConnectTimeout` (option `connect_timeout`, default 15),
keepalives, no forwarding, `-p`/`-l`/`-i` from the URL and the `identity` option, `ssh_bin` option, `--` before the
host), remote command exactly `docker system dial-stdio`; HTTP/1.1 is spoken over its stdin/stdout. Every wait for
data is bounded by the `timeout` option (default 30 s, as for sockets: `select()` on the stdout pipe, then
`TimeoutError` -> a `RuntimeError` naming the engine). The process is killed when the connection closes, its pipes
are closed, and its stderr is appended to connection errors (`(ssh: ...)`). Hosts and users starting with `-` are
refused; nothing goes through a shell. Of the SSH collector's options, the system-ssh ones apply: `identity`,
`ssh_bin`, `connect_timeout`, `ssh_option` (repeatable `-o`, placed first so it wins), `insecure_host_key`
(`StrictHostKeyChecking=no`, throwaway known_hosts), `known_hosts` (`UserKnownHostsFile`). The paramiko-only ones
(`transport=paramiko`, `allow_agent`, `look_for_keys`, `ssh_config`) are a `ValueError`; `$SECMONK_SSH_PASSWORD` is
not used (BatchMode). Error messages pass hosts through `strip_url_secrets` and never echo a `user:password` part. `~/.ssh/config`, the agent and known_hosts are the
user's (BatchMode: no prompts, so an unknown host key fails with ssh's message).

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
asset type `container` (id `container:<name>` on a local unix socket, `container:<label>/<name>` on a remote engine:
label `host:port` for tcp, the ssh host (port only when not 22, never the user) for ssh; `Endpoint.label`), name from
`Names`. Planned, not built: asset type `container-host` for the engine host, properties
`image_ref`, `image_id`, `exposure` (`published-ports` if any `PublicPort`), `privileged`, `state`, `compose_project`, plus engine / containerd / runc components from `/version`.

## Limitations / gotchas

*Describes current behaviour. What is still to do (and how to verify it) is tracked in the plan [on-linux-docker.md](../../plans/on-linux-docker.md); measurements and real-data validation are in the [probe log](../../references/probes.md).*

- Docker Desktop (macOS/Windows) engine runs in a VM: socket paths are on the host but the container FS is in the VM; the API hides this (works over the socket). Colima/Podman Machine likewise.
- `/containers/{id}/export` of a running container is not a consistent snapshot; large (GBs) - stream, set a size cap, avoid `/export` when `/archive` is enough.
- Image stores: Docker >= 25 with the containerd image store changes `/images/*/get` output to OCI layout (`index.json` + `blobs/`, still includes `manifest.json`) and `RepoDigests`/`Id` semantics (Id = manifest digest). Handle both layouts.
- `docker save` of a multi-platform image only includes the host's platform (older engines), or requires `?platform=` (API >= 1.48) with the containerd store.
- Stopped container whose image was deleted: `Image` is a bare sha256; `/images/{id}/get` fails (404) -> fall back to `/containers/{id}/export`.
- Rootless podman: `/containers/json` is the Docker-compatible endpoint, labels and `Image` semantic differ slightly; `libpod` API adds `Digest`, `Names` without slash.
- Do not follow symlinks while extracting tar streams (path traversal, `..`, absolute links); read members in memory, only the whitelisted paths.
- Security: access to the Docker socket = root on host; document that scanning requires it, and never mount the socket into a scanner container without understanding that.

## Implementation notes

Implemented in `src/secmonk/collectors/docker_engine.py` (client, endpoint resolution, selectors, collector) and
`src/secmonk/collectors/docker_transport.py` (`Endpoint`, contexts, TLS, `UnixHTTPConnection`, `SSHHTTPConnection`).
**Verified only offline**: a fake unix-socket server (`tests/collectors/test_docker.py`) serving the synthetic fixtures,
temp `$DOCKER_CONFIG` trees with generated contexts, a fake and a real-pipe stand-in for `ssh ... dial-stdio`, and a
loopback HTTPS server with throwaway certificates requiring a client cert (`tests/collectors/test_docker_remote.py`).
Never run against a real engine, a real remote over ssh, or a real TLS engine: see the plans.

- Endpoint resolution: see [Where the data lives](#where-the-data-lives). None found -> `RuntimeError("Docker engine socket not found: tried ...")`.
- `list_contexts(**opts) -> list[dict]`: `{name, host, description, current}`, the implicit `default` first (host = the
  first existing well-known socket); `current` is the context resolution would use (none when `socket`/`host`/
  `$DOCKER_HOST` override contexts). Hosts go through `strip_url_secrets` (no userinfo); unreadable entries are listed
  with `host: None` and the error as description.
- Container selectors: `DockerEngineCollector.expand_targets(target, **opts)` and the pure
  `select_containers(selector, rows)` on `/containers/json` rows. Comma-separated items (stripped, empties and
  duplicates dropped, order kept); `image:<ref>` and exact names/ids pass through unchanged; `re:<regex>` (`re.search`,
  at most 256 characters) and globs (`*?[`, `fnmatch.fnmatchcase`) are tested on every container name (no leading `/`)
  and the 12-char id and yield the first name. A pattern that matches nothing, a bad or too long regex -> `ValueError`
  naming it and the available containers (each shortened to 64 characters). Names come from the engine, possibly a
  remote untrusted one, so regex backtracking is bounded (`_check_regex`, on the `re` parser's tree): a quantified
  group containing another quantifier or an alternation (`(a+)+`, `(a|aa)*`) and more than 3 repeating quantifiers
  are refused with a `ValueError`; names and ids longer than 128 characters are never tested against a pattern (they
  can still be given exactly). Only when a pattern is present is the engine listed (running containers,
  all with `opts["all"]`). `collect()` refuses a selector it was handed unexpanded.
- Only GET requests; unversioned API paths (engine latest) - `/version` is not enforced against MinAPIVersion.
- `collect("<container id|name>")`: `GET /containers/{id}/json` (metadata) + `GET /containers/{id}/export` streamed straight into `LayeredTarView` as one layer (nothing touches disk). Asset `container:<name>` (local) or `container:<label>/<name>` (remote), type `container`, meta `container_id, image, image_id, labels, state, privileged, published_ports, user, engine` (`strip_url_secrets` of the endpoint: no ssh user) and `engine_context` when it came from a context. `collect("image:<ref>")` streams `GET /images/{ref}/get` to a temp tar and reuses the docker-image archive path. `collect(None)` raises `ValueError` listing running containers.
- Helpers for the CLI and the web API: `list_containers(all=False, **opts)` (engine options as for `collect`), `list_contexts(**opts)`, `select_containers(selector, rows)`, `export_image(ref, dest)`, `EngineClient.ping()/version()`.
- Image assets read through a remote engine keep their content identity (`image:<repo>@<digest>`), without engine label.
- Option values may be strings (CLI `-o`): `timeout` / `connect_timeout` are positive seconds, `tls_verify` /
  `insecure_host_key` / `all` booleans; anything else is a `ValueError` naming the option.
- A context (or `--host`) that points at a **local unix socket** keeps `container:<name>`, without label: two local
  engines (say Colima and OrbStack contexts) with a same-named container share one asset id, and their scans replace
  each other's inventory. Known limitation; tracked in [on-macos.md](../../plans/on-macos.md) section D.
- Not done: `/archive` partial fetch, one-scan-per-ImageID dedupe, host asset + engine/containerd/runc components, `Privileged` as scoring input (stored in meta only).


## Review fixes (2026-11)

- An explicit endpoint (`-o socket=...` or `$DOCKER_HOST`) that does not exist is a `RuntimeError`; the well-known paths are only tried when nothing was requested.
- Rootless Docker (`$XDG_RUNTIME_DIR/docker.sock`) is a candidate socket (before the rootless podman one).
- An interrupted `/containers/<id>/export` or `/images/<ref>/get` marks the inventory **partial** (`Inventory.partial`), so removal
  detection ignores that scan (see data-model). Container labels are stored with secret-looking keys redacted (`<redacted>`).
