---
title: Inventory of containers and Linux filesystems
summary: Inventory of container images (registry, tarball, OCI), live containers on local or remote engines (context, ssh, tcp+TLS; name/glob/regex selectors) and rootfs trees - usage, asset ids, layer cache, warnings, criteria.
read_when: you change how container images, running containers or Linux directory trees are inventoried, or debug their asset ids, layers or cache
type: feature
context: features
status: implemented
tags: [docker, container, rootfs, inventory, dependencies, linux]
updated: 2026-11-10
verified: 2026-11-10
code: src/secmonk/collectors/
related: [tech/collectors/docker-image.md, tech/collectors/docker-engine.md, tech/collectors/rootfs.md, tech/collectors/dependencies.md, features/inventory-dependencies.md, features/README.md]
---

# Inventory of containers and Linux filesystems

## What the user gets

The software inside a container image, a running container or a Linux directory tree - OS, distro packages (dpkg/apk/rpm), **language dependencies**
(npm, Python, Go, Rust, Java, .NET, PHP) and **Go/Rust binaries and jars** - without a Docker daemon (images), without running anything, ready for
`secmonk match` / `secmonk scan`. Language packages are parsed by the shared parsers described in [inventory-dependencies](inventory-dependencies.md).

## Usage

```bash
# registry image (anonymous pull by default; default platform linux/amd64)
secmonk collect docker-image alpine:3.20
secmonk collect docker-image ghcr.io/org/app:1.4
secmonk collect docker-image mirror.gcr.io/library/debian:12-slim     # mirror when Docker Hub rate-limits (429)
secmonk collect docker-image alpine@sha256:<digest>
# private registry: -o username=U with SECMONK_REGISTRY_PASSWORD in the environment (or inline `auths` in ~/.docker/config.json)
SECMONK_REGISTRY_PASSWORD=... secmonk collect docker-image registry.example.com/app:1 -o username=ci

# offline: `docker save` / `skopeo copy ... oci:dir`
secmonk collect docker-image ./image.tar
secmonk collect docker-image ./oci-layout-dir

# live container (needs access to the engine socket; read-only GETs)
secmonk collect docker-engine web                 # container name or id
secmonk collect docker-engine image:nginx:1.25    # a local image through the engine
secmonk scan docker-engine 'web,db'               # several containers: comma-separated
secmonk scan docker-engine 'shop-*'               # glob on names / 12-char ids (running containers)
secmonk scan docker-engine 're:^api-[0-9]+$' -o all=true    # regex; all=true includes stopped containers

# another engine: Docker CLI context, remote host over ssh, tcp (+TLS)
secmonk scan docker-engine web -o context=colima
secmonk scan docker-engine 'web,db' -o host=ssh://deploy@build-01.example.test       # runs `docker system dial-stdio` there
secmonk scan docker-engine web -o host=tcp://engine.example.test:2376 -o tls_ca=ca.pem -o tls_cert=cert.pem -o tls_key=key.pem
DOCKER_HOST=ssh://build-01.example.test secmonk containers

# any directory (extracted rootfs, chroot, mounted disk)
secmonk collect rootfs /mnt/disk
secmonk scan docker-image alpine:3.20         # collect + save + match
secmonk scan docker-engine web
secmonk containers                            # list containers of the local Docker/Podman engine
```

## Behaviour & rules

- Image assets are `image:<repo>@<digest>` (manifest digest; for tarballs the image id), so re-scanning a re-tagged image creates a new asset; container assets by name: `container:<name>` on the local engine, `container:<engine>/<name>` on a remote one (`<engine>` = `host:port` for tcp, the ssh host, plus `:port` when not 22, for ssh; never the ssh user), so same-named containers on two hosts stay apart.
- Layers are cached in the per-user cache (`~/.cache/secmonk/blobs/`, or `$SECMONK_CACHE`; digest-verified, never inside the current directory) and applied in order with whiteouts; later layers win.
- Language files are parsed while the layers stream (`LangAccumulator`): only parsed components are kept, so memory does not grow with binary size; later layers and whiteouts replace or remove them. Directory trees (`rootfs`) use `walk_dir`. Installed metadata beats binaries beats lockfiles beats manifests.
- Packages are matched on their *source* package (dpkg `Source`, apk origin, rpm source rpm). rpm versions are shown with an epoch (`0:1.2-3.el9`).
- Warnings are shown, never silent: unsupported rpm BerkeleyDB, no package DB (distroless), skipped zstd layers.
- Env variable values from the image config are not stored (names only).
- Engine: `--socket` / `-o host=` / `-o context=` > `$DOCKER_HOST` > `$DOCKER_CONTEXT` > the Docker CLI's current context > `/var/run/docker.sock`, Docker Desktop/Colima/Rancher/OrbStack/Podman paths. Hosts: `unix://`, `tcp://` (TLS from the context, `$DOCKER_TLS_VERIFY`/`$DOCKER_CERT_PATH` or `tls_ca`/`tls_cert`/`tls_key`/`tls_verify`), `ssh://[user@]host[:port]` (system `ssh`, non-interactive, `-o identity=`). An engine or context that was asked for and cannot be used is an error, never replaced by another one; none found -> clear error. Details: [docker-engine](../tech/collectors/docker-engine.md).
- Container selectors: comma-separated items; `re:<regex>` and globs (`*`, `?`, `[`) match container names and 12-char ids of running containers (`-o all=true`: also stopped); exact names and `image:<ref>` pass through. A pattern matching nothing is an error listing the available containers. Regexes that could backtrack catastrophically on a hostile name (nested quantifiers such as `(a+)+`, a repeated alternation, more than 3 repeating quantifiers) are refused; names over 128 characters are only reachable by their exact name.
- Remote engines: `-o timeout=N` bounds each wait for data (default 30 s, ssh included); the SSH collector's `identity`, `ssh_option`, `known_hosts`, `insecure_host_key`, `connect_timeout` apply to `ssh://`; paramiko-only options are refused. Same-named containers on two *local* engines (two contexts on unix sockets) share the asset id `container:<name>`.

## Acceptance criteria

- `alpine:3.20` yields the OS + 14 apk packages with ecosystem `Alpine:v3.20`; `debian:12-slim` yields 88 deb packages (`Debian:12`).
- A rocky/alma/rhel rootfs yields rpm packages whose version starts with the epoch; an Alpine rootfs with a vulnerable `xz-libs` produces an `osv-package` finding (tests/test_e2e_alpine.py).
- No network needed for tarballs, OCI dirs, rootfs dirs.
- `web,shop-*,re:^api-` on an engine running `web`, `shop-a`, `shop-b`, `api-1` scans the four containers once each; `nosuch-*` fails naming the running containers.
- A container on `ssh://deploy@build-01.example.test` is stored as `container:build-01.example.test/<name>` with `engine` `ssh://build-01.example.test` (verified offline only, 2026-11-10).
- `python:3.12-slim` yields OS + 87 deb + `pip 25.0.1` (PyPI, from site-packages in the streamed layers); `registry:2` yields the Go binary `/bin/registry` with stdlib 1.20.8 and 85 exact `osv-package` findings (verified 2026-11-07 on real OSV data, see [dependencies](../tech/collectors/dependencies.md)).
- Findings on Debian images carry distro triage (`--hide-minor`, `--hide-deferred`): see [matching](../tech/engine/matching.md).

## Implemented by

[docker-image](../tech/collectors/docker-image.md), [docker-engine](../tech/collectors/docker-engine.md), [rootfs](../tech/collectors/rootfs.md)
