---
title: Inventory of containers and Linux filesystems
summary: Inventory of container images (registry, tarball, OCI), live containers and rootfs trees - usage, asset ids, layer cache, source-package matching, warnings and acceptance criteria.
read_when: you change how container images, running containers or Linux directory trees are inventoried, or debug their asset ids, layers or cache
type: feature
context: features
status: implemented
tags: [docker, container, rootfs, inventory, dependencies, linux]
updated: 2026-11-07
verified: 2026-11-07
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

# any directory (extracted rootfs, chroot, mounted disk)
secmonk collect rootfs /mnt/disk
secmonk scan docker-image alpine:3.20         # collect + save + match
secmonk scan docker-engine web
secmonk containers                            # list containers of the local Docker/Podman engine
```

## Behaviour & rules

- Image assets are `image:<repo>@<digest>` (manifest digest; for tarballs the image id), so re-scanning a re-tagged image creates a new asset; container assets by name.
- Layers are cached in the per-user cache (`~/.cache/secmonk/blobs/`, or `$SECMONK_CACHE`; digest-verified, never inside the current directory) and applied in order with whiteouts; later layers win.
- Language files are parsed while the layers stream (`LangAccumulator`): only parsed components are kept, so memory does not grow with binary size; later layers and whiteouts replace or remove them. Directory trees (`rootfs`) use `walk_dir`. Installed metadata beats binaries beats lockfiles beats manifests.
- Packages are matched on their *source* package (dpkg `Source`, apk origin, rpm source rpm). rpm versions are shown with an epoch (`0:1.2-3.el9`).
- Warnings are shown, never silent: unsupported rpm BerkeleyDB, no package DB (distroless), skipped zstd layers.
- Env variable values from the image config are not stored (names only).
- Engine socket: `$DOCKER_HOST`, `/var/run/docker.sock`, Docker Desktop/Colima/Rancher/OrbStack/Podman paths. Not found -> clear error.

## Acceptance criteria

- `alpine:3.20` yields the OS + 14 apk packages with ecosystem `Alpine:v3.20`; `debian:12-slim` yields 88 deb packages (`Debian:12`).
- A rocky/alma/rhel rootfs yields rpm packages whose version starts with the epoch; an Alpine rootfs with a vulnerable `xz-libs` produces an `osv-package` finding (tests/test_e2e_alpine.py).
- No network needed for tarballs, OCI dirs, rootfs dirs.
- `python:3.12-slim` yields OS + 87 deb + `pip 25.0.1` (PyPI, from site-packages in the streamed layers); `registry:2` yields the Go binary `/bin/registry` with stdlib 1.20.8 and 85 exact `osv-package` findings (verified 2026-11-07 on real OSV data, see [dependencies](../tech/collectors/dependencies.md)).
- Findings on Debian images carry distro triage (`--hide-minor`, `--hide-deferred`): see [matching](../tech/engine/matching.md).

## Implemented by

[docker-image](../tech/collectors/docker-image.md), [docker-engine](../tech/collectors/docker-engine.md), [rootfs](../tech/collectors/rootfs.md)
