---
title: Inventory of containers and Linux filesystems
type: feature
context: features
status: implemented
tags: [docker, container, rootfs, inventory]
updated: 2026-11-07
code: src/secmonk/collectors/
related: [tech/collectors/docker-image.md, tech/collectors/docker-engine.md, tech/collectors/rootfs.md]
---

# Inventory of containers and Linux filesystems

## What the user gets

The software inside a container image, a running container or a Linux directory tree - OS, distro packages, Python and npm packages -
without a Docker daemon (images), without running anything, ready for `secmonk match` / `secmonk scan`.

## Usage

```bash
# registry image (anonymous pull; default platform linux/amd64)
secmonk collect docker-image alpine:3.20
secmonk collect docker-image ghcr.io/org/app:1.4
secmonk collect docker-image mirror.gcr.io/library/debian:12-slim     # mirror when Docker Hub rate-limits (429)
secmonk collect docker-image alpine@sha256:<digest>

# offline: `docker save` / `skopeo copy ... oci:dir`
secmonk collect docker-image ./image.tar
secmonk collect docker-image ./oci-layout-dir

# live container (needs access to the engine socket; read-only GETs)
secmonk collect docker-engine web                 # container name or id
secmonk collect docker-engine image:nginx:1.25    # a local image through the engine

# any directory (extracted rootfs, chroot, mounted disk)
secmonk collect rootfs /mnt/disk
secmonk scan docker-image alpine:3.20
```

## Behaviour & rules

- Image assets are identified by manifest digest, so re-scanning a re-tagged image creates a new asset; container assets by name.
- Layers are cached in `.cache/secmonk/blobs/` (digest-verified) and applied in order with whiteouts; later layers win.
- Packages are matched on their *source* package (dpkg `Source`, apk origin, rpm source rpm). rpm versions are shown with an epoch (`0:1.2-3.el9`).
- Warnings are shown, never silent: unsupported rpm BerkeleyDB, no package DB (distroless), skipped zstd layers.
- Env variable values from the image config are not stored (names only).
- Engine socket: `$DOCKER_HOST`, `/var/run/docker.sock`, Docker Desktop/Colima/Rancher/OrbStack/Podman paths. Not found -> clear error.

## Acceptance criteria

- `alpine:3.20` yields the OS + 14 apk packages with ecosystem `Alpine:v3.20`; `debian:12-slim` yields 88 deb packages (`Debian:12`).
- A rocky/alma/rhel rootfs yields rpm packages whose version starts with the epoch; an Alpine rootfs with a vulnerable `xz-libs` produces an `osv-package` finding (tests/test_e2e_alpine.py).
- No network needed for tarballs, OCI dirs, rootfs dirs.

## Implemented by

[docker-image](../tech/collectors/docker-image.md), [docker-engine](../tech/collectors/docker-engine.md), [rootfs](../tech/collectors/rootfs.md)
