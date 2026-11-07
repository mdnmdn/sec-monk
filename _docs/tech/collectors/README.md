---
title: Inventory collectors — index
type: tech
context: tech
status: draft
tags: [collector, index]
updated: 2026-11-07
---

# Inventory collectors

A collector discovers software on a **target** and emits `Component` records (name, version,
PURL/CPE, category, source path) plus an `Asset` envelope. Collectors never match vulnerabilities;
the shared engine does ([vision](../../product/vision.md) §6: *different collectors, one shared engine*).

| Collector | Doc | Target | Status |
|---|---|---|---|
| macOS | [macos.md](macos.md) | `.app` bundles, Homebrew (formulae + casks), pkgutil receipts | implemented (fixture-tested on Linux) |
| Docker image | [docker-image.md](docker-image.md) | Image from registry, `docker save` tarball, or OCI layout → OS packages + language packages | implemented |
| Docker engine | [docker-engine.md](docker-engine.md) | Running containers via the Docker Engine API (unix socket) | implemented |
| Filesystem / rootfs | (shared with docker-image) | dpkg/apk/rpm DBs + lockfiles under a directory | implemented |

## Template

New collector docs start from [`_meta/templates/tech-collector.md`](../../_meta/templates/tech-collector.md).
User-facing behaviour of each scan target is described in [`features/`](../../features/).
