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
| Homebrew | [homebrew.md](homebrew.md) | Homebrew/Linuxbrew prefix: active kegs, casks, vendored PyPI/npm packages, upstream identity (also used by macOS) | implemented |
| Docker image | [docker-image.md](docker-image.md) | Image from registry, `docker save` tarball, or OCI layout → OS packages + language packages | implemented |
| Docker engine | [docker-engine.md](docker-engine.md) | Running containers via the Docker Engine API (unix socket) | implemented |
| SSH (agentless) | [ssh.md](ssh.md) | `user@host[:port]` Linux/macOS: harvests metadata files over SSH, then reuses rootfs/macOS collectors | implemented (fixture + in-process sshd tested) |
| Windows | [windows.md](windows.md) | PowerShell inventory JSON / osquery / live `winreg`: OS build + UBR, Uninstall keys, Appx, Chocolatey, Scoop, .NET | implemented (fixture-tested on Linux; script untested on real Windows) |
| Filesystem / rootfs | (shared with docker-image) | dpkg/apk/rpm DBs + lockfiles under a directory | implemented |

## Template

New collector docs start from [`_meta/templates/tech-collector.md`](../../_meta/templates/tech-collector.md).
User-facing behaviour of each scan target is described in [`features/`](../../features/).
