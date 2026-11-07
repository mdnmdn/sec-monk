---
title: Inventory collectors — index
type: tech
context: tech
status: implemented
tags: [collector, index, architecture]
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
| SSH (agentless) | [ssh.md](ssh.md) | `user@host[:port]` Linux/macOS/Windows: harvests metadata files over SSH, then reuses rootfs/macOS collectors (Windows: runs the PowerShell inventory script, see [windows.md](windows.md)) | implemented (fixture + in-process sshd tested) |
| Windows | [windows.md](windows.md) | PowerShell inventory JSON / osquery / live `winreg`: OS build + UBR, Uninstall keys, Appx, Chocolatey, Scoop, .NET | implemented (fixture-tested on Linux; script untested on real Windows) |
| Rootfs | [rootfs.md](rootfs.md) | dpkg/apk/rpm DBs + OS + language packages under a directory (shared with docker-image, docker-engine, ssh) | implemented |
| Process (`process`) | [process.md](process.md) | Running processes: launch origin (launchd daemon/agent, GUI app, terminal, ssh, cron), software identity + version of each executable, provenance (quarantine/download URL, signature, install time), trust flags. Shared core + per-OS backends (macOS now; Linux/Windows designed) | implemented (fixture-tested on Linux; not run on a real Mac) |
| Filesystem (`fs`) | [dependencies.md](dependencies.md) | Folder/repo: lockfiles, manifests, installed packages, Go/Rust binaries, jars (shared lang parser registry; `walk_dir` / `LangAccumulator`) | implemented |

Real-data validation of each collector and the reachability of external hosts: [probe log](../../references/probes.md). Open work: [plans](../../plans/README.md). See [architecture](../architecture.md) for how collectors, the lang registry and the engine fit together, and [features/README.md](../../features/README.md) for the user-facing catalogue.

## Template

New collector docs start from [`_meta/templates/tech-collector.md`](../../_meta/templates/tech-collector.md).
User-facing behaviour of each scan target is described in [`features/`](../../features/).
