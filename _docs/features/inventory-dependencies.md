---
title: Dependency inventory (folders, repos, images, containers, SSH hosts)
summary: Language dependency inventory for npm, Python, Go, Rust, Java, .NET, PHP, Swift and Dart across folders, repos, images, containers and SSH hosts - usage, evidence precedence, acceptance criteria.
read_when: you change how project dependencies are collected or matched, or need the precedence rules between installed metadata, binaries, lockfiles and manifests
type: feature
context: features
status: implemented
tags: [cli, dependencies, collector, npm, python, go, rust, java, dotnet, php, swift, dart]
updated: 2026-11-11
verified: 2026-11-11
code: src/secmonk/collectors/fs.py
related: [tech/collectors/dependencies.md, features/inventory-docker.md, features/inventory-ssh.md, features/inventory-homebrew.md, references/package-formats/README.md, features/README.md]
---

# Dependency inventory

## What the user gets
Every third-party library used by a project or deployed in an image/container/server —
npm, Python (pip/venv/conda/poetry/uv/pipenv), Go, Rust, Java (Maven/Gradle/jars),
.NET (NuGet), PHP (Composer), Swift (SwiftPM `Package.resolved`) and Dart/Flutter (`pubspec.lock`) — matched
exactly against OSV advisories.

| Ecosystem | Files read | OSV ecosystem |
|---|---|---|
| npm | package-lock / shrinkwrap, yarn.lock, pnpm-lock.yaml, bun.lock, node_modules | `npm` |
| Python | dist-info / egg-info, conda-meta, poetry.lock, Pipfile.lock, uv.lock, pdm.lock, pinned requirements | `PyPI` |
| Go | go.mod, go.sum, Go binaries | `Go` |
| Rust | Cargo.lock, cargo-auditable binaries | `crates.io` |
| Java | jars (pom.properties, manifest), pom.xml, gradle.lockfile | `Maven` |
| .NET | *.deps.json, packages.lock.json, project.assets.json, packages.config, project files | `NuGet` |
| PHP | composer.lock, vendor/composer/installed.json | `Packagist` |
| Swift | Package.resolved v1/v2/v3 (SwiftPM, Xcode projects and workspaces) | `SwiftURL` |
| Dart / Flutter | pubspec.lock | `Pub` |

## Usage
```bash
secmonk sync osv -e npm -e PyPI -e Go -e crates.io -e Maven -e NuGet -e Packagist -e SwiftURL -e Pub
secmonk scan fs ./my-service                 # project folder or git repo
secmonk scan fs . -o binaries=false          # lockfiles/manifests/installed only
secmonk scan docker-image ghcr.io/org/app:1.2  # OS packages + language deps + Go/Rust binaries + jars
secmonk scan docker-engine my-container      # live container (runtime-installed deps too)
secmonk scan ssh deploy@10.0.0.5             # remote server (see inventory-ssh)
secmonk scan homebrew                        # Python/npm packages vendored inside Homebrew formulae
secmonk inventory show <asset> --category library
```
Options: `-o binaries=false`, `-o max_files=N` (`fs`); `-o binaries=true` on `ssh` (off by default there).

## Behaviour & rules
- Installed metadata beats binaries beats lockfiles beats manifests for the same package;
  all evidence paths are kept.
- Dev/test dependencies are inventoried and flagged in `meta` (not dropped).
- Unpinned declarations are ignored (no guessing versions): `Package.swift` and `pubspec.yaml` are not read.
- Swift pins on a branch or revision are listed without a version (with a warning) and cannot match;
  Dart packages from self-hosted pub servers, path and SDK packages are not listed.
- Directories are walked with `walk_dir` (fs, rootfs, homebrew, ssh harvest dir); image layers and engine exports are parsed while streaming (`LangAccumulator`).
- Verified 2026-11-07 on real OSV data: `scan fs tests/fixtures/lang` found 453 components in 7 ecosystems with findings in all of them; details in [dependencies](../tech/collectors/dependencies.md).

## Acceptance criteria
- Each ecosystem parser has real (tool-generated) fixtures and tests.
- The same parser results are produced for a folder, an image and an SSH harvest of the same files.
- A known-vulnerable pin (e.g. lodash 4.17.20, log4j-core 2.14.1, golang.org/x/text 0.3.7,
  smallvec 1.6.0, swift-nio-http2 1.19.1, Dart http 0.13.1) produces an `osv-package` finding once the ecosystem
  is synced.

## Implemented by
[tech/collectors/dependencies.md](../tech/collectors/dependencies.md)
