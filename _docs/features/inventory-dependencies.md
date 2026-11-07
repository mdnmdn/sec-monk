---
title: Dependency inventory (folders, repos, images, containers, SSH hosts)
type: feature
context: features
status: implemented
tags: [cli, dependencies, collector, npm, python, go, rust, java, dotnet, php]
updated: 2026-11-07
code: src/secmonk/collectors/fs.py
related: [tech/collectors/dependencies.md, features/inventory-docker.md, features/inventory-ssh.md, features/inventory-homebrew.md, references/package-formats/README.md, features/README.md]
---

# Dependency inventory

## What the user gets
Every third-party library used by a project or deployed in an image/container/server —
npm, Python (pip/venv/conda/poetry/uv/pipenv), Go, Rust, Java (Maven/Gradle/jars),
.NET (NuGet) and PHP (Composer) — matched exactly against OSV advisories.

## Usage
```bash
secmonk sync osv -e npm -e PyPI -e Go -e crates.io -e Maven -e NuGet -e Packagist
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
- Unpinned declarations are ignored (no guessing versions).
- Directories are walked with `walk_dir` (fs, rootfs, homebrew, ssh harvest dir); image layers and engine exports are parsed while streaming (`LangAccumulator`).
- Verified 2026-11-07 on real OSV data: `scan fs tests/fixtures/lang` found 453 components in 7 ecosystems with findings in all of them; details in [dependencies](../tech/collectors/dependencies.md).

## Acceptance criteria
- Each ecosystem parser has real (tool-generated) fixtures and tests.
- The same parser results are produced for a folder, an image and an SSH harvest of the same files.
- A known-vulnerable pin (e.g. lodash 4.17.20, log4j-core 2.14.1, golang.org/x/text 0.3.7,
  smallvec 1.6.0) produces an `osv-package` finding once the ecosystem is synced.

## Implemented by
[tech/collectors/dependencies.md](../tech/collectors/dependencies.md)
