---
title: Language dependency scanning
type: tech
context: tech
status: draft
tags: [collector, dependencies, npm, python, go, rust, java, dotnet, php]
updated: 2026-11-07
code: src/secmonk/collectors/lang/
fixtures: tests/fixtures/lang/
related: [features/inventory-dependencies.md, references/package-formats/README.md, tech/collectors/rootfs.md, tech/collectors/ssh.md]
---

# Language dependency scanning

One set of **file parsers**, three ways of feeding them files:

```
                      collectors/lang/  (registry of LangParser)
     javascript.py  python.py  php.py  golang.py  rust.py  java.py  dotnet.py
                 ▲                    ▲                          ▲
                 │ walk_dir()         │ walk_dir(rootfs=True)    │ LangAccumulator.feed()
        ┌────────┴───────┐   ┌────────┴─────────┐      ┌─────────┴──────────┐
        │ fs collector   │   │ rootfs / DirView │      │ docker-image layers│
        │ project / repo │   │ ssh harvest dir  │      │ docker-engine export│
        └────────────────┘   └──────────────────┘      └────────────────────┘
```

## Parser contract (`lang/base.py`)

`LangParser(name, ecosystem, evidence, match(path), parse(path, bytes), sniff(head)?, binary?)`.
Parsers are pure functions of `(relative path, content)`; they return `CAT_LIBRARY`
components with a PURL (→ OSV ecosystem via `engine/purl.PURL_TO_OSV`) and
`meta.evidence`, `meta.parser`, plus scope hints (`dev`, `direct`, `optional`, …).

| Evidence | Meaning | Examples |
|---|---|---|
| `installed` | What is actually on disk | `*.dist-info/METADATA`, `node_modules/*/package.json`, `vendor/composer/installed.json`, `*.deps.json` |
| `binary` | Build info embedded in an artifact | Go buildinfo, Rust `.dep-v0` (cargo-auditable), jar `pom.properties` |
| `lockfile` | Resolved dependency graph | package-lock, yarn.lock, pnpm-lock, poetry.lock, uv.lock, Pipfile.lock, composer.lock, go.sum, Cargo.lock, packages.lock.json, gradle.lockfile |
| `manifest` | Declared + pinned | requirements `==`, go.mod, pom.xml literal versions, csproj PackageReference |

`dedupe()` merges identical PURLs across files, keeping the strongest evidence and all paths
(`meta.paths`). Unpinned declarations (ranges, `pyproject.toml`, `Cargo.toml`) are not reported.

## Walkers

- **`walk_dir()`** — `os.walk`, no symlink following, prunes VCS/IDE/cache dirs (`SKIP_DIRS`) and,
  for rootfs mode, `/proc /sys /dev /run`. Path pre-filter `wants(path)`, then reads 512 bytes for
  `sniff` (binaries are recognized by magic bytes), size caps per parser
  (`max_binary_bytes` default 256 MB), file-count cap.
- **`LangAccumulator`** — for image layers streamed bottom-up: parses each wanted member as it
  streams and keeps **only parsed components per path**; whiteouts / opaque dirs / later
  overwrites remove or replace them. Memory stays proportional to the number of components, not
  to binary sizes.

## Options

| Option | Default | Effect |
|---|---|---|
| `-o binaries=false` | true | skip Go/Rust executables and jars (faster on big trees) |
| `-o max_files=N` | 200000 | stop after N parsed files |

## Matching

Components carry OSV ecosystems (`npm`, `PyPI`, `Go`, `crates.io`, `Maven`, `NuGet`,
`Packagist`) and go through the exact `osv-package` strategy (confidence 1.0). Sync the
ecosystems you need: `secmonk sync osv -e npm -e PyPI -e Go -e crates.io -e Maven -e NuGet -e Packagist`.

## Known gaps

See each format doc in [references/package-formats](../../references/package-formats/README.md).
Cross-cutting: no reachability analysis; vendored/copied source without metadata is invisible;
unpinned manifests are skipped by design.
