---
title: Language dependency scanning
type: tech
context: tech
status: implemented
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
(`meta.paths`). The scope flags `dev`/`optional`/`dev_optional`/`peer` survive only if every merged
instance carries them. A parser may return `list[Component]` or `(list[Component], list[str])`; the second
form lets it add warnings without failing (e.g. Go-looking binary without build info). Per-entry
construction goes through `safe_library()`, so one malformed entry never drops the rest of a file.

**Vendored files are not project evidence**: lockfile and manifest parsers are skipped for paths inside
`node_modules`, `site-packages`, `dist-packages`, `vendor` and `.cargo/registry|git`; installed-metadata
parsers (`package.json` in node_modules, dist-info, `vendor/composer/installed.json`) and binaries still run. Unpinned declarations (ranges, `pyproject.toml`, `Cargo.toml`) are not reported.

## Walkers

- **`walk_dir()`** — `os.walk`, no symlink following, prunes VCS/IDE/cache dirs (`SKIP_DIRS`; `.tox`/`.nox`
  test environments stay pruned, `.next`/`.nuxt` only lose their `cache` dir) and,
  for rootfs mode, `/proc /sys /dev /run`. Path pre-filter `wants(path)`, then reads 512 bytes for
  `sniff` (binaries are recognized by magic bytes), size caps per parser
  (`max_binary_bytes` default 256 MB), file-count cap. Files are opened with `O_NOFOLLOW|O_NONBLOCK`,
  checked with `fstat` (regular files only; FIFOs/devices/symlink swaps are refused) and read with a
  `cap+1` limit, so a race between `lstat` and `open` cannot cause a hang or an oversized read.
  Binary parsers only see executables: `*.so`, `*.so.*`, `*.node`, `*.dylib`, ELF objects/shared
  libraries without exec bit or `PT_INTERP` are skipped (`binary_candidate()`).
- **`LangAccumulator`** — for image layers streamed bottom-up: parses each wanted member as it
  streams and keeps **only parsed components per path**; whiteouts / opaque dirs / later
  overwrites remove or replace them. `feed(..., layer=, mode=)` and
  `remove_under(prefix, only_older=, layer=)` track the layer generation of each path, so a whiteout
  only removes entries of *older* layers. Memory stays proportional to the number of components, not
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

## Verified end to end (2026-11-07, real OSV data)

| Target | Result |
|---|---|
| `scan fs tests/fixtures/lang` | 453 components in 7 ecosystems → findings in all of them, e.g. log4j-core 2.14.1 → CVE-2021-44228 **P1 (KEV)**, golang.org/x/text 0.3.7 → CVE-2022-32149, smallvec 1.6.0 → CVE-2021-25900, guzzle 7.4.0, lodash 4.17.20, minimist 1.2.5, requests 2.25.0 |
| `scan docker-image python:3.12-slim` | pip 25.0.1 from site-packages via streaming layers |
| `scan docker-image registry:2` | Go binary `/bin/registry` → stdlib 1.20.8 → 85 findings (exact `osv-package`) |

Runtimes that carry an OSV ecosystem (Go `stdlib`, `pkg:npm/electron`, .NET runtime packs) use
exact package matching too.

## Known gaps

- Interpreters installed from source (e.g. CPython in `python:*` images under `/usr/local`) are not
  detected as runtimes yet.
- Go binaries built without modules (GOPATH mode) expose only the stdlib version.

See each format doc in [references/package-formats](../../references/package-formats/README.md).
Cross-cutting: no reachability analysis; vendored/copied source without metadata is invisible;
unpinned manifests are skipped by design.
