---
title: Package formats
summary: Index of the per-ecosystem package format references read by the language parsers, with PURL type and the files each one covers.
read_when: you look for the document that covers a language ecosystem's lockfiles, manifests or binaries
type: reference
context: references
status: reference
tags: [package-format, dependencies]
updated: 2026-11-07
verified: 2026-11-07
related: [tech/collectors/dependencies.md]
---

# Package formats

Formats read by the language parsers (`src/secmonk/collectors/lang/`).

| Doc | Ecosystem / PURL | Covers |
|---|---|---|
| [go.md](go.md) | Go / `pkg:golang` | go.mod, go.sum, Go binary build info (ELF/Mach-O/PE) |
| [rust.md](rust.md) | crates.io / `pkg:cargo` | Cargo.lock v1-v4, cargo-auditable `.dep-v0` binaries |
| [java.md](java.md) | Maven / `pkg:maven` | jar/war/ear/fat/shaded jars (pom.properties, MANIFEST, filename), pom.xml, gradle.lockfile, gradle verification-metadata |
| [dotnet.md](dotnet.md) | NuGet / `pkg:nuget` | *.deps.json (apps + shared runtime), packages.lock.json, project.assets.json, packages.config, csproj/fsproj/vbproj, Directory.Packages.props |
| [javascript.md](javascript.md) | npm / `pkg:npm` | package-lock.json v1/v2/v3, npm-shrinkwrap.json, yarn.lock v1 + berry, pnpm-lock.yaml v5-v9, bun.lock, installed node_modules/**/package.json |
| [python.md](python.md) | PyPI / `pkg:pypi` (+ `pkg:conda`) | installed dist-info/egg-info, conda-meta, poetry.lock, Pipfile.lock, uv.lock, pdm.lock, pinned requirements*.txt |
| [php.md](php.md) | Packagist / `pkg:composer` | composer.lock, vendor/composer/installed.json (Composer 1 + 2) |
