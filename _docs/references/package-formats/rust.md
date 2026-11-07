---
title: Rust Cargo.lock and cargo-auditable binaries
type: reference
context: references
status: implemented
tags: [package-format, dependencies, rust, binary]
updated: 2026-11-07
sample: mixed
fixtures: tests/fixtures/lang/rust/
code: src/secmonk/collectors/lang/rust.py
related: [tech/collectors/dependencies.md]
---

# Rust: Cargo.lock and cargo-auditable binaries

OSV ecosystem `crates.io`, PURL type `cargo` (`pkg:cargo/smallvec@1.6.0`, no namespace).

**Fixture provenance.** `Cargo.lock` / `Cargo.toml` are real (`cargo generate-lockfile` for smallvec `=1.6.0`
and time `=0.1.43`, v4 lockfile, no build). `hello-auditable-linux-x86_64` is **semi-synthetic**: a real
zero-dependency stripped hello-world (341 KB) with a hand-made `.dep-v0` section added by
`objcopy --add-section` (zlib JSON in the cargo-auditable schema). `hello-plain-linux-x86_64` is the same
program without the section (the non-auditable case). No third-party crate was compiled.

## Cargo.lock (v1-v4)

TOML `[[package]]` tables (`name`, `version`, optional `source`, `checksum`, `dependencies`). Emitted:
registry sources `registry+https://github.com/rust-lang/crates.io-index` and `sparse+https://index.crates.io/`.
Skipped: packages **without `source`** (the workspace's own crates and path dependencies; they are the project,
not a dependency), **git sources** (`git+https://...#sha`; not in OSV crates.io, a name match would be a false
positive) and **alternative registries**. v1 lockfiles list the same tables (plus a `[metadata]` checksum
table, ignored). `meta.lock_version` records the file's `version`.

`Cargo.toml` is not parsed: requirements such as `^1.2` are unpinned, so no version can be claimed.

## cargo-auditable binaries

Section `.dep-v0` holds zlib-compressed JSON:

```json
{"packages":[{"name":"smallvec","version":"1.6.0","source":"crates.io","kind":"runtime",
              "dependencies":[2],"root":true}]}
```

`source` is `crates.io`, `registry`, `git`, `local` or `other`; `kind` is `runtime` or `build`; `dependencies`
are indices into `packages`; `root: true` is the binary's own crate (skipped). Only `crates.io` is emitted;
build-kind packages are emitted with `meta.kind="build"` (not linked into the binary, but part of what
was built). Decompression is capped at 64 MB.

Locating the section (pure Python, `rust.py`):

- **ELF** 32/64-bit, LE/BE: `e_shoff` (0x28 / 0x20), `e_shentsize/e_shnum/e_shstrndx`, section header
  (`sh_name`, `sh_offset`, `sh_size`), names from the `.shstrtab`.
- **Mach-O 64** (cffaedfe / feedfacf): header 32 bytes, `LC_SEGMENT_64` (0x19) load commands; each section
  header is 80 bytes (`sectname[16] segname[16] addr size offset ...`); the name `.dep-v0` is matched in any segment.
- **PE**: `e_lfanew` at 0x3C, COFF header, 40-byte section headers.

## Pitfalls / known gaps

- **Non-auditable Rust binaries** carry no dependency list. Stripped, they yield nothing (only `rustc` version
  strings and registry paths in panic messages remain; not parsed). Most distro-built Rust tools are in this
  group; adoption of `cargo auditable` is growing (Alpine, Arch, Fedora enable it).
- Fat Mach-O and 32-bit Mach-O are not read.
- Alternative-registry and git dependencies are invisible to OSV matching by design.
- Cargo.lock in a library crate is often not committed; then nothing is found for the project.
