---
title: Go modules and binaries
type: reference
context: references
status: implemented
tags: [package-format, dependencies, go, binary]
updated: 2026-11-07
sample: real
fixtures: tests/fixtures/lang/go/
code: src/secmonk/collectors/lang/golang.py
related: [tech/collectors/dependencies.md]
---

# Go modules and binaries

OSV ecosystem `Go`, PURL type `golang`. Fixtures are real: a tiny module (golang.org/x/text v0.3.7,
github.com/google/uuid with a `replace`, a local-path `replace`) built with Go 1.24.7,
`CGO_ENABLED=0 -trimpath -ldflags="-s -w"` for linux/amd64 and darwin/arm64 (about 2 MB each).
`tests/fixtures/lang/go/osv/` holds two real OSV records (GO-2022-1059, GO-2021-0069).

## PURL / OSV mapping

| Thing | PURL | OSV package name |
|---|---|---|
| module `golang.org/x/text` | `pkg:golang/golang.org/x/text@0.3.7` | `golang.org/x/text` |
| standard library | `pkg:golang/stdlib@1.24.7` (category `runtime`) | `stdlib` |

- **Versions have no leading `v`.** Checked over the whole OSV Go database (31k range events, none start with
  `v`): `v0.3.7` -> `0.3.7`. Pseudo-versions (`0.0.0-2020...-abc`) and `+incompatible` stay verbatim
  (PURL encodes `+` as `%2B`).
- **stdlib** versions: `go1.22.3` -> `1.22.3`, `go1.21` -> `1.21.0`, `go1.22rc1` -> `1.22.0-rc.1`;
  `devel ...` -> unversioned. OSV stdlib ranges look like `introduced 1.14.0-0 / fixed 1.14.12`.
- Matching is proven in `test_golang.py::test_osv_range_real_records` via `in_osv_range`.

## go.mod (manifest)

`require` (single-line or block), `// indirect` -> `meta.direct=False`, `go`/`toolchain` lines -> meta.
`replace old [ver] => new ver` is applied (component becomes `new@ver`, `meta.replaced_from`);
a version-specific replace beats a generic one. A replacement to a local directory (`./`, `../`, `/`, drive
path) drops the module. `exclude` and `retract` are ignored. `vendor/` directories are not special: a
`vendor/modules.txt` is not parsed (the go.mod/binary give the same answer).

## go.sum (lockfile)

`module version h1:` lines -> components with `meta.gosum=True`. `module version/go.mod h1:` lines are
skipped: they only prove the go.mod was read for the dependency graph. go.sum **over-approximates** (old versions
linger after upgrades) and knows nothing of `replace`; **go.mod wins when both exist**. Parsers are
per-file, so the walker/consumer should drop `gosum` components when a sibling go.mod was parsed.

## Binaries (the important case)

Go >= 1.13 embeds `runtime/debug.BuildInfo` in every executable, **even stripped** (`-s -w` removes
symbols/DWARF, not this section). Layout (`.go.buildinfo`, 16-byte aligned):

```
off  size
0    14   magic  \xff Go buildinf:
14   1    pointer size (4/8)
15   1    flags: bit0 = big-endian, bit1 = strings inline (Go >= 1.18)
16   16   unused (inline format)
32   ..   uvarint len + runtime version  ("go1.24.7")
..   ..   uvarint len + modinfo text
```

modinfo is framed by 16-byte sentinels (`modinfo` is `sentinel + text + sentinel`, strip when byte -17 is `\n`).
Text lines, tab separated: `path <main pkg>`, `mod <path> <ver|(devel)> <sum>`, `dep <path> <ver> <h1>`,
`=> <path> <ver> <h1>` (replacement of the preceding dep), `build <k>=<v>` (GOOS, GOARCH, vcs.revision, -trimpath...).

Implementation: scan the first 64 MB for the magic at a 16-byte-aligned *file* offset. This is
format-agnostic (ELF, Mach-O, PE) and needs no section parsing. Detection: `\x7fELF`, thin Mach-O
(feedface/feedfacf, either endianness), `MZ`; fat Mach-O (`cafebabe`) is skipped because it collides with Java
classes. Emits: stdlib (runtime), main module (`meta.main`, `(devel)` -> no version), every dep (replacement
used, `meta.replaced_from`); build settings in `meta.build`.

## Pitfalls

- **Go < 1.18** stores pointers to the strings instead of inline data (flags bit1 clear); resolving them needs
  the container's section/segment tables. Not supported: such binaries yield nothing.
- Go 1.13-1.17 binaries also lack the inline form; very old (<1.13) have no build info at all.
- Binaries built with `-buildvcs`/`go build` without module mode (GOPATH) have no `dep` lines.
- Local-directory replacements are dropped (no OSV identity); versions `(devel)` on the main module mean a
  local build, not a release.
- UPX-packed or garble-obfuscated binaries may hide the magic.
- The binary lists *modules*, not the packages actually linked: findings are over-approximate (govulncheck
  symbol analysis is out of scope).
