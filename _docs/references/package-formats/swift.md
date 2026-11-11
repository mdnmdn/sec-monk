---
title: Swift packages (SwiftPM / SwiftURL)
summary: SwiftPM Package.resolved v1, v2 and v3 fields, the repository-URL identity used by OSV SwiftURL, PURL form, skipped pin kinds, pitfalls and fixtures.
read_when: you change the Swift Package.resolved parser, debug a SwiftURL match or need the Package.resolved format and its quirks
type: reference
context: references
status: implemented
tags: [package-format, dependencies, swift, swifturl]
updated: 2026-11-11
verified: 2026-11-11
sample: mixed
fixtures: tests/fixtures/lang/swift/
code: src/secmonk/collectors/lang/swift.py
related: [tech/collectors/dependencies.md, references/vuln-sources/osv.md]
---

# Swift packages

PURL `pkg:swift/<host>/<owner>/<repo>@<version>` (purl spec: namespace = host + owner path), OSV ecosystem
`SwiftURL`. OSV names a Swift package by its **repository URL without scheme and `.git`**, so the component name is
`github.com/apple/swift-nio`, the same string the engine looks up in `affected.package` (lowercased on both sides).

## Parsers

| Parser | Match | Evidence |
|---|---|---|
| `swift-package-resolved` | `Package.resolved` (SwiftPM root, `*.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/`, `*.xcworkspace/xcshareddata/swiftpm/`) | lockfile |

`Package.swift` is not parsed: it is Swift source and its requirements (`from:`, `.upToNextMajor`, ranges) are
unpinned. Lockfiles under `.build/checkouts/` (swift build) and `SourcePackages/checkouts/` (Xcode) belong to
dependencies and are skipped as vendored.

## Fields

| Format | Pins | Fields used |
|---|---|---|
| v1 (SwiftPM < 5.6) | `object.pins[]` | `package`, `repositoryURL`, `state.{version,revision,branch}` |
| v2 (5.6+) | `pins[]` | `identity`, `kind`, `location`, `state.{version,revision,branch}` |
| v3 (5.9+ / Xcode 15) | `pins[]` + top-level `originHash` | as v2 |

| Value | Result |
|---|---|
| `location` / `repositoryURL` https, ssh, `git@host:owner/repo.git` | `host/path` without user, port and `.git`; host lowercased, path case kept |
| `state.version` | component version (a leading `v` is stripped, raw kept as `meta.raw_version`) |
| no `state.version` (branch or revision pin) | component with `version=None`, `meta.revision` / `meta.branch`, one warning per file: inventoried, not matchable |
| `kind: fileSystem` / `localSourceControl`, file paths | skipped (the project's own code) |
| `kind: registry` (identity `scope.name`) | skipped with a warning: OSV has no data keyed by registry identity |
| credentials in the URL | removed from `meta.location` (`strip_url_secrets`) |

Package.resolved has no direct/transitive or dev information.

## OSV SwiftURL data (probe 2026-11-11, `SwiftURL/all.zip`, 113 KB, 64 records)

- 33 distinct `SwiftURL` package names; 30 are `github.com/<owner>/<repo>` (e.g. `github.com/apple/swift-nio-http2`,
  `github.com/vapor/vapor`, mixed case kept: `github.com/marmelroy/Zip`), with purl `pkg:swift/github.com/...`.
- Three names are **not** URLs (`CocoaMQTT`, `swift-crypto`, `swift-nio-http2`): they can never match a
  Package.resolved pin. Tracked in [engine-and-quality.md](../../plans/engine-and-quality.md).
- Ranges are `SEMVER` (98) and `ECOSYSTEM` (48), versions bare (`1.19.2`, `2.0.0-alpha.1`); compared with
  `SemverVersion`.

## Fixtures

`tests/fixtures/lang/swift/` (synthetic lockfiles, one per format version, real OSV record; see its README).
