---
title: Dart and Flutter packages (pub / Pub)
summary: pubspec.lock fields, dependency kinds and sources (hosted, git, path, sdk), pub.dev hosts and mirrors, PURL form, OSV Pub naming, pitfalls and fixtures.
read_when: you change the Dart pubspec.lock parser, debug a Pub match or need the pubspec.lock format and its quirks
type: reference
context: references
status: implemented
tags: [package-format, dependencies, dart, flutter, pub]
updated: 2026-11-11
verified: 2026-11-11
sample: mixed
fixtures: tests/fixtures/lang/dart/
code: src/secmonk/collectors/lang/dart.py
related: [tech/collectors/dependencies.md, references/vuln-sources/osv.md]
---

# Dart and Flutter packages

PURL `pkg:pub/<name>@<version>`, OSV ecosystem `Pub`; the OSV package name is the pub.dev name (always lowercase
`[a-z0-9_]`).

## Parsers

| Parser | Match | Evidence |
|---|---|---|
| `pubspec-lock` | `pubspec.lock` | lockfile |

`pubspec.yaml` is not parsed: its constraints (`^1.2.0`, `any`) are unpinned. Lockfiles under `.pub-cache/` belong
to downloaded packages and are skipped as vendored. Parsed with the depth-guarded YAML loader shared with pnpm
(`javascript.load_yaml`), 16 MB cap.

## Fields

`packages.<name>`:

| Field | Values | Result |
|---|---|---|
| `dependency` | `direct main` | `meta.direct=true` |
| | `direct dev` | `meta.direct=true`, `meta.dev=true` |
| | `direct overridden` | `meta.direct=true`, `meta.overridden=true` |
| | `transitive` | `meta.direct=false` (never `dev`: the lock does not say which transitives only dev deps pull in) |
| `source` | `hosted` | component when `description.url` is pub.dev, `pub.dartlang.org` (Dart 2 locks) or the `pub.flutter-io.cn` mirror, or absent; **skipped** for other servers (private repositories: a same-named package would be a false positive, same rule as Cargo alternative registries) |
| | `git` | component with the version from the package's pubspec at that ref; `meta.source=git`, `meta.git_url` (credentials removed), `meta.resolved_ref`, `meta.git_path` |
| | `path`, `sdk` | skipped (own packages; `flutter`/`flutter_test` with version `0.0.0`) |
| `version` | `"0.13.1"`, `"0.3.5+1"` | component version |

Top-level `sdks.dart` is kept as `meta.dart_sdk`.

## OSV Pub data (probe 2026-11-11, `Pub/all.zip`, 26 KB, 14 records)

- 11 distinct `Pub` names (`http`, `dio`, `archive`, `shared_preferences_android`, …), purl `pkg:pub/<name>`.
- Ranges `ECOSYSTEM` (20) and `SEMVER` (7); versions include build metadata (`0.3.5+1`); compared with
  `SemverVersion`.

## Fixtures

`tests/fixtures/lang/dart/` (synthetic Dart 3 and Dart 2 locks, real OSV record; see its README).
