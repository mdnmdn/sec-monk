---
title: JavaScript packages (npm, yarn, pnpm, bun)
type: reference
context: references
status: implemented
tags: [package-format, dependencies, npm]
updated: 2026-11-07
sample: mixed
fixtures: tests/fixtures/lang/javascript/
code: src/secmonk/collectors/lang/javascript.py
related: [tech/collectors/dependencies.md]
---

# JavaScript packages

PURL `pkg:npm/<name>@<version>`; scope becomes the namespace (`@babel/code-frame` ->
`pkg:npm/%40babel/code-frame@7.12.13`, name shown as `@babel/code-frame`). OSV ecosystem `npm`.
Every parser matches on the **basename** so it works on folders, repos and image filesystems.

## Parsers

| Parser | Match | Evidence | Notes |
|---|---|---|---|
| `npm-package-lock` | `package-lock.json`, `npm-shrinkwrap.json` | lockfile | v1 `dependencies` tree; v2/v3 `packages` map |
| `yarn-lock` | `yarn.lock` | lockfile | v1 custom format or berry (has `__metadata:`) |
| `pnpm-lock` | `pnpm-lock.yaml` | lockfile | lockfileVersion 5.x, 6.0, 9.0 |
| `bun-lock` | `bun.lock` | lockfile | text JSONC (Bun >= 1.2); binary `bun.lockb` is not read |
| `node-modules` | `.../node_modules/<pkg>/package.json` | installed | needs `name` + `version` |

## Formats and fields

**package-lock.json** (npm 10.9 wrote v1/v2/v3 on request; fixtures generated with `--lockfile-version 1|2|3`).

| Field | Use |
|---|---|
| `packages["node_modules/a/node_modules/b"]` | name = text after the LAST `node_modules/`; `name` field wins (aliases) |
| `packages[""]` | root project - skipped; keys without `node_modules/` (workspace folders) skipped |
| `link: true` | skipped (symlink to workspace) |
| `inBundle` / `bundled` | emitted with `meta.bundled=true` (shipped inside another package's tarball; still on disk) |
| `dev`, `optional`, `peer`, `devOptional` | meta `dev`/`optional`/`peer`/`dev_optional` = true |
| `resolved` | meta `resolved_host` (registry host, `git` for git urls); `file:` skipped |
| v1 `version: "npm:real@1.0.0"` | alias -> real name/version |
| v1 `version: "github:o/r#sha"` | emitted with `version=None`, meta `non_registry_version` |

**yarn.lock v1**: blocks `"spec1", "spec2":` then indented `version "x"`, `resolved "url#sha1"`. Name is taken
from the first spec (first `@` after index 0, so scopes and git URLs containing `@` work); `foo@npm:bar@^1` aliases map to `bar`.

**yarn berry** (valid YAML): key `"name@npm:^1"`, `resolution: "name@npm:1.2.3"`. Entries whose resolution is
`workspace:`, `portal:`, `link:`, `exec:`, git or http are skipped. `patch:` resolutions
(`fsevents@patch:fsevents@npm%3A2.3.2#...`) yield the inner npm version (meta `patched`); the plain npm entry normally
exists as well and the two merge. No dev/prod information exists in the lockfile.

**pnpm-lock.yaml**: v5 keys `/name/1.2.3_peer@1`, `/@scope/name/1.2.3`; v6 `/name@1.2.3(peer@1)`; v9
`name@1.2.3(peer@1)` in `packages:` (metadata) + `snapshots:` (instances, peer suffix). Both sections are read and
deduplicated; suffix after `_`/`(` is dropped; keys with `link:`/`file:`/URL versions are skipped; `name`/`version`
fields (tarball deps) override the key. `dev`/`optional` flags exist only in v5/v6; v9 has none (scope unknown).

**bun.lock**: JSONC (trailing commas). `packages` map: `"key": ["name@1.2.3", registry, {deps}, integrity]`; ids
with `workspace:`/`github:`/`file:`/`link:` skipped; `npm:` aliases resolved. `dev_direct` is set for root
`devDependencies` only (transitive dev status is not in the file).

**node_modules/**/package.json**: only when the path's last two segments are `node_modules/<name or @scope/name>/package.json`.
`node_modules/lodash/test/fixtures/package.json` and a project's own `package.json` are NOT read. pnpm's
`.pnpm/<id>/node_modules/<name>/package.json` layout matches. Meta `license`.

## Pitfalls

- npm lockfile `version` can be non-semver (git/tarball URLs): never put those into the PURL.
- `dev` is lost by yarn (all) and pnpm v9; do not infer "prod" from its absence there.
- Yarn berry lists `node-gyp` etc. for optional native deps (real, not a bug in the parser).
- The same name can occur at several versions (nested node_modules) - each version is its own component.

## Fixtures

Real (generated with npm 10.9.9 / yarn 1.22 / yarn 4 / pnpm 8+9 / bun 1.2, `--ignore-scripts`, registry-resolved, project
with lodash 4.17.20, minimist 1.2.5, @babel/code-frame 7.12.13, semver 7.3.5 (dev), fsevents 2.3.2 (optional)):
`npm-v1|v2|v3/package-lock.json`, `yarn-v1/yarn.lock`, `yarn-berry/yarn.lock`, `pnpm-v6|v9/pnpm-lock.yaml`,
`bun/bun.lock`, `installed/node_modules/**/package.json` (real files; the `lodash/test/fixtures/package.json` one is
synthetic). Edge cases (aliases, git versions, v5 pnpm keys, patch-only berry) are inline synthetic data in
`tests/collectors/lang/test_javascript.py`.


## YAML safety

yarn berry and pnpm lockfiles are YAML. libyaml's C parser overflows the C stack (segfault, killing the whole
scan) on deeply nested input, so `load_yaml()` estimates nesting first (flow brackets, indentation, `- - -`
chains): more than 200 levels is rejected with a warning; more than 40 uses the pure-Python SafeLoader;
otherwise CSafeLoader. Berry `resolution` suffixes such as `::__archiveUrl=...` are stripped from the version.
