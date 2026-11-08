---
title: PHP packages (Composer / Packagist)
summary: Composer composer.lock and vendor/composer/installed.json fields, PURL form, the v version prefix versus OSV ranges, dev branches, pitfalls and fixtures.
read_when: you change the PHP Composer parser, debug a Packagist version match or need the lockfile format and its quirks
type: reference
context: references
status: implemented
tags: [package-format, dependencies, packagist, php]
updated: 2026-11-07
verified: 2026-11-07
sample: mixed
fixtures: tests/fixtures/lang/php/
code: src/secmonk/collectors/lang/php.py
related: [tech/collectors/dependencies.md]
---

# PHP packages

PURL `pkg:composer/<vendor>/<name>@<version>`, OSV ecosystem `Packagist`; name as OSV spells it is `vendor/name`.

## Parsers

| Parser | Match | Evidence |
|---|---|---|
| `composer-lock` | `composer.lock` | lockfile |
| `composer-installed` | `<any dir>/composer/installed.json` (normally `vendor/composer/installed.json`) | installed |

## Fields

| Field | Use |
|---|---|
| `packages[]`, `packages-dev[]` (lock) | `packages-dev` => meta `dev` |
| installed.json Composer 2: `{"packages": [...], "dev": true, "dev-package-names": [...]}` | names in `dev-package-names` => `dev` |
| installed.json Composer 1: plain list | no dev info |
| `name` | `vendor/name` -> namespace + name |
| `version` | `v1.43.0` -> `1.43.0` (raw kept as meta `raw_version`) |
| `source.reference` | meta `reference` (git commit) |
| `license[]`, `abandoned`, `type` | meta |

## Version prefix `v` (verified)

Downloaded `Packagist/all.zip` from osv-vulnerabilities.storage.googleapis.com (11 MB): in all 1591 packages the
`ECOSYSTEM` range events (`introduced`/`fixed`) are **bare** (0 of them start with `v`), e.g. `symfony/symfony` fixed
`5.1.43`; so a lock version `v5.1.40` must compare as `5.1.40`. However the explicit `affected[].versions` lists
mirror Packagist tags and are mostly `v`-prefixed (7987 of 22907 distinct strings; e.g. symfony/symfony 25261 `v...` vs
163 bare entries, guzzlehttp/guzzle mixed). The matcher should therefore use ranges, and when comparing against
`versions` lists try both `1.2.3` and `v1.2.3`.

## Dev branches

`dev-master`, `dev-main`, `1.x-dev` are VCS branches, not releases: emitted with `version=None`, meta `dev_branch`
(visible in the inventory, never matched). PURL without version.

## Pitfalls

- A lock version `V2.0.0` (uppercase) is also normalized.
- `installed.json` lists only installed packages; platform requirements (`php`, `ext-*`) never appear.
- Packages with `replace`/`provide` (e.g. `symfony/symfony` replaces components) are not expanded.

## Fixtures

Real (Composer 2, `guzzlehttp/guzzle 7.4.0` + `phpunit/phpunit 9.5.0` dev, trimmed to a few packages and slimmed of
`require`/`autoload` keys): `composer2/composer.lock`, `composer2/vendor/composer/installed.json`. Synthetic Composer 1
list with a `dev-master` entry: `composer1/vendor/composer/installed.json`.
