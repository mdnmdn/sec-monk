---
title: GitHub Advisory Database
type: reference
context: references
status: draft
tags: [vuln-source, ghsa, osv, github]
updated: 2026-11-07
sample: real
reachable: partial
fixtures: tests/fixtures/sources/ghsa/
related: [references/vuln-sources/osv.md, tech/engine/matching.md]
---

# GitHub Advisory Database (GHSA)

## Summary

`github/advisory-database` is the repository behind GitHub security advisories, published **in OSV format**
(schema 1.4.0 in the repo copy). The prototype does not ingest it directly: the OSV bulk data already contains
every *reviewed* advisory, enriched. Field semantics are in [osv.md](osv.md).

## Access

| What | Result (2026-11-07) |
|---|---|
| `git clone --depth 1 --filter=blob:none https://github.com/github/advisory-database` | works (tree: 37,571 reviewed + 363,332 unreviewed JSON files; HEAD 2026-11-07) |
| `raw.githubusercontent.com/github/advisory-database/main/<path>` | works for files, 404 for directories (no listings) |
| `api.github.com` (REST/GraphQL advisories API), github.com HTML | blocked |

Layout: `advisories/github-reviewed/YYYY/MM/GHSA-xxxx-xxxx-xxxx/GHSA-xxxx-xxxx-xxxx.json` and
`advisories/unreviewed/YYYY/MM/GHSA-.../GHSA-....json` (year/month = **published** month; a modified advisory stays in
its original folder). Example raw URL:
`https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2021/12/GHSA-jfh8-c2jp-5v3q/GHSA-jfh8-c2jp-5v3q.json`.

## Data format

Fixture: `tests/fixtures/sources/ghsa/GHSA-jfh8-c2jp-5v3q.json` (log4j, raw repo copy).

Same top-level keys as OSV (`schema_version`, `id`, `modified`, `published`, `aliases`, `summary`, `details`, `severity`, `affected`,
`references`, `database_specific`). Differences vs. the OSV-bulk copy of the same advisory (compare
`osv/maven-GHSA-jfh8-c2jp-5v3q.json`):

| Aspect | Repo copy | OSV bulk copy |
|---|---|---|
| `schema_version` | `1.4.0` | `1.9.0`/`1.9.2` |
| `modified` | `2025-10-22T19:13:24Z` | `2025-10-22T19:37:02.616807Z` (OSV re-stamps) |
| `affected[].package.purl` | absent | present (`pkg:maven/org.apache.logging.log4j/log4j-core`) |
| `affected[].versions[]` | absent | enumerated published versions in range |
| `affected[].database_specific.source` | absent | URL of repo file |
| `database_specific` | `cwe_ids`, `severity`, `github_reviewed`, `github_reviewed_at`, `nvd_published_at` | same |

Unreviewed advisories (NVD-imported, GitHub has not matched packages) usually have `"affected": []` and are **not in OSV bulk**
(checked: `GHSA-m5pg-8h68-j225` returns 404 in the PyPI/npm/Maven/Go/crates.io/RubyGems buckets). Reviewed ones are
(`GHSA-jfh8-c2jp-5v3q` in `Maven/`, `GHSA-x4vh-j75g-268g` in `npm/`, `GHSA-fhq3-2gf3-8f3j` in `PyPI/` all confirmed).

## Mapping

Identical to [osv.md](osv.md#mapping). GHSA specifics: `database_specific.cwe_ids` -> cwe column, `database_specific.severity`
(`LOW|MODERATE|HIGH|CRITICAL`) -> severity label, `aliases` normally holds the CVE id.

## Quirks & pitfalls

- Use OSV bulk for GHSA (purl + versions + one-stop delta). Only clone this repo if unreviewed advisories are wanted (no packages -> useless for matching).
- The same GHSA id appears in several OSV ecosystem folders when an advisory spans ecosystems.
- A GHSA with a `PYSEC`/`GO` sibling: link through `aliases`, dedupe on CVE.

## Status / TODO

No direct importer planned; reachable via OSV (`git`/raw only as a cross-check).
