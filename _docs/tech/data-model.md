---
title: Data model (SQLite schema)
type: tech
context: tech
status: implemented
tags: [data-model, sqlite, matching]
updated: 2026-11-07
code: src/secmonk/db.py
related: [decisions/0002-sqlite-local-mirror.md, tech/engine/matching.md, tech/architecture.md, references/vuln-sources/debian-tracker.md]
---

# Data model

The authoritative DDL is in `src/secmonk/db.py` (`SCHEMA`, `SCHEMA_VERSION = 2`). This page explains intent.

## Schema version and migrations

| Item | Behaviour |
|---|---|
| `PRAGMA user_version` | Set to `SCHEMA_VERSION` (2) on every connect. |
| Create | `init_schema()` runs the whole `SCHEMA` with `CREATE TABLE/INDEX IF NOT EXISTS`, so new tables (e.g. `distro_triage`) appear on existing DBs. |
| Added columns | `_ADDED_COLUMNS` (`finding.triage`, `finding.triage_source`) are added with `ALTER TABLE ... ADD COLUMN` when missing (lightweight, additive only; no data rewrite). |
| Connection | WAL, `synchronous=NORMAL`, foreign keys on. |

Schema v2 = v1 + `distro_triage` + `finding.triage` / `finding.triage_source`.

## Vulnerability mirror

| Table | Key | Purpose |
|---|---|---|
| `source_sync` | `source` | Last sync, status (`ok` / `error` / `partial`), delta cursor. OSV keeps per-ecosystem rows `osv:<Ecosystem>`; one row each for `cvelist`, `kev`, `epss`, `nvd`, `euvd`, `msrc`, `debian-tracker`. |
| `raw_record` | `(source, record_id)` | Verbatim JSON as published — re-normalize without re-downloading. |
| `vulnerability` | `(source, id)` | Normalized facts per source: summary, dates, `state`/`withdrawn`, CVSS (score/vector/version), severity, CWEs, `extra` JSON (SSVC, ADP KEV, references…). |
| `alias` | `(vuln_id, alias, source)` | Undirected id edges (GHSA ↔ CVE, DEBIAN-CVE ↔ CVE, EUVD ↔ CVE). |
| `affected` | autoinc | What is affected — see below. |
| `kev` | `cve_id` | CISA KEV catalog (full snapshot). |
| `epss` | `cve_id` | Latest EPSS score/percentile (no history yet; FIRST import replaces, EUVD-derived rows never overwrite). |
| `distro_triage` | `(ecosystem, package, cve_id, source)` | What a distro security team decided beyond affected ranges: see below. |

### `affected` — package-based and product-based rows in one table

| `range_type` | Producer | Lookup columns | Version data | Matched? |
|---|---|---|---|---|
| `ECOSYSTEM`, `SEMVER` | osv | `ecosystem` (normalized, e.g. `Debian:12`, `Ubuntu:22.04`, `Red Hat:9`), `package` (normalized name; source package for distros) | `events` (OSV events) | yes: `osv-package` |
| `VERSIONS` | osv (only when the entry has no ECOSYSTEM/SEMVER range) | same | `versions` explicit list | yes: `osv-package` |
| `GIT` | osv, cvelist | none | commit events | no, stored only |
| `CVE` | cvelist (CNA/ADP `affected`), euvd, msrc | `vendor`, `product` (normalized lowercase), optional `ecosystem`+`package` from `packageName`/`collectionURL` | `events` from `version/lessThan/lessThanOrEqual/changes`; `versions` for exact; MSRC: `[{introduced:"0"},{fixed:<FixedBuild>}]` | yes: `cve-product` (`status = unaffected` rows are skipped) |
| `CPE` | nvd, cvelist `cpeApplicability` | `vendor`, `product`, `cpe` | `events` from `versionStart*/versionEnd*`; `introduced_exclusive` for `versionStartExcluding` | yes: `cpe-product` |
| `CVE-UNPARSED` | cvelist | vendor/product (+ `cpe` for cpeApplicability) | raw entry in `extra.raw`, or `extra.dropped_bounds` | no, kept for later |

**`CVE-UNPARSED` policy.** A bound that is not a version (`log4j-core*`, `128.*`, a URL such as Microsoft's
`https://aka.ms/OfficeSecurityReleases`, free text) must never widen a range to "all versions". For CNA `affected` entries the
importer first tries `changes[]`, then the free-text expression parser; if nothing usable remains the row is `CVE-UNPARSED`.
For `cpeApplicability` any dropped non-version bound turns the whole row into `CVE-UNPARSED` (the dropped values are recorded in
`extra.dropped_bounds`); the matcher only reads `CVE` and `CPE`, so these rows never produce findings.

Events follow OSV semantics: `introduced` (inclusive, `"0"` = beginning), `fixed` (exclusive),
`last_affected` (inclusive), `limit`; plus our `introduced_exclusive` (NVD `versionStartExcluding`; the matcher approximates it as
an inclusive start and then rejects a version equal to the bound). `status` = `affected` | `unaffected` (e.g. Mozilla CNA records
listing only unaffected versions) | `unknown`. OSV distro urgency (`ecosystem_specific.urgency`) is kept in `affected.extra`.

### `distro_triage` (schema v2)

Filled by `sync debian-tracker` (full snapshot replace). Read by `engine/match.py:_triage` for OS-package findings.

| Column | Meaning |
|---|---|
| `ecosystem`, `package`, `cve_id` | Normalized OSV ecosystem (`Debian:12`), **source** package, CVE |
| `status` | `open` / `resolved` / `not-affected` / `undetermined` |
| `urgency` | `unimportant` / `low` / `medium` / `high` / `not yet assigned` / `end-of-life` ... (Debian's, unrelated to CVSS) |
| `fixed_version` | Distro fixed version; `0` = never affected |
| `nodsa` | `no-dsa` / `postponed` / `ignored` (Debian deferral decisions) |
| `note`, `advisory` | Free-text reason; DSA/DLA id when known (text imports) |
| `source` | `debian-tracker` (part of the PK, room for more trackers) |

## Inventory

| Table | Key | Purpose |
|---|---|---|
| `asset` | `id` (`macos:<host>`, `homebrew:<host>`, `image:<repo>@<digest>`, `container:<name>`, `rootfs:<path>`, `repo:<path>` / `dir:<path>`, `ssh:<host>`, `windows:<host>`) | Target + `type` (`desktop`, `server`, `container-image`, `container`, `repo`, `directory`) + OS + platform + `meta` (labels, env, exposure, git info). |
| `scan` | autoinc | One collector run. |
| `component` | `key` (purl, else `name:<category>/<vendor>/<name>@<version>`) | Deduplicated software identity shared across assets. |
| `asset_component` | `(asset_id, component_id)` | Presence; `last_scan_id` tells whether it is still installed. |

## Findings

`finding (asset_id, component_id, vuln_id)` — `vuln_id` is canonical (CVE when known);
`advisory_ids` lists every matched id/alias; `matched_by` (`osv-package`, `cve-product`,
`cpe-product`), `confidence`, `fixed_version`, enrichment snapshot (severity, CVSS, EPSS, KEV),
`priority` P1–P4, lifecycle `status` (`open` → `fixed` when no longer detected; `suppressed`
is sticky), `first_seen/last_seen/fixed_at`.

| Column (v2) | Meaning |
|---|---|
| `triage` | Distro triage label: `unimportant`, `no-dsa`, `postponed`, `ignored`, `end-of-life`, `low`, `medium`, `high` ... (`NULL` = none). Drives priority caps and `findings --hide-minor` / `--hide-deferred`. |
| `triage_source` | `debian-tracker` (tracker row wins) or `osv` (urgency from the OSV record). |

Not stored as findings: tracker `not-affected` / fixed-in-tracker matches, Homebrew formula-patched CVEs and withdrawn records
(counted in the match stats only).
