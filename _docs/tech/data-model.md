---
title: Data model (SQLite schema)
type: tech
context: tech
status: implemented
tags: [data-model, sqlite]
updated: 2026-11-07
code: src/secmonk/db.py
related: [decisions/0002-sqlite-local-mirror.md, tech/engine/matching.md]
---

# Data model

The authoritative DDL is in `src/secmonk/db.py` (`SCHEMA`). This page explains intent.

## Vulnerability mirror

| Table | Key | Purpose |
|---|---|---|
| `source_sync` | `source` | Last sync, status, delta cursor. OSV keeps per-ecosystem rows `osv:<Ecosystem>`. |
| `raw_record` | `(source, record_id)` | Verbatim JSON as published — re-normalize without re-downloading. |
| `vulnerability` | `(source, id)` | Normalized facts per source: summary, dates, `state`/`withdrawn`, CVSS (score/vector/version), severity, CWEs, `extra` JSON (SSVC, ADP KEV, references…). |
| `alias` | `(vuln_id, alias, source)` | Undirected id edges (GHSA ↔ CVE, DEBIAN-CVE ↔ CVE, EUVD ↔ CVE). |
| `affected` | autoinc | What is affected — see below. |
| `kev` | `cve_id` | CISA KEV catalog (full snapshot). |
| `epss` | `cve_id` | Latest EPSS score/percentile (no history yet). |

### `affected` — two flavours in one table

| `range_type` | Producer | Lookup columns | Version data | Matched? |
|---|---|---|---|---|
| `ECOSYSTEM`, `SEMVER` | osv | `ecosystem` (normalized, e.g. `Debian:12`, `Ubuntu:22.04`, `Red Hat:9`), `package` (normalized name; source package for distros) | `events` (OSV events) | ✅ package strategy |
| `VERSIONS` | osv | same | `versions` explicit list | ✅ package strategy |
| `GIT` | osv, cvelist | — | commit events | ❌ stored only |
| `CVE` | cvelist (CNA/ADP `affected`), euvd | `vendor`, `product` (normalized lowercase), optional `ecosystem`+`package` from `packageName`/`collectionURL` | `events` converted from `version/lessThan/lessThanOrEqual/changes` | ✅ product strategy |
| `CPE` | nvd, cvelist `cpeApplicability` | `vendor`, `product`, `cpe` | `events` from `versionStart*/versionEnd*`; `introduced_exclusive` for `versionStartExcluding` | ✅ product strategy |
| `CVE-UNPARSED` | cvelist | vendor/product | raw entry in `extra` | ❌ kept for later |

Events follow OSV semantics: `introduced` (inclusive, `"0"` = beginning), `fixed` (exclusive),
`last_affected` (inclusive), `limit`; plus our `introduced_exclusive`.
`status` = `affected` | `unaffected` (e.g. Mozilla CNA records listing only unaffected versions).

## Inventory

| Table | Key | Purpose |
|---|---|---|
| `asset` | `id` (`macos:<host>`, `image:<repo>@<digest>`, `container:<name>`, `rootfs:<path>`) | Target + OS + platform + `meta` (labels, env, exposure). |
| `scan` | autoinc | One collector run. |
| `component` | `key` (purl, else `name:<category>/<vendor>/<name>@<version>`) | Deduplicated software identity shared across assets. |
| `asset_component` | `(asset_id, component_id)` | Presence; `last_scan_id` tells whether it is still installed. |

## Findings

`finding (asset_id, component_id, vuln_id)` — `vuln_id` is canonical (CVE when known);
`advisory_ids` lists every matched id/alias; `matched_by` (`osv-package`, `cve-product`,
`cpe-product`), `confidence`, `fixed_version`, enrichment snapshot (severity, CVSS, EPSS, KEV),
`priority` P1–P4, lifecycle `status` (`open` → `fixed` when no longer detected; `suppressed`
is sticky), `first_seen/last_seen/fixed_at`.
