---
title: Data model (SQLite schema)
summary: SQLite schema v2 covering migrations, vulnerability mirror tables, affected and distro_triage, inventory and partial scans, findings, the run history (job), database location.
read_when: you change db.py, add a table or column, or need to know what the database stores and where it lives (including the scan/sync run history)
type: tech
context: tech
status: implemented
tags: [data-model, sqlite, matching]
updated: 2026-11-10
verified: 2026-11-10
code: src/secmonk/db.py
related: [decisions/0007-process-monitor.md, decisions/0004-sqlite-schema-v2.md, decisions/0006-per-user-state-locations.md, tech/engine/matching.md, tech/architecture.md, references/vuln-sources/debian-tracker.md]
---

# Data model

The authoritative DDL is in `src/secmonk/db.py` (`SCHEMA`, `SCHEMA_VERSION = 2`). This page explains intent.

## Schema version and migrations

| Item | Behaviour |
|---|---|
| `PRAGMA user_version` | Set to `SCHEMA_VERSION` (2) on every connect. |
| Create | `init_schema()` runs the whole `SCHEMA` with `CREATE TABLE/INDEX IF NOT EXISTS`, so new tables (e.g. `distro_triage`, `job`) appear on existing DBs. |
| Added columns | `_ADDED_COLUMNS` (`finding.triage`, `finding.triage_source`, `alias.kind`, `asset_component.paths`, `asset_component.meta`) are added with `ALTER TABLE ... ADD COLUMN` when missing (lightweight, additive only; no data rewrite). |
| Connection | WAL, `synchronous=NORMAL`, foreign keys on. |

Schema v2 = v1 + `distro_triage` + `finding.triage` / `finding.triage_source` + `alias.kind` + `asset_component.paths` / `.meta`
(+ the additive `job` table, 2026-11-10: no version bump, it appears on connect). Rationale and history: [ADR-0004](../decisions/0004-sqlite-schema-v2.md) (supersedes ADR-0002); file location and permissions: [ADR-0006](../decisions/0006-per-user-state-locations.md).

**Location.** The database is `$SECMONK_DB` (a file) or `<data dir>/secmonk.db`, where the data dir is `$SECMONK_HOME`, else `$XDG_DATA_HOME/secmonk`, else `~/.local/share/secmonk` (`%LOCALAPPDATA%\secmonk` on Windows); `--db` overrides. Caches (cvelist git clone, image blobs) live in `$SECMONK_CACHE`, else `$XDG_CACHE_HOME/secmonk`, else `~/.cache/secmonk` (`%LOCALAPPDATA%\secmonk\cache`). Never relative to the current directory; directories are 0700, the DB file 0600 (`src/secmonk/paths.py`).

## Vulnerability mirror

| Table | Key | Purpose |
|---|---|---|
| `source_sync` | `source` | Last sync, status (`ok` / `error` / `partial`), delta cursor. OSV keeps per-ecosystem rows `osv:<Ecosystem>`; one row each for `cvelist`, `kev`, `epss`, `nvd`, `euvd`, `msrc`, `debian-tracker`, written by the CLI from `SyncResult` (sources never write their main row). Internal rows: `cvelist:git`, `cvelist:years`, `nvd:progress`. `db.set_sync_state`: `last_sync` only moves for status `ok`/`partial`; an `error` keeps the previous records/cursor/last_sync and only updates status + message. |
| `raw_record` | `(source, record_id)` | Verbatim JSON as published — re-normalize without re-downloading. |
| `vulnerability` | `(source, id)` | Normalized facts per source: summary, dates, `state`/`withdrawn`, CVSS (score/vector/version), severity, CWEs, `extra` JSON (SSVC, ADP KEV, references…). |
| `alias` | `(vuln_id, alias, source)` | Id edges (GHSA ↔ CVE, DEBIAN-CVE ↔ CVE, EUVD ↔ CVE). Column `kind` = `alias` (same vulnerability) \| `upstream` (OSV `upstream`: the CVEs a downstream advisory derives from; never merge on these); old rows migrate to `alias`, re-sync to reclassify. |
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
| `asset` | `id` (`macos:<host>`, `homebrew:<host>`, `image:<repo>@<digest>`, `container:<name>` (local engine) or `container:<label>/<name>` (remote engine reached with `-o host=` / `-o context=`; label = `host:port` for tcp, the ssh host with `:port` unless 22, never the user), `rootfs:<path>`, `repo:<path>` / `dir:<path>`, `ssh:<host>` or `ssh:<host>:<port>` (IPv6 bracketed; Linux, macOS and Windows hosts), `windows:<host>`, `process:<host>` (running processes only, see [process collector](collectors/process.md))) | Target + `type` (`desktop`, `server`, `container-image`, `container`, `repo`, `directory`, `host-processes`; Homebrew assets are `server`) + OS + platform + `meta` (labels, env, exposure, git info, ssh `machine_id`). |
| `scan` | autoinc | One collector run. |
| `component` | `key` (purl, else `name:<category>/<vendor>/<name>@<version>`) | Deduplicated software identity shared across assets; `meta` = identity facts used for matching (vendor/product hints, source package...), shared by every asset with this key (the last writer wins). |
| `asset_component` | `(asset_id, component_id)` | Presence; `last_scan_id` tells whether it is still installed. Per-asset facts: `paths` (JSON list of **every** location of the component on this asset; `source_path` = the first) and `meta` (JSON: this asset's own users, install location, scope...). |

### Partial scans

A collector can mark its `Inventory` `partial` (`partial_reason`): SSH stream aborted/truncated, docker-engine export incomplete, docker-image layer skipped/unreadable, rootfs
file/count limits hit. `save_inventory` still records the scan (`scan.meta = {"partial": true, "partial_reason": ...}`) and upserts the components it saw, but a partial scan is
**not** a reference for removal. `current_components(asset)` = components whose `last_scan_id >=` the latest *non-partial* scan (so: everything the last complete scan saw, plus anything
seen by later partial scans; components absent from the last complete scan stay removed). An asset with only partial scans shows everything ever seen.
Several copies of one component on an asset (two `Foo.app` bundles, a library in two virtualenvs) share one row; `asset_component.paths` lists all of them and `asset_component.meta` is that asset's own copy of the collector's `meta`.

Process assets (`process:<host>`) reuse these tables unchanged: a running app shares its `component` row with `macos:<host>` /
`homebrew:<host>`; running-process facts (pids, launch kinds, executables, provenance, flags) are under `meta.process`, and the
process tree under `asset.meta.processes`. Executables without a package identity use the category `executable` (no version, never
matched). No schema change: only the comments in `db.py` list the new id and type.

## Findings

`finding (asset_id, component_id, vuln_id)` — `vuln_id` is canonical (a CVE id when the advisory's alias set or `upstream` list has one; see [matching](engine/matching.md#canonicalization--dedupe));
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

## Run history

`job` — one row per `scan` or `sync` run, from the CLI or the web UI (`ops.record_run` on its own connection, so recording
never commits the scan's own transaction; `web/jobs.py`; both store through `ops.finish_run`); read by
`secmonk history` and `GET /api/jobs` through `reports.job_dict`. Written on the real table even for `scan --no-save`:
`ephemeral_overlay` only shadows the inventory and finding tables, so a no-save run is listed while its inventory and
findings are not stored.

| Column | Meaning |
|---|---|
| `id` | autoincrement; also the web job id |
| `kind`, `origin` | `scan` \| `sync`; `cli` \| `ui` |
| `title` | `scan <collector> <target>` / `sync <sources>` (a URL target keeps its user name, never a password) |
| `params` | JSON. Scan: `{collector, target, options[], save, min_confidence}`; sync: `{sources[], ecosystems[], since, full, limit, path}` (+ `ids` from the CLI). Redacted (`collectors/base.redact_option`): keys naming a file keep their value (exactly `identity`, `tls_ca`, `tls_cert`, `tls_key`, `known_hosts`, `ssh_config`, or `*_file` / `*_path`); any other key matching `pass` (password, passphrase, `tls_key_passphrase`…), `token`, `secret`, `…key` or `looks_secret` becomes `***`; `ssh_option` values go through `redact_command` (and `sshpass -p X` is masked); URL passwords, queries and fragments are dropped while user names are kept, so a run can be repeated (`strip_url_secrets(keep_user=True)`, `scrub_text`) |
| `status` | `running` \| `ok` \| `partial` \| `error`. Scan: ok = every target ok; partial = a partial inventory or some targets failed; error = every target failed, or the run failed before any target (no match, engine unreachable) |
| `started_at`, `finished_at` | ISO timestamps (UTC) |
| `error` | error message (URL credentials scrubbed); `interrupted` for a run stopped with Ctrl-C or SIGTERM (CLI) or whose process is gone (see `owner`) |
| `result` | JSON. Scan: `{saved, targets[{target, asset, scan_id, stats, warnings, partial, findings[] (finding rows, at most `ops.STORED_FINDINGS` = 500 per target; CLI runs: its display filters, then capped), counts, error}], stats (summed), counts (summed)}`; sync: `{sources[{source, status, records, seconds, message}]}` |
| `log` | JSON list of log lines (the last `JOB_LOG_LINES` = 300; URL credentials scrubbed) |
| `summary` | JSON `reports.job_summary` of the stored result, written at the end; lists (`db.job_rows`) read it and `json_array_length(log)` instead of the log |
| `owner` | JSON `{pid, host}` of the process running it. A `running` row whose owner is gone (`db.owner_alive`: other host name, or `os.kill(pid, 0)` finds no process; on Windows only this process's rows count as alive) reads as `error` / `interrupted` (`reports.job_dict`, nothing written); a web server started with actions enabled also writes that (`db.job_mark_interrupted`, errors such as a locked database ignored). A run that does finish later overwrites it. No process-start token: a reused pid keeps a dead run `running` until that pid ends |

Retention: inserting a run deletes rows with `id <= new_id - JOB_KEEP` (200).
