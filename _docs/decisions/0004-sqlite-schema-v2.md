---
title: ADR-0004 — SQLite schema v2
summary: Decision record for SQLite schema v2 - tables, alias kinds, per-asset facts, additive migrations via user_version, file location and 0600 permissions. Supersedes ADR-0002.
read_when: you are about to change the database schema, add a migration or question why the store is one SQLite file
type: decision
context: decisions
status: accepted
tags: [data-model, storage]
updated: 2026-11-07
verified: 2026-11-07
supersedes: decisions/0002-sqlite-local-mirror.md
related: [tech/data-model.md, decisions/0006-per-user-state-locations.md]
code: src/secmonk/db.py
---

# ADR-0004 — SQLite schema v2 (supersedes ADR-0002)

## Context
[ADR-0002](0002-sqlite-local-mirror.md) chose one SQLite file as mirror and inventory store, with a sketch of the tables
(`vulnerability`, `alias`, `affected_range`, `kev`, `epss`) and a default of `./secmonk.db`. The implementation grew beyond it:
distro triage, package- and product-based affected rows in one table, per-asset facts, an alias edge kind, migrations, and a
security review that moved the file out of the working directory.

## Decision
- **One SQLite file**, WAL, `synchronous=NORMAL`, foreign keys on. The authoritative DDL is `SCHEMA` in `src/secmonk/db.py`;
  [tech/data-model.md](../tech/data-model.md) explains it.
- **Tables**: mirror `source_sync`, `raw_record`, `vulnerability`, `alias`, `affected` (replaces the sketched `affected_range`; `range_type`
  ECOSYSTEM / SEMVER / GIT / VERSIONS / CPE / CVE / CVE-UNPARSED), `kev`, `epss`, `distro_triage`; inventory `asset`, `scan`,
  `component`, `asset_component`; results `finding`.
- **Raw-first is kept**: `raw_record` stores each source record verbatim next to the normalized projection, so re-normalizing needs no
  download.
- **`alias.kind`** (`alias` | `upstream` | `related`): only `alias` edges mean "same vulnerability"; canonicalization never follows the others
  (distinct CVEs must not merge).
- **Per-asset facts**: `asset_component.paths` (every location of a component on the asset) and `asset_component.meta` (users, install
  location, scope); `component.meta` is the shared identity used for matching.
- **Versioning**: `PRAGMA user_version = SCHEMA_VERSION` (2), only ever raised. `init_schema` is idempotent (`CREATE ... IF NOT EXISTS`) and
  migrates additively with `_ADDED_COLUMNS` (`finding.triage`, `finding.triage_source`, `alias.kind`, `asset_component.paths`,
  `asset_component.meta`) via `ALTER TABLE ... ADD COLUMN`. No destructive migrations.
- **Location and permissions**: the file lives in the per-user data directory (not the CWD) and is created with mode 0600; see
  [ADR-0006](0006-per-user-state-locations.md). `SECMONK_DB` / `--db` override it.
- Every row carries its `source`; `source_sync` keeps per-source status, cursor and last successful sync (freshness).

## Consequences
- Zero-ops, portable, inspectable with `sqlite3`; one writer at a time (fine for a CLI).
- Additive-only migrations mean a column can be added but not removed or retyped; a breaking change needs a new ADR and an explicit migration.
- Findings are recomputable from the inventory and the mirror, so they are not a source of truth.
