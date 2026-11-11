---
title: Data model — schema v3 (state + mirror), Store traits, migrations
summary: Schema v3 (state and mirror SQLite files, v2-compatible superset), promoted columns, Store traits, sqlx migrations, dialect rules for PostgreSQL/MySQL, concurrency with read-only Python readers.
read_when: you write a migration, a Store method or a query in secmonk-store, add a column, or reason about Python modules reading the database
type: tech
context: tech
status: implemented
tags: [data-model, sqlite, store, migrations, rust]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-store/src/, rust/crates/secmonk-store/migrations/]
fixtures: rust/crates/secmonk-store/tests/golden/
related: [decisions/0005-schema-v3-store-sqlx.md, decisions/0006-python-read-only-db-access.md, decisions/0010-source-staging-adapter.md, tech/contracts.md, tech/configuration.md]
---

# Data model — schema v3

Schema v2 is the Python one (`src/secmonk/db.py` `SCHEMA`, explained in
[Python data-model](../../../_docs/tech/data-model.md)). Schema v3 is owned by `secmonk-store`; its DDL lives in
`rust/crates/secmonk-store/migrations/` and this page explains intent. Decision: [rust ADR-0005](../decisions/0005-schema-v3-store-sqlx.md).

## Rules

| # | Rule | Why |
|---|---|---|
| R1 | **Two databases**: `mirror` (vulnerability data, rebuildable) and `state` (inventory, findings, run history). No foreign key and no Store query crosses them. | Proposal §10.2: the mirror can stay a local SQLite file while state moves to PostgreSQL. |
| R2 | **v2-compatible superset** while Python reads the store: every v2 table and column keeps its name, type affinity and meaning; v3 adds tables and nullable/defaulted columns only. | The unchanged `secmonk` read code (`reports`, `queries`, `match`) runs on v3 read-only. |
| R3 | **What is queried is a column.** A JSON key that any WHERE / JOIN / ORDER BY needs is promoted to a column; JSON columns are payload, never filtered by Rust code. | Removes `json_extract` dialect differences. |
| R4 | During the transition the host writes a promoted value **both** to its column and to its JSON key. | Python code still reads the JSON key (R2). Dropped when the last Python reader is ported. |
| R5 | Forward-only, additive migrations (as Python ADR-0004); one ordered set per database and dialect; checksummed. | |
| R6 | One writer: the host's write actor (per database file a single-connection write pool: every write transaction queues on it, in arrival order). Modules never write v3 ([rust ADR-0006](../decisions/0006-python-read-only-db-access.md)). | |
| R7 | The schema version of a database is the highest applied migration; the host refuses to open a database with a migration it does not know (a newer app wrote it). | No silent downgrade. |

## Mirror database (`mirror.sqlite3`)

| Table | Change from v2 | Key |
|---|---|---|
| `source_sync` | unchanged | `source` |
| `raw_record` | unchanged | `(source, record_id)` |
| `vulnerability` | unchanged | `(source, id)`; index `id` |
| `alias` | `kind` gets `NOT NULL DEFAULT 'alias'` | `(vuln_id, alias, source)`; index `alias` |
| `affected` | + index `(source, vuln_id)` (row deletes of the source stream) | `rowid_` autoincrement (kept for R2) |
| `kev`, `epss`, `distro_triage` | unchanged | as v2 |
| `store_meta` | new: `key TEXT PK, value TEXT` (`schema`, `created_at`, `app_version`) | `key` |
| `source_applied` | new (migration `0002`): `source TEXT PK, seq INTEGER NOT NULL, applied_at TEXT`: the last row batch applied per source, written in the batch's transaction; migration `0003` adds `generation TEXT` (the staging generation of that seq; NULL = recorded before W4.4, which costs one repair; `native-rust` for a source synced by its native importer, rust ADR-0011) | `source` |

No promoted columns: the only JSON query on mirror data in v2 (`msrc.py` on `affected.extra.document`) runs inside the
source's staging database ([rust ADR-0010](../decisions/0010-source-staging-adapter.md)), not on v3.

## State database (`state.sqlite3`)

| Table | Change from v2 | Why |
|---|---|---|
| `asset` | unchanged (`meta` JSON keeps labels, image facts, process tree) | Rust reads `meta.inventory_version`, `id_verified`, `engine` for the reuse rule by decoding JSON, not by SQL. |
| `scan` | + `partial INTEGER NOT NULL DEFAULT 0`, + `partial_reason TEXT`, + `job_id INTEGER NULL` (no foreign key: job rows are pruned), + index `(asset_id, id)` | `partial` drives `current_components` (v2: `json_extract(meta,'$.partial')`); `job_id` links a scan to its run. |
| `component` | + `product TEXT`, + `product_source TEXT`, + `bundle_id TEXT`; index `product_source` | `queries.unmatched` filters on `product_source` and shows `product`, `bundle_id` (v2: `json_extract`). |
| `asset_component` | unchanged | |
| `finding` | unchanged | Lifecycle and `suppressed` stickiness as v2. |
| `job` | + `log_lines INTEGER NOT NULL DEFAULT 0` | The list reads it instead of `json_array_length(log)`. Status values reserve `queued`, `cancelled` (not written by the prototype). |
| `store_meta` | new: as in the mirror, plus `initialized` | `initialized` is set by the first write of a sync row, an asset or a job; it drives the API's `no-db` answer. |

Promoted values (R4): `scan.partial`/`partial_reason` mirror `scan.meta.partial`/`partial_reason`; `component.product`,
`product_source`, `bundle_id` mirror `component.meta.product`, `product_source`, `bundle_id` (set by `engine.classify`
and the collectors).

## Store traits

`secmonk-store` exposes domain operations, never SQL (proposal §10.2):

| Trait | Operations (implemented 2026-11-11, signatures in `secmonk-store/src/lib.rs`) |
|---|---|
| `MirrorStore` | `apply_rows(&RowsBatch) -> ApplyStats {upserts, deleted, skipped}` (one transaction; table and column allowlists in `mirror_schema.rs`; the whole batch is validated before the transaction, so a bad op writes nothing; at most 5000 ops, the schema's `maxItems`; **source binding**: every row and key carries `source == batch.source`, and for `kev` / `epss`, whose keys have no `source`, an update or delete touches only the batch source's rows, while the owning source may replace another's row, as FIRST EPSS scores win over EUVD's in Python; **idempotent**: the batch's `seq` and `generation` are recorded in `source_applied` in the same transaction and a batch at or below that seq is skipped, `skipped = true`; **generation-bound**: a batch with a `generation` other than the recorded one, or with `acked_through` above the applied seq (none = 0), writes nothing and answers `needs_repair = true`; a batch without a generation keeps the plain seq rule), `applied_seq(source)`, `applied_state(source) -> AppliedState {seq, generation}`, `reset_applied_seq(source)` (tests, manual recovery, and the switch of a source from `py-sources` to its native importer: rust ADR-0011), `begin_repair(source) -> Box<dyn MirrorRepair>` (one transaction on the write connection: deletes the source's rows in every mirror table, `source_sync` `<source>:*` included; `apply(&RowsBatch)` per export batch, same allowlists and binding, no seq check; `commit(high_water, generation) -> RepairStats {deleted, upserts, batches}` records the applied state; dropping it rolls back), `sync_state(source)`, `count_rows(table, source)` and `row_keys(table, source)` (reads of the rows whose `source` column is the source, primary keys in key order, `Invalid` for `affected`: the `MirrorView` of the native importers), `is_initialized()`, `checkpoint()` (`wal_checkpoint(TRUNCATE)` on both files) |
| `StateStore` | `save_inventory(&Inventory, job_id) -> scan_id` (port of `engine/inventory.save_inventory` **without** its `classify` call: the engine classifies on ingest), `asset_exists`, `asset_reuse_facts(asset_id) -> {name, platform, meta, last_seen, latest_scan_id, latest_scan_partial}`, `update_asset_meta`, `update_asset_reused(asset_id, name, meta)` (the reuse rule's write: name, meta, `last_seen` in one statement, no scan row), `latest_scan_id`, `replace_findings(asset_id, &[Finding], &BasedOn)` (stale check, `StoreError::Stale`), `job_insert` / `job_finish` / `job_rows(kind, limit)` / `job_row` / `job_mark_interrupted` (ports of `db.py`, `JOB_KEEP` 200, `JOB_LOG_LINES` 300), `is_initialized()` |
| `SqliteStore` | the SQLite backend of both traits: `open(state_path, mirror_path, &StoreOptions)` / `open_urls(state_url, mirror_url, ..)` creates the files 0600, runs the migrations, stamps `user_version` and `store_meta`, holds the write pools and the read-only pools (`read_pool()`: extension point for the API read queries, added later as trait methods), `state_path()` / `mirror_path()`, `close()` (called last by `Host::shutdown`) |

Every write operation runs inside one transaction. `save_inventory` is golden-tested against the Python function
(`tests/golden/save_inventory.json`, generated by `gen_save_inventory.py`: two inventories, duplicate keys, a
partial re-scan; every v2 column of `asset`, `scan`, `component`, `asset_component` equal after normalizing
timestamps, JSON text byte-equal thanks to `serde_json` `preserve_order`). `replace_findings` has no Python
counterpart (Python updates findings in place); it is unit-tested. Errors: `StoreError::{Sqlx, Migrate, Invalid,
Stale, NotFound, Corrupt, Io}`; `Invalid` maps to `invalid-params`, `Stale` to `stale` on the wire.

## SQL library and migrations

| Choice | Pick | Notes |
|---|---|---|
| Driver and pools | **sqlx 0.9** (`sqlite` feature, tokio, runtime-checked queries, no compile-time macros; later `postgres`, `mysql`) | Chosen by the spike (2026-11-11): +1.24 MB release size vs +1.09 MB for rusqlite, ~6 s slower dev build. Avoid `sqlx::Any`. sqlx and rusqlite **cannot coexist** in one build (`links = "sqlite3"` conflict): a fallback to `rusqlite` + `refinery` replaces sqlx entirely, behind the same traits. |
| Statement building | **sea-query** for dialect-specific upserts and placeholders | Hand-written SQL only in SQLite-specific migrations. |
| Migrations | **sqlx migrate** without the `macros` feature: the SQL files are embedded with `include_str!` and handed to `Migrator::with_migrations` (`src/migrations.rs`), directories `migrations/{state,mirror}/{sqlite,postgres,mysql}/NNNN_name.sql` | Table `_sqlx_migrations` (checksummed) replaces `PRAGMA user_version` (which the store still sets to 3 for humans, never lowering it). A database with an applied migration the app does not know is refused (`VersionMissing`, R7; tested). Each database has `sqlite/0001_schema_v3.sql` (the v3 DDL in full); the mirror also has `sqlite/0002_source_applied.sql` and `sqlite/0003_source_applied_generation.sql` (a v2 import is a backlog item). `store_meta` keys: `schema`, `created_at`, `app_version`, `initialized`. |

## Dialect-portable rules (for PostgreSQL / MySQL later)

| Topic | SQLite (now) | PostgreSQL | MySQL / MariaDB | Rule |
|---|---|---|---|---|
| Upsert | `ON CONFLICT … DO UPDATE` | same | `ON DUPLICATE KEY UPDATE` | Built by sea-query; never `INSERT OR REPLACE` (it deletes and re-inserts). |
| Text keys | `TEXT` | `TEXT` | `VARCHAR(n)` ≤ 768 chars indexed, `utf8mb4_bin` | Long keys (`component.key`, `asset.id`) get a `CHAR(64)` sha256 companion with the unique index on MySQL. |
| JSON | `TEXT` | `jsonb` | `JSON` | Payload only (R3). |
| Booleans | `INTEGER` 0/1 | `boolean` | `TINYINT(1)` | Decoded in the Store layer. |
| Timestamps | ISO-8601 UTC `TEXT` (`2026-11-11T08:00:00+00:00`) | `timestamptz` | `DATETIME(6)` UTC | Same string at the API in every backend. |
| Ids | `INTEGER PRIMARY KEY AUTOINCREMENT` | `bigint generated always as identity` | `BIGINT AUTO_INCREMENT` | |
| Placeholders, `IS ?`, pragmas | — | — | — | No dialect syntax outside the backend module; null-safe comparisons written explicitly. |
| Concurrency | one writer | row locks | row locks | Finding lifecycle writes use explicit transactions; `replace_findings` locks the asset row (`SELECT … FOR UPDATE`) on server databases. |

## Files under `data_dir`

| Path | Content |
|---|---|
| `db/state.sqlite3` (+ `-wal`, `-shm`) | state database, mode 0600 |
| `db/mirror.sqlite3` (+ `-wal`, `-shm`) | mirror database, mode 0600 |
| `modules/py-sources/staging.sqlite3` | v2 staging database of the source adapter (module-owned) |

The Python version's `secmonk.db` is never opened: different directory and file names, so both versions run side by
side ([configuration](configuration.md)). Importing a v2 database is a backlog item.

## Concurrency with Python readers

| Topic | Rule |
|---|---|
| Journal | WAL, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000` on every host connection. The write connection of each file is opened at start and kept for the app's lifetime (`min_connections = 1`), so `-wal` and `-shm` exist while modules read. Files are created 0600 before SQLite opens them (`-wal`/`-shm` inherit the mode; tested). |
| Readers | `py-engine` / `py-procmon`: `file:…?mode=ro` (never `immutable=1`: it ignores the WAL), one read transaction per request (consistent snapshot). `PRAGMA query_only=ON` where no TEMP table is needed; `engine.match` cannot use it (it blocks TEMP writes too) and uses `mode=ro` plus an SQLite authorizer that allows writes on `temp` only and no `ATTACH` (W2.2, 2026-11-11). The host's own read pools open the files read-only (`SQLITE_OPEN_READONLY`). Spike (2026-11-11): a read-only Python connection on the live WAL database while the Rust host holds a write transaction gets no lock errors and does not see uncommitted rows. Opening `mode=ro` when the `-shm` file cannot be created is untested: the host keeps a connection open for the app's lifetime so `-wal` and `-shm` exist **(verify)**. |
| SQLite versions | sqlx bundles SQLite 3.51.3; the Python modules use their interpreter's SQLite, which may be older. Schema and queries use no feature newer than both (checked in the migration review). |
| Copies and backups | A file copy must include the `-wal` file, or use the backup API (`VACUUM INTO` / sqlx backup); never copy the main file alone. |
| TEMP tables | Readers create TEMP shadows (`finding` for persisted matches; the inventory tables for ephemeral ones). Verified by W2.2 (2026-11-11): a `mode=ro` connection can create and write TEMP tables (they live in the connection's own temp database); `PRAGMA query_only=ON` blocks them. |
| Checkpoints | Long read transactions hold back checkpoints. Requests are short; the host runs `PRAGMA wal_checkpoint(TRUNCATE)` after a sync job, when no module request is in flight. |
| Write ordering | The host commits an inventory before it calls `engine.match`; the module's new read transaction sees it. |
| Locations | `data_dir` on a local disk: WAL needs shared memory on one host (no network shares). |
