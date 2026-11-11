---
title: ADR-0005 — Schema v3 (state + mirror), Store traits, sqlx + sea-query, sqlx migrations
summary: Schema v3 (state + mirror files, v2 superset), Store traits in domain terms, sqlx 0.9 with sea-query and embedded sqlx migrations, one write actor.
read_when: you choose or question the SQL library, the migration tool, the database split, or the v2-compatibility rule
type: decision
context: decisions
status: accepted
tags: [data-model, store, sqlite, migrations, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/data-model.md, decisions/0006-python-read-only-db-access.md]
---

# ADR-0005 — Schema v3, Store traits, sqlx

## Context

User direction (A4): a new schema v3 with migrations, SQLite first behind a `Store` abstraction ready for
PostgreSQL/MySQL, at a path different from the Python version's. The proposal (§10) flagged JSON-queried fields, asked
to split the mirror from the inventory, and suggested sqlx + sea-query. Python engine modules must keep running their
v2 SQL on it ([ADR-0006](0006-python-read-only-db-access.md)).

## Decision

- Two databases (`state`, `mirror`), each with its own URL; no cross-database query in Rust.
- v3 = v2 superset while Python reads it: new tables/columns only; promoted columns (`scan.partial`,
  `component.product`, `product_source`, `bundle_id`, `job.log_lines`) written together with their JSON keys
  ([data-model](../tech/data-model.md)).
- `StateStore` / `MirrorStore` traits in domain terms; one write actor; SQL only in `secmonk-store`.
- **sqlx 0.9** (runtime queries, no macros) for connections and pools, **sea-query** for dialect-specific statements, **sqlx migrate** (embedded,
  checksummed, `migrations/{state,mirror}/{sqlite,postgres,mysql}/`). Forward-only, additive.
- The W1.2 spike (2026-11-11) built sqlx and rusqlite inside Tauri: sqlx +1.24 MB vs +1.09 MB, ~6 s slower dev
  builds; accepted for the async fit and the later PostgreSQL/MySQL backends. sqlx and rusqlite cannot be linked
  together (`links = "sqlite3"`): the fallback (rusqlite + refinery) would replace sqlx, not sit beside it.
- sqlx bundles SQLite 3.51.3; Python readers may run an older SQLite, so v3 uses no feature newer than both.

## Consequences

- The mirror can stay local SQLite when state moves to PostgreSQL.
- Some duplication (column + JSON key) until the Python readers are ported; removed by a later migration.
- MySQL needs key hashing for long text keys; planned, not built.

## Implementation notes (2026-11-11, W2.1)

- sqlx 0.9 with `runtime-tokio`, `sqlite-bundled`, `migrate` and **no** `macros` feature: migrations are embedded
  with `include_str!` and `Migrator::with_migrations`; runtime queries only. sea-query 1.0 builds the dynamic
  mirror upserts and key deletes; fixed statements are hand-written SQLite inside the backend module.
- The write actor is a single-connection write pool per file; reads use read-only pools.
- `save_inventory` matches the Python rows column by column (golden test); the store does not classify (the
  engine does, on ingest), unlike the Python function.
