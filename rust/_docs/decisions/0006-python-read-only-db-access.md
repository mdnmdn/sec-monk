---
title: ADR-0006 — Python engine modules read SQLite read-only; all writes go through the Rust host
summary: Accepted 2026-11-11. Engine modules (match, reports, procmon) open the v3 SQLite files read-only for heavy queries and return results; the host is the only writer; what this means when state moves to PostgreSQL.
read_when: you write an engine module, change how matches are persisted, or plan the PostgreSQL backend
type: decision
context: decisions
status: accepted
tags: [data-model, python, modules, security, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/contracts.md, tech/data-model.md, decisions/0005-schema-v3-store-sqlx.md, decisions/0010-source-staging-adapter.md]
---

# ADR-0006 — Read-only DB access for Python engine modules

## Context

Coordinator proposal A2e (2026-11-11, user said go, to be reviewed): `reports.*` and `match_asset` run many queries;
shipping all the data through the protocol would mean re-implementing them. The store must still have one writer.

## Decision

- A module whose manifest declares `db-read` and which the config enables receives, in the host's `hello`, a grant
  with the state and mirror paths. It opens `file:<state>?mode=ro` (URI), attaches the mirror read-only, and runs each
  request in one read transaction. Reports also set `query_only`; matches cannot (see Consequences) and use an authorizer. It never calls `secmonk.db.connect`.
- Writes the engine needs are **returned, not executed**: `engine.match` (persisted) returns the asset's complete
  finding set computed in a TEMP shadow of `finding`; the host replaces it in one transaction after a staleness check.
  Ephemeral matches (no-save scans, process monitor) use TEMP copies of the inventory tables and write nothing.
- Sources never get a grant; they stream row operations ([ADR-0010](0010-source-staging-adapter.md)).

## Consequences

- The unchanged Python read code serves 13 of the 22 routes; the store stays single-writer.
- Requires schema v3 to stay a v2 superset ([ADR-0005](0005-schema-v3-store-sqlx.md)).
- **Verified (W2.2, 2026-11-11, SQLite 3.51, `rust/python/tests/test_engine.py`)**: TEMP tables and TEMP writes work on a
  `mode=ro` connection; `PRAGMA query_only=ON` forbids them, so matches run without it and with an authorizer
  (writes only on the `temp` database, no ATTACH/DETACH, no CREATE/DROP elsewhere). The unchanged `match_asset` runs
  against a TEMP `finding` shadow (its `commit()` made a no-op) and the TEMP shadow of `finding` copies the DDL from
  `sqlite_master` (AUTOINCREMENT tables need the authorizer to allow CREATE TABLE on `temp`). The persisted match's finding
  set equals what `match_asset` writes on a writable copy (key fields, row by row). Unqualified table names resolve across
  the attached mirror because state and mirror share no table except `store_meta`.
- The W1.2 spike (2026-11-11) showed a Python `mode=ro` connection reading the live WAL database while the Rust host
  held a write transaction: no lock errors, uncommitted rows invisible. Untested: `mode=ro` when `-shm` cannot be
  created. `immutable=1` must not be used (it ignores the WAL).
- Readers hold back WAL checkpoints; requests are short and the host checkpoints after syncs.
- **PostgreSQL later.** Options, in order of preference: (1) by then match and reports are Rust (the planned
  migration order makes this the normal case), so no Python reads state; (2) the mirror stays SQLite (R1 of
  [data-model](../tech/data-model.md)) and Python reads only it; (3) a read-only role and DSN granted in `hello`,
  which needs a dialect port of the Python SQL (`json_extract`, `?`); (4) named store queries over the protocol
  (`store.query.<name>`), served by the host. A Python module never gets a writable DSN.

## Acceptance

Accepted by the user on 2026-11-11 as written: Python engine modules read the database read-only and every write goes through the Rust host. Option (4) stays a later choice for PostgreSQL.

## Implementation notes (2026-11-11, W4.2)

- Built as decided: `secmonk-host` sets `allow_db_read: true` and `HostSettings` carries both database paths;
  `hello.rs` grants `db_read` (`uri_flags: "mode=ro"`) only to modules whose manifest declares `db-read`
  (`py-engine`, `py-procmon`; test `host_hello_settings_and_grants`). Status: accepted (2026-11-11).
