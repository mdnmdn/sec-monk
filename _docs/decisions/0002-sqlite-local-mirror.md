---
title: ADR-0002 — SQLite local mirror
summary: Superseded sketch of the single SQLite mirror (raw plus normalized tables, default ./secmonk.db). Read ADR-0004 for the current schema and ADR-0006 for the DB location.
read_when: you want the history of the SQLite mirror choice, otherwise you read ADR-0004 and ADR-0006 instead
type: decision
context: decisions
status: superseded
tags: [data-model, storage]
updated: 2026-11-07
verified: 2026-11-07
---

# ADR-0002 — SQLite as the local vulnerability mirror and inventory store

> Superseded by [ADR-0004](0004-sqlite-schema-v2.md) (current tables and migrations) and [ADR-0006](0006-per-user-state-locations.md) (DB location: no longer `./secmonk.db`).

## Context
Vision §6: "scans never hit external APIs directly"; a sync job mirrors sources locally.

## Decision
- A single SQLite file (default `./secmonk.db`, override with `SECMONK_DB` or `--db`).
- Raw source records are stored as-is (JSON) **plus** a normalized projection used for matching
  (`vulnerability`, `alias`, `affected_range`, `kev`, `epss`). Raw-first lets us re-normalize
  without re-downloading.
- Every row carries `source` and fetch timestamps (vision §10, data freshness).
- Schema created with idempotent `CREATE TABLE IF NOT EXISTS` + a `schema_version` pragma.

## Consequences
- Zero-ops, portable, inspectable with `sqlite3`.
- Concurrency limited to one writer — fine for a CLI prototype. Postgres later if needed.
