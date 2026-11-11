---
title: ADR-0010 — Sources emit mirror row operations; prototype adapter runs them on a v2 staging database
summary: Sources stream mirror row operations that the host applies; py-sources runs the unchanged Python sources on a v2 staging file and streams its change log (prototype adapter).
read_when: you work on sync, a source module, the mirror row stream, or question the staging copy of the mirror
type: decision
context: decisions
status: proposed
tags: [vuln-source, modules, data-model, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/contracts.md, tech/data-model.md, decisions/0006-python-read-only-db-access.md, decisions/0011-native-sources.md]
---

# ADR-0010 — Source row stream and the staging adapter

## Context

Python sources write SQL directly through `sources/base.py` helpers and their own statements (kev, epss,
debian-tracker, cvelist, osv, msrc, nvd), and **read their previous state** while syncing: cursors in `source_sync`,
`raw_record` for re-normalization (cvelist, nvd), `vulnerability.modified` to skip unchanged records, MSRC merges of
`extra`, snapshot guards counting existing rows. The host must be the only writer ([ADR-0006](0006-python-read-only-db-access.md)),
and `src/` must not change.

## Decision

- **Contract**: `source.sync` streams batches of row operations on the mirror tables (`upsert` by primary key,
  `delete` by key; `affected` deletes match a full row), each batch applied in one transaction, then `source.ack`
  ([contracts (d)](../tech/contracts.md#d-source-row-stream)). A future native source (Python or Rust) emits the same
  stream directly.
- **Prototype adapter**: `py-sources` keeps a v2 database `modules/py-sources/staging.sqlite3` created by
  `secmonk.db.connect`, installs AFTER INSERT/UPDATE/DELETE triggers on the mirror tables that append JSON row images
  to a change log, runs the unchanged `ops.sync_source`, streams the log in order, deletes acknowledged entries.
  Un-acknowledged entries are replayed at the next sync; `source.export` rebuilds the v3 mirror from staging.
- **As built (W2.2)**: log table `_sm_log(seq, src, tbl, op, row JSON, batch)`, current source in `_sm_ctx`, batch counter in
  `_sm_meta`; triggers are recreated when a mirror table's columns change. Changes are cut into batches (≤ 5000 ops, ≈ 2 MiB) and
  numbered once, so a replay is byte-identical; `source.ack(source, through_seq)` deletes up to that batch for that source.
  `affected` has no natural key: its delete carries the whole row and an update is delete + insert. The decisive test replays
  all eight sources' streams on an empty mirror and compares it with staging row by row; a second full sync proves deletes and
  updates. The sync runs to completion, then streams (no overlap), and a cancel is raised from the progress callback.
  `source.export` ignores `through_seq` (required by the schema; send 0).

## Alternatives

| Option | Why not now |
|---|---|
| Python sources write the mirror file directly (one writer per file: the active sync) | Breaks the one-writer rule the user decided; needs locking between host reads and module writes. Cheapest; kept as the fallback if staging cost hurts. |
| Rewrite the 8 sources to emit records | Weeks of work and a second implementation of each feed before the prototype runs. |
| Wrap the sqlite3 connection and translate statements | Fragile: sources use varied SQL, savepoints and reads. |

## Consequences

- Disk: the mirror exists twice (staging + v3) until sources emit natively, and the change log holds a third copy of every
  changed row until acknowledged (SQLite does not shrink the file; `VACUUM` between syncs is an option); a full OSV + CVE List
  mirror is several GB **(verify)**.
- Throughput of millions of row ops over JSON stdio must be measured **(verify)**.
- A host crash between apply and ack replays a batch. As built (W3.1): the store records each source's last applied
  `seq` in `source_applied`, in the batch's transaction, and skips a batch at or below it, so a replay writes nothing
  twice (this matters for `affected`, which has no natural key). `source.export` restarts its seqs at 1: the host
  calls `reset_applied_seq` before applying it. `source.export` stays the repair path.
- The host acknowledges after the stream's `end`, not per batch: `py-sources` serves one request at a time, so an ack
  cannot interleave with the stream. Batches applied before a failed stream are still acknowledged.
- The store binds every batch to its source: a row or key naming another source is refused (the whole batch). For
  `kev` and `epss`, whose keys have no `source`, a source updates or deletes only its own rows; the owning source may
  replace another's (FIRST EPSS scores replace EUVD's, as in Python).
- Seqs come from one counter in the staging database (`_sm_meta.next_batch`), so they only grow across syncs, which
  is what the per-source skip relies on.
- Seeding staging from an existing Python `secmonk.db` would skip the first full download (backlog).
- As built (W4.4, review M1/M5): seqs are bound to the staging file. Staging has a random `generation`
  (`_sm_meta.generation`) and remembers the highest acknowledged seq per source (`_sm_meta."acked:<source>"`); both
  travel in every batch (optional fields, the format stays `secmonk-mirror-rows/1`). The store records the generation
  with the applied seq (mirror migration `0003`) and answers `needs_repair` instead of skipping when the generation differs
  (staging recreated: seqs restart at 1) or `acked_through` exceeds the applied seq (mirror reset or restored); a stream
  with no batch on a mirror without applied state also repairs. The repair is `source.export` applied in one
  transaction after deleting the source's rows, recorded with the export's `high_water` and generation, then acknowledged
  through `high_water`; this replaces `reset_applied_seq` + plain apply (which duplicated `affected` rows). Mirrors
  written before W4.4 (no generation) repair each source once. Not covered: a staging file restored from an older copy of
  the same generation (its seqs repeat and would be skipped) **(open)**.

**Status note (2026-11-11):** native sources (Rust, no staging, no log, no export; `kev` first) are decided in
[rust ADR-0011](0011-native-sources.md); this ADR still governs `py-sources`.
