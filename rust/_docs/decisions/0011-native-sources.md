---
title: ADR-0011 — Native importers diff against the mirror through a read-only view; no staging, no log, no export
summary: "Rust sources emit secmonk-mirror-rows/1 without staging: read-only MirrorView, native-rust generation, switch to and from py-sources, repair = next sync, per-source selection in sec-monk.toml."
read_when: you port a source to Rust, change how sync applies native batches, switch a source between Rust and Python, or debug seq/generation/repair of a native importer
type: decision
context: decisions
status: accepted
tags: [vuln-source, rust, modules, data-model, decision, kev]
updated: 2026-11-11
verified: 2026-11-11
related: [decisions/0010-source-staging-adapter.md, tech/source-kev.md, tech/contracts.md, tech/engine-service.md, tech/configuration.md, tech/component-lifecycle.md]
---

# ADR-0011 — Native importers

## Context

[rust ADR-0010](0010-source-staging-adapter.md) gives every source the same contract: `source.sync` streams
`secmonk-mirror-rows/1` batches that the host applies, then `source.ack`; `source.export` rebuilds the mirror. Its
prototype adapter (`py-sources`) gets seq, `generation` and `acked_through` from a staging database and a change log.
Stage 6 of the [standard process](../tech/component-lifecycle.md#6-later-the-rust-port) ports a component to Rust;
`kev` (CISA KEV) is the first source ported (user choice, 2026-11-11: the smallest feed). A Rust source has no
staging copy and no log, yet it needs its previous state: the snapshot guard counts the stored rows, a snapshot replace
must delete the CVEs that left the feed, and its batch seqs must stay above the applied seq or the store skips them.

## Decision

1. **Crate `secmonk-sources`** (the native importers) implements the existing `Source` trait in-process (`kev` first, `NATIVE_SOURCES`).
   Downloads use the workspace `reqwest` (rustls), as `secmonk-runtime`: no new HTTP stack. It depends on traits,
   model, safeio, reqwest, tokio; never on the store, the module host or the engine.
2. **Read-only view, no handle.** `secmonk-traits` gains `MirrorView` (`applied`, `count_rows(table, source)`,
   `row_keys(table, source)`), implemented by the engine (`StoreMirrorView`) over two new read methods of
   `MirrorStore`. A native importer computes its batches against the mirror as it is: deletes for stored keys absent from
   the new snapshot, upserts for every entry, then the `source_sync` row. Writes still go only through
   `MirrorStore::apply_rows` (one writer, rust ADR-0006).
3. **Seq and generation.** Native batches carry `generation = "native-rust"` (`NATIVE_GENERATION`) and no
   `acked_through`; seqs continue from the applied seq when it belongs to that generation, else start at 1. The trait
   method `Source::native()` (Rust only, default `false`) tells the engine. Before a native stream the engine resets an
   applied state of another generation (`reset_applied_seq`: **switch from `py-sources` to the native importer**;
   job log `<source>: native importer: applied state of generation <g> (seq N) reset; full sync against the mirror`).
   A batch the store skips
   or refuses is an error of that source, never silently dropped.
4. **No ack, no export, repair = the next sync.** `ack` is a no-op, `export` answers `unknown-method`, and the engine
   never repairs a native importer from an export. Every sync is a diff against the current mirror, so a stream cut
   after some batches, a reset or restored mirror, or rows lost in between converge on the next sync.
5. **Switch back to `py-sources`** (repair from the staging export). A `py-sources` batch after native syncs carries its staging generation, which differs from
   `native-rust`: the store answers `needs_repair`. Only an **ok** run repairs: the engine then rebuilds the source from
   the staging export (rust ADR-0010; job log `<source>: repair from py-sources export: the last applied batches came
   from the native importer`), which holds the new snapshot because the staging sync ran first. After a run
   that is not ok (`error`: offline, HTTP error, guard refusal; `partial`: `--limit`) staging is still the state from
   before the switch to the native importer (plus a subset), so its export would replace newer mirror rows with older
   ones: the engine applies nothing, keeps the mirror and the native applied state, acknowledges nothing, and reports
   the source as `error` (`<status>: <message>; not applied: mirror keeps the native importer data until a successful
   py-sources sync`);
   the next ok `py-sources` run repairs (its un-acknowledged batches are replayed into the same repair).
6. **Selection** per source in `sec-monk.toml`: `[sources.implementation] <name> = "rust" | "python"`. A source's
   default becomes `rust` only when its differential test against `py-sources` is green (`DEFAULT_RUST_SOURCES`; kev
   since 2026-11-11). A name that cannot be served as configured refuses the start: `rust` without a Rust
   implementation, `python` without an enabled module providing it, so a misspelled name is never silently ignored.
   The host puts the native importers ahead of `py-sources` (a name served twice is taken from the first); `py-sources` keeps serving the others
   and stays the reference.

This narrows rust ADR-0010 for native importers only: its staging adapter, ack and export rules stay as they are for
`py-sources`.

## Alternatives

| Option | Why not |
|---|---|
| A new row op (`replace` / `truncate` of a source's table) | A contract change the store and the schema must learn; the snapshot guard still needs the stored row count. |
| A small staging file per native importer (last snapshot + keys) | A second copy that differs from the mirror after a mirror reset or restore; the native importer keeps no copy by design. |
| Native batches without a generation (plain seq rule) | The applied state would keep the staging generation, so a later `py-sources` batch with a lower seq would be skipped instead of repaired. |
| Native `export` = a fresh snapshot; every switch from `py-sources` goes through the repair path | A second download, and `begin_repair` deletes the raw records the Python source keeps. |
| Timestamp seqs (no read of the applied state) | Wrong when the clock goes back: batches skipped silently. |

## Consequences

- The mirror is the only store of the native importer's data: nothing is kept outside it; disk for the kev staging copy is
  saved once `py-sources` stops syncing kev (its staging still holds its last kev state).
- The view's reads and the batch applies are not one transaction: correct because jobs are serialized (one sync at a
  time). A concurrent writer of the same source would make the store skip a native batch, which fails the source
  instead of losing data (`tests/engine.rs` `a_native_batch_the_store_skips_is_an_error`).
- A stream cut between batches (host stop, crash) leaves a mixed mirror until the next sync: the deletes and some
  upserts of the new snapshot are applied while `source_sync` (the last op) still shows the previous ok run (status,
  cursor, records). The next sync converges, since it is computed against the mirror as it is
  (`tests/engine.rs` `native_kev_resets_a_staging_applied_state_and_converges_after_a_partial_stream`).
- A reset mirror is rebuilt by the next native sync except the raw records of CVEs that left the feed (the Python
  source keeps them; `py-sources` would restore them from staging). Nothing reads `raw_record` of kev today.
- Native feed errors are worded like Python where it is cheap (`OSError`, missing keys, the guard); JSON and download
  errors differ in wording, not in status ([source-kev](../tech/source-kev.md)).
- The `Source` trait gained one defaulted method; `MirrorStore` two read methods; the wire contract is unchanged
  (`generation` was already optional and free-form within its pattern).
- Open: retire `py-sources`' kev after one release ([component lifecycle](../tech/component-lifecycle.md)); a native
  source that is not a snapshot (deltas with cursors) reads its cursor through the view the same way **(verify)** when
  the next source is ported.
