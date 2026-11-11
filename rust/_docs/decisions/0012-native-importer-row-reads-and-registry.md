---
title: ADR-0012 — Native importers read stored rows per record or by page, produce operations as a stream, and register in one table
summary: "MirrorView gains rows_by_id (at most 500 ids) and rows_page (paged scan); native operations become an async stream; one IMPORTERS table with default_rust; shared importer code in native, feed, decode, py."
read_when: you port a source that rewrites the children of a record (alias, affected) or replaces a whole table, add a native importer, change MirrorView or the registration of native importers, or need why serde_json parses floats exactly
type: decision
context: decisions
status: proposed
tags: [vuln-source, rust, data-model, decision, euvd]
updated: 2026-11-11
verified: 2026-11-11
related: [decisions/0011-native-sources.md, tech/source-euvd.md, tech/source-msrc.md, tech/source-debian-tracker.md, tech/component-lifecycle.md, tech/data-model.md, tech/configuration.md, tech/engine-service.md]
---

# ADR-0012 — Native importer row reads, operation stream and registry

## Context

[rust ADR-0011](0011-native-sources.md) gave the native importers a read-only `MirrorView` with `applied`,
`count_rows` and `row_keys`, enough for kev (a snapshot table with a natural key) and epss (upserts only). The next
sources in roadmap R1 write more (`src/secmonk/sources/euvd.py`, `msrc.py`, `debian_tracker.py`):

- `euvd` rewrites the children of each record it imports (`replace_children`: every `alias` and `affected` row of the
  record, then the new ones), and `affected` has no natural key: a delete names a whole row
  (`secmonk-mirror-rows/1`: one row equal on every given column);
- `msrc` deletes the `affected` rows of one CVE that came from one monthly document (`extra.document`) and reads the
  stored `vulnerability` row (`modified`, `extra.kbs`) before deciding to write it;
- `debian-tracker` replaces every `distro_triage` row of its source (about 10^5 rows), which with `row_keys` would hold
  all keys as JSON maps at once (about 570 bytes per key, 226 MiB per 400 000 keys, measured in
  [source-epss](../tech/source-epss.md#volume-measured)).

Three sources ported in parallel by different agents also need registration that does not make them edit the same
lines (`NATIVE_SOURCES`, the `native_source` match, `DEFAULT_RUST_SOURCES` in `secmonk-config`, one test file).

## Decision

1. **Two reads more on `MirrorView`** (read-only, implemented by `StoreMirrorView` over two new `MirrorStore` reads):
   - `rows_by_id(table, source, ids)`: the rows of `source` whose id column (`MirrorTable::id_column`:
     `raw_record.record_id`, `vulnerability.id`, `alias` / `affected` `vuln_id`, `kev` / `epss` / `distro_triage`
     `cve_id`; none for `source_sync`) is one of at most `MAX_VIEW_IDS` = 500 ids, in storage order. An importer reads
     the stored rows of the records it rewrites, one chunk of records at a time; memory is bounded by the chunk.
   - `rows_page(table, source, after, limit)`: the rows of `source` in rowid order after a cursor, at most
     `MAX_VIEW_PAGE` = 5 000 per page, `RowPage { rows, next }`. An importer that replaces a whole table compares the
     stored rows page by page with its new snapshot (held compactly by the importer) and emits deletes for the ones
     that left; memory is one page.
   Rows carry every writable column in the mirror's column order (not `affected.rowid_`): text as strings, integers and
   reals as numbers, JSON columns parsed. Given back as an `affected` delete key, a row deletes one row equal to it.
   `row_keys` stays (kev). `rows_page` scans the rowid range after the cursor (`+source` keeps SQLite from using a
   `source` index and sorting all of the source's rows for every page); pages are not a snapshot: rows the source's
   own batches insert between pages (also an `affected` row deleted and inserted again) appear in later pages.
2. **Exact JSON round trip.** The workspace enables `serde_json`'s `float_roundtrip`: a JSON column read back and
   re-serialized by the store gives the stored text again, so a full-row delete key matches (tested in
   `secmonk-store/tests/store.rs` with floats that the default parser rounds differently). Where an importer replaces
   every `affected` row of a record it keys the deletes by `{source, vuln_id}` instead (`rows::DeleteKey::Record`),
   which matches whatever the JSON holds.
3. **Operations as an async stream.** `native::Outcome.ops` is a stream of `StepResult<RowOp>` (`native::iter_ops`
   wraps a list), so an importer reads the view between chunks while the engine applies the batches already cut. Reads
   of records not yet emitted are not affected by those applies; an importer that emits the same record twice in a run
   keeps what it emitted itself instead of reading it back (euvd emits only the last record of an id). An error of the
   stream ends the run as a failed source; the batches applied before it stay and the next sync converges
   (ADR-0011 §4). Everything Python checks before writing (the whole input, one transaction there) is checked before
   the first operation.
4. **One registry table.** `secmonk_sources::IMPORTERS: &[Importer { name, default_rust, new }]`, generated by the
   `importers!` list in `lib.rs` (one line per module, alphabetical). Each importer module declares its
   `pub const IMPORTER`, with `default_rust: true` only once its differential test against `py-sources` is green
   (ADR-0011 §6). `NATIVE_SOURCES` and `secmonk_config::DEFAULT_RUST_SOURCES` are removed; `Config::source_impl(source,
   default)` takes the default from the host, which takes it from the importer. A new importer adds files plus one line.
5. **Shared Python semantics, per-source tests.** `secmonk-sources` gains `py` (whitespace, `float(str)`,
   truthiness, type names, `UnicodeDecodeError` text) and `rows` (the `base.py` write helpers as row builders, and
   `replace_aliases` / `replace_affected` against stored rows). Differential tests live in
   `secmonk-engine/tests/native_<source>.rs` on the shared harness `tests/common/` (`Diff`, mirror comparisons,
   `check_row_contract`); importer tests in `secmonk-sources/tests/<source>.rs` on `tests/common` (`MemView`, an
   in-memory view that applies batches, indexed by key and id, and pages by a rowid that never goes back, as the
   store). Checklist: [component lifecycle](../tech/component-lifecycle.md#porting-a-source-to-a-native-importer).
6. **Shared importer code, no per-importer copies.** What more than one importer needs lives in one module (the full
   list is in the checklist):
   - `native`: `Outcome { status, records, total, cursor, message, ops }` (`records` is the end entry's count, `total`
     the `source_sync.records` when it differs: msrc's `SyncResult.total`), `snapshot_guard(old, new, full)`,
     `internal(source, msg)`, `Progress` (job log lines), besides `limit`, `first_seq`, `stream`;
   - `feed`: `Get` and `get` (one GET with `Accept`, the cap message, a same-origin redirect policy, the `ETag` /
     `Last-Modified` validators), `get_streamed` (the body parsed on the blocking pool while it arrives, a bounded
     channel of 16 chunks), `origin` / `same_origin`, `exists_like_python` (`Path.exists()`, with the Win32 codes on
     Windows), `rglob`, `json_error`;
   - `decode`: `open_decoded` (compression from the magic bytes, a decompressed-size cap, BOM, SHA-256 of the content,
     the first I/O error kept as the message);
   - `py`: `float_repr`, `repr`, `repr_str` (with `str.isprintable`), `str_of`, `iter_items` (a lazy `for x in v`:
     a string is never expanded into one value per character up front), `no_attr`.
   A rule only one source needs stays in its module (epss's gzip by file name, its finite floats).

## Alternatives

| Option | Why not |
|---|---|
| `row_keys` for every table, `affected` keyed by `rowid_` | `rowid_` is not in the row contract; a delete by rowid is a new op (contract change); `row_keys` of a whole table is the 570 bytes/key read this avoids |
| A new row op `replace_children(source, vuln_id)` / `delete_where(source)` | a wire and store contract change that `py-sources` would never emit; the store would learn per-source semantics |
| A streamed read (`Stream` of rows from the store) instead of pages | holds a read connection for the whole sync while batches are written on the other; pages need no open cursor between calls |
| Compute every operation up front (as kev) | a large `--path` import (EUVD dump, debian JSON) would hold all operations in memory; the stream keeps one chunk |
| Registration by `inventory` / linker sections | a new dependency and global state for three names; the macro list is one line per importer |

## Consequences

- `MirrorView` has five methods; the test fakes of kev and epss implement the new two as unreachable.
- Reads between chunks and applies are not one transaction: correct because jobs are serialized (ADR-0011).
- `float_roundtrip` makes float parsing slower (about 2x for floats, serde_json's estimate) everywhere in the
  workspace. JSON columns written before it was enabled may hold a float whose text the exact parser reads as another
  value than the old parser did: comparing such a stored row with the same row built again can find them different,
  so the first import after the change may delete and insert those `affected` rows once (same content); later imports
  compare equal.
- `raw_value` is enabled for importers that split a large document into records without building one tree (euvd).
- msrc reads `vulnerability` (`modified`, `extra`) and its `affected` rows per CVE with `rows_by_id` and deletes the
  rows of one document with `DeleteKey::Row` ([source-msrc](../tech/source-msrc.md)); debian-tracker pages
  `distro_triage` with `rows_page` ([source-debian-tracker](../tech/source-debian-tracker.md)). Both are implemented
  with green differential tests.
- The importers ported in parallel had kept local copies of shared code; they were moved into the modules of §6 with
  every importer's output unchanged (the differential tests are the check). Internal errors of every importer now read
  `<source>: native importer: <msg>`.
