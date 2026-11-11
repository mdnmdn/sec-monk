---
title: Source epss — the native (Rust) FIRST EPSS source
summary: The Rust epss source in secmonk-sources - CSV(.gz) parsing with size, line and row caps, guard, limit, API mode, no deletes, EUVD row ownership, measured 400k-row cost, differences from Python, tests.
read_when: you change the Rust epss source, switch epss between Rust and Python, debug an epss sync or its EUVD rows, or need the measured cost of a 400k-row native sync
type: tech
context: tech
status: implemented
tags: [vuln-source, epss, rust, sync, performance]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-sources/src/epss.rs, rust/crates/secmonk-sources/src/native.rs, rust/crates/secmonk-sources/src/batch.rs, rust/crates/secmonk-sources/src/feed.rs, rust/crates/secmonk-store/src/sqlite/mirror.rs, rust/crates/secmonk-host/src/engine.rs]
fixtures: [tests/fixtures/sources/epss/, tests/fixtures/sources/euvd/]
related: [tech/source-kev.md, decisions/0011-native-sources.md, decisions/0010-source-staging-adapter.md, tech/data-model.md, tech/engine-service.md, tech/configuration.md, tech/contracts.md]
---

# Source epss (native importer)

The second source ported to Rust, after [kev](source-kev.md), on the same pattern
([rust ADR-0011](../decisions/0011-native-sources.md)): `secmonk_sources::epss::EpssSource` implements `Source`
in-process and emits `secmonk-mirror-rows/1` batches computed against the mirror through the read-only `MirrorView`.
The feed is described in the Python tree's [EPSS reference](../../../_docs/references/vuln-sources/epss.md); the
reference implementation is `src/secmonk/sources/epss.py` `EpssSource.sync` plus `ops.sync_source` /
`db.set_sync_state`.

## Selection

`[sources.implementation] epss = "rust"` (the default since 2026-11-11, `DEFAULT_RUST_SOURCES`) or `"python"`
([configuration](configuration.md#schema)). The host lists it ahead of `py-sources` (`native_sources`); switching
behaves as for kev ([source-kev](source-kev.md#one-sync), [engine-service](engine-service.md)): the first native sync
after `py-sources` resets the applied state (job log `epss: native importer: applied state of generation <g> (seq N)
reset; full sync against the mirror`), the first ok `py-sources` sync after native ones repairs from the staging export.

## One sync

| Step | Behaviour |
|---|---|
| Mode | `options.ids` given (non-empty list, even of blank ids): API mode. Else bulk mode. |
| Load (bulk) | `options.path` (non-empty): the local file, a regular file only (as kev: a directory answers `IsADirectoryError: [Errno 21] Is a directory: '<path>'`, a missing file `FileNotFoundError: [Errno 2] …`, a FIFO or device `OSError: not a regular file: '<path>'`); gzip when the name ends in `.gz`, else plain; origin `file <path>`. Else the daily file `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (workspace `reqwest`, rustls, `https_only`, connect and read timeout 120 s as httpx there, at most `MAX_DOWNLOAD` = 128 MiB compressed, held in memory); origin the URL. |
| Decompress, split | `flate2::read::GzDecoder` (one gzip member; bytes after it are ignored, as Python's `decompressobj`), output capped at `MAX_DECOMPRESSED` = 1 GiB (also for plain files): `DecompressError: decompressed data exceeds the 1073741824 byte limit`. A truncated or empty gzip file: `DecompressError: truncated gz data (no end-of-stream marker)`; a corrupt one `DecompressError: corrupt gz data: <flate2 text>`. Lines split on `\n`, each at most `MAX_LINE` = 64 KiB before it is buffered whole (`ValueError: EPSS line longer than 65536 bytes`), decoded as strict UTF-8. Runs on the blocking pool. |
| Parse | `_parse_rows`: stripped lines; blank ones skipped; `#` lines set the current `score_date` from the first `score_date:YYYY-MM-DD`; a line starting with `cve,` (any case) is the header; then `cve,epss,percentile[,…]`: fewer than three fields, or a number Python's `float` refuses, skips the line; the CVE is stripped and upper-cased. Numbers follow `float(str)`: surrounding whitespace, sign, `_` between digits, exponents, Unicode decimal digits (`０.５` is 0.5; table of the 68 digit ranges of Unicode 15.1, from Python 3.13); `nan` becomes a NULL score (SQLite stores a NaN as NULL); an infinity skips the line (below). At most `MAX_ROWS` = 2 000 000 rows (`ValueError: EPSS file has more than 2000000 rows; refusing`) and `MAX_CVE_BYTES` = 64 MiB of CVE ids (`ValueError: EPSS file has more than 67108864 bytes of CVE ids; refusing`); comment and date lines keep nothing. |
| Limit | `options.limit` (>= 1; 0 is `invalid-params`): reading stops after N rows; no guard; status `partial`; the cursor is kept. |
| Guard | Without `limit`: no rows is refused even with `full` (`ValueError: EPSS file has no rows; refusing`); without `full`, fewer rows than half of the stored `source = 'epss'` rows (`MirrorView::count_rows`) is refused (`ValueError: EPSS file has only 10 rows (stored: 30, < 50%); refusing (use --full to force)`). Exactly half is accepted. |
| Rows | One `epss` upsert per parsed row, file order (a duplicate CVE is upserted twice, the later one is stored, as with `INSERT OR REPLACE`): `cve_id`, `score`, `percentile`, `date` (the current `score_date`, null before any), `source = "epss"`. **No deletes**: the Python source never deletes, so a CVE that leaves the file keeps its last score. Last the `source_sync` upsert. |
| `source_sync` | ok / partial: `last_sync`, `cursor` = the last row's `score_date` (ok only; Python's `COALESCE` keeps the old one otherwise), `records` = rows, `status`, `message` `<N> scores from <origin>`. error: status and message only. |
| API mode | Ids stripped, upper-cased, blank ones dropped, cut to `limit`; `GET https://api.first.org/data/v1/epss?cve=<id>,<id>…` per 100 ids (the comma percent-encoded, as httpx), answers capped at 16 MiB; rows from `data[]` (`cve` as given, `epss` / `percentile` as strings or numbers, `date` string or null); progress `epss: <N> scores from API` per request; message `<N> scores from FIRST API (<M> ids)`; cursor = the last row's `date`. Every answer is read before anything is emitted (Python rolls back on any error). |
| Batches | Built while the engine reads the stream (`native::stream`, `batch::Cutter`): at most 5 000 ops and about 2 MiB each, one batch in memory at a time, `generation = "native-rust"`, seqs after the applied seq of that generation, else from 1. |

`options.ids` reaches the source only from a direct caller: the engine's sync plan never sends ids (`sync_options` in
`secmonk-engine/src/sync.rs`), as `py-sources` (which accepts them) is never sent any either. The API mode is ported
because `py-sources` exposes `ids` in its sync options; it is tested against a local server, not compared with
`py-sources` (that would need the network).

## Ownership with EUVD rows

The `epss` key is `cve_id` alone: FIRST (`source = 'epss'`) and EUVD (`source = 'euvd'`, `euvd.py` writes scores of
its records with a NULL percentile) share it. Python's rules, kept by the store's source binding
([data-model](data-model.md#store-traits), `owner_of_sourceless_key` in `secmonk-store/src/sqlite/mirror.rs`):

| Case | Result |
|---|---|
| FIRST row for a CVE with a EUVD row | replaced: all five columns, `source` becomes `epss` (Python's `INSERT OR REPLACE`) |
| EUVD row for a CVE with a FIRST row | not written (Python's `ON CONFLICT … WHERE epss.source='euvd'`) |
| EUVD row for its own CVE | updated |
| FIRST file lacks a CVE that has a EUVD row | the EUVD row stays (the native importer emits no delete) |

The native importer needs no new store rule: it only upserts rows of its own source. Tested through the engine
(`native_epss_replaces_euvd_rows_of_its_cves_and_keeps_the_others`) and against `py-sources` with EUVD synced on both
mirrors (differential test below).

## Diff strategy and memory

The importer emits every row of the file, as the Python source writes every row. It does not read the stored scores
to emit only changed rows: the daily file carries a new `score_date` on every row, so on a daily sync every row
changes and such a read would save nothing; it would only shorten a second sync of the same file on the same day,
at the cost of reading 300-400k stored rows first. It needs no `row_keys` either (no deletes): it reads
`applied` and `count_rows` only, so `MirrorView` is unchanged and no new decision record was needed. The parsed rows
are kept in a compact list because the guard must see the whole file before anything is emitted; the JSON rows are
built per batch. A row takes 48 bytes (CVE id as a boxed string, two `f64`, the `score_date` inline as ten bytes)
plus its id on the heap; date and comment lines allocate nothing. Worst case for any input within the caps: 2 000 000
rows = 96 MiB, up to half of that again while the list grows, 64 MiB of ids (`MAX_CVE_BYTES`) and about 32 MiB of
allocator rounding, so about 250 MiB; the real 2026 file (about 300 000 rows, 4 MiB of ids) takes about 20 MiB.
Measured on 400 000 rows: +23 MiB (below).

## Volume (measured)

Measured on 2026-11-11 on an Apple M2 (8 cores, 24 GiB RAM, macOS 26.5, internal SSD), test binary built with the
workspace's release profile (`opt-level = "s"`) with LTO off and 16 codegen units (`CARGO_PROFILE_RELEASE_LTO=false
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`, to keep the build short). Input: a synthetic file of 400 000 rows in the real
layout, generated at run time (gzip 3.6 MiB), `secmonk-engine/tests/real_modules.rs` `epss_volume_*` (ignored tests,
each run in its own process under `/usr/bin/time -l`; the peak resident set is of the test process, so the Python
child of `py-sources` is not counted). Sample: synthetic.

| Measurement | Time | Peak resident set |
|---|---|---|
| Baseline (file generated, a store opened) | 0.5 s | 41 MiB |
| Native stream alone: parse, guard, all 81 batches built, nothing applied | first batch after 0.07 s, all 0.40 s | 64 MiB (+23) |
| **Native importer through the engine**, first sync / re-sync (new `score_date`: every row changes) | **5.3-5.4 s / 5.2-5.3 s** | 93 MiB (+52, both syncs) |
| `py-sources` through the engine, same file, same machine, first sync / re-sync | 16.4 s / 17.6 s | (child process) |
| `MirrorView::count_rows` over 400 000 rows | 0.02 s | |
| `MirrorView::row_keys` over 400 000 keys (not used by epss; for the record) | 0.25 s | +226 MiB (fill alone 64 MiB, with the read 290 MiB) |

Reading: the native path is about 3 times faster than `py-sources` here; of its 5.3 s, 0.4 s is parsing and building
batches and the rest is `MirrorStore::apply_rows` (about 12-13 µs per upsert, 80 transactions). The 72 s of the backlog
(host-side apply through `py-sources`) was not reproduced on this machine: the same path took 16-18 s. `row_keys`
holds every key as a JSON map (about 570 bytes per key): fine for kev (about 1 500 keys), too much memory for a source with
hundreds of thousands of keys to delete. The mirrors of both paths are compared at the end of the run (equal).

Re-run: `cargo test --release -p secmonk-engine --test real_modules --no-run`, then
`SECMONK_REQUIRE_VENV=1 /usr/bin/time -l <binary> --ignored --exact epss_volume_sync --nocapture` (also
`epss_volume_baseline`, `epss_volume_native_stream`, `epss_volume_row_keys`; `SECMONK_EPSS_ROWS`,
`SECMONK_EPSS_FILL_ONLY=1`, `SECMONK_EPSS_NATIVE_ONLY=1`).

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | `INSERT OR REPLACE` per row, one transaction | upserts in batches of 5 000, one transaction per batch: same rows |
| Stream cut between batches | (py-sources batches too) | the applied upserts stay, `source_sync` (the last op) still shows the previous run; the next sync converges |
| Plain file size | unbounded | 1 GiB (`ValueError: EPSS file exceeds the 1073741824 byte limit`) |
| Rows per file | unbounded | 2 000 000 (`ValueError: EPSS file has more than 2000000 rows; refusing`); also with `--limit` above 2 000 000 on a larger file, where Python returns `partial` (a limit up to 2 000 000 stops reading first, as Python) |
| Bytes of CVE ids per file | unbounded | 64 MiB (`ValueError: EPSS file has more than 67108864 bytes of CVE ids; refusing`) |
| Download | streamed, unbounded | at most 128 MiB compressed, read into memory, then decompressed |
| A score or percentile `inf` | stored in staging as infinity; it has no JSON form, so the py-sources stream cannot carry it | the line is skipped |
| `score_date` digits | `\d` (any Unicode digit) | ASCII digits |
| Invalid UTF-8 | `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 4: invalid start byte` | the same text without the reason (`…in position 4`) |
| Corrupt gzip, HTTP errors | zlib / httpx wording (`HTTPStatusError: Client error '404 Not Found' …`) | `DecompressError: corrupt gz data: <flate2 text>`, `HTTP 404 for <url>` / reqwest wording; same `error` status |
| A line over 64 KiB after the `--limit`-th row, in the same decompressed chunk | `ValueError` (Python checks the whole chunk) | not read (reading stops at the limit) |
| `--path` a FIFO or device | blocks reading it | refused: `OSError: not a regular file: '<path>'` |
| API answer not an object, `data` not a list, entry not an object, `cve` not a string, `date` not a string | `AttributeError` / `TypeError` / stored as given | `epss: API answer …` messages; the sync fails |
| Relative `--path` | the module's working directory | the host process's working directory (the UI sends absolute paths) |

Equal by test: rows of every parser case of `EPSS_ODD` (stored floats compared exactly), the ok, partial and guard
messages, the empty-file refusal, `IsADirectoryError`, the truncated-gzip and long-line messages, entry `status` and
`records`, `source_sync` (timestamps aside), the EUVD rows.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/src/epss.rs` (unit) | line parsing (`score_date`, header, whitespace, `_`, exponent, Unicode decimal digits, NaN, infinities); `date_lines_keep_nothing_and_cve_bytes_are_capped` (200 000 date lines and a row: 48-byte rows, no allocation per date line; the CVE-bytes cap); gzip: empty, half header, mid stream, no trailer, bad CRC, garbage, trailing bytes; decompression cap on a small gzip that expands to 4 MiB, plain-file cap, row cap, line cap (exactly 64 KiB accepted), invalid UTF-8; `--limit` stops before a truncation |
| `secmonk-sources/tests/epss.rs` | rows of the fixture, gzip equal to plain, score dates and duplicates, seqs (native generation, restart after another), 12 000 rows in batches of 5 000, guard / limit / full / empty file, error entries (`FileNotFoundError`, `IsADirectoryError`, long line), bulk download, 404 and size cap, API mode (request line, 100-id batches, `--limit`, blank ids, a bad answer) against a local server; the fake view panics if `row_keys` is called |
| `secmonk-sources/src/batch.rs` | `Cutter` / `cut` limits and numbering |
| `secmonk-engine/tests/engine.rs` | `native_epss_replaces_euvd_rows_of_its_cves_and_keeps_the_others`; `native_epss_batches_follow_the_row_contract` (fixture, limit, odd lines with a null date and an empty id, a failed run; every batch and end validated against `source/rows.schema.json` and `source/sync-end.schema.json`) |
| `secmonk-engine/tests/real_modules.rs` `native_epss_matches_py_sources` | **differential** (needs `rust/python/.venv`; `SECMONK_REQUIRE_VENV=1` fails instead of skipping): `py-sources` and the native source on their own mirrors, EUVD synced through `py-sources` on both (a CVE shared with the FIRST file, one only in EUVD); all mirror tables equal (`source_sync.last_sync` aside) after: EUVD first, first sync, no-op, update as gzip (removed, changed, added rows), EUVD again, `EPSS_ODD` with `full`, `limit`, guard refusal, empty file (with and without `full`), a directory, a truncated gzip, a 70 000-byte line, invalid UTF-8 (message aside), `full` with a small file; on a third mirror py-sources -> native (log line checked) -> a failed and a limited py-sources run (nothing applied) -> py-sources (repair from the export; mirror equal to its staging and, for the `epss` rows of source `epss` and the `source_sync` row, to the Python-only mirror) |
| `secmonk-engine/tests/real_modules.rs` `epss_volume_*` | the measurements above (ignored) |
| `secmonk-host/src/engine.rs`, `secmonk-config/tests/config.rs` | epss and kev native by default; one or both switched to `python` |

Fixtures: `tests/fixtures/sources/epss/epss_scores-sample.csv` (10 rows, synthetic, read only) and `api-sample.json`
(2 rows); `tests/fixtures/sources/euvd/exploited-sample.json`. The gzip, update, small, empty, odd, truncated, long-line,
EUVD and 400 000-row variants are written at test time (synthetic, nothing committed).
