---
title: Source debian-tracker — the native (Rust) Debian Security Tracker source
summary: The Rust debian-tracker source in secmonk-sources - streamed JSON and repo text lists, compact rows, distro_triage paged compare with deletes, guard, limit, caps, measured volume, differences, tests.
read_when: you change the Rust debian-tracker source, switch debian-tracker between Rust and Python, debug a distro_triage sync, or port a source that replaces a whole table and want the paged-compare example
type: tech
context: tech
status: implemented
tags: [vuln-source, debian, distro, rust, sync, matching]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-sources/src/debian_tracker.rs, rust/crates/secmonk-sources/src/native.rs, rust/crates/secmonk-sources/src/feed.rs, rust/crates/secmonk-sources/src/decode.rs, rust/crates/secmonk-sources/src/py.rs, rust/crates/secmonk-store/src/sqlite/mirror.rs, rust/crates/secmonk-engine/src/view.rs]
fixtures: [tests/fixtures/sources/debian-tracker/]
related: [decisions/0012-native-importer-row-reads-and-registry.md, decisions/0011-native-sources.md, tech/source-euvd.md, tech/source-epss.md, tech/source-kev.md, tech/component-lifecycle.md, tech/data-model.md, tech/configuration.md]
---

# Source debian-tracker (native importer)

The fifth source ported to Rust, and the first that replaces a whole table of about 10^5-10^6 rows
([rust ADR-0011](../decisions/0011-native-sources.md), [ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)).
`secmonk_sources::debian_tracker::DebianTrackerSource` implements `Source` in-process and writes only
`distro_triage` (and its `source_sync` row). The formats are described in the Python tree's
[Debian tracker reference](../../../_docs/references/vuln-sources/debian-tracker.md) (written from documented formats,
fixtures synthetic, no real tracker data seen); the reference implementation is
`src/secmonk/sources/debian_tracker.py` `DebianTrackerSource.sync` plus `ops.sync_source` / `db.set_sync_state`.

## Selection

`[sources.implementation] debian-tracker = "rust"` (the default since 2026-11-11: `IMPORTER.default_rust` in
`debian_tracker.rs`, set because the differential test is green) or `"python"` ([configuration](configuration.md#schema)).
`in_all` is `true`, as `py-sources` reports it (the Python source sets no `in_all = False`), so `sync all` includes
it, last in `ops.SYNC_ALL_ORDER`. Switching behaves as for kev: the first native sync after `py-sources` resets the
applied state (job log `debian-tracker: native importer: applied state of generation <g> (seq N) reset; full sync
against the mirror`); a failed or `partial` `py-sources` run after native ones is not applied; the next ok one repairs
from the staging export.

## One sync

| Step | Behaviour |
|---|---|
| Input | `options.path` a directory: a repository checkout (the directory holding `data/`, or `data/` itself). `options.path` anything else: a tracker JSON file, opened with `feed::open_regular` (missing: `FileNotFoundError: [Errno 2] No such file or directory: '<path>'`; a FIFO or device: `OSError: not a regular file: '<path>'`); origin `file <path>`. No path: `GET https://security-tracker.debian.org/tracker/data/json` (workspace `reqwest`, rustls, `https_only`, connect and read timeout 300 s as httpx there), at most `Caps::download` = 512 MiB (`ValueError: tracker download exceeds 536870912 bytes`, also from `Content-Length`); HTTP errors `HTTP 404 for <url>`; origin the URL. |
| JSON reading | `decode::open_decoded` (shared). Compression by magic bytes: gzip (one member; trailing bytes ignored, as zlib there), plain; bzip2 and xz are refused (`debian-tracker: native importer: bzip2 input is not supported; decompress the file or use gzip`). Decompressed bytes at most `Caps::decompressed` = 1 GiB (gzip: `DecompressError: decompressed data exceeds the 1073741824 byte limit`; plain: `debian-tracker: native importer: the document is larger than 1073741824 bytes; refusing`); a truncated gzip `DecompressError: truncated gz data (no end-of-stream marker)`. A leading UTF-8 BOM is skipped (`json.loads` of bytes). The download is parsed while it arrives (`feed::get_streamed`: a bounded channel of 16 chunks to the parser on the blocking pool): the body is never held whole. The document is read with `serde_json` visitors, no tree: per package its CVE entries (a repeated key keeps its first place and its last value, as a Python dict; at most `Caps::entry_bytes` = 64 MiB of kept data per package, counted as held: per release the `Rel` struct, 168 bytes, its slots in the list and key map, its key twice and the text of its fields; per entry its slots and key twice), per entry only `releases`, per release only `status`, `fixed_version`, `urgency`, `nodsa`, `nodsa_reason`. A top level that is not an object: `TypeError: tracker JSON: top level is not an object`; syntax errors `invalid JSON: <serde_json text>`. Cursor: `ETag`, else `Last-Modified`, else the SHA-256 of the decompressed bytes (BOM included), as Python. |
| JSON rows | `rows_from_json` in order: packages sorted by name (a repeated package: the last value), the first `limit` packages with `limit` (non-objects counted); per package a non-object is skipped; per entry a non-object is skipped, `TEMP-*` counted and skipped, `releases` falsy is nothing, a truthy non-object `AttributeError: 'list' object has no attribute 'items'`; per release a non-object skipped, the codename stripped and lower-cased: `sid` / `unstable` counted, an unknown codename counted, else `Debian:<n>` (wheezy 7 ... duke 15). Columns as `_json_row`: `status` lower-cased (a truthy non-string: `AttributeError: 'int' object has no attribute 'lower'`), `fixed_version` as `str()` (strings, ints, bools, floats in Python's `repr`), `resolved` + `0` is `not-affected`, `urgency` stripped, lower-cased, `*` removed and noted (non-string: `... no attribute 'strip'`), `nodsa` = `nodsa_reason` when `postponed` / `ignored` else `no-dsa` when `nodsa` is present, `note` = stripped `nodsa` text and the star note joined with `; `. The error of the first failing package in name order is the run's (Python's generator order); a package beyond `limit` cannot fail the run. |
| Checkout rows | `data/CVE/list`, then `data/DSA/list` and `data/DLA/list`; a list that is missing or not a regular file is empty (`_read_text`). Each file at most `Caps::file_bytes` = 512 MiB, each line at most `Caps::line_bytes` = 1 MiB (`debian-tracker: native importer: <path>: a line is longer than 1048576 bytes; refusing`); lines as Python's text mode reads them (`\n`, `\r\n` and `\r` end a line; invalid UTF-8 replaced by U+FFFD). The line patterns are the Python regular expressions (`regex` crate, leftmost-first like `re`; `\s` widened to `str.isspace`), and the block logic of `rows_from_cve_list` (sid urgency inherited, explicit releases, sid `<unfixed>` / `<undetermined>` / `<not-affected>` propagated to bullseye, bookworm, trixie, forky; a later row of the same key replaces the earlier one), `_split_paren`, `_text_row`. Advisories are matched when each advisory block ends (`attach_advisories`: the first advisory of a row, or the first whose version equals its `fixed_version`; references without a row counted). At most `Caps::entry_bytes` per CVE or advisory block (per kept line its record, 96 or 72 bytes, plus the line's length). `limit`: the rows of the first `limit` package names (sorted). Cursor: SHA-256 of Python's `repr(sorted(rows))`, computed from the rows. |
| Caps on what is kept | `Caps::packages` = 1 000 000 JSON packages, `Caps::rows` = 3 000 000 rows built, `Caps::strings` = 2 000 000 distinct strings, `Caps::string_bytes` = 128 MiB of them (`debian-tracker: native importer: more than N rows; refusing`, ...). Every row is built and checked before the first operation (Python builds the list inside its transaction): any failure is an `error` with only the `source_sync` row. |
| Guard | Without `limit` and without `full`: `count_rows(distro_triage, debian-tracker)`, then `native::snapshot_guard` (shared with kev) with the prefix `debian-tracker: `; none new: `debian-tracker: refusing to replace the data with an empty snapshot (use --full to force)`; fewer than half the stored rows: `debian-tracker: refusing to replace <old> rows with a snapshot of only <n> (< 50%; use --full to force)` (Python's `snapshot_guard`). |
| Operations (snapshot) | The rows sorted by `(ecosystem, package, cve_id)`, the last row of each key kept (`INSERT OR REPLACE` in Python's order). The stored rows are read with `MirrorView::rows_page` (5 000 per page) until the last page, **all before the first operation is emitted**, so the pages never see this run's writes. A stored row whose key is not new: a delete `{ecosystem, package, cve_id, source}`; a stored row equal on every column: nothing; then an upsert (every column) per new or changed row. Deletes first, then upserts. |
| Operations (`limit`) | An upsert per row of the subset; nothing read, nothing deleted; status `partial`, no cursor (as Python). |
| `source_sync` | `status` `ok` / `partial`, `records` = the rows built (JSON: duplicates of a key counted, as Python's `len(rows)`), message `<n> triage rows from <origin>; skipped <t> TEMP ids, <s> sid entries, <u> unknown-release entries` plus `; <k> advisory refs without a matching row` when there are some. Error: status and message only. |
| Batches | `native::stream`: at most 5 000 ops and about 2 MiB each, `generation = "native-rust"`, built while the engine reads the stream. |

## Diff strategy

Python deletes every row of the source and inserts the snapshot. The native run emits only the difference, with the same
end state: reads `count_rows` (guard) and every page of `rows_page(distro_triage, debian-tracker)`; no `rows_by_id`.
Deletes are keyed by the table's primary key (`distro_triage` has one), so a delete removes exactly the stored row. A
stored row whose key columns are not text (never written by either implementation) is deleted by its stored values.

## Memory

Rows are 36 bytes (a release index and eight string ids); strings are kept once (`Arc<str>` with a map for lookups).
Within the caps, estimated worst case: rows 108 MiB, twice that while the list grows or is sorted; the strings about
230 MiB (128 MiB of text, about 50 bytes of bookkeeping each); the package map about 100 MiB at 1 000 000 packages;
one package or block being read at most 64 MiB (counted as held, see JSON reading); one page of stored rows (about
5 MiB) and one batch (2 MiB); 12 bytes per delete plus the strings of keys that left. Together about 0.7 GiB. Not
bounded by these caps: a JSON string that is read (a key or a kept field; ignored values are skipped without
buffering) is held twice while it is read, in `serde_json`'s scratch buffer and in the `String` the visitor makes of
it, so a pathological file with one huge string costs up to twice the decompressed cap (2 GiB) on top.

### Volume (measured)

Measured on 2026-11-11 on an Apple M2 (8 cores, 24 GiB RAM, macOS 26.5, internal SSD), test binary built with the
workspace's release profile with LTO off and 16 codegen units (`CARGO_PROFILE_RELEASE_LTO=false
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`). Input: a synthetic tracker JSON in the real layout, 100 000 packages x 3 CVE
entries x (bookworm, sid, trixie), 600 000 rows, 119 MiB, generated at run time; the second file drops every tenth
package (60 000 deletes) and changes a third of the rows. `secmonk-engine/tests/native_debian_tracker.rs`
`debian_tracker_volume_*` (ignored), each run in its own process under `/usr/bin/time -l`; the peak resident set is of
the test process (the Python child of `py-sources` not counted, the host's apply of its batches counted). Sample:
synthetic.

| Measurement | Time | Peak resident set |
|---|---|---|
| Baseline (both files generated in memory, a store opened) | 1.2 s | 132 MiB |
| Native stream alone: parse, guard, compare (empty mirror), all 121 batches built, nothing applied | first batch after 4.2 s, all 6.2 s | 214 MiB |
| **Native importer through the engine**: first sync / re-sync with changes / unchanged re-sync | **24-25 s / 15-16 s / 8-9 s** | 215 MiB (all three) |
| `py-sources` through the engine, same files: first sync / re-sync with changes / unchanged re-sync | 110 s / 140 s / 143 s | 1.15 GiB (host side included) |

Reading: the native path is 4-18 times faster; the unchanged re-sync emits only the `source_sync` row (its 8-9 s are
parsing the 119 MiB file and reading 120 pages). The mirrors of both paths are equal at the end of the run. Re-run:
`cargo test --release -p secmonk-engine --test native_debian_tracker --no-run`, then
`SECMONK_REQUIRE_VENV=1 /usr/bin/time -l <binary> --ignored --exact debian_tracker_volume_sync --nocapture`
(`SECMONK_DT_PACKAGES` for the size, `SECMONK_DT_NATIVE_ONLY=1` for the native half only).

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | every row of the source deleted and inserted, one transaction | the same rows; only the difference is written, in batches (`rowid` differs, not compared) |
| Stream cut between batches | (py-sources batches too) | the applied deletes / upserts stay, `source_sync` shows the previous run; the next sync converges |
| `--path` to a `.bz2` / `.xz` file | decompressed | refused: `... bzip2 input is not supported; decompress the file or use gzip` (no bzip2 / xz crate in the workspace) |
| Decompressed size | 2 GiB for compressed input, unbounded plain | 1 GiB for both |
| Download | read whole into memory (512 MiB cap) | parsed as it arrives (same cap) |
| Repository lists, lines, rows, strings, packages | unbounded | the caps above |
| `fixed_version` a list or object | stored as Python's `str()` of it | the run fails: `debian-tracker: <pkg> <cve> <release>: fixed_version is a list; refusing` |
| An integer above 2^64 in `fixed_version` | its digits | a float's `repr` (`serde_json` without arbitrary precision) |
| JSON syntax errors, `NaN` literals, lone surrogate escapes, UTF-16 / UTF-32 input, nesting deeper than 128 | `json.loads` wording; accepted (UTF-16/32 detected) | `invalid JSON: <serde_json text>`; refused; same `error` status |
| `OSError` while reading | `<class>: <text>` | the same for open errors; read errors `OSError: <io text>` |
| HTTP errors | httpx wording | `HTTP 404 for <url>` / reqwest wording |
| `--path` a FIFO or device | blocks reading it (JSON) / skipped (lists) | refused (JSON) / skipped (lists) |
| Checkout cursor with unassigned code points | `repr` escapes them | kept (no Unicode tables); the cursor differs only for such text |
| `str.lower()`, `\d` | Python's Unicode tables | Rust's / the `regex` crate's; equal for tracker text |

Equal by test: the `distro_triage` and `source_sync` rows (last sync time aside) after every step below, and the entry
`status`, `records` and `message` of every step but the JSON syntax error.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/src/debian_tracker.rs` (unit) | JSON rows of odd releases (case and whitespace of codenames, `*` urgency, `nodsa` forms, a float fixed version, TEMP, sid, unknown codenames, a repeated CVE key), limit; every error text; BOM, gzip, truncated gzip, the caps (the per-package cap counts the size of a `Rel`); the package-line pattern against Python's (`(low)` as the argument, Unicode whitespace and digits); `_split_paren`, `_text_row`; a checkout with CRLF / CR lines, invalid UTF-8, a repeated CVE block, TEMP, advisories (the advisory whose version equals the fixed version is kept, orphans), the line cap. Expected values checked against the Python functions on the same inputs. Python's `repr(float)` and `repr(str)` are tested in `py.rs`, the decoder (BOM, gzip, caps, SHA-256) in `decode.rs` |
| `secmonk-sources/tests/debian_tracker.rs` | over `common::MemView`: the JSON fixture (33 rows, message, cursor of Python), a second run (only the status row), an update (deletes of the removed package, upserts of the changed and new rows only), the checkout (31 rows, advisories, Python's cursor; JSON rows -> checkout rows), limit, guard, `--full` with an empty file, errors and caps, a FIFO, the download (gzip parsed as it arrives, digest cursor, 404, download cap); `MemView` pages by rowid as the store (a delete between pages, an exactly full last page) and a snapshot compared over two full pages (10 000 stored rows: 5 000 deletes, 1 000 upserts, unchanged rows not rewritten) |
| `secmonk-engine/tests/native_debian_tracker.rs` `native_debian_tracker_matches_py_sources` | **differential** (needs `rust/python/.venv`; `SECMONK_REQUIRE_VENV=1`): `py-sources` and the native importer on their own mirrors; all mirror tables equal after: the JSON fixture, no-op, an update (removed package and release, changed fields, `*` urgency, `nodsa_reason`, fixed `0`, TEMP, unknown and sid releases, package names colliding in case), the checkout, JSON again, gzip, BOM, gzip with trailing bytes, limit (JSON and checkout), guard, empty file, `--full`, five bad documents with Python's texts, an empty checkout, a truncated gzip; then on the real store tables of exactly one and two full `rows_page` pages (5 000 / 10 000 rows; also 15 000, half deleted, a third changed); a JSON syntax error (message aside); a switch mirror py-sources -> native (log line) -> a failed and a limited py-sources run (not applied) -> an ok run (repair, equal to its staging and to the Python-only mirror) |
| `secmonk-engine/tests/native_debian_tracker.rs` `native_debian_tracker_batches_follow_the_row_contract` | every batch and end of five runs (fixture, update, checkout, limit, a missing file) applied to a real store and validated against `source/rows.schema.json` and `source/sync-end.schema.json`; `distro_triage` deletes among them |
| `secmonk-engine/tests/native_debian_tracker.rs` `debian_tracker_volume_*` (ignored) | the measurements above |

Fixtures: `tests/fixtures/sources/debian-tracker/tracker-sample.json` and `repo/data/{CVE,DSA,DLA}/list` (synthetic,
read only; no README in the fixture directory, provenance in the Python tree's
[Debian tracker reference](../../../_docs/references/vuln-sources/debian-tracker.md)). The variants (update, gzip, BOM,
bad documents, large tables) are written at test time (synthetic, nothing committed).
