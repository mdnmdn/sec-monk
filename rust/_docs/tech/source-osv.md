---
title: Source osv — the native (Rust) OSV.dev bulk source
summary: "The Rust osv source in secmonk-sources - path imports and the bucket (all.zip, modified_id.csv delta, osv:<Eco> cursors), per-record rows and skips as Python, zip safety caps, memory, volume, differences, tests."
read_when: you change the Rust osv source, switch osv between Rust and Python, debug an osv sync (a per-ecosystem cursor, a delta, a refused archive or member), or port a source that reads untrusted zip archives
type: tech
context: tech
status: implemented
tags: [vuln-source, osv, purl, zip, rust, sync]
updated: 2026-11-12
verified: 2026-11-12
code: [rust/crates/secmonk-sources/src/osv.rs, rust/python/src/secmonk_modules/sources/test_hooks_osv.py, rust/crates/secmonk-sources/src/native.rs, rust/crates/secmonk-sources/src/rows.rs, rust/crates/secmonk-store/src/sqlite/mirror.rs]
fixtures: [tests/fixtures/sources/osv/, tests/fixtures/lang/dart/, tests/fixtures/lang/swift/]
related: [decisions/0012-native-importer-row-reads-and-registry.md, decisions/0011-native-sources.md, tech/source-nvd.md, tech/source-euvd.md, tech/component-lifecycle.md, tech/data-model.md, tech/configuration.md]
---

# Source osv (native importer)

The vulnerability source with the largest volume, ported to Rust after [kev](source-kev.md), [epss](source-epss.md),
[euvd](source-euvd.md), [msrc](source-msrc.md), [debian-tracker](source-debian-tracker.md) and [nvd](source-nvd.md)
([rust ADR-0011](../decisions/0011-native-sources.md), [ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)).
`secmonk_sources::osv::OsvSource` implements `Source` in-process. The bucket and the record format are described in
the Python tree's [OSV reference](../../../_docs/references/vuln-sources/osv.md) (real probes, 2026-11-07); the
reference implementation is `src/secmonk/sources/osv.py` `OsvSource.sync` plus `ops.sync_source` /
`db.set_sync_state`.

## Selection

`[sources.implementation] osv = "rust"` or `"python"` ([configuration](configuration.md#schema)). The default is
`rust` since 2026-11-12 (`IMPORTER.default_rust` in `osv.rs`): see [Default](#default). Switching behaves as for the
other native importers: the first native sync after `py-sources` resets the applied state (job log `osv: native
importer: applied state of generation <g> (seq N) reset; full sync against the mirror`); a failed `py-sources` run
after native ones applies nothing (`...; not applied: mirror keeps the native importer data until a successful
py-sources sync`); the first ok one repairs osv from the staging export. The cursor rows `osv:<Eco>` are mirror rows
(the store accepts `<source>:<qualifier>` keys in a batch of `<source>` and deletes them in a repair), so both
implementations continue each other's deltas.

Raw storage (`raw_record`) is off by default, as in Python; the native importer turns it on when the host process has
`SECMONK_OSV_STORE_RAW` set to `1`, `true` or `yes` (stripped, any case; read at each sync), or through
`OsvSource::with_store_raw`. `py-sources` under the host never sees that variable (it is not in `MODULE_PASSTHROUGH`).

## One sync

| Step | Behaviour |
|---|---|
| Mode | `options.path` (non-empty): one import from the path; else one pass per ecosystem of `options.ecosystems` (empty: `DEFAULT_ECOSYSTEMS`, the 15 of Python: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist, Pub, SwiftURL, Debian, Alpine, Red Hat, Rocky Linux, AlmaLinux). A release-qualified name fails the run before anything: `OSV ecosystem 'Debian:12' is release-qualified; use the base name ('Debian'). Per-release zips are stale legacy dumps; the base-name zip contains all releases.` `since` and `ids` are ignored, as in Python. |
| Path | A directory: its entries whose name ends in `.json` (`sorted(p.glob("*.json"))`: not recursive, hidden names and directories so named included), at most `Caps::files` = 1 000 000 files and `Caps::entries` = 2 000 000 entries visited (`osv: <dir>: more than ... ; refusing`). A name ending in `.zip` (`Path.suffix`, any case): the archive (below; a missing file `FileNotFoundError: [Errno 2] No such file or directory: '<p>'`, a FIFO or device `OSError: not a regular file: '<p>'`, not a zip `BadZipFile: File is not a zip file`). Anything else: one JSON file. Each file: `feed::open_regular` (a regular file; anything else, a missing file or a directory is logged `osv: bad file <p>: <OSError text>` and skipped, as Python logs `OSError`), at most `Caps::member_bytes` = 50 MiB (`MAX_MEMBER_SIZE`; logged and skipped), strict UTF-8 (a BOM is a JSON error, as `read_text` + `json.loads`), a list taken as its records. Message `from <path>` (`str(Path)`), status `ok` (also with `limit`), cursor = the largest `modified` (by instant; the first of equals, the original string). |
| Bucket state | Per ecosystem the row `osv:<Eco>` (`MirrorView::rows_page(source_sync, "osv:<Eco>")`, or the row this run wrote for an ecosystem listed twice). A cursor is used only when its status is `ok` and `full` is off. |
| Delta | GET `<bucket>/<Eco>/modified_id.csv` (`urllib.parse.quote` of the name: `Red%20Hat`), at most `Caps::csv_bytes` = 256 MiB, decoded as UTF-8 with replacement characters (httpx's `.text`). Lines split as `str.splitlines()`, stripped; `<ts>,<ID>` lines whose timestamp parses (`parse_ts`: `Z`, 0-9 fractional digits, naive = UTC; `nvd::fromisoformat`) and is later than the cursor. More than `DELTA_MAX_IDS` = 5000: log `osv <Eco>: <n> changes since cursor, falling back to full zip` and the full import (only 5001 are kept while counting). Else oldest first (a stable sort): GET `<bucket>/<Eco>/<ID>.json` each (at most 50 MiB; `json.loads(bytes)`: UTF-8 with or without BOM, UTF-16 and UTF-32 detected as Python does), a 404 is skipped and counts as a success, any other failure (HTTP status, transport, JSON, not an object) is counted and logged; an id with `/`, `\` or a dot segment is not fetched (logged, treated as not found). The cursor stored is the last success before the first failure if it is later than the old one, else the old one; row `ok`, `records` = imported, message `delta` / `delta, N failed`; a failure makes the run `partial`. |
| Full | GET `<bucket>/<Eco>/all.zip` streamed into an anonymous temporary file (`tempfile::tempfile`: private, removed when closed; never extracted), at most `Caps::download_bytes` = 4 GiB (Python's messages: `<Eco>/all.zip is N bytes, above the 4294967296 byte limit` from `Content-Length`, `<Eco>/all.zip exceeds the ... byte download limit` while streaming). Then the archive (below). Row: `ok`, `records`, cursor = the largest `modified` (kept when none, as `COALESCE`), message `full`; with `limit` reached: `partial` and the cursor set to NULL (Python's `UPDATE ... SET cursor=NULL`), so the next run is a full one again. Any `limit` makes the run `partial` (`bool(opts.limit)`), as in Python. |
| Archive | `zip` (the workspace's crate, stored and deflate only) over the file, through the central directory in its order. Refused as a whole (no record read): an unreadable directory `BadZipFile: File is not a zip file`; duplicate member names (`<what>: duplicate member names; refusing`); more than `Caps::zip_entries` = 2 000 000 entries; `.json` members declaring more than `Caps::zip_total` = 64 GiB uncompressed; a member needing zip version > 6.3 (`NotImplementedError: zip file version N`). Per `.json` member (not ending in `/`), in order, until the limit: an unsafe name (absolute, a drive, a `..` part, a backslash, a NUL) skipped; declared size above 50 MiB skipped (`oversized`); compressed-patched or strong-encryption flags `NotImplementedError` (stops the import); a local header that cannot be read, has another signature or another name than the directory (`File name in directory ... and header ... differ.`) skipped as a bad member; data running into the next local header (`Overlapped entries: '<name>' (possible zip bomb)`) skipped, except when two directory entries share one local header (Python only warns there); encrypted `RuntimeError: File <ZipInfo filename=... compress_type=... file_size=N compress_size=N> is encrypted, password required for extraction` (stops the import, Python's `repr(ZipInfo)`); bzip2 and lzma members skipped (logged); other methods `NotImplementedError: That compression method is not supported`; a member above 1 MiB whose size is more than `Caps::zip_ratio` = 200 times its compressed size skipped (`compression ratio above 200 (possible zip bomb)`). Reading: the declared size bounds the output (`zip`'s size limit), at most 50 MiB, the CRC checked; a corrupt member is logged and skipped. A stop inside the import: from `--path` the run's status is `error` with `<class>: <text>` (the records before it stay, as in `py-sources`); for an ecosystem `<Eco>: <text>` among the run's errors, no `osv:<Eco>` row. |
| Record (`import_record`) | Not an object, or no truthy `id`: ignored (not counted). The rows below, or the record is **skipped** (logged `osv: skipping <id>: <reason>`, not counted, its stored rows untouched) wherever Python raises inside the record's savepoint: a truthy `severity`, `references`, `aliases`, `upstream`, `affected`, `cwe_ids`, `ranges`, `binaries`, `custom_ranges` or `versions` that is not iterable (a number, `true`), a `severity` element that is not an object, a truthy non-string `details` (when the summary comes from it), `package.name`, `package.ecosystem` or `package.purl`, a list or object bound to a text column, an integer beyond 64 bits there. Native skips (see the differences): a float in a text column, range events that are not a list of objects, more than `Caps::affected` = 10 000 `affected` rows. |
| Rows of a record | `raw_record` (raw storage on: `modified`, `data` = the record); `vulnerability`: `id` = `str(id)`, `summary` (or the first line of the stripped `details`, 300 characters), `details`, `published`, `modified`, `withdrawn` (strings; an integer or bool as its text, NULL for null: TEXT affinity), severity from `database_specific.severity`, else the `Ubuntu` word, else the score (`normalize_severity`, `severity_from_score`); CVSS: the first `CVSS_V3` vector is used (score by the CVSS 3.1 formula, `_roundup`; version from the vector), its `CVSS_V4` vector to `extra.cvss_v4_vector`; a v4-only record keeps the v4 vector, version `4.0` and a score from the label (LOW 3.0, MEDIUM 5.5, HIGH 8.0, CRITICAL 9.5, `extra.score_derived`); `cwes` = `cwe_ids` strings (a string: itself); `extra` = `{source_db, references (first 10 truthy urls), score_derived?, cvss_v4_vector?}`. `alias` rows from `aliases` (kind `alias`) and `upstream` (kind `upstream`, upgraded to `alias` when listed in both), never the record's own id. `affected` (not for a truthy `withdrawn`): per entry with a package and a truthy name, ecosystem = `purl.normalize_ecosystem` (Ubuntu, Red Hat, Rocky, Alma releases collapsed), package = `purl.normalize_name`, purl = `_strip_purl` (a port of `packageurl-python` 0.17.6 `from_string` / `to_string` and `urllib.parse.urlsplit`; the text before `?` / `#` when it raises); one row per ECOSYSTEM / SEMVER / GIT range (Go: the `introduced: 0` placeholder replaced by `custom_ranges`), events verbatim (`[]` when falsy), `extra` in Python's key order (`custom_range`, `ecosystem_variant`, `raw_ecosystem`, `database_specific`, `binaries`, `urgency`, `repo`; NULL when empty); a `VERSIONS` row (string versions, events NULL) when the entry has no ECOSYSTEM / SEMVER range. |
| Children | `replace_children` against the stored rows. Records are taken in groups (at most 25 records, 4 MiB of record text or 20 000 new rows); per group one `MirrorView::rows_by_id` per table (`alias`, `affected`, `vulnerability`) for the ids not written in this run. Aliases: a delete per stored alias that is not new, an upsert per new alias not stored with that kind. `affected`: nothing when stored and new rows are the same multiset; else one record-keyed delete per stored row (`DeleteKey::Record`) and the new rows. A record id already written in this run (the same advisory in two ecosystems, or twice in a directory) replaces what was written (its aliases, and its `affected` rows when their SHA-256 over the sorted rows differs) without reading it back. A record with more stored `affected` rows than 10 000 (only from `py-sources` before a switch) ends the run: `osv: native importer: <id>: <n> stored affected rows (more than 10000); refusing, sync osv with the python implementation`. More than `Caps::records` = 2 000 000 distinct ids in one run: `osv: native importer: more than 2000000 records in one run; refusing`. |
| End | **Path**: `ok`, `records` = imported, `source_sync.records` = the osv vulnerabilities after the run (`SyncResult.total`: the stored count before the run plus the ids written that had no row), cursor as above, message `from <path>`; a stop: `error`, message `<class>: <text>`. **Bucket**: `error` when every ecosystem failed, `partial` when one failed, a delta had failures or a full import ran with `limit` set, else `ok`; `records` = the sum of the ecosystems' imports, the total as above (not for `error`), no cursor (the `osv` row keeps its own), message the errors joined by `; ` or `<N> ecosystems`. Native ecosystem errors read `<Eco>: HTTP 404 for <url>` / reqwest text (see the differences). |
| Batches | Cut while the engine reads the stream (`native::stream_deferred`): at most 5 000 ops and about 2 MiB each, `generation = "native-rust"`, seqs after the applied seq of that generation, else from 1. The `osv:<Eco>` row of an ecosystem follows its last record. |

## Memory (worst case, estimated)

A 64-bit build; every term is bounded by a cap above. The download goes to disk, not memory.

| Term | Bound |
|---|---|
| Archive index | the `zip` crate's central directory (about 250 bytes per entry plus the name) and the importer's index (about 80 bytes plus the name): about 0.6 GiB at 2 000 000 entries with short names; a real `npm/all.zip` (about 200 000 entries) about 65 MiB |
| One member or file | at most 50 MiB of text, parsed into up to about 32 times that for a record of only tiny values (1.6 GiB), a few MiB for a real one (real records are under 1 MiB) |
| Records in flight | the reader's channel holds 2 planned records, the group at most 25 records or 4 MiB of record text (plus the record that crosses it) and 20 000 new rows (plus the crossing record's at most 10 000): about 40 MiB of rows |
| Stored rows of a group | 25 ids × at most 10 000 `affected` rows a native run writes: 250 000 rows, about 300 MiB; more only for rows `py-sources` wrote before a switch (read once, then the run is refused) |
| Ids written in the run | per id its text, its aliases, a count and a digest: about 200 bytes, 0.4 GiB at 2 000 000 ids; 20 MiB for the 100 000 records of the volume test |
| Delta | the CSV text (at most 256 MiB, twice while it is decoded), 5 001 changed ids, one record (50 MiB) |
| `--path` directory | the listing: about 150 bytes per file, 150 MiB at 1 000 000 files |
| Batch | one batch: at most 5 000 operations and about 2 MiB of JSON |

Sum at the caps, the terms that coexist (index, one pathological member, a group, its stored rows, the ids): about
0.6 + 1.6 + 0.04 + 0.3 + 0.4 GiB, about 3 GiB, reached only with a 2-million-entry archive of pathological records
after a `py-sources` history. The default ecosystems stay far below: see the volume measurement.

## Volume (measured)

Measured on 2026-11-12 on an Apple M2 (8 cores, 24 GiB RAM, macOS 26.5, internal SSD), test binary built with the
workspace's release profile with LTO off and 16 codegen units (`CARGO_PROFILE_RELEASE_LTO=false
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`). Input: a synthetic corpus of 100 000 records over five ecosystems (PyPI, npm,
Maven, Debian, Alpine), one `all.zip` each (70 MiB of zips per day; about 2 KiB of JSON per record: 1-4 affected
entries with an ECOSYSTEM or SEMVER range, 5-20 versions, an alias, a CVSS 3.1 vector, CWEs, references; 250 000
`affected` rows), served by a local HTTP server and imported with `full` (the bucket path, zips included); the second
day changes the fixed version and `modified` of every third record. `secmonk-engine/tests/native_osv.rs`
`osv_volume_sync` (ignored), each run in its own process under `/usr/bin/time -l`; the peak resident set is of the test
process (the Python child of `py-sources` not counted, the host's apply of its batches counted) and includes the corpus
(both days generated and held: 331 MiB alone). Sample: synthetic.

| Measurement | First sync | Re-sync, changed | Re-sync, unchanged | Peak resident set |
|---|---|---|---|---|
| Baseline (corpus generated, nothing synced) | | | | 331 MiB |
| **Native importer through the engine** | **12.6-16.3 s** | **13.5-15.5 s** | **8.9-11.6 s** | 549 MiB |
| `py-sources` through the engine | 49.9-50.6 s | 69.6-76.2 s | 75.1-78.0 s | 502 MiB (host side) |

Reading: the native path is 3.5 to 8.8 times faster than `py-sources` at every step; it adds about 220 MiB to the
baseline (the server's copy of the zips, the store, the importer). The unchanged re-sync still rewrites every
`vulnerability` row (as Python) but no `alias` or `affected` row. The mirrors of both paths were equal at the end of the
combined run (`assert_mirrors_equal`, all tables); 10 000 records: native 0.9-1.4 s, `py-sources` 6.0-6.1 s per step.
Re-run: `cargo test --release -p secmonk-engine --test native_osv --no-run`, then `SECMONK_REQUIRE_VENV=1
/usr/bin/time -l <binary> --ignored --exact osv_volume_sync --nocapture` (`SECMONK_OSV_RECORDS` for the size,
`SECMONK_OSV_NATIVE_ONLY=1` / `SECMONK_OSV_PY_ONLY=1` for one half, both for the baseline).

## Default

`default_rust: true` since 2026-11-12: the differential tests are green (`--path` imports, the bucket against a local
server, raw storage, the switch both ways) and the native path is faster than `py-sources` at every step of the volume
measurement (roadmap D2 allowed osv to stay Python if it were not). A sync from the real bucket is also limited by the
network (about 434 MB of zips for the default ecosystems), the same for both versions. The real bucket itself was not
read by the native importer (the tests use a local server serving the shapes of the reference) **(verify)**.
`[sources.implementation] osv = "python"` selects `py-sources` again.

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | per record `INSERT OR REPLACE` / `replace_children` in a savepoint, commits every 2000 | the same rows, in batches of 5 000 ops; aliases and `affected` rows that did not change are not rewritten (`affected.rowid_` differs, not compared) |
| Stream cut between batches | (py-sources batches too) | the applied records stay, `osv:<Eco>` rows only after an ecosystem's last record; the next sync converges (each record is computed against the stored rows) |
| The downloaded `all.zip` | kept in the user cache (`<cache>/osv/<Eco>.zip`) | an anonymous temporary file, gone after the import |
| Sizes and counts | the download (4 GiB, `SECMONK_OSV_MAX_ZIP_MB`) and each member (50 MB) | the caps above; `SECMONK_OSV_MAX_ZIP_MB` is not read (`Caps::download_bytes`) |
| A record with more than 10 000 `affected` rows | written | skipped (logged) |
| A float in a text column (`published: 1.5`) | stored as text by SQLite (`"1.5"`) | the record is skipped (SQLite's REAL-to-TEXT conversion is not ported) |
| Range `events` that are not a list of objects (`{"a": 1}`, `"x"`, `["x"]`) | stored as given | the record is skipped (`secmonk-mirror-rows/1` requires a list of objects) |
| Archive members with an unsafe name (`../x.json`, `/x.json`, `C:x.json`, a backslash, a NUL) | read (the name is only used in logs) | skipped |
| Duplicate member names | each one read | the archive is refused |
| A member above 1 MiB compressed more than 200 to 1 | read (when under 50 MB) | skipped |
| bzip2 and lzma members | read | skipped (the workspace's `zip` crate is built without them) |
| A deflate stream that ends before the declared size | may stop the import with `EOFError` | a bad member (logged) |
| JSON: `NaN` / `Infinity` literals, nesting deeper than 128, lone surrogate escapes | accepted by `json.loads` (surrogates then refused by SQLite where bound) | the member or file is a bad one (logged) |
| Integers beyond 64 bits in a record | exact in staging | parsed as floats; the mirrors are equal (the store parses the text `py-sources` sends the same way) |
| Delta ids with `/`, `\` or a dot segment | fetched | not fetched (logged, treated as not found) |
| `modified_id.csv` with a `charset` in `Content-Type` | decoded with it | always UTF-8 with replacement characters |
| HTTP errors | httpx wording (`Client error '404 Not Found' for url '...'`) | `HTTP 404 for <url>` / reqwest wording; same status |
| `SECMONK_OSV_STORE_RAW` under the host | never set in the module (not passed through): raw storage off | read from the host process environment |
| `--path` a FIFO or device | blocks reading it | refused: a bad file (`not a regular file`), or `OSError: not a regular file: '<p>'` for a `.zip` |
| Relative `--path` | the module's working directory | the host process's working directory (the UI sends absolute paths) |
| purls with a non-ASCII authority (`pkg:x///<host>/n`) that NFKC-normalizes to `/?#@:`, or an IPv6 zone id | `urlsplit` refuses / accepts them | accepted / refused (the NFKC check is not ported; Rust's IPv6 parser) |
| Unicode case and digit rules | Python 3.13's tables (Unicode 15.1) | Rust's (`to_lowercase`), Python's `isdigit` table copied; equal for real ecosystems and names |
| Log lines of skipped records and bad members | Python's exception texts | similar texts (not compared) |

Equal by test: every mirror table (timestamps aside) after the steps below, the entry `status`, `records` and
`message` of every step but the HTTP errors, and the request lines of the bucket steps.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/src/osv.rs` (unit) | 75 purls rebuilt as `_strip_purl` does (values from Python 3.13.5 with packageurl-python 0.17.6), ecosystems and Ubuntu variants (`normalize_ecosystem`, `_ubuntu_variant`), names; CVSS 3.x scores of 11 vectors and of all 2 592 CVSS 3.1 base vectors (SHA-256 of Python's joined `repr`); `parse_ts`, `splitlines`, the CSV selection, `quote`; text binding; `json.loads(bytes)` encodings; unsafe names, suffixes, release-qualified names; the rows and skips of `import_record` (ids, summaries, CVSS choices, derived scores, aliases, withdrawn, Go custom ranges, binaries, urgency, VERSIONS rows, events, the row cap) |
| `secmonk-sources/tests/osv.rs` | over `common::MemView`: the fixture directory (rows, totals, cursor) and a second run (no alias or `affected` operation); the sample zip, the Pub and SwiftURL records; changed, withdrawn and repeated records; limit, raw storage, skipped records and bad files, a missing `.json` / `.zip`, not a zip; a FIFO; 131 records in groups with an id repeated across groups. Archives built byte by byte: a compression bomb member, path tricks, the entry and total caps, duplicate names, the member cap, a lying declared size, overlapping data, another name in the local header, two directory entries for one local header, encryption, bzip2 and unknown methods. The bucket against a local server: first sync of two ecosystems (request lines), a delta (changed, new, gone, old lines), a failing id (`partial`, the cursor before it), `full` with a limit (`partial`, cursor NULL) and the full import after it, one and all ecosystems failing, release-qualified names, more than 5000 changes, the download cap |
| `secmonk-engine/tests/native_osv.rs` `native_osv_matches_py_sources_on_path_imports` | **differential** (needs `rust/python/.venv`; `SECMONK_REQUIRE_VENV=1`): `py-sources` and the native osv on their own mirrors; all mirror tables equal after: the fixture directory twice, the sample zip, the Pub and SwiftURL records, an update (log4j trimmed and changed, Go withdrawn, 33 purls of every shape, a repeated id across files, odd values Python stores as text, seven records Python skips, a skipped record keeping its stored rows, bad files), a limit, the update again, 131 records, an integer beyond 64 bits, seven archives built at test time (encrypted after a good member, an unknown method, a lying size, overlapping data, another local name, stored members with a directory and a text member, members that are not records), not a zip, an empty directory. A switch mirror py-sources -> native (log line) -> a failed py-sources run (nothing applied) -> ok py-sources runs (repair; equal to its staging and to the Python-only mirror for the osv rows). Last the documented differences: a float in a text column, events that are not a list, a path trick and a bomb member |
| `secmonk-engine/tests/native_osv.rs` `native_osv_matches_py_sources_on_the_bucket` | **differential, bucket**: `py-sources` started through the test-only entry point `secmonk_modules.sources.test_hooks_osv` (`SECMONK_TEST_OSV_HOOK` names a file with the local server's URL) and the native importer against one local server; every mirror table, the entries (messages except HTTP errors) and the request lines equal after: the first sync of PyPI, Red Hat, Pub and SwiftURL; a delta (changed, new, gone, old and bad lines); a failing id (`partial`); the retry; `full` with a limit; the run after it; an ecosystem listed twice; a full import with a withdrawn and a changed record; more than 5000 changes; one and every ecosystem failing; a bad zip; a release-qualified name |
| `secmonk-engine/tests/native_osv.rs` `native_osv_matches_py_sources_with_raw_storage` | `SECMONK_OSV_STORE_RAW=1` for `py-sources`, `with_store_raw(true)` natively: all tables equal (raw records included) after the fixture directory, the update and the sample zip |
| `secmonk-engine/tests/native_osv.rs` `native_osv_batches_follow_the_row_contract` | every batch and end of four `--path` runs (fixtures, the update, a limit, a missing zip) and three bucket runs (full, delta, `full` with a limit) applied to a real store and validated against `source/rows.schema.json` and `source/sync-end.schema.json`; alias and record-keyed `affected` deletes among them; the `osv:PyPI` row read back (`partial`, cursor NULL) |
| `secmonk-engine/tests/native_osv.rs` `osv_volume_sync` | ignored, run by hand: the measurement above |

Test-only hook in `rust/python` (`secmonk_modules/sources/test_hooks_osv.py`): `python -I -m
secmonk_modules.sources.test_hooks_osv serve ...` wraps the unchanged `OsvSource.sync` so that, when
`$SECMONK_TEST_OSV_HOOK` names a JSON file `{"bucket": "<url>"}`, the source reads that bucket; then it runs the
normal module entry point. Only the differential test starts it (its runtime rewrites the manifest's entry); the host
never starts it and never passes `SECMONK_TEST_*` variables to a module; `sync.py` and `src/` are unchanged.

Fixtures: `tests/fixtures/sources/osv/` (real records and `sample-all.zip`, read only; provenance in the Python tree's
[OSV reference](../../../_docs/references/vuln-sources/osv.md)), `tests/fixtures/lang/dart/osv-pub-GHSA-4rgh-jx4f-qfcq.json`
and `tests/fixtures/lang/swift/osv-swifturl-GHSA-ccw9-q5h2-8c2w.json` (real, read only). Every other record, archive
and the volume corpus are written at test time (synthetic, nothing committed).

Unverified **(verify)** against the real bucket: the layout of real `all.zip` files for the `zip` crate (ZIP64 for the
largest ecosystems, data descriptors, member names), real entry counts against `Caps::zip_entries`, real compression
ratios against the 200 to 1 cap (JSON compresses about 3.4 to 5 to 1 in the reference), and the largest real record and
`affected` count against the 50 MiB and 10 000 caps.
