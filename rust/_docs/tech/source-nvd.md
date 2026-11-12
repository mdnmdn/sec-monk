---
title: Source nvd — the native (Rust) NVD CVE API 2.0 source
summary: The Rust nvd source in secmonk-sources - pages written one by one as Python commits them, delta windows and cursors, API key, pacing and retries, CVSS, CWE and CPE rows, caps and memory, volume, differences from Python, tests.
read_when: you change the Rust nvd source, switch nvd between Rust and Python, debug an nvd sync (cursor, windows, retries, API key, CPE rows), or port a paged API source whose status is known only after its last page
type: tech
context: tech
status: implemented
tags: [vuln-source, nvd, cve, cvss, cpe, rust, sync]
updated: 2026-11-12
verified: 2026-11-12
code: [rust/crates/secmonk-sources/src/nvd.rs, rust/python/src/secmonk_modules/sources/sync.py, rust/crates/secmonk-sources/src/native.rs, rust/crates/secmonk-sources/src/feed.rs, rust/crates/secmonk-sources/src/rows.rs, rust/crates/secmonk-engine/src/sync.rs]
fixtures: [tests/fixtures/sources/nvd/]
related: [decisions/0012-native-importer-row-reads-and-registry.md, decisions/0011-native-sources.md, tech/source-euvd.md, tech/source-msrc.md, tech/component-lifecycle.md, tech/data-model.md, tech/engine-service.md, tech/configuration.md]
---

# Source nvd (native importer)

The sixth vulnerability source ported to Rust, after [kev](source-kev.md), [epss](source-epss.md),
[euvd](source-euvd.md), [msrc](source-msrc.md) and [debian-tracker](source-debian-tracker.md)
([rust ADR-0011](../decisions/0011-native-sources.md), [ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)).
`secmonk_sources::nvd::NvdSource` implements `Source` in-process. The API is described in the Python tree's
[NVD reference](../../../_docs/references/vuln-sources/nvd.md) (the API was not reachable from the dev sandbox: the
shapes are from the NVD documentation, the fixture is synthetic); the reference implementation is
`src/secmonk/sources/nvd.py` `NvdSource.sync` plus `ops.sync_source` / `db.set_sync_state`.

## Selection

`[sources.implementation] nvd = "rust"` or `"python"` ([configuration](configuration.md#schema)). The default is
`rust` since 2026-11-12 (`IMPORTER.default_rust` in `nvd.rs`): see [Default](#default). Switching behaves as for the other
native importers: the first native sync after `py-sources` resets the applied state (job log `nvd: native importer:
applied state of generation <g> (seq N) reset; full sync against the mirror`); a failed `py-sources` run after native
ones applies nothing (`...; not applied: mirror keeps the native importer data until a successful py-sources sync`);
the first ok one repairs nvd from the staging export. The stored cursors (`nvd`, `nvd:progress`) are mirror rows, so
both implementations continue each other's delta.

## One sync

Modes by precedence, as in Python: `--path`, then `ids` (`SyncOptions.ids`, not sent by the engine's sync jobs today),
then the API.

| Step | Behaviour |
|---|---|
| Load (path) | `options.path` (non-empty). A directory: its entries whose name ends in `.json`, not recursive, sorted by name (`sorted(path.glob("*.json"))`: hidden names and directories so named included; an unreadable directory yields none), at most `Caps::entries` = 100 000 entries visited and `Caps::files` = 10 000 files. Anything else is read as one document. Each document is read when its turn comes (as Python's generator): `feed::open_regular` (a regular file; a directory answers `IsADirectoryError: [Errno 21] Is a directory: '<path>'`, a missing file `FileNotFoundError: [Errno 2] ...`, a FIFO or device `OSError: not a regular file: '<path>'`), at most `Caps::file_bytes` = 256 MiB (`nvd: <path>: larger than 268435456 bytes; refusing`). `since`, `full` are ignored. |
| Load (ids) | One `GET <api>?cveId=<ID>` per id (`strip().upper()`), in order. |
| Load (API) | Before any request: the stored cursor = the later of the `nvd` and `nvd:progress` cursors (`MirrorView::rows_page(source_sync, <key>)`; one that does not parse is skipped), the end = now. `full`, or no stored cursor and no `since`: one paged query without filter (mode `full`). Else from `since` (`parse_since`: `2020`, `2020-05`, a date or a timestamp; naive is UTC; `ValueError: Invalid isoformat string: '<since>'` and Python's range messages) or the stored cursor: windows of 119 days up to the end, oldest first (mode `delta since <iso>`). Each query is paged: `resultsPerPage=2000&startIndex=N`, `N` += the page's record count, until a page without records or `N >= totalResults` (a `totalResults` that is not a number fails after its page: `TypeError: '>=' not supported between instances of 'int' and '<type>'`). Window parameters `lastModStartDate` / `lastModEndDate` as `YYYY-MM-DDTHH:MM:SS.mmmZ`, encoded as httpx does (`:` as `%3A`). At most `Caps::requests` = 10 000 requests per run. |
| HTTP | `feed::fetch` over one workspace `reqwest` client per run (`feed::fetch_client`: rustls, `https_only` unless a test URL, connect and read timeout 60 s, as httpx; plus a total limit of 600 s per request, `Timing::request_total`, which httpx does not have: running out is a transport error and is retried), `Accept: application/json`, the key as header `apiKey` (`HeaderValue::set_sensitive`), **redirects not followed** (a 3xx is an error, so the key never leaves the API origin), each answer at most `Caps::response_bytes` = 64 MiB. Pacing: at least 0.6 s (with a key) or 6 s (without) between the end of one request and the next. Retries: 403, 429, 500, 502, 503, 504 and transport errors (no answer, a body cut short) up to 5 times, waiting `Retry-After` (seconds, or an RFC 2822 date with a zone) or 2 s × 2^attempt, at most 120 s; job log `nvd: native importer: HTTP 503 for <url>; retry 1 of 5 in 2.0 s`. A failure after the retries: `HTTPStatusError: HTTP <code> for <url>` / `TransportError: <reqwest text>` (URLs without query: `strip_url_secrets`). |
| Split | Per document: strict UTF-8 (`UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe9 in position 10: invalid continuation byte`), the JSON parsed without building its tree: only `totalResults` and the byte ranges of the members of `vulnerabilities` (`serde_json::RawValue`; a repeated key: the last), each at most `Caps::record_bytes` = 8 MiB (`nvd: a record is larger than 8388608 bytes; refusing`), at most `Caps::records` per document. Shapes as `_store_pages` meets them: a document that is not an object `AttributeError: '<type>' object has no attribute 'get'`; `vulnerabilities` absent or an empty list, string or object: no records; `null`, a bool or a number `TypeError: '<type>' object is not iterable`; a non-empty string or object `TypeError: string indices must be integers, not 'str'`. |
| Check (the page's transaction) | The records of the page up to the limit are planned in order (the steps below) before anything of the page is emitted, on the blocking pool. The first failing record discards the page, as Python's rolled-back transaction: the run stops there. Then the stored `affected` rows of the page's CVE ids (not yet emitted in this run) are counted through `MirrorView::rows_by_id`, 50 ids per call: a CVE with more than `Caps::matches` stored rows (only rows `py-sources` wrote before a switch) refuses the run at this page, before its first operation (`nvd: native importer: <id>: <n> stored affected rows (more than 50000); refusing, sync nvd with the python implementation`; caught: `partial` / `error`). More than `Caps::records` = 1 000 000 records in the run: `nvd: more than 1000000 records in one run; refusing`. |
| Rows per CVE (`_store_cve`) | `item["cve"]`, `cve["id"]`. Python's errors come first in its order (`_best_cvss`, `_english`, `_cwes`), then the native type refusals (`lastModified`, the text columns, the score). `raw_record` upsert (`modified` = `lastModified`, `data` = the CVE object). `vulnerability` upsert: `summary` = the `value` of the first description with `lang` `en`; `published`; `modified` = `lastModified`; `state` = `vulnStatus` (`REJECTED` for `Rejected`, then `withdrawn` = `lastModified`); CVSS of the best metric: Primary before any other type, then 4.0 > 3.1 > 3.0 > 2.0, the first of equals; `severity` = `normalize_severity(cvssData.baseSeverity or metric.baseSeverity)`, else `severity_from_score(baseScore)`; `cvss_score`, `cvss_vector` = `vectorString`, `cvss_version` = `version`; `cwes` = the `CWE-*` values of the weaknesses, Primary first, without repeats; `extra` = `{sourceIdentifier, cveTags}` (`cveTags` absent: `[]`). Not rejected: one `affected` row per vulnerable cpeMatch of every node of every configuration, de-duplicated per CVE by `matchCriteriaId` (else the match's JSON with sorted keys; `1`, `1.0` and `true` are one id, as in Python): criteria split on unescaped `:` and unescaped; not `cpe` or fewer than 6 fields: no row; `events` from `versionStartIncluding` (`introduced`), `versionStartExcluding` (`introduced_exclusive`), `versionEndExcluding` (`fixed`), `versionEndIncluding` (`last_affected`), an end-only range gets a leading `introduced: "0"`; no bound: version `*` = `[{introduced: "0"}]`, another version = `versions: [v]`, `-` or empty = no row; `vendor` / `product` normalized (`norm_vendor_product`), `cpe` = the criteria, `range_type` `CPE`, or `CVE-UNPARSED` with `extra.cpe_update` for an update field other than `*`, `-`, empty; `extra.matchCriteriaId`. At most `Caps::matches` = 50 000 rows per CVE (`nvd: <id>: more than 50000 CPE match rows; refusing`). |
| Children | `replace_children` against the stored rows. A checked page is emitted in chunks: records are planned again in groups of at most 5 and the stored `affected` rows of their ids read with one `MirrorView::rows_by_id` per group; a chunk closes at 500 records, 4 MiB of record text or 50 000 new rows (checked per record), or 50 000 stored rows (checked per group). Per CVE: nothing when the stored and new rows are the same multiset, else a delete per stored row keyed `{source, vuln_id}` (`DeleteKey::Record`) then the new rows. A CVE id already emitted in this run (the same CVE on two pages or twice in one) replaces the rows it emitted (one record-keyed delete per row, then the new ones) instead of reading them back: the engine may not have applied them yet (rust ADR-0012 §3). The stored rows were counted in the page's check (above); a CVE over the cap found here (the mirror changed during the run) is an internal error. `alias` rows: nvd never writes any (Python's `replace_children` deletes none in practice), so none are read. |
| `nvd:progress` | API delta: when a window completes (its last page written) and the run may move the cursor, the internal row `nvd:progress` (`status` ok, `cursor` = the window end, `records` 0, message `last completed window end`) is written at once, before the next window's first request, as Python's `set_sync_state` commits it. A later failure of the run (caught, uncaught, or a stream that ends early) does not undo it, so the next run starts after the completed windows (Python: `tests/sources/test_review_fixes.py::test_nvd_partial_failure_keeps_completed_windows`). Until 2026-11-12 (review W10.3) the native importer held the row back until the next page and dropped it on a failure. |
| End | The run's end is known only after its last page (`native::stream_deferred`): **path / ids**: status `ok` (also with `limit`), `records` = records written, no cursor, message `from file <path>` / `<N> ids`. **API**: `ok`, or `partial` when `limit` stopped it (message suffix `, limit reached`); cursor = the end of the last completed window, or the run's end after a complete full pull (none after a limited one); message `<mode>, NVD API with key` / `without key`. **A failure** (what Python's `except (httpx.HTTPError, OSError, ValueError, KeyError)` catches, and the native refusals): `partial` when records were written (counted up to the failing record of the failing page, as Python counts them), else `error`; the cursor of the completed windows; message `<class>: <text>`. **Python's uncaught errors** (`TypeError`, `AttributeError`, reaching `ops.sync_source`): `error`, no records, no cursor. A `--since` run moves the cursor (and writes `nvd:progress`) only when `since <= stored cursor`. Messages: the API key replaced by `***` (keys of 8 characters or more), then `scrub_text`. |
| Batches | Cut while the engine reads the stream: at most 5 000 ops and about 2 MiB each, `generation = "native-rust"`, seqs after the applied seq of that generation, else from 1. |

## Shared code added for nvd

`native::stream_deferred(name, ops, tail, ...)` with `native::Tail` / `TailCell`: the batches of a run whose status,
records, cursor and message the importer leaves in `tail` before its operations end; the `source_sync` row and the end
entry are built from it after the last operation (`stream` is unchanged for the others). `feed::fetch_client(timeout,
allow_http, no_redirects)` (one client per run) and `feed::fetch(&client, &Get, headers, total)` with `feed::FetchError`
(`Transport`, `Status { code, retry_after, message }`, `Other`): one GET with extra headers and an optional total time
limit, whose failure says whether a retry makes sense (the retry policy stays in `nvd.rs`). `py::is_decimal` (Python's
`str.isdecimal()`, what `re`'s `\d` matches). Importer tests: `common::serve_heads` (records whole request heads;
status 0 closes without an answer). Differential tests: `common::EnvRuntime` / `Diff::py_sources_env` (extra
environment for one `py-sources` process).

Test-only hook in `rust/python` (`secmonk_modules/sources/sync.py` `_nvd_test_hook`): when `$SECMONK_TEST_NVD_HOOK`
names a JSON file `{"api_url", "now"}`, an nvd sync of `py-sources` points the unchanged source at that URL, makes its
sleeps no-ops and fixes its "now"; without it the originals are restored. The host never passes `SECMONK_TEST_*`
variables to a module (`MODULE_PASSTHROUGH` in `secmonk-runtime`), so production modules never see it; `src/` is
unchanged.

## Memory (worst case, estimated)

Within the caps, a 64-bit build. Pages are taken one at a time, so the terms of one page bound the run:

| Term | Bound |
|---|---|
| Page text | 256 MiB for a file (up to twice that while it is read), 64 MiB for an API answer (128 MiB while it arrives) |
| Record ranges | 16 bytes per record, at most 1 000 000 per page: 16 MiB (32 while the vector grows) |
| Ids emitted in the run | one entry per distinct CVE id (the id and a count, about 70 bytes): 70 MiB at 1 000 000 |
| Check pass | one record at a time: at most 8 MiB of text, parsed into up to about 32 times that for a record of only tiny values (256 MiB), moved into `raw_record.data`, plus at most 50 000 rows of about 1.2 KiB (60 MiB) |
| Emission chunk: records | 4 MiB of record text plus the record that crosses it (8 MiB): 12 MiB, parsed as above: up to about 400 MiB for tiny-value records, a few tens of MiB for real ones |
| Emission chunk: new rows | 50 000 plus the crossing record's 50 000: 100 000 rows, about 120 MiB |
| Emission chunk: stored rows | 50 000 plus one group (5 CVEs) of stored rows: 300 000 rows (about 360 MiB) when each holds the 50 000 a native run can write; more only for rows `py-sources` wrote before a switch, read once, then the run is refused |
| Batch | one batch: at most 5 000 operations and about 2 MiB of JSON |

Sum at the caps: about 256 + 32 + 70 + 400 + 120 + 360 + 2 MiB, about 1.2 GiB, reached only with a full-size file of
pathological records (the check pass and the emission of one page do not overlap). Real API pages (2 000 CVEs, a few
MiB to some tens of MiB) stay far below: see the volume measurement.

## Volume (measured)

Measured on 2026-11-12 on an Apple M2 (8 cores, 24 GiB RAM, macOS 26.5, internal SSD), test binary built with the
workspace's release profile with LTO off and 16 codegen units (`CARGO_PROFILE_RELEASE_LTO=false
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`). Input: a synthetic corpus in the API's page layout, 100 000 CVEs in 50 pages
of 2 000 (304 MiB, about 3 KiB per CVE: 1-6 vulnerable cpeMatch entries of three shapes plus a non-vulnerable platform,
CVSS 3.1 Primary and 4.0 Secondary metrics, CWE, descriptions, references; 349 996 `affected` rows), generated at run
time; the second day changes the configuration and `lastModified` of every third CVE and rejects every 50th.
`secmonk-engine/tests/native_nvd.rs` `nvd_volume_*` (ignored), each run in its own process under `/usr/bin/time -l`;
the peak resident set is of the test process (the Python child of `py-sources` not counted, the host's apply of its
batches counted), and includes generating the corpus. Sample: synthetic.

| Measurement | Time | Peak resident set |
|---|---|---|
| Baseline (both days generated, a store opened) | 11-26 s (generation) | 196 MiB |
| Native stream alone: read, split, check, plan and cut every batch against an empty mirror, nothing applied | first batch after 0.15 s, all 182 batches (549 997 ops) 11.5 s; 20 000 `rows_by_id` reads 0.65 s of it | 260-354 MiB |
| **Native importer through the engine**: first sync / re-sync with changes / unchanged re-sync (two runs) | **29.4-31.8 s / 30.2-30.4 s / 20.1-20.4 s** | 279-316 MiB |
| `py-sources` through the engine, same files: first sync / re-sync with changes / unchanged re-sync | 88.9 s / 120.8 s / 115.3 s | 360 MiB (host side) |

Reading: the native path is 3 to 5.7 times faster than `py-sources`; about 11 s of a native first sync is the
importer (each record is parsed twice: once in the check of its page, once when it is emitted) and the rest is
`MirrorStore::apply_rows`. The unchanged re-sync still rewrites every `raw_record` (new `fetched_at`, as Python) and
`vulnerability` row, but no `affected` row. The mirrors of both paths were equal at the end of a combined run
(`assert_mirrors_equal`, all tables). An earlier combined run on the same machine under other load measured native
46 / 91 / 99 s and `py-sources` 325 / 336 / 260 s (same ordering, both slower); the table keeps the runs made without
other load. Re-run: `cargo test --release -p secmonk-engine --test native_nvd --no-run`, then
`SECMONK_REQUIRE_VENV=1 /usr/bin/time -l <binary> --ignored --exact nvd_volume_sync --nocapture`
(`SECMONK_NVD_CVES` for the size, `SECMONK_NVD_NATIVE_ONLY=1` / `SECMONK_NVD_PY_ONLY=1` for one half;
`nvd_volume_native_stream` for the importer alone).

## Default

`default_rust: true` since 2026-11-12: the differential test is green and the native path is faster than
`py-sources` at every step of the volume measurement (roadmap D2 allowed nvd to stay Python if it were not). The
volume figures (about 30 s native against 89 s `py-sources` for a first sync of 100 000 CVEs) are `--path` imports:
a sync from the live API is limited by the request pacing (0.6 s with a key, 6 s without, per page of 2 000 CVEs:
about 100 s or 17 min of pauses alone for a full pull of 330 000 CVEs) and by the network, the same for both
versions. The differential tests compare `--path` imports (`native_nvd_matches_py_sources`) and the API path against a
scripted local server (`native_nvd_api_matches_py_sources`: paging, windows, cursors, `nvd:progress`, retries,
`--since`, limit); the importer tests add the key, redirects and pacing. The live API itself is unverified
**(verify)**. `[sources.implementation] nvd = "python"` selects `py-sources` again.

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | per page one transaction (`INSERT OR REPLACE`, `replace_children`, inserts) | the same rows, in batches of 5 000 ops; `affected` rows that did not change are not rewritten (`affected.rowid_` differs, not compared) |
| Stream cut between batches | (py-sources batches too) | the applied pages stay, `source_sync` shows the previous run; the next sync converges (each CVE is computed against the stored rows; a delta restarts from the stored cursors) |
| Sizes and counts | unbounded | the caps above; a cap stops the run at that page like a caught error (`partial` / `error`) |
| API key | `opts.api_key` or the module's `NVD_API_KEY` environment variable | only the call secret (`secrets.api_key`, which the engine reads from `[sources] nvd_api_key_env`); module environments never carry it |
| Total time of one request | none (httpx's 60 s apply to each connect / read / write) | 600 s per request (`Timing::request_total`), then a transport error, retried |
| HTTP errors | httpx wording (`HTTPStatusError: Client error '404 Not Found' for url '<url with query>'`, `ConnectError: ...`) | `HTTPStatusError: HTTP 404 for <url without query>`, `TransportError: <reqwest text>`; same status. A body over 64 MiB: `nvd: <url>: larger than ... bytes` (not retried) |
| `Retry-After` dates | `email.utils.parsedate_to_datetime` (RFC 2822 forms, obsolete ones included) | RFC 2822 / IMF-fixdate with a zone (`GMT`, `UT`, `UTC`, `Z`, `±hhmm`); other forms use the backoff |
| `--since` / stored cursor forms | `datetime.fromisoformat` of Python 3.13 | the same forms except ISO week dates (`2020-W01-1`: `Invalid isoformat string`; a stored cursor in that form is skipped); offsets of 24 h or more read `Invalid isoformat string` instead of the timedelta message |
| A number in a text field (`published`, `lastModified`, `vulnStatus`, a description `value`, `vectorString`, `version`) or a string `baseScore` where a severity label exists | stored as text / converted by SQLite (`5` becomes `"5"`, `"9.8"` becomes 9.8); a list or object fails when SQLite binds it | the run stops at that page: `nvd: <id>: <field> is not a string` / `nvd: <id>: baseScore is not a number` (counted as caught: `partial` or `error`) |
| A CVE `id` that is not a string | stored (`5` as `"5"`; `null` fails on `NOT NULL`) | `nvd: a CVE id is not a string` |
| JSON syntax errors, `NaN` / `Infinity` literals, nesting deeper than 128, a UTF-8 BOM, lone surrogate escapes | `json.loads` wording (`JSONDecodeError: Expecting value: ...`), literals accepted, depth about 1 000, BOM refused, surrogates accepted then refused by SQLite | `invalid JSON: <serde_json text>`; literals, deeper nesting, BOM and lone surrogates refused; same status |
| UTF-16 / UTF-32 API answers | decoded by httpx (`resp.json()`) | invalid UTF-8 |
| `matchCriteriaId` equal to another match's JSON text | the same `seen` key | different keys (the dumped form has its own domain) |
| `--path` a FIFO or device | blocks reading it | refused: `OSError: not a regular file: '<path>'` |
| Relative `--path` | the module's working directory | the host process's working directory (the UI sends absolute paths) |
| Unicode digits in `--since` (`٢٠٢٠`) | `\d` matches, then `fromisoformat` refuses | ASCII digits only; same refusal |

Equal by test: every mirror table (timestamps aside) after the steps below, and the entry `status`, `records` and
`message` of every step but the JSON syntax error.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/src/nvd.rs` (unit) | CPE splitting and unescaping (`(?<!\\):`); the best CVSS metric (type, version, first of equals, V2 severity outside `cvssData`, a falsy label, a bool score); CWEs and descriptions; rejected CVEs; every cpeMatch shape (`_add_cpe`) and the `seen` keys; the Python texts of the checked errors (KeyError, TypeError, AttributeError) and the native refusals; page splitting and its shapes; `fromisoformat` / `parse_since` against values checked with Python 3.13 (non-ASCII input included: no byte slicing of the text, review W10.3 M1); query encoding (httpx), `Retry-After` |
| `secmonk-sources/tests/nvd.rs` | over `common::MemView`: the fixture's rows and a second run (no `affected` rewrite); changed, rejected and repeated CVEs across pages and in one page; 1 300 records in chunks (at most 500 ids per `rows_by_id`) and progress lines; `limit` (later files not read); a failing page keeps the pages before it (caught: `partial` with Python's count, uncaught: `error`), a directory named `.json`, invalid UTF-8, a missing file, an empty directory, `limit` 0; caps; stored rows over the cap refuse a page before its first operation (`stored_rows_beyond_the_cap_refuse_the_page_before_its_first_operation`). Against a local server (`serve_heads`): a full pull's paging, the `apiKey` header on every request and the key in no line, entry or row; a delta of two windows from the stored cursors (request lines, `nvd:progress` rows, cursor); a failing second window, caught (`partial`) and uncaught (`error`): the first window's `nvd:progress` row kept and the next run resuming after it; `--since` without and with trust; a bad `--since`; a cursor in the future; retries with `Retry-After` and after a dropped connection, a status not retried, retries used up; a redirect not followed (the other server sees nothing); ids; pacing; the request cap; a non-number `totalResults` |
| `secmonk-engine/tests/native_nvd.rs` `native_nvd_matches_py_sources` | **differential** (needs `rust/python/.venv`; `SECMONK_REQUIRE_VENV=1`): `py-sources` and the native nvd on their own mirrors through the engine; all mirror tables equal after: the fixture twice; update 1 (a directory of two pages: the Log4j CVE with another configuration and CVSS 4.0 / 3.1 / 2.0 metrics and CWEs in both types, a CVE with every cpeMatch shape, a CVE rejected later); update 2 (that CVE rejected with `configurations: null`, a configuration shrunk, a CVE twice in one page and again on the next page); `limit`; update 1 again; 601 records in one page with an id repeated in another chunk; ten failing second pages (two caught, eight uncaught: shapes, metrics, a string score, a numeric criteria, an unhashable id, a null CWE value), invalid UTF-8, a directory named `.json`, a directory without pages; then the JSON syntax error (message aside). A switch mirror py-sources -> native (log line) -> native update 2 -> a failed py-sources run (nothing applied) -> ok py-sources runs (repair; equal to its staging and to the Python-only mirror); last the documented difference of a number in a text field |
| `secmonk-engine/tests/native_nvd.rs` `native_nvd_api_matches_py_sources` | **differential, API path** (review W10.3 M2): `py-sources` with the test-only hook and the native importer against the same scripted local server, step by step; every mirror table, the entries (messages except HTTP errors) and the request lines equal after: a full pull over two pages; retries (429 with `Retry-After`, 503, 403); a third window failing after two completed ones (`nvd:progress` = the `nvd` cursor); the next run resuming after them; an uncaught error in the second window; `--since` after and before the stored cursor; a full pull with a limit; retries used up. The scenarios of `tests/sources/test_review_fixes.py` (`test_nvd_retries_throttling_with_retry_after`, `test_nvd_gives_up_after_max_retries`, `test_nvd_partial_failure_keeps_completed_windows`, `test_nvd_since_accepts_year_and_never_skips_a_gap`, `test_nvd_limit_is_honored`) |
| `secmonk-engine/tests/native_nvd.rs` `native_nvd_batches_follow_the_row_contract` | every batch and end of five `--path` runs (fixture, update 1, update 2, a limit, a missing file) and of an API delta of two windows against a local server applied to a real store and validated against `source/rows.schema.json` and `source/sync-end.schema.json`; record-keyed `affected` deletes and the `nvd:progress` row (read back from the store) among them |
| `secmonk-engine/tests/native_nvd.rs` `nvd_volume_*` | ignored, run by hand: the measurement above (`nvd_volume_native_stream` counts the `rows_by_id` reads and their time through a wrapping view) |

Fixture: `tests/fixtures/sources/nvd/cve-2021-44228.json` (synthetic API envelope, read only; the fixture directory has
no README, its provenance is in the Python tree's [NVD reference](../../../_docs/references/vuln-sources/nvd.md)). The
other pages, the bad documents and the volume corpus are written at test time (synthetic, nothing committed).

Unverified **(verify)** against the live API: the request shapes and the `apiKey` header (from the NVD documentation;
the sandbox could not reach the API), the rate limits behind the 0.6 s / 6 s pacing, the largest real CVE record and
cpeMatch count (the 8 MiB and 50 000 caps assume real records stay well below), real page sizes.
