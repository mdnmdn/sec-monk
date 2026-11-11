---
title: Source euvd — the native (Rust) ENISA EUVD source
summary: The Rust euvd source in secmonk-sources - file and API loading with size, record and per-record caps, the per-record rows, children replaced against stored rows, EPSS rows next to FIRST, differences from Python, tests.
read_when: you change the Rust euvd source, switch euvd between Rust and Python, debug an euvd sync or its epss rows, or port msrc or debian-tracker and want the example of a source that rewrites the children of a record
type: tech
context: tech
status: implemented
tags: [vuln-source, euvd, enisa, rust, sync, epss]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-sources/src/euvd.rs, rust/crates/secmonk-sources/src/rows.rs, rust/crates/secmonk-sources/src/py.rs, rust/crates/secmonk-sources/src/native.rs, rust/crates/secmonk-store/src/sqlite/mirror.rs, rust/crates/secmonk-engine/src/view.rs]
fixtures: [tests/fixtures/sources/euvd/, tests/fixtures/sources/epss/]
related: [decisions/0012-native-importer-row-reads-and-registry.md, decisions/0011-native-sources.md, tech/source-epss.md, tech/source-kev.md, tech/component-lifecycle.md, tech/data-model.md, tech/configuration.md]
---

# Source euvd (native importer)

The third source ported to Rust, after [kev](source-kev.md) and [epss](source-epss.md), and the first that writes
`vulnerability`, `alias` and `affected` ([rust ADR-0011](../decisions/0011-native-sources.md),
[ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)). `secmonk_sources::euvd::EuvdSource`
implements `Source` in-process. The feed is described in the Python tree's
[EUVD reference](../../../_docs/references/vuln-sources/euvd.md) (endpoint shapes unverified, fixture synthetic); the
reference implementation is `src/secmonk/sources/euvd.py` `EuvdSource.sync` plus `ops.sync_source` /
`db.set_sync_state`.

## Selection

`[sources.implementation] euvd = "rust"` (the default since 2026-11-11: `IMPORTER.default_rust` in `euvd.rs`, set
because the differential test is green) or `"python"` ([configuration](configuration.md#schema)). Switching behaves as
for kev and epss: the first native sync after `py-sources` resets the applied state (job log `euvd: native importer:
applied state of generation <g> (seq N) reset; full sync against the mirror`); the first ok `py-sources` sync after
native ones repairs euvd from the staging export. The Python euvd source reports `ok` also with `--limit`, so a limited
`py-sources` run repairs too.

## One sync

| Step | Behaviour |
|---|---|
| Load (file) | `options.path` (non-empty): `feed::read_bytes` (a regular file only; a directory answers `[Errno 21] Is a directory: '<path>'`, a missing file `[Errno 2] No such file or directory: '<path>'`, a FIFO or device `not a regular file: '<path>'`), at most `Caps::total_bytes` = 256 MiB (`<path>: larger than 268435456 bytes`); origin `from file <path>`. |
| Load (API) | `GET <base>/exploitedvulnerabilities?size=100` (its records count as exploited), `GET <base>/lastvulnerabilities`, and with `limit` `GET <base>/vulnerabilities?page=N&size=100` from page 0 until `limit` records or an empty page; base `https://euvdservices.enisa.europa.eu/api`; workspace `reqwest` (rustls, `https_only`, connect and read timeout 60 s); each answer at most `Caps::response_bytes` = 32 MiB, all together at most 256 MiB; every answer is read before anything is emitted; origin `from <base>`. HTTP errors read `HTTP 404 for <url>`. |
| Decode, split | Strict UTF-8 with Python's `UnicodeDecodeError` text (`'utf-8' codec can't decode byte 0xe9 in position 12: invalid continuation byte`). The document is a list of records, or an object whose `items` (else `content`) is a list (a repeated key: the last one, as `json.loads`); anything else is `unexpected EUVD response shape (no list of records)`. Records are kept as byte ranges of the text (`serde_json::RawValue`, no tree of the document): at most `Caps::records` = 1 000 000 (`euvd: more than 1000000 records; refusing`), each at most `Caps::record_bytes` = 1 MiB (`euvd: a record is larger than 1048576 bytes; refusing`). `limit` with `--path` keeps the first N records (`_items(doc)[:limit]`). |
| Check | Every record is parsed and checked in order before the first operation (Python writes all records in one transaction): the first failing record fails the run with only the `source_sync` row. Texts as Python words them: a record that is not an object `AttributeError: 'int' object has no attribute 'get'`; `products` a number or `true` `TypeError: 'int' object is not iterable` (`'float'`, `'bool'` for those types); `aliases` not a string `TypeError: expected string or bytes-like object, got 'list'`; `baseScore` a string, list or object `TypeError: '>=' not supported between instances of 'str' and 'float'`; `epss` (only when the record has a CVE alias) a string `float()` refuses `could not convert string to float: 'x'`, a list or object `TypeError: float() argument must be a string or a real number, not 'list'`. Native checks (no Python counterpart or another text, see differences): a non-string id, text field or product field, more than `Caps::children` = 10 000 product objects plus CVE aliases in one record (`euvd: <id>: more than 10000 products and CVE aliases; refusing`), an infinite `epss`. Records without a truthy `id` are skipped. |
| Rows per record | Only the **last** record of an id is written in full (Python overwrites the earlier ones; their `epss` upserts remain, so those are emitted in order). Full record: `raw_record` upsert (`modified` = `dateUpdated`, `data` = the record); `vulnerability` upsert with every column (`summary` = `description`, `published`, `modified`, `severity` from `baseScore` (`severity_from_score`; a bool counts as 1 / 0), `cvss_score`, `cvss_vector`, `cvss_version`, `cwes` = `[]`, `extra` = `{exploited, epss, assigner, vendors, products}`: `exploited` the record's truthy flag or the exploited view, `epss` as given, vendors and products sorted and distinct, non-empty strings only); the aliases: the CVE ids among `aliases` split on whitespace and commas, upper-cased, kind `alias`; `affected`: one row per product object (`vendor` / `product` normalized as `norm_vendor_product`, `range_type` `CVE`, `version_type` `euvd`, `versions` `[version]` when truthy, `status` `affected`, `extra` the product object). Then per CVE alias (duplicates included, as the Python loop) an `epss` upsert `{cve_id, score, percentile: null, date: dateUpdated[:10], source: "euvd"}` when `epss` is not null (`float()` semantics: numbers, bools, numeric strings; `nan` is a NULL score). Last the `source_sync` upsert. |
| Children | `replace_children` against the stored rows. Records are taken in groups of 5; for each group the importer reads the stored `alias` and `affected` rows of its ids (`MirrorView::rows_by_id`, one call per table). A chunk closes at 500 records, 2 MiB of record text, 20 000 new child rows or 50 000 stored rows, whichever comes first; its operations are then emitted. A record with more stored rows of one table than `Caps::children` (possible only for rows `py-sources` wrote from a larger record before a switch) ends the run after that read: `euvd: native importer: <id>: <n> stored affected rows (more than 10000); refusing, sync euvd with the python implementation`; batches emitted before stay (ADR-0011 §4). Aliases: a delete per stored alias that is not new, an upsert per new alias not stored with kind `alias`. `affected`: nothing when the stored and new rows are the same multiset; else a delete per stored row keyed `{source, vuln_id}` (`rows::DeleteKey::Record`: any one row of the record, so N deletes remove the N stored rows whatever their JSON holds), then the new rows. |
| No deletes of records | A record that left the views keeps its rows (the Python source only adds and refreshes). |
| `source_sync` | `status` `ok` (also with `limit`), `records` = distinct ids written, no cursor (the stored one is kept, as `COALESCE`), message `<N> records from file <path>` / `<N> records from <base>`. Error: status and message only. |
| Batches | Cut while the engine reads the stream (`native::stream`): at most 5 000 ops and about 2 MiB each, `generation = "native-rust"`, seqs after the applied seq of that generation, else from 1. The operations are an async stream: the view is read between chunks while the engine applies the batches already cut ([ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md) §3). |

## EPSS rows next to FIRST

`epss` rows of source `euvd` share the key `cve_id` with FIRST rows (source `epss`). The store's owner rule
([data-model](data-model.md#store-traits), `owner_of_sourceless_key`) gives Python's result without anything in the
importer: an euvd upsert never replaces a FIRST row (`ON CONFLICT … WHERE epss.source='euvd'`), refreshes its own row,
and a FIRST row replaces an euvd row. The store's update also writes `percentile` (null) and `source` (euvd) where
Python updates only `score` and `date`; equal, because an euvd row always has a null percentile. Compared in both orders
by the differential test (EUVD before FIRST, FIRST before EUVD), with the native epss importer on the Rust mirror.

## Memory (worst case)

Estimated from the sizes of the types (not measured); a 64-bit build. Every term is bounded by a cap above:

| Term | Bound |
|---|---|
| Document text | 256 MiB (`Caps::total_bytes`); while a file is read the buffer may grow to twice that before anything else is allocated; API answers at most 32 MiB each (64 MiB while one is read) |
| Record ranges | 16 bytes per record, 32 with the vector's growth: 32 MiB at 1 000 000 records |
| Last record of each id (`LastIndex`) | one 64-bit hash and an index per distinct id (the ids themselves are not kept): about 34 bytes per id, 51 while the table grows: 51 MiB at 1 000 000; a second map keeps the id text only for two ids whose hashes collide (keys random per run: expected empty) |
| Check pass | one record at a time: at most 1 MiB of text, parsed into at most about 32 times its size for a record of only tiny values (`[[],[],…]`, `{"":0,…}`), cloned once into `raw_record.data`, plus its at most 10 000 child rows (about 1.2 KiB each): about 100 MiB for one such record, a few KiB for a real one |
| Emission chunk: records | 2 MiB of record text plus the group that crosses it (at most 5 records of 1 MiB): at most 7 MiB, parsed and cloned as above: up to about 220 MiB for tiny-value records (a few MiB for real ones) |
| Emission chunk: new child rows | 20 000 plus the crossing group (5 × 10 000): 70 000 rows, about 85 MiB |
| Emission chunk: stored rows | 50 000 plus the crossing group (5 records × 10 000 rows × 2 tables): 150 000 rows, about 180 MiB. Rows above the caps can only come from `py-sources` writes before a switch; such a group is read once (its size is what `py-sources` stored for 5 records) and the run is refused |
| Batch | one batch: at most 5 000 operations and about 2 MiB of JSON |

Sum of the steady terms: about 256 + 32 + 51 + 220 + 85 + 180 + 2 MiB, about 0.85 GiB, reached only with a full-size
document of pathological records; reading a 256 MiB file peaks at about 0.5 GiB before the other terms exist. The real
views (at most a few hundred records, well under 1 MiB) take a few MiB.

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | `INSERT OR REPLACE` / `replace_children` per record, one transaction | the same rows, in batches of 5 000 ops; aliases and `affected` rows that did not change are not rewritten (`affected.rowid_` differs, not compared) |
| Stream cut between batches | (py-sources batches too) | the applied records stay, `source_sync` still shows the previous run; the next sync converges (each record is computed against the stored rows) |
| File and answer size | unbounded | 256 MiB in total, 32 MiB per API answer |
| Records | unbounded | 1 000 000 per run, 1 MiB per record, 10 000 product objects plus CVE aliases per record |
| Stored `alias` / `affected` rows of one record above 10 000 (written by `py-sources` from a larger record) | rewritten | the run is refused after reading them (`… stored affected rows (more than 10000); refusing, sync euvd with the python implementation`) |
| A number in a text field (`description`, `datePublished`, `dateUpdated`, `baseScoreVector`, `baseScoreVersion`) | stored as text by SQLite (`5` becomes `"5"`); a list or object fails when SQLite binds it | the run fails: `euvd: <id>: <field> is not a string` |
| A truthy non-string `id` (`5`) | stored: `record_id` / `id` `"5"` (TEXT affinity) | the run fails: `euvd: a record id is not a string` |
| A non-string, non-null product `vendor` / `product` | the run fails: `AttributeError: 'int' object has no attribute 'strip'` (`norm_vendor_product`), or `TypeError` from `sorted` (`'<' not supported between instances of 'int' and 'str'`) or the set (`unhashable type: 'list'`) | the run fails: `euvd: <id>: products[].vendor is not a string` (same status, other text) |
| A truthy non-string product `version` (`3`) | stored in `versions` as given (`[3]`) | the run fails: `euvd: <id>: products[].version is not a string` |
| Integers above the 64-bit range in a record | kept exact by Python (its own database) | parsed as a float (`18446744073709551616123` becomes `1.8446744073709552e22`); `py-sources` sends the exact text, which the Rust store parses the same way, so both mirrors are equal |
| A lone surrogate escape (`"\ud800"`) | accepted by `json.loads`; the run then fails when SQLite stores the record (`UnicodeEncodeError: … surrogates not allowed`), or the record is skipped when it has no id | the run fails at that record: `invalid JSON: …` (also for a record without id) |
| `epss` `"inf"` | stored as infinity in staging (no JSON form for the stream) | the run fails: `euvd: <id>: epss is not finite` |
| JSON syntax errors, `NaN` / `Infinity` literals, nesting deeper than 128 | `json.loads` wording (`Expecting value: …`), literals accepted, depth about 1 000 | `invalid JSON: <serde_json text>`; literals and deeper nesting refused; same `error` status |
| HTTP errors | httpx wording | `HTTP 404 for <url>` / reqwest wording; same status |
| `--path` a FIFO or device | blocks reading it | refused: `not a regular file: '<path>'` |
| Relative `--path` | the module's working directory | the host process's working directory (the UI sends absolute paths) |
| `str.upper()` of aliases, `\s` | Python's Unicode tables | Rust's (`to_uppercase`; whitespace = Unicode White_Space plus `\x1c`-`\x1f`, as `str.isspace`); equal for CVE ids |

Equal by test: every mirror table (timestamps aside) after the steps below, the entry `status`, `records` and
`message` of every step but the JSON syntax error, and the texts of the checked errors listed under Check.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/src/euvd.rs` (unit) | splitting (list, `items`, `content`, repeated keys, shapes, syntax, record and size caps); the error texts of every checked case (also the children cap); a lone surrogate escape; `LastIndex` with a forced hash collision; the rows of one record (normalized vendors, sorted extra lists, `epss` from a string, duplicate CVE aliases, a bool score) |
| `secmonk-sources/src/py.rs`, `rows.rs` (unit) | `float(str)`, whitespace, truthiness, `UnicodeDecodeError` texts (checked against Python 3.13); `norm_vendor_product`, `severity_from_score`, `normalize_severity`, `alias_set`, `replace_aliases`, `replace_affected` |
| `secmonk-sources/tests/euvd.rs` | over `common::MemView`: the fixture's rows, a second run (aliases untouched), children changed and shrunk, a repeated id (last record written, earlier `epss` kept), limit, the error entries (only the `source_sync` row), 700 records in chunks (at most 500 ids per `rows_by_id`), caps; `a_repeated_id_across_chunks_and_identical_products` (the two records of an id 601 records apart; two identical products kept, then both deleted and one inserted); `stored_rows_beyond_the_caps_refuse_the_run`; the API views and pages against a local server (request lines, the exploited flag of the last record, a 404) |
| `secmonk-store/tests/store.rs` `stored_rows_read_back_by_id_and_by_page` | `rows_by_id` / `rows_page` return what was written (spec order, JSON parsed, other sources excluded, limits); every row read back deletes exactly itself, with floats that need exact parsing; `rows_page_scans_the_rowid_range_without_a_sort` (`EXPLAIN QUERY PLAN` of every table: a rowid range search, no temporary B-tree) |
| `secmonk-engine/tests/native_euvd.rs` `native_euvd_matches_py_sources` | **differential** (needs `rust/python/.venv`; `SECMONK_REQUIRE_VENV=1`): `py-sources` and the native euvd (with the native epss) on their own mirrors; all mirror tables equal after: EUVD first, no-op, FIRST after EUVD, EUVD after FIRST, an update (products, aliases, repeated id, skipped records, odd types), children removed and a zero score, limit, an id whose two records are 601 records apart (different chunks), two identical products (unchanged, then one removed), the stored text of `affected.extra` equal in both mirrors (key order of the feed), seven bad inputs with Python's texts, a directory, invalid UTF-8; JSON syntax error (message aside); a switch mirror py-sources -> native (log line) -> a failed py-sources run (nothing applied) -> ok py-sources runs (repair; equal to its staging and, for the euvd rows, to the Python-only mirror); last the documented difference of a number in a text field |
| `secmonk-engine/tests/native_euvd.rs` `native_euvd_batches_follow_the_row_contract` | every batch and end of five runs (fixture, update, shrink, limit, a missing file) applied to a real store and validated against `source/rows.schema.json` and `source/sync-end.schema.json`; alias and `affected` deletes among them |
| `secmonk-host/src/engine.rs`, `secmonk-config/tests/config.rs` | the default selection follows `IMPORTERS` (`default_rust`); every importer switched to `python` |

Fixtures: `tests/fixtures/sources/euvd/exploited-sample.json` (2 records, synthetic, read only; the fixture directory has
no README, its provenance is in the Python tree's [EUVD reference](../../../_docs/references/vuln-sources/euvd.md));
`tests/fixtures/sources/epss/epss_scores-sample.csv`. The variants (scores, update, shrink, bad records, large lists)
are written at test time (synthetic, nothing committed).
