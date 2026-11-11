---
title: Source msrc — the native (Rust) Microsoft MSRC CVRF source
summary: The Rust msrc source in secmonk-sources - file, directory and API loading with caps, two passes over deflated documents, per-document affected rows replaced row by row, differences from Python, tests.
read_when: you change the Rust msrc source, switch msrc between Rust and Python, debug an msrc sync or its KB and fixed-build rows, or port a source whose rows belong to one of several input documents
type: tech
context: tech
status: implemented
tags: [vuln-source, msrc, windows, rust, sync]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-sources/src/msrc.rs, rust/crates/secmonk-sources/src/rows.rs, rust/crates/secmonk-sources/src/py.rs, rust/crates/secmonk-sources/src/native.rs, rust/crates/secmonk-sources/src/feed.rs, rust/crates/secmonk-engine/src/view.rs]
fixtures: [tests/fixtures/sources/msrc/]
related: [decisions/0012-native-importer-row-reads-and-registry.md, decisions/0011-native-sources.md, tech/source-euvd.md, tech/source-kev.md, tech/component-lifecycle.md, tech/data-model.md, tech/configuration.md]
---

# Source msrc (native importer)

The fourth vulnerability source ported to Rust, after [kev](source-kev.md), [epss](source-epss.md) and
[euvd](source-euvd.md) ([rust ADR-0011](../decisions/0011-native-sources.md),
[ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)). `secmonk_sources::msrc::MsrcSource`
implements `Source` in-process. The feed is described in the Python tree's
[MSRC reference](../../../_docs/references/vuln-sources/msrc.md) (CVRF v3 JSON; the API is not reachable from the dev
sandbox, the shape is unverified and the fixture synthetic); the reference implementation is
`src/secmonk/sources/msrc.py` `MsrcSource.sync` plus `ops.sync_source` / `db.set_sync_state`. Only JSON is read (the
API is asked for `application/json`); there is no XML parser and so no external-entity question.

## Selection

`[sources.implementation] msrc = "rust"` (the default since 2026-11-11: `IMPORTER.default_rust` in `msrc.rs`, set
because the differential test is green) or `"python"` ([configuration](configuration.md#schema)). Switching behaves as
for the other native importers: the first native sync after `py-sources` resets the applied state (job log `msrc:
native importer: applied state of generation <g> (seq N) reset; full sync against the mirror`); a failed `py-sources`
run after native ones applies nothing (`...; not applied: mirror keeps the native importer data until a successful
py-sources sync`); the first ok one repairs msrc from the staging export. `in_all` is true, as in Python (no
`in_all = False`; `ops.SYNC_ALL_ORDER` lists msrc).

## One sync

| Step | Behaviour |
|---|---|
| Load (path) | `options.path` (non-empty). Missing (`feed::exists_like_python`, as `Path.exists()`: `ENOENT`, `ENOTDIR`, `EBADF`, `ELOOP`; on Windows the Win32 codes 2, 3, 21, 123, 1921 **(verify)** on Windows): `path not found: <path>`; another error: the `OSError` text. A file: that document. A directory (`feed::rglob`): every entry whose name ends in `.json` below it (`rglob("*.json")` of Python 3.13: hidden names included, directories so named included, symlinked directories not entered, unreadable directories skipped), at most `Caps::entries` = 100 000 entries visited (`msrc: more than 100000 entries under <path>; refusing`) and `Caps::documents` = 2 000 documents. Anything else (a FIFO, a device): `not a regular file: '<path>'`. Each document through `feed::read_bytes` (a regular file only), at most `Caps::document_bytes` = 64 MiB. `limit`, `since` and `full` are ignored, as in Python. |
| Order (path) | By `(str(CurrentReleaseDate or ""), str(path))`, as `_local_docs`. A document that cannot be read or parsed (an `OSError` such as `[Errno 21] Is a directory: '<path>'`, `<path>: larger than 67108864 bytes`, invalid UTF-8, invalid JSON, a cap of one document) has no date, sorts first, and the run stops there: nothing after it is imported (status `partial` if vulnerabilities were imported before it, else `error`; message the error). |
| Load (API) | `GET <base>/updates` (at most `Caps::updates_bytes` = 16 MiB), months sorted by `CurrentReleaseDate`, those `>= since`, those newer than the stored cursor (read through `MirrorView::rows_page(source_sync)`; skipped with `full`), the newest `limit`; then per month `msrc: <ID>` in the job log and `GET CvrfUrl` or `<base>/cvrf/<ID or Alias>`. Base `https://api.msrc.microsoft.com/cvrf/v3.0`; `Accept: application/json`; `feed::get` over the workspace `reqwest` (rustls, `https_only`, connect and read timeout 120 s as httpx there). A `CvrfUrl` on another origin than the base is not requested: `msrc: document URL <url> is not on <origin>; refusing`, and the run stops there. A document request follows redirects only within its own origin (at most 10): a redirect elsewhere fails with `<url>: redirect to <target> is not on <origin>; refusing` and stops the run at that month; `/updates` follows up to 10 redirects anywhere. A failing download (`HTTP 404 for <url>`) stops the run at that month. |
| Decode, check, hold | Per document: a UTF-8 BOM dropped (`utf-8-sig`), strict UTF-8 with Python's `UnicodeDecodeError` text, JSON parsed without building the tree of the document: only `ProductTree`, `DocumentTracking` (each at most `Caps::tree_bytes` = 4 MiB: `msrc: <name>: ProductTree larger than 4194304 bytes; refusing`) and the byte ranges of the `Vulnerability` elements (each at most `Caps::vulnerability_bytes` = 8 MiB). Then the text is deflated (`flate2`, fast level) and held. Caps over the run refuse it before anything is written (status `error`): all documents at most `Caps::total_bytes` = 4 GiB as read (`msrc: documents larger than 4294967296 bytes in total; refusing`) and `Caps::held_bytes` = 512 MiB deflated, at most `Caps::vulnerabilities` = 500 000 vulnerabilities (`msrc: more than 500000 vulnerabilities in total; refusing`). |
| First pass | Every held document in order, inflated one at a time (on the blocking pool), every vulnerability through the steps of `import_cvrf` (below) against the stored `vulnerability` rows (`modified`, `extra`) of its CVE, read per chunk of at most 500 vulnerabilities and about 4 MiB with `MirrorView::rows_by_id`, and the state this run leaves. Each chunk is parsed on the blocking pool; the steps of a chunk run on the async task (they update the run's per-CVE state and the `(CVE, document)` rows kept across chunks, and are bounded by the chunk). Nothing is emitted. It yields the status, the counts, the cursor and the per-document errors (job log `msrc: <name>: <error>`). |
| Per document (`import_cvrf`) | The product tree (`_walk_products`: every object with a string `ProductID` and a `Value`, depth first); the document id (`DocumentTracking.Identification.ID.Value`), `CurrentReleaseDate`, `InitialReleaseDate`. Per vulnerability with a `CVE`: the highest numeric `BaseScore` (first of equals; a bool counts), the first `Description` note, the KB numbers of every remediation (`\d{6,8}`, Unicode digits), and one `affected` row per (normalized product, `FixedBuild`) of the vendor-fix remediations (`Type` `2` or `Vendor Fix`) with `extra = {kb, product_ids, full_names, supersedes, document}`. Product names normalize as `normalize_product_name` (arch suffix, Server Core suffix, `Windows Server, version X`). |
| Per-document errors | What Python's `except (ValueError, KeyError, TypeError, AttributeError)` catches stops the document at that vulnerability (a `Vulnerability` member that is not a list fails before the first one: a truthy number or `true` is not iterable, a truthy string or object gives `'str' object has no attribute 'get'` for its first character or key; only its type and truthiness are read from its text, it is never parsed into a tree): the vulnerabilities before it stay written (one transaction per vulnerability there), the document's count is not added, the cursor stops advancing, the status becomes `partial`. Cases as Python: a document, a tracking block, a vulnerability, a score set, a note or a remediation that is not an object; a list member that is a number; a product name that is not a string; an unhashable `FixedBuild` (list, object); a non-string truthy `Vector` in the branch that writes the vulnerability row. Native-only cases are under differences. |
| Rows per vulnerability | `affected`: the stored rows of this CVE whose `extra.document` is this document id (`json_extract(extra,'$.document') IS ?`; null matches null) are replaced: nothing when they equal the new rows as a multiset, else one delete per stored row keyed by the full row (`rows::DeleteKey::Row`, rust ADR-0012 §2) and the new rows, sorted by (product, fixed build). Rows of other documents stay. `vulnerability` and `raw_record`: written in full (summary = `Title`, details, `published` = `InitialReleaseDate`, `modified` = `CurrentReleaseDate`, severity from the score, `cvss_score`, `cvss_vector`, `cvss_version` = the vector's first part without `CVSS:`, `cwes` `[]`, `extra = {document, kbs}` with the stored KBs merged) unless the stored row is newer (`modified > CurrentReleaseDate`, both non-empty); then only `extra.kbs` is updated when the document brings new KB numbers (an upsert of `source`, `id`, `extra`), else nothing. |
| Second pass | The operation stream: the same steps over the same documents from the same starting state, now emitting, per chunk, with the stored `affected` rows of the chunk's CVEs read through `rows_by_id`. A `(CVE, document)` pair the run writes twice (the same document twice under a directory, a CVE twice in one document) uses the rows the run wrote the first time, not a read (the engine may not have applied them yet; rust ADR-0012 §3); the first pass lists those pairs. |
| `source_sync` | Ok / partial: `records` = msrc vulnerability rows after the run (stored before plus the CVEs the run created: `SyncResult.total`), cursor = the newest `CurrentReleaseDate` of the documents imported before the first per-document error (kept when none, as `COALESCE`), message `<N> vulnerabilities`. A run that stopped: `records` = vulnerabilities imported, the cursor so far, the message of the error. The entry's `records` is the number of vulnerabilities imported (`SyncResult.records`): `Outcome.records`, while `Outcome.total` carries `source_sync.records` (`native::stream`). Error: status and message only. |
| Batches | Cut while the engine reads the stream (`native::stream`): at most 5 000 ops and about 2 MiB each, `generation = "native-rust"`, seqs after the applied seq of that generation, else from 1. |

## Memory (worst case, estimated)

Within the caps: the deflated documents, at most 512 MiB; while loading, one document as read (at most 64 MiB, up to
twice that while the buffer grows) and its deflated copy; per pass one inflated document (64 MiB), its product tree and
tracking block parsed (at most 4 MiB of text each, up to about 16 times that as `serde_json::Value` for a tree of only
tiny values: 128 MiB), 16 bytes per vulnerability range, and one chunk. Nothing else of a document is parsed into a
tree: a `Vulnerability` member that is not a list is judged by its type and truthiness, read from its text (no
allocation, whatever its size), and a `for` over a string or object (`py::iter_items`: `ProductID`, `CVSSScoreSets`,
`Notes`, `Remediations`, the `/updates` `value`) yields one character or key at a time (a string of N characters is
never expanded into N values). The chunk: at most 500 vulnerabilities and about 4 MiB of
text plus one vulnerability of up to 8 MiB, parsed (a few times the text, up to about 16 times: 200 MiB), its rows
(the vulnerability once more in `raw_record.data`) and the stored `affected` rows of its CVEs; the state per CVE of the
run, twice (as stored at the start and as the run leaves it: `modified` and `extra` with the KB list, about 200 bytes
plus the KBs; 500 000 CVEs about 200 MiB) and the `(CVE, document)` pairs (about 50 MiB); one batch (2 MiB). Estimate:
about 1.3 GiB at the caps. One case adds to it, as in Python: a `ProductID` string whose characters are product ids
of the tree gives one `product_ids` entry per character, so one vulnerability of 8 MiB can build a row of about 8
million entries (about 1 GiB more while it is emitted). Until 2026-11-11 (review W9.6) two more cases were not
bounded: every `for` over a string built one value per character up front, and a `Vulnerability` member that is not a
list was parsed whole, each up to several GiB for a 64 MiB document (three times: once when the document is
checked, once per pass); both are gone. Not measured. A full MSRC history (about 130 monthly documents, about 20 000 CVEs) is
expected well below 300 MiB, deflated documents included; the size of real documents is unverified **(verify)**.

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | per vulnerability one transaction (`DELETE` + `INSERT OR REPLACE` + inserts) | the same rows, in batches of 5 000 ops; `affected` rows that did not change are not rewritten (`affected.rowid_` differs, not compared) |
| Stream cut between batches | (py-sources batches too) | the applied vulnerabilities stay, `source_sync` still shows the previous run; the next sync converges (each vulnerability is computed against the stored rows) |
| Sizes and counts | unbounded | caps above; a cap over the run refuses it, a cap of one document stops the run at it |
| API documents | downloaded and imported one month at a time | every month is downloaded (and held deflated) before the first operation, because the `source_sync` row and the status are fixed before the stream starts; a failing download stops the run at the same month |
| `CvrfUrl` on another host | requested | refused (`msrc: document URL ... is not on ...`) |
| A document request redirected | followed, up to 20 redirects, to any host (httpx) | followed within the origin of the request, up to 10; elsewhere refused (`<url>: redirect to <target> is not on <origin>; refusing`); `/updates`: up to 10, any host |
| `--path` a FIFO or device | no documents (`rglob` of a non-directory), status `ok` | refused: `not a regular file: '<path>'` |
| A non-string `CVE`, `CurrentReleaseDate`, `InitialReleaseDate`; a number or bool as `FixedBuild` (when a product matches); a falsy non-string `Vector` (`0`, `false`, `[]`, `{}`) in the branch that writes the row | stored as text by SQLite, compared or sorted as Python values (a list fails when bound and stops the run) | the document fails: `msrc: a CVE is not a string`, `msrc: DocumentTracking.<field> is not a string` (checked once per document, before its first vulnerability), `msrc: <CVE>: FixedBuild is not a string`, `msrc: <CVE>: Vector is not a string`; status `partial` |
| JSON syntax errors, `NaN` / `Infinity` literals, nesting deeper than 128 | `json.loads` wording, literals accepted, depth about 1 000 (`RecursionError` beyond, an uncaught error) | `invalid JSON: <serde_json text>`, the run stops there; literals and deeper nesting refused |
| UTF-16 / UTF-32 API answers | decoded by `json.loads` of bytes | invalid UTF-8 |
| HTTP errors, odd `/updates` shapes | httpx wording, Python exceptions | `HTTP 404 for <url>`; `AttributeError: '<type>' object has no attribute 'get'`, `TypeError: ...`, `msrc: an update's CurrentReleaseDate is not a string`; same `error` status |
| Case folding in product names, `\w` | `re.IGNORECASE` (also `ſ`, Kelvin sign), Unicode `\w` | ASCII case folding; `char::is_alphanumeric` or `_` |
| `str()` of non-string values (`Type`, `ProductID`, KB, `Supercedence`, titles) | Python `str` / `repr` | the same for JSON values (`py::str_of`: ints, `repr(float)`, `True`, `None`, lists and objects with quoted strings, non-printable characters escaped as `repr` does); unassigned code points inside lists are kept, Python escapes them (no Unicode tables) |
| Relative `--path` | the module's working directory | the host process's working directory (the UI sends absolute paths) |

Equal by test: every mirror table (timestamps aside) after the steps below, and the entry `status`, `records` and
`message` of every step but the JSON syntax error.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/src/msrc.rs` (unit) | product name normalization (Python's cases and the suffix edge cases); `str()` of JSON values (`repr(float)`, `repr(str)` and `for` over a value themselves: `py.rs` tests); KB numbers; one vulnerability's rows (first max score, first description note, KB of non-fix remediations, numeric product ids, `Type` 2.0 skipped); every per-vulnerability and per-document error text; a `Vulnerability` member that is not a list (every type and falsy form; a 1 MiB key read without building it); the newest / older / KB-merge decision and the vector error only in the writing branch; document parsing (repeated keys, non-object documents, syntax, caps); `/updates` ordering and origins (`feed::origin` / `same_origin` in `feed.rs` tests, with `exists_like_python` and `rglob`) |
| `secmonk-sources/tests/msrc.rs` | over `common::MemView`: the fixture's rows, a second run (nothing rewritten in `affected`), two months in a directory ordered by date, an older month after a newer one (extra-only upsert, its own row replaced), a revised month (one product gone, the other month's row kept), a document twice in one run, per-document errors (rows before the failing vulnerability kept, log lines, no cursor), errors that stop the run (a directory named `.json`, an undated document then invalid UTF-8, invalid JSON, a missing path, an empty directory, a FIFO), `limit` ignored with a path and 0 refused, 600 vulnerabilities in chunks (at most 500 ids per `rows_by_id`), caps; the API against a local server (request lines, cursor, `full`, `limit`, `since`, a `CvrfUrl` on another origin, a 404 after a good month, a document redirected within the origin then one redirected to another origin, an `/updates` list) |
| `secmonk-engine/tests/native_msrc.rs` `native_msrc_matches_py_sources` | **differential** (needs `rust/python/.venv`; `SECMONK_REQUIRE_VENV=1`): `py-sources` and the native msrc on their own mirrors; all mirror tables equal after: the fixture twice, July and August in one directory, July again with a new KB and a changed build, August revised (Windows 10 removed, a build changed, the Excel CVE gone, nested branches, numeric ids, a duplicate CVE, no CVE, `Type` 2.0, a string `ProductID`, an empty vector, a bool score), the same document twice in a directory with `limit`, five per-document errors, a directory named `.json`, an undated document then invalid UTF-8 with a BOM, an unreadable single file, an empty directory; JSON syntax error (message aside); a switch mirror py-sources -> native (log line) -> a failed py-sources run (nothing applied) -> an ok py-sources run (repair; equal to its staging and, for the msrc rows, to the Python-only mirror); last the documented difference of a numeric `FixedBuild` |
| `secmonk-engine/tests/native_msrc.rs` `native_msrc_batches_follow_the_row_contract` | every batch and end of six runs (fixture, July, July with a new KB, August revised, the fixture again, a missing file) applied to a real store and validated against `source/rows.schema.json` and `source/sync-end.schema.json`; full-row `affected` deletes and the extra-only `vulnerability` upsert among them |

Fixture: `tests/fixtures/sources/msrc/cvrf-2024-Aug.synthetic.json` (synthetic, read only; the fixture directory has no
README, its provenance is in the Python tree's [MSRC reference](../../../_docs/references/vuln-sources/msrc.md)). The
other months and the bad documents are written at test time (synthetic, nothing committed). A missing `--path` is
covered only by the importer tests: the engine refuses a path that does not exist before any source runs.
