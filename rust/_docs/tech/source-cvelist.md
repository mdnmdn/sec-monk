---
title: Source cvelist — the native (Rust) CVE List v5 source
summary: "The Rust cvelist source in secmonk-sources - --path walks, raw ids, the hardened git subprocess (sparse partial clone, diff cursor, years), per-record errors, CNA/ADP and CPE rows, caps, memory, volume, differences, tests."
read_when: you change the Rust cvelist source, switch cvelist between Rust and Python, debug a cvelist sync (git cursor, years, clone cache, record errors), or port a source that runs an external program
type: tech
context: tech
status: implemented
tags: [vuln-source, cve, cvelist, adp, ssvc, git, rust, sync]
updated: 2026-11-12
verified: 2026-11-12
code: [rust/crates/secmonk-sources/src/cvelist.rs, rust/crates/secmonk-sources/src/native.rs, rust/crates/secmonk-sources/src/rows.rs, rust/crates/secmonk-sources/src/feed.rs, rust/crates/secmonk-safeio/src/within.rs]
fixtures: [tests/fixtures/sources/cvelist/]
related: [decisions/0012-native-importer-row-reads-and-registry.md, decisions/0011-native-sources.md, tech/source-nvd.md, tech/source-euvd.md, tech/component-lifecycle.md, tech/data-model.md, tech/configuration.md]
---

# Source cvelist (native importer)

The seventh vulnerability source ported to Rust, after [kev](source-kev.md), [epss](source-epss.md),
[euvd](source-euvd.md), [msrc](source-msrc.md), [debian-tracker](source-debian-tracker.md) and [nvd](source-nvd.md)
([rust ADR-0011](../decisions/0011-native-sources.md), [ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)).
`secmonk_sources::cvelist::CvelistSource` implements `Source` in-process. The feed and the mapping are described in the
Python tree's [CVE List v5 reference](../../../_docs/references/vuln-sources/cvelist-v5.md); the reference
implementation is `src/secmonk/sources/cvelist.py` `CveListSource.sync` plus `ops.sync_source` / `db.set_sync_state`.
Python has no bulk (release zip) or `delta.json` mode: the modes below are all it has.

## Selection

`[sources.implementation] cvelist = "rust"` or `"python"` ([configuration](configuration.md#schema)). The default stays
`python` (`IMPORTER.default_rust = false` in `cvelist.rs`): see [Default](#default). Switching behaves as for the other
native importers: the first native sync after `py-sources` resets the applied state (job log `cvelist: native importer:
applied state of generation <g> (seq N) reset; full sync against the mirror`); a failed `py-sources` run after native
ones applies nothing (`...; not applied: mirror keeps the native importer data until a successful py-sources sync`);
the first ok one repairs cvelist from the staging export. The internal rows `cvelist:git` and `cvelist:years` are mirror
rows, so both implementations continue each other's cursor and year range; each keeps its own clone (below).

## One sync

Modes by precedence, as in Python: `--path`, then `ids` (`SyncOptions.ids`, not sent by the engine's sync jobs
today), then the git mode.

| Step | Behaviour |
|---|---|
| Load (path) | `options.path` (non-empty). `Path.exists()` (`feed::exists_like_python`): missing gives status `error`, `path not found: <path>`; another `OSError` gives `git failed: <text>` (Python's `except` wording). A file (symlinks followed) is the only record file, whatever its name; a directory is walked for `CVE-*.json` (`feed::rglob`: hidden names included, symlinked directories not entered), sorted as Python sorts paths (by component: `a/x` before `a-b/x`); anything else (a FIFO, a device) is refused: `cvelist: not a regular file or a directory: '<path>'`. Each file is opened with `feed::open_regular` (a directory named `CVE-x.json` is a record error, as Python's `IsADirectoryError`). `limit` stops the walk; the status stays `ok` (Python ignores the limit flag here). Message `imported <n> from <path>`. |
| Load (ids) | `ids` stripped and upper-cased; `["@referenced"]` is refused natively (status `error`, see Differences). One `GET <raw base>cves/<year>/<n/1000>xxx/<id>.json` per id (`cve_path`: the file name keeps the id's digits, the folder is the numeric value; a non-CVE id is a record error `ValueError: not a CVE id: '<id>'`), with the workspace `reqwest` client (`feed::fetch_client`, timeout 30 s, redirects followed as httpx does), at most `Caps::file_bytes` per answer; 404 is logged (`cvelist: <id> not found`) and is no error; another status or a transport error is a record error. `limit` is checked before each request. No `dateUpdated` comparison (as Python). Message `fetched <n> ids`. |
| Load (git) | See [Git mode](#git-mode). Message `git <head[:10]>, years <first>..<last>`, plus `, limit reached` and `, <n> record errors`. |
| Records | Files are taken in groups (at most 50 files, read in rounds of 8 on as many threads, at most 8 MiB of text per group); each is read (at most `Caps::file_bytes` = 4 MiB, else a record error), decoded as strict UTF-8 and parsed. Per file, in walk order, as `_import_files`: the limit (`count >= limit` before the next file: the run stops, `hit_limit`); a file that does not parse is a record error; a value that is not an object with a `cveMetadata` key is skipped; unless `full`, `_is_newer` (the stored `vulnerability.modified`, or what this run emitted for the id, `>=` the record's `dateUpdated`: skipped; a `cveMetadata` that is truthy but not an object, or a non-string `dateUpdated` against a stored row, is a record error as Python's); then `import_record`. Every 500 files: job log `cvelist: <n> records`. A record error is counted and logged (`cvelist: skipping <file>: <Class>: <text>`), nothing of it is emitted (Python's SAVEPOINT rollback). |
| Rows per record (`import_record`) | Planned completely before anything is emitted, with every check Python makes while writing (an attribute or iteration error, `float()` of the score, a list or object in a text column, `.strip()` of a non-string vendor, an unhashable `matchCriteriaId`, a version number of more than 4 300 digits). `raw_record` upsert (`modified` = `dateUpdated`, `data` = the record). `vulnerability` upsert: `summary` = the first English `rejectedReasons` value (rejected) or the first English description, else `title`; CVSS from the CNA's metrics (4.0 > 3.1 > 3.0 > 2.0, the first of equals), else the first ADP with one (`extra.cvss_source` = `cna` / `adp:<shortName>`); `severity` = `normalize_severity(str(baseSeverity))`, else `severity_from_score`; `cwes` from the CNA, else the first ADP with any (any JSON value, repeats removed with Python's `==`); `extra` = `cvss_source`, `ssvc` (ADP `metrics[].other` of type `ssvc`, options flattened, `version` / `timestamp` / `role`), `adp_kev`, `assigner`, `title`, the first 20 reference URLs of CNA and ADPs; `withdrawn` = `dateRejected` when `state` is `REJECTED`. Not rejected: the `affected` rows of every CNA and ADP `affected[]` entry (`extra.container` `cna` / `adp:<shortName>`): `convert_version_entry` per version (`CVE` events or exact versions, `GIT` for commit data, `CVE-UNPARSED` with `extra.raw`; `changes[]` sorted with the generic version comparator; free-text expressions such as `< 2.5.4`, `3.0.0 - 3.0.3`, `2.3 and earlier`), one `unaffected` row for unaffected-only entries, a `CVE-UNPARSED` row for `defaultStatus: affected` without usable versions; `packageName` normalized per ecosystem (`purl.normalize_name`), ecosystem from the `collectionURL` host (`urllib` hostname rules); then one row per vulnerable `cpeApplicability` cpeMatch (breadth first, de-duplicated by `matchCriteriaId` or the match's JSON), `CVE-UNPARSED` with `extra.dropped_bounds` / `extra.cpe_update` when a bound is not a version or the CPE has an update field. At most `Caps::rows` = 10 000 rows per record (a record error). |
| Children | `replace_children` against the stored rows: per group, `MirrorView::rows_by_id` reads the `vulnerability` rows of the group's ids (for `_is_newer` and the total), then the `affected` rows only of the ids a record of the group may be imported for (an unchanged re-sync reads none). Per CVE: nothing when the stored and new rows are the same multiset, else a delete per stored row keyed `{source, vuln_id}` (`DeleteKey::Record`) then the new rows. An id already emitted in this run (two files of one CVE) replaces the rows it emitted instead of reading them back (rust ADR-0012 §3). Stored rows of one CVE above `Caps::rows` (only rows `py-sources` wrote) make that record an error (`... stored affected rows (more than 10000); refusing, sync cvelist with the python implementation`). `alias` rows: cvelist never writes any, so none are read. |
| End | **path / ids**: `partial` with record errors, else `ok`; no cursor. **git**: `ok` when the walk ended without the limit and without record errors; then the internal rows `cvelist:git` (`cursor` = HEAD, message `git <head[:10]>`, records 0) and `cvelist:years` (`cursor` = the first year, message `oldest synced year`) are written and the cursor is HEAD; else `partial`, no cursor, the internal rows unchanged. `records` = records imported; `source_sync.records` = the source's `vulnerability` rows after the run (`SyncResult.total`: the count before the run plus the ids this run created). **A failure before the records** (`git failed: <detail.strip()[:300]>`, the path errors, a walk cap): `error`, nothing but the `source_sync` row. Messages pass `scrub_text`. |
| Batches | Cut while the engine reads the stream (`native::stream_deferred`): at most 5 000 ops and about 2 MiB each, `generation = "native-rust"`, seqs after the applied seq of that generation, else from 1. |

## Git mode

The same sequence as `_sync_git`, run on the blocking pool as the first step of the operation stream:

1. Years: the previous and current year, widened to the first four digits of `--since` (Unicode decimal digits, as
   `re`'s `\d`) and to the stored `cvelist:years` cursor (ASCII digits).
2. The clone directory (`<cache>/cvelist-native`, [Clone location](#clone-location)) is created 0700; a symlink is
   refused (`<dir> is a symlink; refusing to use it`), group and other permissions are removed. When it holds a `.git`
   whose `remote.origin.url` (`git config --local --get`) is not the configured URL, it is deleted and cloned again
   (job log `cvelist: cache has a foreign/unknown origin; re-cloning`).
3. No `.git`: `git clone --depth 1 --filter=blob:none --sparse -- <url> <dir>` (job log `cvelist: cloning (partial,
   sparse)`); the stored cursor is then not used.
4. `git sparse-checkout add cves/<year>...` for every year.
5. An existing clone: `git fetch --depth 1 origin main`, `git rev-parse FETCH_HEAD`. With a stored cursor (`^[0-9a-f]{40}([0-9a-f]{24})?$`, not
   `--full`): when it differs from the new commit, `git diff --name-only --no-renames --end-of-options <cursor> <new> -- cves`
   gives the changed `.json` paths and only the years not checked out before are walked; when the diff fails (a cursor
   the clone does not have: another clone, shallow history) every year is walked (job log `cvelist: diff unavailable,
   falling back to dateUpdated comparison`). Then `git reset --hard FETCH_HEAD` and `git sparse-checkout reapply`.
6. `git rev-parse HEAD`; the changed files that exist, then the `CVE-*.json` files of each walked year (sorted by
   component), each path once.

Files of the clone are read with `secmonk_safeio::read_within(path, <clone>, cap)`: a path that resolves outside the
clone (a symlink in the repository) or is not a regular file is a record error, never read. A year directory that is
not a directory is skipped.

**The git subprocess.** Program `git` from `PATH` (`with_git` in tests). Arguments are fixed (the list above); values
come only from the configured URL, the clone path, the year list and a validated commit id, each a separate argument
after `--` or `--end-of-options` where git allows it; no shell. Every call gets Python's `_GIT_HARDEN` flags
(`-c core.fsmonitor= -c core.hooksPath=/dev/null -c core.pager=cat -c core.sshCommand=ssh -c protocol.ext.allow=never`),
stdin empty, and an environment **cleared** down to `PATH`, `TMPDIR` / `TEMP` / `TMP`, the proxy variables (`HTTPS_PROXY`,
`HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`, both cases), `SSL_CERT_FILE`, `SSL_CERT_DIR` and the Windows system variables,
plus `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` (`NUL` on Windows), `GIT_TERMINAL_PROMPT=0`, `LC_ALL=C`
(no `HOME`: no user-level git file is read). Each call is limited to `Caps::git_timeout` = 3 600 s (then killed,
`Command 'git <sub>' timed out after 3600 seconds`) and `Caps::git_output` = 64 MiB of standard output (`git <sub>:
output larger than ... bytes`); 64 KiB of standard error are kept for the message. A non-zero exit is Python's
`CalledProcessError` (the diff falls back, `git config` reads as "not this origin", anything else is `git failed:
<stderr>`); a timeout, a program that does not start or an output over the cap is `git failed: <text>` everywhere.

### Clone location

`Importer::new` receives only the mirror view, so the native importer cannot use the host's `data_dir` layout. It
takes the per-user cache directory as `secmonk/paths.cache_dir()` resolves it (`$SECMONK_CACHE`, else
`$XDG_CACHE_HOME/secmonk`, else `~/.cache/secmonk`; Windows `%LOCALAPPDATA%\secmonk\cache`; relative values ignored)
plus `cvelist-native` (`default_cache_dir`), so it never shares a working tree with a Python process. `py-sources`
keeps its clone in `<data_dir>/cache/secmonk/cvelistV5`. The two clones are separate: after a switch the first sync of
the other implementation clones again and walks every year, skipping records by `dateUpdated`. Without any of those
variables (no home directory) the git mode fails: `cvelist: native importer: no cache directory for the clone ...`.

## Memory (worst case, estimated)

Within the caps, a 64-bit build:

| Term | Bound |
|---|---|
| File list | path and shown text of every listed file, about 300 bytes each: 300 MiB at `Caps::files` = 1 000 000 (the real repository has about 420 000 records; two years are about 130 000) |
| Paths seen (git mode) | about 150 bytes per path: 150 MiB at 1 000 000 |
| Ids emitted | the id and its `dateUpdated` (about 100 bytes) per imported id: 100 MiB at 1 000 000 |
| A group of records | 8 MiB of text plus one round of 8 files of 4 MiB: 40 MiB of text, parsed into up to about 32 times that for records of only tiny values (1.3 GiB, pathological), about 5 to 10 times for real records |
| Rows of one record | at most 10 000 new rows (about 1.2 KiB each): 12 MiB |
| Stored rows of one group | `affected` rows of at most 50 ids, at most 10 000 each when the native importer wrote them: 500 000 rows, about 600 MiB, reached only if every record of a group has 10 000 rows; more only for rows `py-sources` wrote before a switch (read once, then those records are refused) |
| git output | 64 MiB (the changed-path list) plus 64 KiB of standard error |
| Batch | one batch: at most 5 000 operations and about 2 MiB of JSON |

The pathological sum is about 2.5 GiB; real records (2 to 35 KiB, a handful of rows) keep a run at a few hundred
MiB: see the volume measurement.

## Volume (measured)

Measured on 2026-11-12 on an Apple M2 (8 cores, 24 GiB RAM, macOS 26.5, internal SSD), test binary built with the
workspace's release profile with LTO off and 16 codegen units (`CARGO_PROFILE_RELEASE_LTO=false
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`). Input: a synthetic corpus in the repository layout, 100 000 records (224 MiB,
about 2.3 KiB each: two or three CNA `affected` entries of different shapes, a CVSS 3.1 metric, a CWE, references, a
CISA-ADP SSVC container, a `cpeApplicability` node on every third; 383 334 `affected` rows), generated at run time; the
second day has every third record newer with one changed range. `secmonk-engine/tests/native_cvelist.rs`
`cvelist_volume_*` (ignored), `--path` imports through the engine; the peak resident set is of the test process (the
Python child of `py-sources` not counted, the host's apply of its batches counted) and includes generating the
corpus. Sample: synthetic.

| Measurement | First sync | Unchanged re-sync | Re-sync, a third newer | `--full` re-sync | Peak resident set |
|---|---|---|---|---|---|
| **Native importer through the engine** (two runs) | **28.9 / 37.0 s** | **11.4 / 11.2 s** | **22.7 / 23.9 s** | **22.4 / 22.3 s** | 122 MiB (native only) |
| `py-sources` through the engine, same files | 148.8 s | 30.6 s | 132.4 s | 175.8 s | 1.9 GiB (both halves in one process, corpus generation included) |

The mirrors of both paths were equal at the end of the combined run (`assert_mirrors_equal`, all tables). An earlier
run of the same corpus, before the native importer read its files on several threads and skipped the `affected` read
for records that are not newer, measured native 41.6 / 30.9 / 45.9 / 37.2 s against `py-sources` 129.3 / 25.7 / 108.6
/ 171.2 s: the unchanged re-sync was then slower than Python, which is why both changes were made.

Reading: on this machine opening a small file costs about 240 µs whatever the language (20 000 files read by a
Python loop: 4.8 s; most of the time is system time), so a `--path` or clone walk of 100 000 files costs about 20 s
before any row work, for both versions. The native importer reads each group's files on 8 threads; the stored rows of
a group are read with two `rows_by_id` calls (the `affected` read only for records that may be imported). The native
stream alone (no engine, nothing applied) took 19.9 s on an empty mirror (4 000 `rows_by_id` reads, 0.3 s) and 19.7 s
over the imported corpus (2 000 reads, 3.3 s); applying the first sync's 246 batches with `MirrorStore::apply_rows`
took 19.2 s. Re-run: `cargo test --release -p secmonk-engine --test native_cvelist --no-run`, then
`SECMONK_REQUIRE_VENV=1 /usr/bin/time -l <binary> --ignored --exact cvelist_volume_sync --nocapture`
(`SECMONK_CVELIST_RECORDS` for the size, `SECMONK_CVELIST_NATIVE_ONLY=1` / `SECMONK_CVELIST_PY_ONLY=1` for one half;
`cvelist_volume_native_stream` for the importer alone). The git mode was not measured at this size: its record work is
the same walk; clone and fetch time are git's and the network's, the same for both versions.

## Default

`default_rust` stays `false` on 2026-11-12, although the differential test is green and the native path is not slower
at any step of the volume measurement. The reason is the [clone location](#clone-location): the importer cannot reach
the host's `data_dir`, so as the default it would keep a second clone (hundreds of MiB per year) in the per-user cache
of the Python version, outside the directory the desktop app owns and cleans. Once `Importer::new` receives the host's
cache directory (a shared change, see [plans/backlog](../plans/backlog.md)), the default can become `rust` with one line
in `cvelist.rs`.

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | per record `INSERT OR REPLACE`, `replace_children`, inserts | the same rows, in batches of 5 000 ops; `affected` rows that did not change are not rewritten (`affected.rowid_` differs, not compared) |
| Stream cut between batches | (py-sources batches too) | the applied records stay, `source_sync` and the internal rows show the previous run; the next sync converges (a git run without a new cursor diffs from the old one) |
| Clone | `SECMONK_CACHE/cvelistV5` (the module's data directory) | `<per-user cache>/cvelist-native`; a separate clone ([Clone location](#clone-location)) |
| git environment | the module's environment minus `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR`, `GIT_EXEC_PATH`, `GIT_EXTERNAL_DIFF`, `GIT_SSH(_COMMAND)`, `GIT_ASKPASS`, `GIT_PAGER`, `GIT_CONFIG_COUNT` / `_KEY_*` / `_VALUE_*`; the user's locale | cleared to the list above (no `HOME`, no `GIT_CONFIG_PARAMETERS`, `LC_ALL=C`); the differential test therefore redirects only Python's git with `GIT_CONFIG_PARAMETERS` |
| git diff | rename detection on (in a partial clone it may fetch blobs to detect renames) | `--no-renames`; the same existing files are imported (a renamed file's old path no longer exists) |
| git limits | 3 600 s per call, output unbounded | 3 600 s per call, 64 MiB of output; a timeout or an empty standard error reads `Command 'git <sub>' ...` (Python lists every argument) |
| Clone directory owner | `ensure_private_dir` refuses a directory owned by another user | not checked (mode and symlink are) |
| Files of the clone | read with symlinks followed | `read_within`: a path leaving the clone or a non-regular file is a record error |
| A year path that is a file | yielded as a record file | skipped |
| `ids == ["@referenced"]` | the ids from `alias` (`CVE-%`) and `kev` without a cvelist row, then raw requests | refused (status `error`): the mirror view reads rows of one named source, and the alias rows of every source would be needed (see [plans/backlog](../plans/backlog.md)) |
| Sizes and counts | unbounded | the caps above; a record over a cap is a record error, a walk over a cap fails the run (`error`) |
| A number or bool in a text column (`cveId`, `dateUpdated`, `datePublished`, `dateRejected`, `state`, the summary, `vectorString`) | stored as text by SQLite (`20260101` becomes `"20260101"`); a list or object fails the record | a record error (`cvelist: <id>: <field> is not a string`); a list or object fails the record in both |
| `NaN` / `Infinity` literals | read by `json.loads`; `py-sources` then cannot stream the row and its whole run fails (`result is not JSON: Out of range float values are not JSON compliant: nan`) | the file is invalid JSON: one record error |
| JSON nesting deeper than 128, integers beyond 64 bits | depth about 1 000; exact integers | refused / read as a float (as the other importers) |
| `--path` a FIFO or device | `ok`, 0 records (`rglob` of a non-directory yields nothing) | refused: `cvelist: not a regular file or a directory: '<path>'` |
| Relative `--path` | the module's working directory | the host process's working directory (the UI sends absolute paths) |
| Record error texts (job log only) | Python's exception texts | close imitations (`AttributeError: 'list' object has no attribute 'get'`, ...); not compared |
| `matchCriteriaId` equal to another match's JSON text; integer ids beyond 2^53 | the same `seen` key; exact integers | different keys (the dumped form has its own domain); compared as floats |
| Regular expressions | Python's `re` (Unicode `\s`, `\b`, case folding) | Rust's `regex`, with `\s` widened to `str.isspace` (`\x1c`-`\x1f`) and `$` matching before a final newline; `\b` and case folding follow Unicode tables that differ from Python's only for rare characters |

Equal by test: every mirror table (timestamps aside) after the steps below, and the entry `status`, `records` and
`message` of every step, the `git failed` message of an unreachable origin included.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/src/cvelist.rs` (unit) | `parse_version_expression` (the cases of `tests/sources/test_cvelist.py` and more); `convert_version_entry` (edge cases, `changes[]` inside bounds, Chrome, Log4Shell, the 4 300-digit limit); the generic comparator against values printed by `secmonk.engine.versions.compare` (Python 3.13); `cve_path`, `ecosystem_from_url` (hostname rules), `normalize_name`, `looks_like_commit`, the years, the cursor pattern; the rows of a record (severity, CWE, SSVC, packages, CPE rows of `test_review_fixes.py`); the record errors Python raises and the not-a-record cases; the per-record cap |
| `secmonk-sources/tests/cvelist.rs` | over `common::MemView`: the fixture directory (rows, re-run with nothing newer, `--full` with a limit, one file); updates, an id three times in one run (record-keyed deletes of stored and of emitted rows), record errors leaving the stored record as it was, non-records, invalid UTF-8, a directory named `CVE-x.json`; 1 203 records in groups and the progress lines; path errors (missing, FIFO, file cap, files cap, `limit` 0, `@referenced`); the ids mode against a local server (request lines, 404, 500, bad JSON, a non-CVE id, the limit before a request). Git mode against a local repository (skipped without git; required with `SECMONK_REQUIRE_VENV=1` or `SECMONK_REQUIRE_GIT=1`): first clone (cursor, years, 0700), unchanged, a commit with a record error (cursor held), the fix (diff over two commits), a file removed upstream, `--since` kept by the next plain sync, `--full` with a limit, a stored cursor `--output=...` never passed to git, an unknown commit (walk fallback); a foreign cache with a hostile `fsmonitor` (never run, re-cloned), a symlink out of the clone (refused), a symlinked cache directory, a missing git program, an unreachable origin |
| `secmonk-engine/tests/native_cvelist.rs` `native_cvelist_matches_py_sources` | **differential** (needs `rust/python/.venv` and git; `SECMONK_REQUIRE_VENV=1`): `py-sources` and the native cvelist on their own mirrors through the engine; all mirror tables and the entries equal after: the fixture directory, again, `--full` with a limit, one file; the variants with a limit and without, and `--full` (Log4Shell updated, Chrome rejected, a record of every version / package / CPE / ADP shape, one id in `a/`, `a-b/`, `a.b/` whose result depends on the component sort, 15 record errors, non-records, invalid UTF-8, a BOM, a directory named `CVE-x.json`); the git mode on a local repository (Python's git pointed at it with `GIT_CONFIG_PARAMETERS`, each `py-sources` with its own `SECMONK_CACHE`): first clone, unchanged, a commit with an update, a new record, a deleted file, a rejection and a record error, the fix, `--since`, a limit, the run after it, `--full`, an unreachable origin; a switch mirror py-sources -> native (log line, its own fresh clone) -> a native update -> a failed py-sources run (nothing applied) -> an ok py-sources run (repair; equal to its staging and, for the cvelist rows, to the Python-only mirror); last the documented differences (a number in a text column; a `NaN` literal) |
| `secmonk-engine/tests/native_cvelist.rs` `native_cvelist_batches_follow_the_row_contract` | every batch and end of the fixture directory, the variants, a git first sync, a missing path, a git rejection and a limited `--full` applied to a real store and validated against `source/rows.schema.json` and `source/sync-end.schema.json`; record-keyed `affected` deletes among them; the `cvelist:years` row read back |
| `secmonk-engine/tests/native_cvelist.rs` `cvelist_volume_*` | ignored, run by hand: the measurement above |

Fixtures: `tests/fixtures/sources/cvelist/` (real records fetched 2026-11-07, read only; provenance in the Python tree's
[reference](../../../_docs/references/vuln-sources/cvelist-v5.md), the directory has no README). The variants, the
local repositories and the volume corpus are written at test time (synthetic, nothing committed).

Unverified **(verify)**: the git mode against the real GitHub repository (clone size and time, `--filter=blob:none`
served by GitHub, the cleared environment with a proxy or a corporate CA), Windows (`NUL`, `SYSTEMROOT`, git for
Windows), the largest real record and `affected` count (the 4 MiB and 10 000 caps assume real records stay far below).
