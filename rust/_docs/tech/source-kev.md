---
title: Source kev — the native (Rust) CISA KEV source
summary: The Rust kev source in secmonk-sources - feed loading (official URL, GitHub mirror, --path, size cap), rows emitted, snapshot guard, limit, seq/generation, selection, differences from Python, differential test.
read_when: you change the Rust kev source, switch kev between Rust and Python, debug a kev sync in the desktop app, or port the next source to Rust using kev as the example
type: tech
context: tech
status: implemented
tags: [vuln-source, kev, rust, sync]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-sources/src/, rust/crates/secmonk-engine/src/sync.rs, rust/crates/secmonk-engine/src/view.rs, rust/crates/secmonk-host/src/engine.rs]
fixtures: [tests/fixtures/sources/kev/]
related: [tech/source-epss.md, decisions/0011-native-sources.md, decisions/0010-source-staging-adapter.md, tech/contracts.md, tech/engine-service.md, tech/configuration.md, tech/component-lifecycle.md, tech/source-euvd.md, decisions/0012-native-importer-row-reads-and-registry.md]
---

# Source kev (native importer)

The first source ported to Rust (stage 6 of the [standard process](component-lifecycle.md#6-later-the-rust-port)).
`secmonk_sources::kev::KevSource` implements `Source` in-process and emits the same `secmonk-mirror-rows/1` batches as
`py-sources`, computed against the mirror through a read-only `MirrorView` instead of a staging copy
([rust ADR-0011](../decisions/0011-native-sources.md)). The feed itself is described in the Python tree's
[KEV reference](../../../_docs/references/vuln-sources/kev.md); the reference implementation is
`src/secmonk/sources/kev.py` `KevSource.sync` plus `ops.sync_source` / `db.set_sync_state`.

Shared with the other native importers ([epss](source-epss.md), [euvd](source-euvd.md)) in `secmonk-sources`:
`feed.rs` (downloads with a size cap, `open_regular` / `read_bytes` for local files, Python-style `OSError` text),
`batch.rs` (`Cutter`: operations cut into batches as they come; `cut` for a list), `native.rs` (crate-private: the
run's `Outcome` with its operations as an async stream, `iter_ops` for a list, the `source_sync` row of
`set_sync_state`, the first seq, the lazy stream of batches and end, the `limit` / name / export checks), `py.rs` and
`rows.rs` (Python semantics and the `base.py` row builders, [rust ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)),
the registry `IMPORTERS` in `lib.rs` (kev's `IMPORTER` in `kev.rs`), and `tests/common` (stream runner, local HTTP
servers, `MemView`).

## Selection

`[sources.implementation] kev = "rust"` (the default since 2026-11-11) or `"python"` in `sec-monk.toml`
([configuration](configuration.md#schema)); the default is `IMPORTER.default_rust` in `kev.rs`. With `rust` the host
builds `KevSource` over `StoreMirrorView` and lists it ahead of `py-sources` (`secmonk-host/src/engine.rs`
`native_sources`, over `secmonk_sources::IMPORTERS`); `/api/sources` and `sync all` see one `kev`.
With `python`, `py-sources` syncs kev as before. A name in `[sources.implementation]` that cannot be served as written
(a typo such as `kve`) refuses the start. After a switch back to `python`, only an ok `py-sources`
run repairs kev from the staging export; a failed or limited run leaves the mirror rows of the native importer unchanged.

## One sync

| Step | Behaviour |
|---|---|
| Load | `options.path` (non-empty): the local file (a regular file only, symlinks followed: a directory answers `[Errno 21] Is a directory: '<path>'`, a FIFO or device `not a regular file: '<path>'` before it is opened), at most `MAX_FEED_BYTES` (32 MiB), origin `from file <path>` (the path as Python's `str(Path)`). Else the official CISA URL, then the `cisagov/kev-data` GitHub mirror on any error (progress line `kev: official feed failed (<error>); trying mirror`). Downloads: workspace `reqwest` (rustls), `https_only`, connect and read timeout 60 s, `Content-Length` and the streamed size checked against the cap (a body without `Content-Length`, chunked or ended by the connection, is cut at the cap; an understated `Content-Length` is read only up to its value), proxies from the environment. |
| Parse | JSON (`serde_json`, nesting bounded); `vulnerabilities` must be an array of objects with a non-empty string `cveID`; mapped fields must be strings or null. `count` other than the number of entries only logs `kev: feed count N != M entries; using entries`. |
| Limit | `options.limit` (>= 1; 0 is `invalid-params`): the first N entries, upserts only, no deletes, status `partial`, cursor kept. |
| Guard | Without `limit` and `full`: an empty snapshot, or one under half of the stored `kev` rows (`MirrorView::count_rows`), is refused with Python's message (`kev: refusing to replace 30 rows with a snapshot of only 9 (< 50%; use --full to force)`); the rule is `native::snapshot_guard`, shared with debian-tracker. |
| Rows | In order: a `kev` delete for every stored key (`MirrorView::row_keys`) not in the snapshot (not with `limit`); per entry a `raw_record` upsert (`modified` = `dateAdded`, `fetched_at` = now, `data` = the entry) and a `kev` upsert (all nine columns; `ransomware` `"1"` when `knownRansomwareCampaignUse` is `Known` else `"0"`; `extra` = the unmapped fields in feed order); last the `source_sync` upsert. |
| `source_sync` | ok / partial: `last_sync` = now, `cursor` = `catalogVersion` only when set (Python's `COALESCE`), `records`, `status`, `message` (`9 entries from file …`). error: only `status` and `message`, so the last good totals stay (as `set_sync_state`). Messages pass `scrub_text`. |
| Batches | At most 5 000 ops and about 2 MiB of JSON each, cut while the engine reads the stream (`native::stream`); `generation = "native-rust"`, no `acked_through`; seqs continue the applied seq of that generation, else from 1. |

The engine applies the batches like any source's; a native stream is never acknowledged nor repaired from an export.
The next sync is the repair: it is computed against the mirror as it is (a cut stream, a reset or restored mirror).
A stream cut between batches leaves the deletes and part of the upserts applied while `source_sync`, the last op, still
shows the previous ok run (status, cursor, records); the next sync converges.
Switch from `py-sources` to the native importer: before the first native sync of a mirror that `py-sources` wrote, the
engine resets the applied state (job log `kev: native importer: applied state of generation <g> (seq N) reset; full
sync against the mirror`). Switch back to `py-sources`: its first ok sync repairs kev from the staging export (job log
`kev: repair from py-sources export: the last applied batches came from the native importer`); a run that is not ok
applies nothing (`<status>: <message>; not applied: mirror keeps the native importer data until a successful
py-sources sync`) ([engine-service](engine-service.md)).

## Differences from the Python source

| Case | Python (`py-sources`) | Rust |
|---|---|---|
| Mirror after a sync | `DELETE FROM kev` + `INSERT OR REPLACE` per entry | deletes only the CVEs that left + upserts: same rows |
| Raw records of CVEs that left the feed | kept | kept (same); not restored after a mirror reset (staging would restore them) |
| Invalid JSON, download errors | `json.loads` / `httpx` wording | `invalid JSON: …` / `HTTP 500 for <url>` / reqwest wording; same `error` status |
| Mapped field not a string | numbers stored as text; arrays fail with a `sqlite3` error | the sync fails: `kev: <cve>: <field> is not a string` |
| Entry not an object, `vulnerabilities` not a list | `TypeError: …` / `AttributeError: …` | `kev: an entry is not an object` / `kev: 'vulnerabilities' is not a list` |
| `cveID` null or `""` | stored as a row with that key | the sync fails: `kev: cveID is not a non-empty string` |
| `count` `9.0` for 9 entries | no mismatch logged (`9.0 == 9`) | `kev: feed count 9.0 != 9 entries; using entries` logged (the sync is the same) |
| `--path` a FIFO or device | blocks reading it | refused: `not a regular file: '<path>'` |
| Feed size | unbounded | 32 MiB |
| Relative `--path` | the module's working directory (`<data_dir>/tmp`) | the host process's working directory (the UI sends absolute paths) |
| `fetched_at` | one timestamp per entry | one per sync |

Equal by test: missing `vulnerabilities` / `cveID` (`'vulnerabilities'`, `'cveID'`), unreadable files
(`[Errno 21] Is a directory: '<path>'`), the guard messages, the ok message, entry `status` / `records`.

## Tests

| Test | What |
|---|---|
| `secmonk-sources/tests/kev.rs` | rows of the fixture, deletes, seq continuation within the native generation and restart after another generation, guard, `limit`, `full`, error entries, the official-to-mirror fallback and the size cap against a local HTTP server (never the network); `the_size_cap_holds_without_a_trustworthy_content_length` (no `Content-Length`, chunked, understated and overstated `Content-Length`) |
| `secmonk-sources/src/{batch,feed}.rs` | batch limits (`Cutter`, `cut`); Python-style paths and `OSError` messages; file cap; `a_fifo_is_refused_without_blocking` |
| `secmonk-engine/tests/engine.rs` | through the engine on a real store: `native_kev_*` (sync, no-op, update, guard, full; reset of an applied state of the py-sources staging generation; a stream cut after two batches converges on the next sync); `a_native_batch_the_store_skips_is_an_error`; `a_failed_or_limited_python_run_after_native_syncs_never_rolls_the_mirror_back`; `native_kev_batches_follow_the_row_contract` (every batch and end of a sync, an update with deletes, a limited and a failed run, validated against `source/rows.schema.json` and `source/sync-end.schema.json` with the dev venv's `jsonschema`) |
| `secmonk-engine/tests/native_kev.rs` `native_kev_matches_py_sources` (harness `tests/common/`) | **differential** (needs `rust/python/.venv`): `py-sources` and the Rust source, each on its own mirror, through the engine; all eight mirror tables equal (timestamps `raw_record.fetched_at` and `source_sync.last_sync` aside) after: first sync, no-op, update (removed, changed, added entries), limit, guard refusal, unreadable file, invalid JSON (message aside), full; a switch from py-sources to the native importer and back to py-sources on a third mirror (equal to the Python-only mirror, then to its staging after the export repair); a reset mirror rebuilt by the next native sync (`kev`, `source_sync`); a failed and a limited Python run after the Rust one leave the mirror and the native applied state unchanged; the stored text of `kev.extra` is equal in both mirrors and keeps the feed's key order. Run with `SECMONK_REQUIRE_VENV=1` so a missing venv fails instead of skipping |
| `secmonk-host/src/engine.rs` | the configuration selects the native importer; `rust` without an implementation, `python` with no module serving the name, and a misspelled name refuse the start |

Fixture: `tests/fixtures/sources/kev/known_exploited_vulnerabilities.json` (9 entries, read only); the update, small and
invalid variants are written at test time.
