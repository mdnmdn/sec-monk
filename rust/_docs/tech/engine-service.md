---
title: Engine service — construction, the 22 service methods, jobs, sync, scan
summary: How secmonk-engine is built from trait objects by secmonk-host, what each engine module does behind the 22 service methods, job and sync semantics, the in-process node services (LocalNode, NodeMatcher, versions and re-match after a sync), known error-path differences from Python.
read_when: you change secmonk-engine, wire a new dependency into the engine, debug a job or sync, serve or consume match/vulninfo/feed in process, or compare an engine answer with the Python server
type: tech
context: tech
status: implemented
tags: [engine, jobs, sync, scan, rust]
updated: 2026-11-13
verified: 2026-11-13
code: [rust/crates/secmonk-engine/src/, rust/crates/secmonk-host/src/engine.rs, rust/crates/secmonk-sources/src/]
related: [plans/node-server-design.md, ../../_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md, tech/architecture.md, tech/api-contract.md, tech/data-model.md, tech/contracts.md, tech/source-kev.md, tech/source-epss.md, decisions/0011-native-sources.md, tech/source-euvd.md, decisions/0012-native-importer-row-reads-and-registry.md]
---

# Engine service

Split from [architecture](architecture.md) on 2026-11-11 to keep both pages short. The engine gets **trait objects
only** ([architecture §2](architecture.md#crate-apis)); the composition root is
[`secmonk-host`](architecture.md#3-composition-secmonk-host-and-the-desktop-app).

## Construction

The contract between the engine and the composition root (`secmonk-host/src/engine.rs` builds it). The engine's
library code never names `secmonk-modhost` or `secmonk-runtime`.

`EngineConfig` (`secmonk-engine/src/deps.rs`): `version`, `data_dir`, `state_db` (path of `db` in `/api/meta` and of
`no-db` messages), `min_confidence` (0.5), `snapshot_mode` (`[ui] snapshot` set: `/api/meta` `mode = "snapshot"`),
`nvd_api_key_env` (read when a sync starts and passed as a call secret, never stored), `allow_actions` (defence in
depth; the API's gate answers 403 first). `EngineDeps` holds the config and the trait objects: `state:
Arc<dyn StateStore>`, `mirror: Arc<dyn MirrorStore>` (`SqliteStore` implements both), `steps: Arc<dyn EngineSteps>`
(`PyEngine` over `py-engine`), `procmon: Option<Arc<dyn Reporter>>` (`py-procmon`; `None` answers
`unsupported-platform`), `sources: Vec<Arc<dyn Source>>`, `probe: Arc<dyn Probe>` (`ProbeService`), `modules:
Option<Arc<dyn ModuleStatus>>` (`/api/meta` `engine.modules`), `node_store: Option<Arc<dyn MirrorNodeStore>>`
(`SqliteStore::mirror_node_store()`; with it a sync job records source versions and re-matches affected assets,
[node services](#node-services); `None` keeps the engine as before). `SecmonkEngine::new(deps)` does no I/O and spawns
nothing (jobs are `tokio::spawn`ed when they start); `shutdown()` first sets a **closing** flag (under the live-jobs
lock: from then on `job_start`, `assets/match` and `processes/save` answer 503 `module-unavailable` "sec-monk is shutting
down", the shape of the host gate's stopping state; a start already inserting its row closes that row as `error` /
`interrupted` and answers the same), then aborts the running job and stores it as `error` / `interrupted`; the first job or history read marks runs of dead processes `interrupted`
(`StateStore::job_mark_interrupted`, as `JobRunner.__init__`).

`secmonk_host::engine::build` fills `EngineConfig` from the `Config` and refuses to build without `py-engine`
(`HostError::Unsupported`: "py-engine is not enabled: list it in [modules] enabled"). `EngineError` carries
`reason: Option<String>` (the module's `data.reason`, e.g. `kubectl-missing`), so the API does not parse hints.

## The service

What `SecmonkEngine` does behind the 22 `EngineService` methods (`secmonk-engine/src/`):

| Module | Port of | Role |
|---|---|---|
| `engine.rs` | `web/data.py`, `JobRunner` | the routes: reads go to `Reporter` (`reports.*`, `procmon.*` on py-engine / py-procmon) after the `no-db` check (`StateStore` or `MirrorStore` initialized); probe routes go to `Probe.call`; the job runner; persisted match + `replace_findings`, re-run once on `stale` |
| `prepare.rs` | `_prepare_sync`, `_prepare_scan`, `_prepare_batch`, `ops.scan_item` | validation of `POST /api/jobs` bodies with Python's messages; redacted params and titles |
| `jobs.rs` | `web/jobs.Job` | live jobs: one at a time, last 20 kept in memory; log lines without control characters, URL secrets scrubbed, at most 500 chars |
| `payload.rs` | `ops.scan_result`, `sync_status`, `stored_result`, `reports.job_payload`, `job_summary` | job payloads and stored results (findings capped at 500 per target) |
| `scan.rs` | `ops.scan_items`, `scan_target`, `_reuse_image` | expand -> reuse rule or collect -> classify -> sanitize -> save -> match ([architecture §7](architecture.md#7-data-flow-of-a-scan-job)) |
| `sync.rs` | `JobRunner._sync`, `ops.sync_source` | per source: `Source.sync` stream -> `MirrorStore.apply_rows` per batch -> `Source.ack(last seq)` after the stream ends -> one entry, or the **export repair** (below); a **native** source takes `sync_native` (below); then `checkpoint` |
| `view.rs` | (new) | `StoreMirrorView`: the read-only `MirrorView` of native importers over `MirrorStore` (`applied_state`, `count_rows`, `row_keys`, `rows_by_id`, `rows_page`; id and page limits checked) |
| `opts.rs` | `parse_opts`, `_str_list`, `_opt_str` | option and body helpers |
| `service.rs`, `params.rs`, `error.rs`, `deps.rs` | `web/data.py` params, `ApiError` | the `EngineService` trait (22 methods), typed query params, `EngineError` / `ErrorKind` with the wire code and `reason`, `EngineDeps` / `EngineConfig` |
| `node/` | (new) | the [node services](#node-services): `keys.rs` (`component_lookup_keys`), `local.rs` (`LocalNode`), `matcher.rs` (`NodeMatcher`), `sync_hooks.rs` (versions and re-match after a sync) |
| `skeleton.rs` | (new) | `SkeletonEngine`: the wave-2 stand-in (`no-db` reads, 501 `not-implemented`), kept for the API's HTTP tests and the gate's tests; the `Gate` takes only `FEATURES` and `current_platform` from it. The real engine never answers 501 |

Jobs: `job_start` validates, refuses a second job (`busy`; the `starting` flag that covers the row insert is held by a
drop guard, so an error or a dropped request future never leaves the engine busy), records the run (`StateStore::job_insert`), then spawns the
work as a tokio task; a second task stores the outcome (`job_finish`: redacted params, capped result, summary,
scrubbed log) whatever happens, including a panic or `shutdown` (`error` / `interrupted`). Writes outside jobs
(re-match, process save) answer `busy` while a job runs.

Sync specifics: the NVD key is read from `nvd_api_key_env` when the job starts and passed as a call secret to every
source (as Python passes `api_key` to all of them); progress frames go to the job log. A batch whose `source` is not
the synced source, a `seq` that does not increase, or an `end` whose `batches` / `last_seq` disagree with what was
received fail that source (`ProtocolError: ...`). Batches applied before a failure are still acknowledged. The ack
comes after the stream because `py-sources` serves one request at a time (`max_inflight = 1`); a host stop before
the ack replays those batches at the next sync, and the store skips them by `seq`
([data model](data-model.md#store-traits)).

**Repair (W4.4).** Batches carry the staging `generation` and the module's `acked_through`; the store refuses to compare a
batch of another generation (staging recreated) or one whose `acked_through` exceeds the applied seq (mirror reset or
restored) and answers `needs_repair`. A stream with no batch on a mirror with no applied state for the source is treated
the same (a first sync then repairs from an empty export). The engine then drains the rest of the stream unapplied
and calls `Source.export`: `MirrorStore::begin_repair` deletes the source's rows (`source_sync` `<source>:*` cursors
included) and applies the export in **one** transaction, committed with the export's `high_water` and `generation`;
then `Source.ack(high_water)`. A failed export rolls back (nothing acknowledged; the next sync decides again). The job
log says why, how many batches were not applied, rows removed and written, and a closing line counts skipped replays
and repaired sources.

**Native importers** ([rust ADR-0011](../decisions/0011-native-sources.md), `Source::native()`, today `kev` and `epss`
from `secmonk-sources`, see [source-kev](source-kev.md) and [source-epss](source-epss.md)). The native importer
computed its batches against the mirror through `StoreMirrorView`, under the generation `native-rust`; it builds them
while the engine reads the stream (one batch in memory at a time). **Switch from `py-sources` to the native importer:**
`sync_native` first resets an applied state of another generation (`reset_applied_seq`; job log `<source>: native
importer: applied state of generation <g> (seq N) reset; full sync against the mirror`), then applies the stream as
above. There is no ack and no export repair: a batch the store skips (`native importer: N batch(es) skipped by the
mirror store …; run the sync again`) or answers `needs_repair` for (`native importer: batch refused by the mirror store
(…); run the sync again`) fails the source, and the next sync, computed against the mirror as it is, is the repair.
**Switch back to `py-sources`:** its batches carry the staging generation, so the store answers `needs_repair`; when the
run's entry is `ok` the engine runs the export repair above (job log `<source>: repair from py-sources export: the last
applied batches came from the native importer`). When it is not ok (`error` or `partial`), the staging export is older
than the mirror: the engine drains the stream, applies and acknowledges nothing, keeps the native applied state and
reports the source as `error` with records 0 and the message `<status>: <message>; not applied: mirror keeps the native
importer data until a successful py-sources sync`; the next ok run repairs.

One failing source never stops the others; the job status is
`ops.sync_status` of the entries. `seconds` of an entry is the host's time for the source (download, staging and
apply), where Python measured the source alone.

## Node services

Module `secmonk_engine::node` (public), the in-process side of the mirror nodes
([proposal](../../../_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md) §3-4, [brief](../plans/node-server-design.md)
§6; types `secmonk_model::node`, traits `secmonk_traits::node`, storage [data model](data-model.md#node-versions)).

| Item | What it does |
|---|---|
| `component_lookup_keys(&ComponentIdentity) -> Vec<String>` | Port of the candidate derivation of `engine/match.py` (+ `purl.py`, `classify.normalize_product_name`): a **superset** of the `affected` rows the matcher reads. Package route (an ecosystem and `library` / `os-package` / `runtime`): `pkg:<eco>/<name>` for the `normalize_name` name, the plain name, the purl's OSV name (`group:artifact`, `@scope/name`), the purl name, `meta.source_package`, `meta.brew_name`. Product route (everything else): `prod:<candidate>` for `meta.product`, `product_alts`, `brew_name` without `@N`, the normalized name (vendors ignored). An ecosystem known only from the purl gives both families. Every key is lowercase (`pkg_key` / `prod_key`, also used by the mirror's `lookup_keys_for_vulns`). |
| `KEYS_VERSION` (`u32`, 1) | The version of `component_lookup_keys`, part of the matcher version: **bump it with any change to `component_lookup_keys`**. Golden: `rust/golden/node/lookup-keys.expected.json` (recorded by `rust/python/scripts/lookup_keys_golden.py` from the Python matcher's own candidate functions on classified components); the `keys` unit test asserts a superset for every component. |
| `matcher_version()` / `default_importer_module()` / `secmonk_version()` | The versions of this build: `py-engine/<secmonk version>+keys/<KEYS_VERSION>` and `python/<secmonk version>`. The `py-engine` hello carries only the module wrapper's version and the engine never sees it, so the `secmonk` package version is read **at build time** from the root `pyproject.toml` (`include_str!`; a change rebuilds). A release of the Python matcher bumps that version and with it every client's cache. |
| `LocalNode::new(Arc<dyn MirrorNodeStore>, Arc<dyn Matcher>, Arc<dyn Reporter>, LocalNodeSettings {node_id, overlap_s, matcher_version, max_concurrent_matches, match_wait})` | `MatchService`, `VulnInfo`, `Feed` of a node with a mirror. `matcher_version` defaults to `matcher_version()`; at most `max_concurrent_matches` (`DEFAULT_MATCH_CONCURRENCY`, 4) `match.components` calls run at once (a semaphore); a call that waits longer than `match_wait` (`MATCH_PERMIT_WAIT`, 2 s) answers `busy` (HTTP 409 by the wire table). |
| `NodeMatcher::new(Arc<dyn MatchService>, Arc<dyn VulnInfo>, Arc<dyn NodeCacheStore>, Arc<dyn VersionOracle>, Arc<dyn StateStore>)` `.with_local_version(v)` | `Matcher` of a state-only node; `poll_changes() -> StepResult<PollStats {hit_keys, changed_ids, resynced, invalidated, summaries, as_of}>`. Its own matcher version (default `matcher_version()`) is saved with the cache (`match.local`). |
| `ChangeSummary::of(&sources)`, `affected_components(&ChangeSummary, components, with_changed_ids)`, `family` / `in_family` | **One** "what changed -> which components" rule for both consumers (the re-match after a sync and `NodeMatcher::poll_changes`): a component is affected when a lookup key is a changed key, it has a match on a changed id, or a resynced source's family covers its keys (`kev` / `epss` cover none: enrichment). |
| `CachedVulnInfo::new(Arc<dyn NodeCacheStore>, Arc<dyn VulnInfo>)` | `VulnInfo` of a state-only node: summaries from `vuln_summary`, misses asked of the service (chunks of 500, only the asked ids cached), `detail` / `search` passed through uncached. Not wired yet (see [ADR-0013 status note](../decisions/0013-mirror-nodes-and-source-versions.md)). |
| `MAX_VIEW_LIMIT` (5 000) | `view_limit` bound shared by `LocalNode` (per ephemeral match) and `NodeMatcher` (refuses more). |

**`match.components` from an ephemeral match.** At most `MAX_COMPONENTS`; distinct keys go into one synthetic
inventory (asset `node:match-components`, the components rebuilt from their identity) matched by the engine's
`Matcher` in **ephemeral** mode with `view_limit` `MAX_VIEW_LIMIT` (5 000) and the request's `min_confidence` (default 0: all). The view
rows (`reports.finding_dict`) carry the component's name, version, category and purl, not its key: components that
these four cannot tell apart (keys that differ by vendor only) go into separate rounds, and a chunk whose
`stats.findings` exceeds its view is split in two and matched again, so every finding comes back. Rows are regrouped
per component into `ComponentMatch`es; every requested component gets a `ComponentResult` (empty matches allowed,
duplicates answered again) with `lookup_keys = component_lookup_keys`; `as_of` = the current versions, `coverage` =
sources with a version + `covered_ecosystems`.

**`match.changes`.** A request matcher other than the node's: every source `resync("matcher")`. Per source of the mirror:
no version on either side `unchanged`; the client has none `resync("new source")`; the node has none `resync("no
version")`; another importer `resync("importer")`; the same version `unchanged`; a record source: `changed_vulns` of the
base source (`osv:PyPI` reads `osv`, a superset) since the client's version minus the overlap, more than 20 000
`resync("too many changes")`, else the ids and `lookup_keys_for_vulns`; a snapshot source: `snapshot_diffs_since`
(`None` `resync("no diff log")`, a diff marked unknown `resync("no diff for this version")`, else the union). A source
the client names that the node no longer has: `resync("source removed")`. `summaries` caps at `MAX_IDS` and lists
`missing`; `detail` / `search` are `reports.vuln_detail` / `reports.vuln_search` (the `/api/vulns/show` and
`/api/vulns/search` payloads; an unknown id is `unknown-vuln`). **Feed**: `status` = versions + node id; `since` of a
record source is always mode **delta**: from `since` minus the overlap when `since` is a plain version or a
`"<importer>@<version>"` token of this node's importer, else every record (`rows_since(None)`, still replace units: a
follower refuses a snapshot page of a record source); a snapshot source is always `rows_snapshot` (each page one read
transaction, pinned to the version of the first page: a cursor of another version answers `stale`); `limit` defaults to 2 000, at most 10 000 (the store clamps further: 500
records, 5 000 rows per page); a base source without its own entry (`osv`) is served at the oldest version of its
qualified entries.

**Versions after a sync.** `Source::importer_version(source)` (defaulted, `None`) names the importer; else
`default_importer_module()` (`python/<secmonk version>`) for a module source, `rust/1` for a native one. After an `ok` run the engine records, for the source and each
qualified row (`osv:PyPI`) whose `source_sync` status is `ok` and has a cursor, `record_complete_version(name, cursor,
importer, VersionKind::default_for(name))`; `partial` and `error` runs record nothing. A snapshot source whose version
moved also stores a `SnapshotDiff` from the version before the job: `kev` and `debian-tracker` hash every row before and
after the run (`MirrorStore::rows_page`, only the previous hashes kept) and record the changed CVE ids (plus
`pkg:<ecosystem>/<package>` keys for `debian-tracker`); `epss` (nearly every row changes daily) and a table above
300 000 rows record a diff whose only key is `*` (`DIFF_UNKNOWN_KEY`), which `match.changes` answers with `resync`.

**Re-match after a sync** (proposal P0). The job snapshots the versions at its start; after the last source it asks
`LocalNode::changes(before)` and selects the assets with `affected_components` (this node is the match service, so a
component's keys are `component_lookup_keys`): a current component whose keys meet a changed key or that a resynced
source's family covers (`osv:PyPI` re-matches the assets with PyPI components, `nvd` every asset), or a finding (any
status, canonical or advisory id) on a changed id. A `resync` of `kev` / `epss` is **enrichment**: no match set
changes, but a finding's KEV, EPSS and priority are read from the mirror at match time, so only the assets that have
open or suppressed findings are matched again, not every asset. Matched again = persisted, the `assets/match` path. The job log says how many; a failure is a
warning, never a failed sync. The state reads are defaulted `StateStore` methods (`asset_ids`, `current_components`,
`asset_findings`, `assets_with_findings_on`; `SqliteStore` implements them, another store answers `invalid-params`
and the step is skipped with a warning).

**`NodeMatcher`.** Per match: `poll_changes` first, then the asset's components (persisted: `current_components` with
their state ids; ephemeral: the inventory, ids 1..n) -> identities -> keys; `match_components` (min_confidence none)
only for keys without a current cached answer; the cached sets; summaries from `cached_summaries`, misses fetched with
`VulnInfo::summaries` and cached; findings with severity, CVSS, EPSS and KEV from the canonical id's summary and
`priority` from `VersionOracle::priority` with the asset's `meta` (one call per distinct fact tuple); `min_confidence`
applied per match. Persisted mode returns the complete `finding_set` (re-detected findings keep `first_seen` and
`suppressed`, open ones not re-detected become `fixed`) and `based_on.latest_scan_id`, which `replace_findings` accepts;
the `view` is the open rows in `queries.findings` order. **Freshness**: answers are stamped `"<matcher>#<epoch>"`;
`poll_changes` re-asks the stored-inventory components hit by changed keys or ids, invalidates hit keys that are not in
the inventory, and on a `resync` raises the epoch and records it for the source; an answer is current when its matcher
is the service's and no source whose family covers the component (`osv:<Eco>` -> `pkg:<eco>/…`, `debian-tracker` ->
`pkg:debian…`, `kev` / `epss` -> none, others -> all) was resynced after its epoch. A component's keys are the
**stored** ones (`component_lookup`, as the service returned them, `NodeCacheStore::stored_lookup_keys`), else
`component_lookup_keys` (a component never answered): one truth, the server's. A matcher change (the service's, or this
node's own `match.local`), or the first poll, starts a new epoch. `kev` / `epss` resyncs refresh the summaries of every
matched id. **One poll at a time** (a `tokio::sync::Mutex`); the epoch, the resync map, the versions and the local
matcher version are saved together in one transaction (`node_sync_set_many`) **after** every call to the service
succeeded: a poll that fails half-way leaves them as they were, and the next poll asks the same changes again.

Differences from py-engine's persisted match (state-only node): facts come from the merged summary of the canonical
id, not from `_vuln_facts` over the alias set; no re-keying of findings whose canonical id drifted (`_rekey`);
`min_confidence` applies to the merged match, not to each raw match; `stats` has no `withdrawn` / `patched` /
`not_affected` counts (the match service already dropped them).

Known differences from the Python server (all on error paths):

- a failed history insert at job start answers 500 (Python: 503);
- the engine's own disabled-actions refusal is 400 (Python: 403); the API's 403 gate answers first, so the browser
  sees 403 as before;
- a scan with `save: false` and no database answers 409 with code `busy`: the status and message are Python's, the
  code is new.

Tests: `tests/engine.rs` runs the engine over a real SQLite store and fake steps, sources and probe, and validates
the payloads the engine builds (meta, sources, collectors, jobs, match result) against `rust/contracts` with the dev
venv's `jsonschema` (skipped without `rust/python/.venv`). `tests/real_modules.rs` starts the real `py-sources` and
`py-engine` from `rust/python/.venv` (skipped without it): a `kev` sync from the repo fixture applied and
acknowledged, a second sync, `sources` read by py-engine, a persisted match written by the host; the repair scenarios of
W4.4. The differential tests of the native importers against `py-sources` are one file each,
`tests/native_<source>.rs` (`native_kev.rs`, `native_epss.rs` with the ignored `epss_volume_*` measurements,
`native_euvd.rs` with its row-contract check; [source-kev](source-kev.md#tests), [source-epss](source-epss.md#tests),
[source-euvd](source-euvd.md#tests)), on the shared harness `tests/common/` (`Diff`, mirror comparisons,
`check_row_contract`).
`tests/engine.rs` `native_kev_*`, `native_epss_*` and
`a_failed_or_limited_python_run_after_native_syncs_never_rolls_the_mirror_back` drive the native sources over the
real store without Python. The venv-gated tests skip without `rust/python/.venv`; with `SECMONK_REQUIRE_VENV=1` in the
environment a missing venv or fixture fails them instead (CI and release checks:
`SECMONK_REQUIRE_VENV=1 cargo test --workspace`).

