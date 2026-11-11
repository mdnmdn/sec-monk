---
title: Engine service — construction, the 22 service methods, jobs, sync, scan
summary: How secmonk-engine is built from trait objects by secmonk-host, what each engine module does behind the 22 service methods, job and sync semantics, known error-path differences from Python.
read_when: you change secmonk-engine, wire a new dependency into the engine, debug a job or sync, or compare an engine answer with the Python server
type: tech
context: tech
status: implemented
tags: [engine, jobs, sync, scan, rust]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-engine/src/, rust/crates/secmonk-host/src/engine.rs]
related: [tech/architecture.md, tech/api-contract.md, tech/data-model.md, tech/contracts.md]
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
Option<Arc<dyn ModuleStatus>>` (`/api/meta` `engine.modules`). `SecmonkEngine::new(deps)` does no I/O and spawns
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
| `sync.rs` | `JobRunner._sync`, `ops.sync_source` | per source: `Source.sync` stream -> `MirrorStore.apply_rows` per batch -> `Source.ack(last seq)` after the stream ends -> one entry, or the **export repair** (below); then `checkpoint` |
| `opts.rs` | `parse_opts`, `_str_list`, `_opt_str` | option and body helpers |
| `service.rs`, `params.rs`, `error.rs`, `deps.rs` | `web/data.py` params, `ApiError` | the `EngineService` trait (22 methods), typed query params, `EngineError` / `ErrorKind` with the wire code and `reason`, `EngineDeps` / `EngineConfig` |
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
and repaired sources. One failing source never stops the others; the job status is
`ops.sync_status` of the entries. `seconds` of an entry is the host's time for the source (download, staging and
apply), where Python measured the source alone.

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
acknowledged, a second sync, `sources` read by py-engine, a persisted match written by the host.

