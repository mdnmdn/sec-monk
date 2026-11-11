---
title: Contracts — module protocol, manifest, inventory, source rows, engine calls, process snapshot
summary: secmonk-wire/1, module manifest, inventory and where classify sits, source row stream, engine calls with read-only DB access, process snapshot, with schema and example paths.
read_when: you implement either side of the module protocol, write a Python module or its Rust port, add a method, or change a payload that crosses the host/module boundary
type: tech
context: tech
status: implemented
tags: [contracts, protocol, modules, python, rust, json-schema]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/crates/secmonk-proto/src/, rust/crates/secmonk-modhost/src/, rust/python/src/secmonk_modules/wire.py]
fixtures: rust/contracts/examples/
related: [tech/architecture.md, tech/api-contract.md, tech/data-model.md, tech/component-lifecycle.md, decisions/0003-module-protocol-json-framed.md, decisions/0006-python-read-only-db-access.md, decisions/0010-source-staging-adapter.md]
---

# Contracts

Every contract is a JSON Schema (draft 2020-12) under [`rust/contracts/schemas/`](../../contracts/schemas/), with
examples under [`rust/contracts/examples/`](../../contracts/examples/) and two catalogs: the module methods
([`catalog/module-methods.json`](../../contracts/catalog/module-methods.json)) and the API routes
([`catalog/api-routes.json`](../../contracts/catalog/api-routes.json)). Each method and route is declared once there
(name, params, result, effect, the Python function it wraps today). How to validate:
[contracts README](../../contracts/README.md). The engine↔ui API is in [api-contract](api-contract.md).

| Contract | Version string | Schema |
|---|---|---|
| (a) Module protocol | `secmonk-wire/1.0` | `wire/envelope.schema.json`, `wire/notify-log.schema.json` |
| (b) Module manifest | `secmonk-module/1` | `module/manifest.schema.json` |
| (c) Inventory | `secmonk-inventory/1` | `inventory/*.schema.json` |
| (d) Source row stream | `secmonk-mirror-rows/1` | `source/*.schema.json` |
| (e) Engine-module calls | catalog | `engine/*.schema.json`, `probe/docker.schema.json` |
| (f) Engine↔ui API | `secmonk-api-routes/1` | `api/*.schema.json` ([api-contract](api-contract.md)) |
| (g) Process snapshot | `secmonk-process-snapshot/1` (existing) | `process/snapshot-1.schema.json` |

## (a) Module protocol: secmonk-wire/1

The envelope of the proposal (§4.2–4.3), unchanged in substance. Rationale: [rust ADR-0003](../decisions/0003-module-protocol-json-framed.md).

**Framing.** A frame is a 4-byte big-endian unsigned length followed by that many bytes of one UTF-8 JSON object.
Length ≤ `max_frame`: hard cap 64 MiB (the cap the W1.2 spike ran with), default 16 MiB, each side announces its
own in `hello` and the sender respects the smaller. A longer frame, invalid UTF-8 or invalid JSON is a protocol
error: the receiver sends `err` with `id: null`, `code: protocol-error` and closes. Bulk results are **streamed in
chunks** (`chunk_items`, default 1000 components or 5000 row operations per event), never one big frame. Compression
is not in v1; a later codec is negotiated in `hello`.

**Channels (child-process stdio).** stdin carries host→module frames, stdout module→host frames, stderr free-text
log lines, forwarded by the host line by line. The Python server duplicates the original stdout descriptor for frames
and points `sys.stdout` (fd 1) at stderr before importing anything, so a stray `print` in a library cannot corrupt
the stream (proven by the W1.2 spike, 2026-11-11). The server also points fd 0 at the null device (a child process that inherits stdin cannot eat frames) and keeps the
frame descriptors non-inheritable. A module exits when stdin reaches EOF (the host died or closed it), cancelling what is in flight (exit 0); a
protocol error ends it with exit 3. Caps enforced by the server: inbound frames above its announced `max_frame` (the
body is never read), outbound frames above the smaller of both announcements (an `internal` error, the module stays up),
`max_inflight` (`busy`), request ids unique per connection.
The server lives in `rust/python` (`secmonk_modules`), not in the `secmonk` package, because `src/` is not edited; a
`secmonk.rpc` module inside the package is a later option once both versions agree on it.

Measured by the spike on macOS arm64 (2026-11-11): spawn to first reply 65 ms; first call importing `univers` 219 ms,
warm `versions.compare` 33 µs; first `fs` collect on `tests/fixtures/lang` 752 ms (453 components), warm 24 ms.
Modules therefore stay alive for the app's lifetime (or `idle_timeout_s`), not one process per call.

**Messages** (field `type`):

| type | Fields | Direction | Meaning |
|---|---|---|---|
| `hello` | `protocol, role, name, version, codecs, limits` (+ module: `runtime, runtime_version, pid, provides, capabilities`; host: `codec, session{module, grants, settings}`) | both, first | Module speaks first; the host answers. No `req` before both. |
| `req` | `id, method, params, deadline_ms?` | both | A call. `id`: positive integer, unique per sender and connection. |
| `res` | `id, result` | callee | Unary result. |
| `err` | `id, code, error, hint?, data?` | callee | Failure; the `{error, hint, code}` shape of today's `ApiError`. |
| `event` | `id, seq, data` | callee | One item of a stream method (`call: stream` in the catalog). |
| `end` | `id, result?` | callee | Stream finished (optional summary result). |
| `progress` | `id, message?, done?, total?, unit?` | callee | Advisory progress of a running request (job log lines). |
| `cancel` | `id, reason?` | caller | Abort request `id`; the callee answers `err code=cancelled` (or its normal end if already done). |
| `notify` | `method, params` | both | No reply. `log` (`wire/notify-log.schema.json`) carries a structured log line tied to a request. |

Both peers may send `req` (the protocol is symmetric so a dialed-out probe can receive calls later); in the prototype
only the host calls. Examples: [`examples/wire/`](../../contracts/examples/wire/) (01–19).

**Hello and capabilities.** The module's `hello` lists `provides` (collectors, sources, `sync_all_order`, methods) and
`capabilities`. The host checks it against the manifest (a module may not claim more than its manifest), then answers
with its `hello`: chosen `codec`, its `limits` (`max_frame` = the negotiated value), and a `session` with the module
name, **grants** (only `db_read` with `uri_flags: "mode=ro"`, only for modules whose manifest declares `db-read` and
whose config allows it) and `settings`, the same keys for every module: `min_confidence`, `module_dir`
(`<data_dir>/modules/<name>`, created by the host; py-sources keeps its staging database there) and
`process: {target, options}` (py-procmon; `target` null = this machine). Implemented in
`secmonk-modhost/src/hello.rs` (2026-11-11). Unlike the rest of `hello`, `session.grants` is **strict**: unknown keys are refused
(`Grants` is `deny_unknown_fields`, the envelope schema closes it), so a new grant needs both peers updated (backlog). The host's registry (collectors, sources for `/api/collectors`, `/api/sources`) is built from the
`provides` of the hellos.

**Timeouts, cancel, crashes.**

| Event | Host behaviour |
|---|---|
| No `hello` within `hello_timeout_s` (20 s) | kill, state `failed`, error `module-unavailable` |
| `deadline_ms` passed | send `cancel`; after `cancel_grace_s` without an answer, kill the module (Python threads cannot be interrupted) and fail pending calls with `timeout` |
| Job cancelled | `cancel` for the request in flight, same grace and kill |
| Module exits with calls pending | each fails with `module-crashed`; restart lazily with backoff (`max_restarts` per `restart_window_s`, then `failed`; the failed state lasts one window, then a start is tried again) |
| Idle (`idle_timeout_s` > 0) | the host closes stdin after that long with nothing in flight; the module exits on EOF; the next call starts it, not counted as a restart |
| Host stops or kills a module | stdin closed, `cancel_grace_s` to exit, then SIGKILL of the module's process group (Unix); on Windows only the module process (no Job object yet) |
| Malformed frame, oversize, unknown message type | `protocol-error` (the host sends `err` with `id: null`), kill, restart |
| Caller drops a call (job cancelled, app exit) | `cancel` for the request, the pending entry is removed; a late answer is ignored |

The handshake also refuses (`module-unavailable`): another protocol major, a `hello.name` other than the module
started, no `json` codec, a `provides` claim beyond the manifest. `max_inflight` is the smaller of the manifest
limit and the module's `hello.limits.max_inflight`. Rust side: `secmonk-modhost` (`session.rs`, `child.rs`,
`supervisor.rs`), tested against a stand-in Python module (`tests/fixtures/echo_module.py`).

**Error codes** (wire `code`; the HTTP mapping is in [api-contract](api-contract.md#errors)):

| Code | Meaning |
|---|---|
| `protocol-error`, `unknown-method`, `invalid-params` | the call itself is wrong |
| `unknown-asset`, `unknown-vuln`, `unknown-collector`, `unknown-source`, `no-db` | a named thing does not exist |
| `unsupported-platform`, `collect-error`, `engine-unreachable`, `host-unreachable` | the target or its tooling failed (today's `COLLECT_ERRORS`, docker / ssh errors) |
| `cancelled`, `timeout`, `module-crashed`, `module-unavailable`, `busy` | lifecycle |
| `stale` | a write based on an outdated read (finding set computed before a newer scan) |
| `internal` | anything else; `error` = `"<Type>: <message>"`, never a traceback |

**Versioning.** `protocol` major must match (`secmonk-wire/1.x`); minors are additive (new optional fields, new
methods); unknown fields are ignored, including inside `hello.provides` (the envelope schema leaves it open; the Rust
host logs unknown keys at debug, `secmonk_proto::message::unknown_fields`); an unknown method answers
`unknown-method`. Local files stay strict: a manifest's `provides` refuses unknown keys. Payload formats carry their own
versions (`secmonk-inventory/1`, `secmonk-mirror-rows/1`, `secmonk-process-snapshot/1`, schema v3). A breaking change
of a method's params or result is a new method name (`engine.match2`), never a silent change.

## (b) Module manifest

One manifest per module (`secmonk-module/1`); on disk a TOML file `rust/python/modules/<name>.toml` (the registry
also reads `.json`) with the same structure as the JSON examples ([`examples/module/`](../../contracts/examples/module/)); Rust modules carry theirs
compiled in.

| Key | Meaning |
|---|---|
| `name`, `version`, `description` | identity; `name` is a slug, unique in the registry |
| `kind` | `probe` · `source` · `engine` · `tool` |
| `runtime` | `python` (child stdio) or `rust` (in-process); flipping it is the last step of a port |
| `protocol` | `secmonk-wire/1` |
| `provides` | collectors / sources / `sync_all_order` / methods it serves (checked against `hello`) |
| `capabilities` | `read-target`, `run-commands`, `network`, `db-read`, `local-system`, `stateful`, `writes-staging`: declared, shown, and the base of grants (`db-read` is the only one the host grants actively) |
| `platforms` | where it may run; elsewhere its methods answer `unsupported-platform` without starting it |
| `python` | `project` (uv project dir), `env` (venv name under `venvs/`), `entry` (interpreter args), `requires_python` |
| `rust` | `crate`, `factory` |
| `lifecycle` | `start` (`lazy`/`eager`), `idle_timeout_s`, `max_restarts`, `restart_window_s` |
| `limits` | `hello_timeout_s`, `request_timeout_s`, `cancel_grace_s`, `max_frame`, `max_inflight`, `memory_mb` |
| `integrity` | `lock_sha256` (the uv.lock of the project), `tree_sha256` (the module sources) |

**Trust.** Modules are code execution. Only modules listed in the config run; in `trust = "pinned"` mode their
`integrity` hashes must match the config pins, and the `uv.lock` and source tree on disk must match them too (hashed
before `uv sync` and again before every start: [configuration § Module integrity](configuration.md#module-integrity)). The UI chooses among installed
modules by name and can never upload a script, name a path or change the module set: the same policy that refuses
`ssh_bin`, `transport`, `ssh_option`, `ssh_config` and `kubectl` from the browser today.

Prototype modules: `py-probe`, `py-sources`, `py-engine`, `py-procmon`, all served by one package (`python -I -m
secmonk_modules serve --stdio --module <name>`, also `serve <name> --stdio`) from one venv (`secmonk-modules`), each in its own process.

## (c) Inventory

The inventory is `models.Inventory` as `secmonk collect -O` writes it (`dataclasses.asdict`) plus two keys:
`schema: "secmonk-inventory/1"` and `classified` (a file without `schema` is a legacy `collect -O` file, read as
`classified: true`). Schemas: `inventory/inventory.schema.json`, `asset.schema.json`, `component.schema.json`;
examples: [`examples/inventory/`](../../contracts/examples/inventory/) (a real `fs` run on a fixture).

**Wire form.** `collector.collect {collector, target, options[]}` is a stream: one `asset` item (with `collector`,
`classified: false`), then `components` items of ≤ 1000, `warning` items, and an `end` with `{partial,
partial_reason, components, warnings}`. `options` are the raw `key=value` strings; the module parses them with
`ops.parse_opts` (one parser for booleans and lists). `collector.expand_targets` takes the same params.

**Where classify sits: in the engine, on ingest.** Collectors return unclassified components (identity evidence:
PURL, bundle id, formula, hints); the host calls `engine.classify` on the assembled inventory before saving or
matching. Today `ops.collect` classifies inside the collect step; the module adapter calls the collector without it (verified by
`tests/test_probe.py`: no `product_source` on application components). Warnings leave the module through `scrub_text` and
are cut at 2000 characters; the module refuses the option `snapshot_out` (a file the caller names) with `invalid-params`.
Error mapping of the probe: `unsupported-platform` (process without a backend), `host-unreachable` (ssh, an unreachable or
denying cluster), `engine-unreachable` (Docker), `collect-error` (the rest of `COLLECT_ERRORS`, kubectl missing), with
`data.reason` = `kubectl-missing` / `k8s-denied` / `k8s-unreachable` where the API has finer codes; texts are `<Type>: <message>`
without URL credentials, or generic like `web/jobs._engine_error` for engines. `docker.image_check.inventory_version` is the
string of `IMAGE_INVENTORY_VERSION` (the schema says string; the stored asset meta holds the integer: compare as strings).
Consequences: alias-table and brew-seed updates reach every stored scan path without touching probes, and a future
remote probe needs no engine data (proposal §2.1).

**Ingest rules (host).** Validate against the schema; caps: 500 000 components, 1 000 warnings, 64 MiB assembled;
asset ids must match the collector's id prefixes; strings are bounded (schema `maxLength`). A partial inventory is
saved with `scan.partial = 1` and is not a reference for removal (unchanged rule). Re-redaction of `meta` on ingest is
a later step (the module runs today's redacting collectors) — listed in [backlog](../plans/backlog.md).

## (d) Source row stream

A source module does not get a database handle. `source.sync {source, options, secrets?}` streams batches of **mirror
row operations** (`secmonk-mirror-rows/1`, `source/rows.schema.json`) and ends with the run's `sync_entry`
(`source/sync-end.schema.json`). The host applies the batches **in order, one transaction per batch**.

| Op | Fields | Host action |
|---|---|---|
| `upsert` | `table`, `row` | `INSERT … ON CONFLICT (<primary key>) DO UPDATE` with the given columns |
| `delete` | `table`, `key` | delete by primary key; for `affected` (no natural key) `key` holds the whole row and deletes **one** matching row |

Tables are the mirror tables only (`source_sync`, `raw_record`, `vulnerability`, `alias`, `affected`, `kev`, `epss`,
`distro_triage`); columns are the v2 columns; JSON columns (`extra`, `events`, `versions`, `cwes`, `raw_record.data`)
travel as JSON values. Anything else (inventory, findings, jobs, an unknown column) is refused with `invalid-params`
and the sync fails. Each batch has a `seq`; after `end` the host calls `source.ack {source, through_seq}`.
`source.export {source}` streams every staging row of a source, to rebuild the mirror.

**Batches and acks.** A batch has ≤ 5000 operations and about 2 MiB of JSON; its `seq` is a counter persisted in staging
(never reused, global across sources). `source.sync` first replays every batch of that source not yet acknowledged (same
seq, same operations), then streams the new changes; the `end` result carries the run's `entry` (a failing source is an `end`
with `entry.status = error`, not an `err`), `batches`, `last_seq`, `ops`. `source.ack` deletes the batches up to `through_seq`
for that source. `source.export` ignores `through_seq` (the schema requires it; send 0) and streams every staging row of the
source as upserts (rows are attributed by `source = name` or `name:*`), batches numbered from 1.

**Generations (W4.4, additive: still `secmonk-mirror-rows/1`).** Every batch may carry `generation` (the random identity
of the staging file, persisted, new when the file is recreated) and `acked_through` (the highest seq the module had
acknowledged for that source). The host compares seqs only within one generation; a batch of another generation, or with
`acked_through` above the host's applied seq, is not applied: the host drains the stream and repairs the source from
`source.export`. The export first numbers every pending change, then ends with two optional fields of
`sync-end.schema.json`: `generation` and `high_water` (the highest seq ever assigned); the host deletes the source's rows,
applies the export and records `high_water` + `generation` in one transaction, then acknowledges through `high_water`,
so any older batch still in the log is skipped when replayed. `acked_through` makes a replayed batch differ from its
first emission outside `ops` (the operations stay identical). An `UPDATE` of an `affected`
row is a delete of the old row plus an insert; `INSERT OR REPLACE` on the other tables is an upsert (the replaced row needs no
delete). Replaying the operations on an empty mirror gives the staging tables row for row (`tests/test_sources.py`).

**Prototype adapter.** `py-sources` runs the unchanged `ops.sync_source` on a **staging SQLite file in schema v2**
owned by the module (`<data_dir>/modules/py-sources/staging.sqlite3`); triggers on the mirror tables record every
row change in a change log; the adapter streams the log and drops acknowledged rows. Sources keep reading their own
previous state (cursors, `raw_record` re-normalization, MSRC merges) unchanged. Cost: the mirror exists twice on disk
until sources emit rows natively. The sync runs to completion first, then the log is streamed (no overlap); a cancel is
raised from the source's progress callback. The staging directory comes from `session.settings.module_dir` (the host sends
`{data_dir}/modules/py-sources`), else `$SECMONK_MODULE_DIR`, else under `$SECMONK_HOME`. Decision and alternatives: [rust ADR-0010](../decisions/0010-source-staging-adapter.md).

## (e) Engine-module calls

Methods (full list, params and result schemas: [`catalog/module-methods.json`](../../contracts/catalog/module-methods.json)):

| Method | Params → result | Wraps today |
|---|---|---|
| `engine.classify` | `{components[≤5000]}` → `{components}` | `engine/classify.classify` |
| `engine.match` (persisted) | `{asset_id, min_confidence, view_limit}` → `{stats, based_on, finding_set, view}` | `engine/match.match_asset` on a read-only connection; the `finding` table shadowed by a TEMP copy of the asset's rows |
| `engine.match` (ephemeral) | `{inventory, min_confidence, view_limit}` → `{stats, view}` | `db.ephemeral_overlay` + `save_inventory` + `match_asset`, all in TEMP tables |
| `versions.compare`, `versions.in_range`, `versions.first_fixed`, `versions.scheme` | see `engine/versions.schema.json` | `engine/versions.*` (used by differential tests and the later Rust port) |
| `scoring.priority` | `{cvss, epss, kev, asset_meta, triage, severity}` → `{priority}` | `engine/scoring.priority` |
| `reports.*` | per route ([api-contract](api-contract.md)) | `reports.*`, `sbom.export_asset` |
| `procmon.payload` / `watch` / `inventory` | process monitor state | `web/api.py` `ProcessMonitor` |

**Persisted match, step by step.** The host has committed the inventory. `py-engine` opens a read transaction,
copies the asset's `finding` rows into a TEMP `finding` table (the name resolves to TEMP first), runs the unchanged
`match_asset`, and returns the asset's **complete finding set** (all statuses, `suppressed` kept sticky by the
unchanged SQL) plus `based_on.latest_scan_id`. The host replaces the asset's findings in one transaction, after checking
that the latest scan id is unchanged (else `stale`, and the job re-runs the match once). Matches of one asset are
serialized by the host.

**Read-only DB access** (proposed: [rust ADR-0006](../decisions/0006-python-read-only-db-access.md)). Engine
modules with the `db_read` grant open `file:<state>?mode=ro` with `uri=True`, `ATTACH 'file:<mirror>?mode=ro' AS
mirror`, `PRAGMA query_only=ON`, `busy_timeout=5000`, and wrap each request in one read transaction (one consistent
snapshot per payload). They never call `secmonk.db.connect` (it runs `init_schema`, a write). The spike showed a
`mode=ro` connection on the live WAL database while the host holds a write transaction: no lock errors, uncommitted
rows invisible. TEMP tables work on a `mode=ro` connection (verified 2026-11-11, SQLite 3.51), but **not** with `PRAGMA query_only=ON`
(it forbids TEMP writes too). So reports use `mode=ro` + `query_only=ON`; matches (persisted and ephemeral) use `mode=ro` plus
an authorizer that allows INSERT / UPDATE / DELETE / CREATE / DROP only on the `temp` database and no ATTACH / DETACH after
setup. Both read both files in one `BEGIN` (a snapshot per request), roll back at the end, and never end the transaction on
behalf of unchanged code (`commit()` is a no-op on that connection). Settings the host sends in `hello.session.settings`:
`min_confidence`, `module_dir` (py-sources), `process` = `{target, options}` (py-procmon). No module ever gets a writable handle.

**Not a module call: the reuse rule.** `ops._reuse_image` becomes host code (Rust, `secmonk-engine`): store reads +
`docker.image_check` on `py-probe` + the trust rule of the Python data-model doc, unchanged.

## (g) Process snapshot

`secmonk-process-snapshot/1` is reused as is (`collectors/process/snapshot.py`): the writer contract is
`process/snapshot-1.schema.json`, readers stay lenient (`snapshot.from_dict`: type checks, caps, re-redaction).
`process.snapshot` on `py-probe` returns it (not used by the prototype UI; it is the future split point between probe
and engine). The prototype's `py-procmon` keeps today's `ProcessMonitor` whole (a subclass that replaces its database access by a read-only
TEMP overlay; target = `settings.process.target`, a snapshot file or `ssh://host`; `snapshot_out` is ignored; saving is
`procmon.inventory` → host). It declares platforms macOS and Linux only; every other module runs on all three. Example:
[`examples/process/snapshot-linux.json`](../../contracts/examples/process/snapshot-linux.json) (synthetic).

## Security rules on this boundary

- **Untrusted targets.** Modules read scanned trees only through `collectors/base.read_within` / `resolve_within` (no
  symlink escapes, size caps); they never extract archives blindly; commands run on a target are fixed, read-only and
  documented. A new module follows the same rules ([component-lifecycle](component-lifecycle.md)).
- **Redaction.** Collectors redact (`redact_command`, `strip_url_secrets`, `redact_labels`) before data leaves the
  module; the host scrubs every log line and stored error (`scrub_text`) and redacts stored options (`redact_option`).
- **No external vulnerability APIs during scans.** Only `source.*` has the `network` capability for vulnerability
  data; probe modules reach the network only to talk to the target (ssh, a Docker engine, a registry the user named).
- **Module output is untrusted input** to the host: schema-validated, capped, never executed or rendered as HTML.
