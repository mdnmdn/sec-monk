---
title: Rust prototype architecture
summary: Components, the Cargo workspace and dependency rules, build features, secmonk-host (start-up phases, preparing gate, shutdown, headless, logging), module lifecycle, transports, UI serving, platform matrix.
read_when: you start work in rust/, add a crate, wire a module or a route, or need to know what is Rust and what is Python in the prototype
type: tech
context: tech
status: implemented
tags: [architecture, rust, tauri, python, modules, desktop]
updated: 2026-11-11
verified: 2026-11-11
code: [rust/Cargo.toml, rust/deny.toml, rust/crates/secmonk-host/src/, rust/apps/desktop/src-tauri/src/, rust/crates/secmonk-modhost/src/]
related: [tech/contracts.md, tech/api-contract.md, tech/data-model.md, tech/configuration.md, tech/component-lifecycle.md, tech/engine-service.md, decisions/0001-rust-workspace-single-process-tauri.md, decisions/0002-rust-core-python-modules.md, plans/backlog.md]
---

# Rust prototype architecture

The prototype is a **single-process Tauri desktop app** in `rust/` that shows today's UI
(`src/secmonk/web/static`, served in place) over a Rust host. The host (`secmonk-host`, shared by the window and the headless server) owns config, store, module host, API router
and jobs; collectors, sources and the engine steps (classify, match, scoring, versions, report payloads) run as
**Python modules over stdio**, launched through a pinned uv. It is the strangler of
[the approved proposal](../../../_docs/inbox/2026-11-08-port-to-compiled-stack.md) §9, step 4 of §15, with the
simplifications listed in [§9 below](#9-prototype-boundary-and-migration-order).

## 1. Components

```
+--------- secmonk-desktop | secmonk-headless (one OS process, composed by secmonk-host) ----------+
|  webview (WKWebView | WebKitGTK | WebView2)                                                      |
|    index.html + secmonk-ui.js + secmonk-views.js   (src/secmonk/web/static, served in place)     |
|        | fetch("/api/...")  X-SecMonk-Request: 1                                                 |
|        v  custom scheme secmonk:// (http://secmonk.localhost on Windows)                         |
|  ui binding ── secmonk-api (router: static files, /api routes, checks, ApiError)  [Gate: 503]    |
|        |  engine service calls (Rust traits, in-process)                                         |
|        v                                                                                         |
|  engine ── secmonk-engine (jobs, sync, scan orchestration, image reuse, run history)            |
|     |  Store traits             |  EngineSteps / Source traits     |  Probe trait                |
|     v                           v                                  v                             |
|  secmonk-store (SQL)       module host (registry, sessions, supervisor, PythonRuntime = uv)      |
|  state.sqlite3              |  in-process: Rust impls (none yet; the session layer supports them)|
|  mirror.sqlite3 <-- ro --+  |  child stdio: py-engine  py-procmon  py-sources  py-probe          |
+--------------------------|--|----------------------------------------------------------------------+
                           +--+ Python engine modules read SQLite read-only; every write goes through the store
```

| Component | Owns | Must never |
|---|---|---|
| **probe** (`secmonk-probe` + `py-probe`) | Reading targets: collectors, discovery, docker/k8s listings, process snapshots; redaction before data leaves it. | Depend on the store or the engine crates; hold vulnerability data; classify or match; run a command that is not fixed and documented. |
| **engine** (`secmonk-engine` + `py-engine`, `py-sources`, `py-procmon`) | Store and mirror (through `secmonk-store`), sync, classify on ingest, match, scoring, finding lifecycle, jobs, the API payloads. | Read a target itself (every target goes through the `Probe` trait); call vulnerability APIs during a scan; trust module output without validation. |
| **ui** (webview + `secmonk-api`) | Rendering payloads; routing `/api` calls to the engine service. | Business logic or SQL; reaching a probe directly; `v-html` / inline scripts. |
| **module host** (`secmonk-modhost`, `secmonk-runtime`) | Manifests, install (uv), launch, framing, `hello`, request multiplexing, cancel, timeouts, restart. | Domain logic; SQL; deciding which module runs from UI input. |
| **Python modules** (`rust/python`, package `secmonk_modules`) | Thin adapters from the protocol to the unchanged `secmonk` package (path dependency on the repo root). | Write the v3 store; read files the host did not grant; print to the frame channel. |

Roles and boundaries are the proposal's §2.1; classification moves to the engine (on ingest), as there.

## 2. Cargo workspace

```
rust/
  Cargo.toml                 workspace, shared lints (unsafe_code = "forbid" everywhere), default-members = crates/*
  deny.toml                  cargo-deny bans that encode the dependency rules below
  sec-monk.toml              dev config (data_dir = "_data")
  crates/
    secmonk-model            Inventory, Asset, Component, finding rows, job rows (serde). No I/O.
    secmonk-proto            secmonk-wire/1: envelope, hello, error codes, method names, frame codec. No I/O.
    secmonk-safeio           scrub_text, strip_url_secrets, redact_option, redact_command (ports, golden-tested)
    secmonk-config           sec-monk.toml, lookup order, data_dir layout, path resolution
    secmonk-traits           Collector/Probe, Source, EngineSteps (Classifier, Matcher, Reporter, VersionOracle)
    secmonk-store            StateStore + MirrorStore traits, sqlite backend, migrations. The only SQL.
    secmonk-runtime          PythonRuntime trait, UvRuntime (download, verify, install, env, launch command)
    secmonk-modhost          registry, transports (inproc, child-stdio), sessions, supervisor, Py* adapters
    secmonk-probe            local probe service: collector allowlist, dispatch to Probe impls
    secmonk-engine           engine service: jobs, sync, scan, reuse rule, run history, payload facade
    secmonk-api              engine<->ui route table, validation, ApiError, static files, security headers
    secmonk-host             composition root: Host::start, preparing Gate, Service, logging, secmonk-headless
  apps/desktop/src-tauri     secmonk-desktop: thin shell over secmonk-host: custom scheme, window (tray later)
  python/                    uv project secmonk-modules: serve --stdio, adapters, conformance tests
  contracts/                 JSON Schemas, catalogs, examples (rust/contracts/README.md)
  golden/                    shared golden outputs for conformance and differential tests
  _docs/                     this tree
```

### Dependency rules

| Crate | May depend on | Must not depend on | Enforced by |
|---|---|---|---|
| `secmonk-model` | serde, serde_json, thiserror | anything async or with I/O | `cargo tree` (no tokio) |
| `secmonk-proto` | serde, serde_json, thiserror; feature `codec` (default): `tokio-util` codec + `bytes` (byte-buffer framing, no runtime, no I/O) | the tokio runtime, I/O | `cargo tree -p secmonk-proto --no-default-features` has no tokio |
| `secmonk-safeio` | regex, serde_json | store, engine | compiler |
| `secmonk-config` | serde, toml, dirs, dunce, rustix (unix, safe `getuid`, `O_NOFOLLOW`) | store, engine | compiler |
| `secmonk-store` | model, sqlx, sea-query, rustix (unix, job owner) | proto, modhost, engine, api | compiler + `deny.toml` |
| `secmonk-traits` | model, proto, async-trait, futures-core | store, modhost | compiler |
| `secmonk-runtime` | config, model, safeio, dunce, reqwest (rustls), sha2, tar, flate2, zip | store, engine, api | compiler |
| `secmonk-modhost` | traits, proto, runtime, config, safeio, model, rustix (unix, process-group kill) | **store**, engine, api | compiler + `deny.toml` + `cargo tree` check |
| `secmonk-probe` | traits, model, proto, modhost | **store**, engine, sources | compiler + CI `cargo tree -p secmonk-probe` must not list `secmonk-store` |
| `secmonk-engine` | traits, store, model, proto, safeio | **modhost** (gets trait objects; `modhost`, `runtime`, `config` only as dev-dependencies of the gated `tests/real_modules.rs`), api | compiler + `deny.toml` (dev wrapper) |
| `secmonk-api` | engine (its service types and errors), http, percent-encoding | **store**, modhost as direct dependencies (the store is reached only through the engine) | compiler |
| `secmonk-host` | everything; with `engine` off only config, runtime, modhost, probe, traits, model, proto, safeio | — | composition root (the only crate that names modhost and engine together) |
| `secmonk-desktop` | host, config, api, tauri + opener (feature `ui`) | store, modhost directly | thin shell |

- **Only `secmonk-store` speaks SQL**: `rust/deny.toml` `[bans]` with `wrappers = ["secmonk-store"]` for `sqlx` and
  `sea-query`, and `rusqlite` denied outright. `secmonk-store` may be wrapped only by `secmonk-engine`,
  `secmonk-host` and `secmonk-desktop`. `secmonk-modhost` may be wrapped by `secmonk-host`, `secmonk-desktop` and
  `secmonk-engine`, the last one **only as a dev-dependency** (the gated real-module test, `secmonk-engine/Cargo.toml`).
  cargo-deny is not installed on the dev machine: the policy is unrun **(verify)**. `cargo tree` on 2026-11-11 showed
  that only `secmonk-store` depends on `sqlx`, that `secmonk-probe` does not reach `secmonk-store`, and that
  `secmonk-api` reaches it only through `secmonk-engine`.
- **Probes never touch the store**: the probe crates cannot name a store type; the CI check covers transitive paths.
- **The engine cannot tell Rust from Python**: it sees `Arc<dyn Collector>`, `Arc<dyn Source>`, `Arc<dyn Matcher>`;
  the desktop crate injects the module host's adapters.
- **The API never reaches the store**: reads go through the engine service (`Reporter` trait or engine-owned store
  reads such as the job list).

### Build features per platform

User direction 2026-11-11: **macOS and Windows ship every component** (probe, engine, ui); **Linux ships engine
and probe, and the ui where possible**. Platform choices are cargo features, so a headless Linux build never
compiles Tauri or a webview.

| Feature (crate) | Default | Pulls in | Off means |
|---|---|---|---|
| `ui` (`secmonk-desktop`) | on | implies `engine`; `tauri`, `tauri-build` (build dependency, `build.rs` checks `CARGO_FEATURE_UI`), `opener` | headless binary: no window, no webview, no WebKitGTK; the same binary runs `secmonk_host::headless` |
| `engine` (`secmonk-desktop`, `secmonk-host`) | on | `secmonk-engine`, `secmonk-store`, `secmonk-api`; the module set including `py-engine` / `py-sources` | probe-only build: exits 2 with a message ("nothing to serve yet"); the shape of later remote probes |
| `probe` (`secmonk-desktop`, `secmonk-host`) | on | `py-probe` wired into `ProbeService` (collectors, discovery, docker/k8s listings) | engine with an empty collector allowlist |
| `codec` (`secmonk-proto`) | on | `tokio-util` codec, `bytes` | message types only (no framing) |

| Platform | Build |
|---|---|
| macOS, Windows | `cargo build -p secmonk-desktop` (all defaults) |
| Linux desktop | same, when WebKitGTK 4.1 is available |
| Linux headless | `cargo build -p secmonk-desktop --no-default-features --features engine,probe`, or `cargo build -p secmonk-host --bin secmonk-headless` |

The Linux headless build was checked on 2026-11-11 with `cargo tree --offline -p secmonk-desktop
--no-default-features --features engine,probe`: no `tauri`, `wry` or WebKit crate is in the graph. It was built and
run on macOS only; a build on a Linux machine is a plan item ([on-linux](../plans/on-linux.md)).

The core crates (`model`, `proto`, `traits`, `safeio`, `config`, `store`, `runtime`, `modhost`) carry no ui
dependency and build on all three OSes unchanged; `cargo build` / `cargo test` at the workspace root build only
`crates/*` (`default-members`), so CI on a Linux machine without WebKitGTK runs every core test. Platform code
inside the core crates is `cfg(target_os)` (spawn flags, default paths), never a feature.

### Crate APIs

Signatures are in the crates (`cargo doc -p <crate>`); this is the map.

- **`secmonk-model`**: serde types in the field order of the Python dataclasses (`serde_json` `preserve_order`):
  `Inventory`, `Asset`, `Component` (+ `key()`), `CollectItem`, `RowsBatch` / `RowOp`, `SyncParams`, `MatchParams`,
  `MatchResult`, `Finding`, `JobRow` / `JobPayload` (`JOB_KEEP` 200, `JOB_LOG_LINES` 300), `ProcessSnapshot`,
  `time::now_iso()`. All contract examples round-trip (`tests/examples.rs`).
- **`secmonk-proto`**: `Message` (tag `type`; `from_slice` validates), `Hello`, `Grants`, `ErrorCode` (19 codes +
  `Other`), `WireError` (the error of every trait; `error` capped at 4096 chars), `methods::*`, `Manifest` and its
  parts, `codec::{FrameCodec, MessageCodec}` (`DEFAULT_MAX_FRAME` 16 MiB, `HARD_MAX_FRAME` 64 MiB).
- **`secmonk-config`**: `load(&LoadOptions) -> Config` (all paths absolute; `LoadOptions::from_env` is the only reader
  of the process environment: `SECMONK_CONFIG`, `SECMONK_STATIC`, cwd, per-user roots), `ConfigOrigin`,
  `Config::layout()` (one method per directory, `Layout::create()`), `Config::sqlite_path(url)`. Keys: see
  [configuration](configuration.md). Unknown keys are refused; new keys are added in this crate.
- **`secmonk-safeio`**: `scrub_text`, `strip_url_secrets`, `redact_command*`, `redact_option`, `redact_labels`,
  `resolve_within`, `read_within`; golden-tested against the Python helpers (`tests/golden/redaction.json`, 514 cases).

**`secmonk-traits`** (`async-trait`: the traits are used as `Arc<dyn ...>`, which native `async fn` in traits does
not allow). Every method returns `StepResult<T> = Result<T, WireError>`; dropping a future or stream cancels the call.
`CallCtx {deadline, progress}`; streams are `ResultStream<T, E>` of `StreamMsg::{Item, End}`.

| Trait | Methods |
|---|---|
| `Collector` | `collectors()`, `expand_targets`, `collect` (stream of `CollectItem`, then `CollectEnd`) |
| `Probe: Collector` | `methods()`, `call(method, params)`: `discover.host`, `docker.*`, `k8s.kubeconfigs`, `process.snapshot` |
| `Source` | `sources()`, `sync_all_order()`, `sync` (stream of `RowsBatch`, then `SyncEnd`), `ack`, `export` |
| `Classifier`, `Matcher` | `classify(components)`, `match_asset(MatchParams)` |
| `Reporter` | `methods()`, `report(method, params)`: `reports.*`, `procmon.*` |
| `VersionOracle` | `compare`, `in_range`, `first_fixed`, `scheme`, `priority` |
| `EngineSteps` | `Classifier + Matcher + Reporter + VersionOracle` (blanket impl) |

`collect::assemble(stream, Caps) -> StepResult<Inventory>` builds the unclassified inventory with the ingest caps
(500 000 components, 1 000 warnings).

### Engine

The engine (`secmonk-engine`: construction from trait objects, the 22 service methods, jobs, sync, scan, known
differences from Python) has its own page: [engine-service](engine-service.md).

## 3. Composition: secmonk-host and the desktop app

`rust/crates/secmonk-host` is the composition root, the only crate that names both the module host and the engine
(features `engine` and `probe`, see [§2](#build-features-per-platform)). Two thin shells run it: `secmonk-desktop`
(Tauri window) and `secmonk-headless` (loopback HTTP, no window).

**`Host::start(config, progress)`** (`host.rs`) runs these steps; each reports a `Phase` (`startup.rs`), which is the
"step N of 5" of the preparing message:

| # | Phase (message text) | Work |
|---|---|---|
| 1 | `Uv` "downloading uv" | create the `data_dir` layout; `UvRuntime::ensure_uv` (download, verify, extract; skipped when present) |
| 2 | `Python` "installing Python" | `ensure()` the managed interpreter; load the registry from `<python_project>/modules` |
| 3 | `ModuleEnv` "installing the module environment" | `ensure_env` once per env of the available Python modules (`uv sync --frozen`; pinned mode verifies pins first) |
| 4 | `Databases` "opening the databases" | `SqliteStore::open`: files 0600, migrations; any backend but `sqlite` is `Unsupported` |
| 5 | `Modules` "starting the modules" | one `ModuleHandle` per Python module with the hello settings (`module_dir`, `process`, `min_confidence`, `db_read`); probe service over `py-probe`; `PySource`s; `PyEngine` for `py-engine` and `py-procmon`; `eager` modules started now, so a broken install fails the start; then `engine::build` |

Spike timings on macOS arm64: uv download ~4 s, Python install 6-8 s, first sync ~4 s, warm start ~27 ms. The first
headless start on 2026-11-11 (`rust/_data/logs`, with the project's path dependency) took 38 s to `ready`, 25 s of it
`uv sync`; a later start was ready about 2 s after the `uv python find` step.

**The preparing `Gate`** (`gate.rs`, `service.rs`). `Service::new(config)` builds a `Gate`, an `EngineService` that
the API router is built on from the first moment; `Service::run` (spawned by the shell) calls `Host::start` and then
`Gate::set_engine`. Until then `/api/meta` answers with `engine.schema` = `preparing` / `failed` / `stopping` /
`starting` (and `engine.step` = the phase text) and **every other route answers 503** `module-unavailable`:

| State | Message | Hint |
|---|---|---|
| `Preparing(phase)` | "sec-monk is preparing its Python runtime (step N of 5: <phase>)" | first start downloads uv and Python into `<data_dir>`; reload when done |
| `Failed(why)` | "sec-monk could not start: <why>" (scrubbed) | check the network and the log files in `<data_dir>/logs`, restart |
| `Stopping` | "sec-monk is shutting down" | none |

The UI shows these through its normal error panel; the hint asks the user to reload. The desktop scheme handler
answers 503 "starting" before the router exists at all.

**Shutdown order** (`Service::shutdown`, `Host::shutdown`): the gate goes to `Stopping` first (every route answers 503
"sec-monk is shutting down", `/api/meta` included); cancel a startup in progress (dropping the `Host::start` future
kills any uv child); then the engine (`engine.shutdown()` sets the `closing` flag, so `job_start`, match and save are
refused; a running job is stored as `error` / `interrupted`); then all modules concurrently (close stdin, wait
`cancel_grace_s`, then kill, the whole process group on Unix); close the stores (`store.close()`). A `ModuleHandle` is
closed for good after `shutdown()`: it never starts the module again. `Service::with_actions` passes `allow_actions`
to the engine. The window calls it on `RunEvent::Exit`; the headless server on Ctrl-C / SIGTERM, then
waits for the starter task. Observed 2026-11-11: both modules logged "stdin closed, exiting" and the host stopped
within 175 ms of the signal.

**Headless** (`headless.rs`, `bin/secmonk-headless.rs`): `secmonk-headless [--config FILE] [--listen 127.0.0.1:8765]`
(also what `secmonk-desktop` runs when built without `ui`). Config as for the window; `--listen`, else `[ui]
http_listen`, else 8765; **loopback addresses only**, port 0 refused (no login exists), `HostPolicy::http` (the full
Host check of `secmonk ui`), actions allowed (loopback). It always serves `ui.static_dir` (there is no bundle). Prints
`listening http://ADDR` on stderr. The loopback server (`secmonk_api::serve_http`) serves at most 64 connections at once, drops a response that cannot be written within 30 s, and its accept loop backs off (50 ms doubling, capped) on an accept error instead of spinning. Exit 0 / 1 runtime / 2 usage.

**Logging** (`logging.rs`): `tracing-subscriber` writes to `<data_dir>/logs/secmonk-desktop.log.<YYYY-MM-DD>` (the
day the process started; mode 0600; append; not rotated while running) and to stderr (headless, and debug desktop
builds). Files older than `[log] keep_days` are removed at start. `RUST_LOG` wins over `[log] level`. Module stderr
lines arrive through `tracing` (target `module`, field `module = <name>`, scrubbed, at most 8 KiB) in the same file.
There are no per-module files yet: `logs/modules/` is created and stays empty ([backlog](../plans/backlog.md)).

**The desktop shell** (`apps/desktop/src-tauri/src`, feature `ui`): `cli.rs` (`--config`), `static_dir.rs`,
`window.rs`, `lib.rs`. It loads the config, initializes logging, creates the `Service`, registers the asynchronous
`secmonk` scheme handler (the router sits in a `OnceLock`; a slow call never blocks the webview thread), and in
`setup` resolves the static directory (**debug builds**: `$SECMONK_STATIC`, then `ui.static_dir`, then the bundle;
**release builds**: the bundled `static` resource only), builds the router, starts the optional `[ui] http_listen`
binding, spawns `Service::run` and opens the window at the scheme origin. `frontendDist` points to an empty
directory: Tauri serves nothing itself. The window has no Tauri capabilities (no IPC); developer tools need a debug
build and `[ui] devtools`; navigation outside the origin is refused and `http(s)` links go to the system browser.
Offline mode skips downloads and fails with a clear message when a pinned artifact is missing.

## 4. Transports

A transport yields a bidirectional byte stream; framing, `hello` and the RPC session sit above it
([contracts](contracts.md) (a)).

| Transport | Now | Used for | Notes |
|---|---|---|---|
| In-process trait call | yes | Rust implementations (none on day one), engine service from the API | No serialization. |
| In-process serialized (`tokio::io::duplex`) | tests | Conformance: every method through both bindings, JSON compared | Same session code as stdio. |
| Child-process stdio | yes | Python modules | `tokio::process`; stdout = frames, stdin = frames, stderr = log lines. |
| SSH exec stdio | later | Remote probes (`secmonk-probe serve --stdio`) | Proposal §3 (b). |
| TLS / WSS dial-out, gRPC wrapper | later | Probe daemons, remote engines, federation | Proposal §5. |

`secmonk-modhost` exposes `Session` (`connect(reader, writer, HandshakeOptions, SessionConfig)`, `call`,
`call_stream`, `notify`, `close`; cancel = dropping the call) over any `AsyncRead + AsyncWrite`; `ChildModule::spawn`
(child stdio), `inproc::connect` / `inproc::handle` (a `RustModule` over `tokio::io::duplex`), `ModuleHandle`
(supervisor, below; `ModuleHandle::python(entry, runtime, HostSettings)`), `Registry::load_dir(dir, &Config)`. A
module adapter (`PyCollector`: `Collector` + `Probe`; `PySource`: `Source`; `PyEngine`: `Classifier`, `Matcher`,
`Reporter`, `VersionOracle`) implements the domain traits on top of a handle. A remote
engine or probe later reuses `Session` unchanged.

**Module lifecycle** (`supervisor.rs`, `child.rs`; tests in `tests/modhost.rs`):

| Topic | Behaviour |
|---|---|
| States | `ModuleState`: `Idle`, `Starting` (a start or the backoff before a restart), `Running`, `Failed`, `Closed` (after `shutdown()`) |
| Start | lazy on the first call, or at host start for `lifecycle.start = "eager"` modules (`py-engine`) |
| Crash | the next call restarts it after a backoff of 100 ms doubling up to 5 s; `max_restarts` per `restart_window_s`, then state `failed` and `module-unavailable` |
| `Failed` window | `failed` lasts one `restart_window_s`; after it the module may be started again from a clean slate (`failed_is_not_forever`) |
| Idle | with `idle_timeout_s > 0` a reaper stops a module with no call in flight after that long; the next call starts it again and does not count as a restart (`idle_modules_stop_and_start_again_...`) |
| Graceful stop | `ChildModule::shutdown(grace)`: close stdin (the module exits on EOF), wait `cancel_grace_s`, else kill |
| Kill | Unix: `killpg(SIGKILL)` of the module's process group (spawned with `process_group(0)`), also on drop and on a failed handshake. Windows: only the module process; the Job object is not implemented |
| Cancel | a dropped call keeps its pending entry and its concurrency permit until the module's final frame for that id; after `cancel_grace` without one the module is killed |
| Module environment | scoped by the manifest capabilities: `command_for(env, entry, capabilities)` passes the target variables only with `read-target` and the network variables only with `network` ([configuration](configuration.md#module-process-environment)) |
| Status | `/api/meta` `engine.modules[]`: `ready` (running), `stopped` (idle), `failed`, `unavailable` (not on this platform) |

## 5. Threading, async, errors, logging

| Topic | Design |
|---|---|
| Runtime | One tokio multi-thread runtime (Tauri's in the window, `Builder::new_multi_thread` in the headless server). Nothing blocks the main thread: the scheme handler is asynchronous and answers through Tauri's responder. |
| Store | A **write actor** per database file, realized as a single-connection sqlx pool (opened at start, never closed): every write transaction (job rows, inventory saves, finding sets, mirror row batches) waits for that connection, in arrival order. Reads use a read-only pool of 4. One writer per database file, as SQLite wants. |
| Module sessions | Per module process: a writer task (frames out), a reader task (frames in, dispatch by id to a oneshot or a bounded mpsc for streams), a stderr task (lines to `tracing`). A full stream channel stops the reader, the pipe fills, the module blocks on write: backpressure end to end. |
| Jobs | One job at a time, as today (409 while running); each job is a task with a `CancellationToken` that sends `cancel` down to the module call it is waiting on. |
| Errors | `thiserror` enums per crate (`ConfigError`, `StoreError`, `RuntimeError`, `ModuleError`, `EngineError`); `anyhow` only in the app crate. Module errors carry the wire code; `secmonk-api` maps codes to HTTP statuses and the `{error, hint, code}` body of today's `ApiError`. Unexpected errors answer 500 `"<Type>: <message>"`, never a backtrace. A panic in a task is caught at the task boundary and becomes `internal`. |
| Logging | `tracing` + `tracing-subscriber` (no appender crate) to `<data_dir>/logs/secmonk-desktop.log.<date>`; module output through target `module`; every module line passes `safeio::scrub_text` before it is written; request params are logged only through `redact_option`. Details in [§3](#3-composition-secmonk-host-and-the-desktop-app). |

## 6. Serving the current UI

| Item | Rule |
|---|---|
| Files | Dev: `ui.static_dir` (default `../src/secmonk/web/static`, or `$SECMONK_STATIC`) served **in place**, never copied in the repo ([rust ADR-0007](../decisions/0007-serve-current-ui-custom-protocol.md)). Release: `resource_dir()/static`, bundled through Tauri `resources` (a copy made at bundle time, acceptable). SPA fallback to `index.html` kept although the UI uses hash routing. `/` and `/index.html` → `index.html`; `/static/*` → the file, resolved inside `static_dir` only (no traversal, regular files, symlinks must stay inside). |
| Origin | macOS/Linux `secmonk://localhost/`; Windows `http://secmonk.localhost/` (Tauri's form for custom schemes on WebView2), confirmed by the spike. `ApiSource(base="")` fetches relative `/api/...`, which stays on that origin and reaches the same handler. |
| `/api/*` | Answered in-process by `secmonk-api`, same paths, methods, payloads and errors as `web/server.py` ([api-contract](api-contract.md)). |
| Headers | The CSP of `web/server.py` (`script-src 'self' 'unsafe-eval'`, `style-src 'self'`, `connect-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control` as today. Tauri's `app.security.csp` does not apply to custom scheme responses, so the handler's header is the only policy (spike: the handler sends today's exact header, rejects traversal, answers 403 without the header; the unchanged `ApiSource("")` worked against it with the real Vue files in Node). Rendering in a real webview is **(verify on a GUI session)**: the spike sandbox blocked WebKit. |
| CSRF header | Every `/api/` request must carry `X-SecMonk-Request: 1` (403 otherwise), kept although the scheme opens no port: one rule for every binding. |
| Host check | No TCP listener, so no DNS rebinding: the handler only checks that the request authority is the app's own (`localhost` / `secmonk.localhost`). The optional dev HTTP binding (`ui.http_listen`, off by default) applies the full `server.py` Host rules and loopback-only actions. |
| IPC | The window gets **no Tauri command permissions**: the only channel from the page to Rust is the scheme. Navigation outside the origin is refused; `http(s)` links open in the system browser through the Rust-side `opener` crate (unit-tested classification in `window.rs`; the real opening is a GUI check in [on-macos](../plans/on-macos.md)). The UI needs no IPC (confirmed by the spike). |
| No build step | The Vue app stays classic scripts with vendored Vue (Python [ADR-0009](../../../_docs/decisions/0009-web-ui-vendored-libraries.md)); no inline scripts or static `style=""`. |

## 7. Data flow of a scan job

```
POST /api/jobs {kind: scan}  -> api: validate (browser option policy, 64 KiB, JSON)  -> engine.JobRunner
  per item:  Probe.expand_targets (py-probe)                                           -> targets
  per target: reuse rule (Rust: Store reads + py-probe docker.image_check)             -> reuse or collect
              Probe.collect (py-probe, stream: asset, components*, warnings, end)      -> Inventory (unclassified)
              validate + caps                                                          -> Inventory
              EngineSteps.classify (py-engine)                                         -> Inventory (classified)
              save:    StateStore.save_inventory (Rust)  -> Matcher.match(persisted) (py-engine, read-only)
                       -> StateStore.replace_findings(asset, finding_set, based_on) (Rust)
              no save: Matcher.match(ephemeral, inventory) (py-engine, TEMP tables, nothing written)
              entry = {asset, scan_id, stats, findings[] (view, <= 500), counts, ...}
  StateStore.finish_job(redacted params, capped result, summary, scrubbed log)
```

A sync job runs `Source.sync` per source: the module streams mirror row batches, the store applies each batch in
one transaction (skipping a replayed `seq`), and the engine acknowledges the last applied batch with `source.ack`
after the stream ends ([contracts](contracts.md) (d), [engine-service](engine-service.md)).

## 8. Platform matrix

| Item | macOS | Linux | Windows |
|---|---|---|---|
| Webview | WKWebView | WebKitGTK 4.1 | WebView2 (Evergreen) |
| UI origin | `secmonk://localhost` | `secmonk://localhost` | `http://secmonk.localhost` |
| uv asset | `uv-aarch64-apple-darwin.tar.gz`, `uv-x86_64-apple-darwin.tar.gz` | `uv-x86_64-unknown-linux-gnu.tar.gz`, `uv-aarch64-unknown-linux-gnu.tar.gz` (musl variants on musl hosts) | `uv-x86_64-pc-windows-msvc.zip`, `uv-aarch64-pc-windows-msvc.zip` |
| uv binary in archive | `uv-<triple>/uv` | `uv-<triple>/uv` | `uv.exe` at the root (flat zip) |
| Webview state | `~/Library/WebKit/<id>`, `~/Library/Caches/<id>`: **outside data_dir** (known exception) | data directory option set to `data_dir/webview` | data directory option set to `data_dir\webview` |
| Pitfalls | — | a `noexec` mount for `data_dir` breaks the managed Python | `MAX_PATH`: keep `data_dir` short; SmartScreen may flag the unsigned `uv.exe` |
| Default data_dir | `~/Library/Application Support/sec-monk` | `$XDG_DATA_HOME/sec-monk` (`~/.local/share/sec-monk`) | `%LOCALAPPDATA%\sec-monk` |
| Default config | `~/Library/Application Support/sec-monk/sec-monk.toml` | `$XDG_CONFIG_HOME/sec-monk/sec-monk.toml` | `%APPDATA%\sec-monk\sec-monk.toml` |
| Venv interpreter | `venvs/<env>/bin/python` | `venvs/<env>/bin/python` | `venvs\<env>\Scripts\python.exe` |
| Module spawn | venv interpreter exec'd directly (never `uv run`, which stays as a parent); `kill_on_drop`, own process group (`process_group(0)`); **every kill is `killpg(SIGKILL)` of the group** (`child.rs` `kill_group`, rustix), so what a module started (ssh, docker, kubectl, git) dies with it; a killed child is reaped at once; the module exits on stdin EOF (tested: no process left after the handle is dropped, and the group kill) | same; `PR_SET_PDEATHSIG` needs `unsafe` (`pre_exec`), not done: a host killed with SIGKILL closes the pipes, so a module exits at its next stdin read, but one busy in a long call (and its children) runs on **(verify on Linux)** | `CREATE_NO_WINDOW` (done, `LaunchSpec::to_command`); **Job object with kill-on-close not implemented** (needs `unsafe` or a wrapper crate; `kill_group` is a no-op there, only the module process is killed; [on-windows](../plans/on-windows.md)); binary stdio (`sys.stdin.buffer`); never spawn `.bat`/`.cmd` |
| File modes | dirs 0700, files 0600 | dirs 0700, files 0600 | per-user profile ACLs (inherited), not checked by the app **(verify)** |
| Live process monitor | yes (`py-procmon`) | yes | no (503 `unsupported-platform`, as today) |
| Collectors that need this OS | macos, homebrew | rootfs live, process (live) | windows (live registry) |
| Signing | Developer ID + notarization (later) | none; AppImage/deb (later) | Authenticode (later) |

Where a probe or engine part is a real problem on one OS it may be Linux-only; the desktop app still builds and starts
on all three and reports the missing capability as an unavailable feature ([rust ADR-0009](../decisions/0009-platform-targets.md)).

## 9. Prototype boundary and migration order

| Part | Day one | Later |
|---|---|---|
| Tauri shell, config, store + schema v3, module host + uv, API router, jobs, run history, reuse rule, redaction helpers | **Rust** | — |
| Collectors, discovery, docker/k8s listings | Python (`py-probe`) | Rust by value: `safeio`, `lang`, `fs`, `rootfs`, process backends first (proposal §9.6) |
| Sources | Python (`py-sources`, staging adapter) | Native record emitters; possibly Python for good |
| classify, match, scoring, versions | Python (`py-engine`) | **Rust first** after the prototype (hot, security-critical; differential tests against `univers`) |
| Report payloads (`reports.*`, `procmon.*`) | Python (`py-engine`, `py-procmon`) | Rust together with the store queries they need |

Simplifications against the proposal (deliberate, cheap to undo):

1. Versions, classify, match and scoring are **pluggable Python modules** here; the proposal keeps them out of the
   module interface. They become Rust in-process code first, then lose their Python binding.
2. One **write path**: Python modules never write the v3 store; sources reach it through a staging adapter
   ([rust ADR-0010](../decisions/0010-source-staging-adapter.md)), engine modules read it read-only
   ([rust ADR-0006](../decisions/0006-python-read-only-db-access.md)).
3. **Schema v3 stays a superset of v2** so the unchanged `secmonk` read code runs on it ([data-model](data-model.md)).
4. `py-procmon` reads this machine **and** matches: the probe/engine split at the snapshot comes later.
5. Modules run on the engine host only; no Python on targets, no remote transports, no federation.
6. One job at a time, as today; jobs can be cancelled internally (app exit), the UI has no cancel button yet.

Migration order after the prototype: [plans/backlog.md](../plans/backlog.md).

## Evidence

- W1.2 feasibility spike (2026-11-11, macOS arm64; scratch code in `/tmp/secmonk-spike/`, not in the repo)
  confirmed: the pinned-uv flow and its environment, the framing and stdout guard, read-only Python reads under a live
  Rust writer, the custom scheme handler with today's CSP and `ApiSource("")` (in Node), sqlx. Not run: Windows,
  Linux desktop, a real webview. Release `.app` executable 4.1 MB.
- W2.1 (2026-11-11): the core crates build, are clippy-clean and pass 75 tests; `uv_audit` passed, see
  [configuration](configuration.md#uv-download-verify-install). On the dev Mac the endpoint security blocks the linker
  from reading one unit-test object of `secmonk-runtime`; that test lives in `tests/module_env.rs`.
- W3.2 (2026-11-11): headless server on macOS arm64 installed into `rust/_data` in 38 s, answered 503 preparing meanwhile,
  and stopped cleanly on SIGINT (log lines quoted in [§3](#3-composition-secmonk-host-and-the-desktop-app)); the
  coordinator's log records a scan of `tests/fixtures/lang` (477 components). The window was built (`.app`) but not
  observed: no GUI session.

## Related docs

[contracts](contracts.md) · [api-contract](api-contract.md) · [engine-service](engine-service.md) · [data-model](data-model.md) ·
[configuration](configuration.md) · [component-lifecycle](component-lifecycle.md) ·
[desktop app feature](../features/desktop-app.md) · Python: [architecture](../../../_docs/tech/architecture.md),
[web-ui](../../../_docs/tech/web-ui.md)
