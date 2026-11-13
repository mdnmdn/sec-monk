---
title: Engine↔ui API contract (the 22 /api routes)
summary: "The 22 /api routes: params, response schemas, Python builders, who answers, gates, errors and their HTTP mapping, the preparing state, option policy, e2e differences from the mock, planned parity test."
read_when: you implement or change a route in secmonk-api, a reports.* module method, or check that the desktop app returns the same payloads as `secmonk ui`
type: tech
context: tech
status: implemented
tags: [contracts, web-ui, api, rust]
updated: 2026-11-13
verified: 2026-11-11
code: [rust/crates/secmonk-api/src/, rust/crates/secmonk-engine/src/error.rs, rust/crates/secmonk-host/src/gate.rs]
fixtures: rust/contracts/examples/api/
related: [tech/contracts.md, tech/architecture.md, tech/engine-service.md, decisions/0007-serve-current-ui-custom-protocol.md]
---

# Engine↔ui API contract

The prototype answers the **same 22 routes** as `src/secmonk/web/server.py` (`do_GET`, `do_POST`, `GET_ROUTES`), with
the same methods, parameters, status codes and payloads, so `static/js/secmonk-views.js` `ApiSource` works unchanged.
The machine-readable form is [`catalog/api-routes.json`](../../contracts/catalog/api-routes.json); each response has a
schema in [`schemas/api/`](../../contracts/schemas/api/) and an example in
[`examples/api/`](../../contracts/examples/api/) (taken from the design mock `_design/mock/data.js`, which
`scripts/design_mock.py` generates from today's builders on the test fixtures, trimmed). The Python reference table is
[web-ui § API](../../../_docs/tech/web-ui.md#api).

## Routes

"Prototype" says who builds the payload: **rust** (host code) or a module method (Python, read-only DB).
Gates: `actions` = refused with 403 when the optional HTTP binding listens on a non-loopback address without
`--allow-actions` (always allowed in the desktop window); `busy` = 409 while a job runs.

| # | Method | Path | Params | Response schema | Python builder (must equal) | Prototype | Gate |
|---|---|---|---|---|---|---|---|
| 1 | GET | `/api/meta` | — | `meta` | `Handler._meta` | rust | |
| 2 | GET | `/api/processes` | `refresh=1` | `processes` | `ProcessMonitor.payload` → `procmon.snapshot_payload` | `procmon.payload` | |
| 3 | GET | `/api/processes/watch` | — | `watch` | `ProcessMonitor.watch` → `procmon.event_dict` | `procmon.watch` | |
| 4 | POST | `/api/processes/save` | — | `process-save` | `ProcessMonitor.save` | `procmon.inventory` → store save → `engine.match` → store | busy |
| 5 | GET | `/api/overview` | — | `overview` | `DataApi.overview` → `reports.overview` | `reports.overview` | |
| 6 | GET | `/api/assets` | — | `assets` | `reports.asset_rows` | `reports.assets` | |
| 7 | GET | `/api/assets/detail` | `id`, `limit` 1..5000 | `asset-detail` | `reports.asset_detail` | `reports.asset_detail` | |
| 8 | GET | `/api/assets/<url-encoded id>/sbom` | `vulns=1` | `sbom` (CycloneDX) | `Handler._sbom` → `sbom.export_asset` | `reports.sbom` + rust headers | |
| 9 | POST | `/api/assets/match` | `id` (query) | `match-result` | `DataApi.match` → `match_asset` | `engine.match` (persisted) → store | busy |
| 10 | GET | `/api/unmatched` | — | `unmatched` | `reports.unmatched_rows` | `reports.unmatched` | |
| 11 | GET | `/api/findings` | `priority`, `asset`, `all`, `fixable`, `hide_minor`, `hide_deferred`, `limit` 1..5000 (200) | `findings-page` | `DataApi.findings` → `reports.findings` | `reports.findings` + rust page | |
| 12 | GET | `/api/vulns/show` | `id`, `raw=1` | `vuln-detail` | `reports.vuln_detail` | `reports.vuln_detail` | |
| 13 | GET | `/api/vulns/search` | `package`, `ecosystem`, `product`, `version`, `limit` 1..1000 (50) | `vuln-search-page` | `reports.vuln_search` | `reports.vuln_search` + rust page | |
| 14 | GET | `/api/sources` | — | `sources` | `DataApi.sources` | rust (`py-sources` hello) + `reports.status` | |
| 15 | GET | `/api/collectors` | — | `collectors` | `DataApi.collectors` → `registry_rows` | rust (`py-probe` hello) | |
| 16 | GET | `/api/jobs` | `kind` scan\|sync, `limit` 1..200 (50) | `job-list` | `JobRunner.list` | rust (store + live jobs) | |
| 17 | GET | `/api/jobs/<id>` | — | `job` | `JobRunner.get` | rust | |
| 18 | POST | `/api/jobs` | body `job-start` | `job` (202) | `JobRunner.start` | rust (JobRunner) | actions, busy |
| 19 | GET | `/api/discover` | `target`, `opt` (repeatable) | `discover` | `JobRunner.discover` → `ops.discover_host` | `discover.host` | actions |
| 20 | GET | `/api/k8s/kubeconfigs` | — | `kubeconfigs` | `ops.k8s_kubeconfigs` | `k8s.kubeconfigs` | actions |
| 21 | GET | `/api/docker/contexts` | — | `docker-contexts` | `ops.docker_contexts` | `docker.contexts` | actions |
| 22 | GET | `/api/docker/containers` | `host`, `context`, `all`, `match`, `opt` (repeatable) | `docker-containers` | `ops.docker_containers` | `docker.containers` | actions |

Not API routes but served by the same handler: `GET /` and `/index.html` (the app), `GET /static/*` (files);
`PUT`, `DELETE`, `PATCH` answer 405; any other `/api/` path answers 404 `no such endpoint <path>`.

## Route notes

| Route | What the host does itself |
|---|---|
| `/api/meta` | `version` (app), `mode` (`live` or `snapshot` when `ui.snapshot` is set), `platform` (`darwin`/`linux`/`windows`, as `backend.current_platform`), `db{path: state db, exists: store initialized}`, `bind` (the scheme origin), `features` (the 8 of `server.py` `FEATURES`), `actions`. Additive: `engine{runtime, schema, step?, modules[]}`: `modules[]` = `{name, runtime, state}` with state `ready` / `stopped` / `failed` / `unavailable`; while the host starts, the gate answers `schema` = `preparing` (+ `step`), `failed`, `stopping` or `starting` and `modules: []`. |
| `/api/findings`, `/api/vulns/search` | Parse and validate params like `web/data.py` (`_one` takes the last value, trims; `_flag` accepts `1/true/yes`; `_int` bounds; priority in `P1..P4`), call the module, wrap `{findings|results, limit, limit_reached: len >= limit}`. |
| `/api/assets/<id>/sbom` | Status 200, `Content-Type: application/vnd.cyclonedx+json; charset=utf-8`, `Content-Disposition: attachment; filename="<id with [^A-Za-z0-9._-]+ → _, trimmed, ≤ 80, or asset>.cdx.json"`, same security headers. |
| `/api/sources` | `registry` and `sync_all_order` from `py-sources`' `hello.provides`; `status` = `reports.status` when the store is initialized, else `null`; answers without a database. |
| `/api/jobs*` | Merge of stored runs (state `job` table, newest first, no log) and the live jobs of this process (the live state is used); `job_payload` shape; a `running` row whose owner is gone reads as `error` / `interrupted` (`owner` = `{pid, host}` as today). |
| `POST /api/jobs` | Ports of `_prepare_sync`, `_prepare_scan`, `_prepare_batch`, `ops.scan_item` validation, `WEB_FORBIDDEN_SCAN_OPTS` (`ssh_bin`, `transport`, `ssh_option`, `kubectl`, `ssh_config` → 400), `MAX_ITEMS` 20, item id slug, `scan_params` / `batch_params` / titles with `redact_target` + `redact_option`. Collector and source names are checked against the hellos. |
| `/api/discover`, `/api/docker/containers` | Allowed `opt` keys: `DISCOVER_WEB_OPTS` / `DOCKER_LIST_OPTS` exactly as in `ops.py` / `web/jobs.py`; one discovery at a time (409); module errors map to the same generic 502 messages and hints (a remote reply is never echoed). |
| `/api/processes*` | Process target from config (`ui.snapshot` = `secmonk ui --snapshot`); `py-procmon` keeps the snapshot and watch baseline. |

**No database.** Reads answer 404 `code: no-db` while the store is **not initialized**: no `source_sync` row, no
asset and no job yet (the v3 files exist from the first start, so "file exists" is no longer the test). Message and
hint are today's (`no database at <state path>`, "Create the local vulnerability mirror first…").

## Implementation notes (secmonk-api, W2.3)

- Route table: `secmonk_api::ROUTES` (22 entries, catalog order); a test compares it with `api-routes.json`
  (method, path, `actions` gate) and checks that the other verb answers 404 `no such endpoint <path>`, as
  `server.py` does. `PUT`, `DELETE`, `PATCH` (and any other verb) answer 405 before every other check.
- Order of checks as Python: method, Host/authority, `X-SecMonk-Request` (every `/api/` path, unknown ones too),
  route lookup, body (POST `/api/jobs`: 415, 400 bad Content-Length, 413, 400 JSON/object), `actions` gate, params.
- Parameters are parsed like `web/data.py` (`parse_qs` drops empty values; `_one`, `_flag`, `_int` with the same
  messages) into typed values (`secmonk-engine` `params`); the engine receives validated input only. `priority` is
  validated by the API, so a bad priority answers 400 even without a database (Python checks it after the database).
- Engine errors (`EngineError`, convertible from `WireError`) map to statuses as in the table below; `code` stays in
  the body only for `no-db`, `unknown-asset`, `unknown-vuln` and the skeleton's `not-implemented` (501).
- `/api/meta`: the engine builds the payload; the router adds the transport facts `bind` and `actions`.
- Skeleton engine (`SkeletonEngine`, the wave-2 stand-in, kept for tests): `no-db` for every database read (with the exact Python message, equal to
  `examples/api/error-no-db.json`), an empty job list, 404 `no job N`, a real `meta` and `collectors` from the probe
  service, 501 `not-implemented` for the rest.
- Real engine (`SecmonkEngine`, [engine-service](engine-service.md)): every route answers; the
  payloads are the modules' `reports.*` / `procmon.*` results or built by the engine from the store and the job
  runner (`meta`, `sources`, `collectors`, `jobs`, `jobs/<id>`, `POST /api/jobs`, `assets/match`). Module errors carry
  their `data.reason` in `EngineError.reason`. Known differences from `server.py`, all on error paths: a failed
  history insert at job start is 500 (Python 503); the engine's own disabled-actions refusal is 400 (the API's 403
  gate answers first); a `save: false` scan without a database is 409 with code `busy` (status and message as
  Python).
- `secmonk_api::serve_http` serves the router over loopback (Tauri-free). The Node harness
  `apps/desktop/tests/nodeapi.cjs` runs the unchanged `secmonk-ui.js` / `secmonk-views.js` against it.

## Request checks (every route)

| Check | Rule |
|---|---|
| CSRF header | `/api/*` without `X-SecMonk-Request: 1` → 403 `missing X-SecMonk-Request header`, GETs included |
| Origin / Host | Desktop scheme: the request authority must be `localhost` (`secmonk://localhost`) or `secmonk.localhost`; else 421. Optional HTTP binding: `server.py` `host_allowed` rules (loopback names, bind address, `--allow-host`, IP literals on a wildcard bind) |
| Methods | GET for reads, POST for actions; a path that does not answer to the verb is 404 `no such endpoint`; `PUT`/`DELETE`/`PATCH`/others 405 |
| Body | POST `/api/jobs`: `Content-Type: application/json` (415), ≤ 64 KiB (413), a JSON object (400) |
| Headers out | CSP of `server.py`, `nosniff`, `no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cache-Control: no-store` (static: `no-cache`) |
| Static files | inside `static_dir` only, regular files, MIME by extension with `charset=utf-8` for text/js/svg |

## Server mode: authentication, scopes, mounts

Server mode (`secmonk_api::Server` in front of the router, served by `secmonk_api::serve`; design:
[node-server-design §3-§4](../plans/node-server-design.md)). Off on loopback by default, required on any other
address ([`check_exposure`](../../crates/secmonk-api/src/http_server.rs): non-loopback needs auth, and TLS or
`insecure_http`). The window (Tauri bridge) never authenticates.

| Path | Auth | Rule |
|---|---|---|
| `/`, `/index.html`, `/rust-ui/*`, `/static/*` | public | the overlay page and scripts (embedded from `rust/ui`) and the UI files; same CSP |
| `GET /auth/info` | public | `{"auth": false}`, or with auth on `{"auth": true, "providers": [...], "login_methods": [...]}` |
| `POST /auth/token` | public | body `{"method": "<name>", ...params}` (≤ 4 KiB; `method` defaults to `api_key`, so `{"api_key": "smk_…"}` works) or `Authorization: ApiKey smk_…` → 200 `{token, token_type: "Bearer", expires_at (unix s), scopes}`, `Cache-Control: no-store`. Any credential failure → 401 `{"error":"invalid credentials"}` + `WWW-Authenticate: Bearer` (same body whatever the reason); throttled client address → 429; unreadable body → 400; auth off → 404 |
| `/api/*` | principal | `GET` needs `ui:read`, `POST` needs `ui:actions` (`admin` implies all); `X-SecMonk-Request: 1` still required; body ≤ 64 KiB |
| a mount prefix (`/node/v1/`) | principal | no CSRF header; body ≤ 4 MiB (413); the mount checks its own scopes |

`Authorization: Bearer <jwt>` or `ApiKey <key>`. Statuses: missing or invalid credential 401 (`authentication
required` / `invalid credentials`, `WWW-Authenticate: Bearer`); missing scope 403 `{"error":"forbidden","hint":"the
API key lacks the scope …"}`; per-key rate limit 429 with `Retry-After: 60`. One `tracing` line per authenticated
request on target `audit` (key id, method, path without query, status); never the header, token, key or body.

**Mounts**: `trait Mount { fn prefix(&self) -> &'static str; async fn handle(&self, req, principal:
Option<Principal>) -> Response }` (`secmonk_api::Mount`); the server authenticates and rate-limits first, the mount
gets `None` only when auth is off and builds answers with `json_response` / `error_response` / `ApiError`.

**Host check** (`HostPolicy::http_server`): loopback names, the bind address, and `[server] allow_hosts`; allow_hosts
names are accepted on any port or none (reverse proxy, `https://scan.example/`); on a wildcard bind (`0.0.0.0`, `::`)
any IP literal with the listen port too.

**Tauri bridge** (`secmonk_api::handle_bridge(&Router, BridgeRequest) -> BridgeResponse`): the `secmonk_api` command of
`rust/ui/README.md`; only `/api/` paths (403 otherwise), `Host` fixed to the router's local authority, no auth,
text (`text/*`, JSON, JavaScript) in `body`, anything else in `body_base64`.

## Errors

Body `{error, hint?, code?}` (`api/error.schema.json`). Wire codes from modules map to statuses:

| Wire code | HTTP | Note |
|---|---|---|
| `invalid-params` | 400 | message passed through (it is ours, never a remote reply) |
| `unknown-asset`, `unknown-vuln`, `no-db` | 404 | `code` kept in the body |
| `busy` | 409 | |
| `unsupported-platform`, `collect-error` | 503 | hint as in `ProcessMonitor._collect_error` |
| `engine-unreachable`, `host-unreachable` | 502 | generic message + hint (`_engine_error`, `discover`) |
| any other code on a probe or discover call | 502 | generic message; only busy, module-unavailable, module-crashed, unsupported-platform and not-implemented keep their own status (as Python's `_engine_error`) |
| `module-unavailable`, `module-crashed`, `timeout` | 503 | the log files in `<data_dir>/logs` (module stderr is in the main log; there is no per-module file yet) |
| `internal` | 500 | `"<Type>: <message>"` |

### Probe failures of the host-facing routes

`EngineError` carries the module's `data.reason` (`reason`). Routes that contact a target map the wire code and the
reason to the statuses and generic messages of `web/jobs.py` (`secmonk_api::error::{discover_error, docker_error,
kubeconfigs_error}`); the remote's own text is never echoed, only the exception type from the module's
`<Type>: <message>`:

| Route | Wire code / `data.reason` | HTTP, `code`, message |
|---|---|---|
| `/api/discover` | `collect-error` + `kubectl-missing` | 424, `kubectl-missing`, "kubectl is not installed on the machine running secmonk ui" |
| | `host-unreachable` + `k8s-denied` | 502, `k8s-denied`, "the cluster refused the request (KubectlError)" |
| | any k8s failure, or target `k8s://…`, + `k8s-unreachable` | 502, `k8s-unreachable`, "cannot reach the Kubernetes cluster (<Type>)" |
| | `host-unreachable`, `collect-error`, `engine-unreachable` (ssh) | 502, no code, "cannot explore the host (<Type>)" |
| | `invalid-params` | 400 with the hint "Expected nothing (this machine) or [ssh://]user@host[:port]." |
| `/api/docker/contexts`, `/api/docker/containers` | `engine-unreachable`, `host-unreachable`, `collect-error` | 502, "cannot reach the Docker engine (<Type>)" |
| | `invalid-params` | 400 with the host / context / selector hint |
| `/api/k8s/kubeconfigs` | any failure except busy / module errors | 500, "cannot list kubeconfigs (<Type>)" |

Busy, `module-unavailable`, `module-crashed` and `timeout` keep the general table (409 / 503) on every route.

### While the host is starting

`secmonk-host`'s `Gate` is the engine behind the router until `Host::start` ends ([architecture §3](architecture.md#3-composition-secmonk-host-and-the-desktop-app)):
`/api/meta` answers 200 (`engine.schema` `preparing` / `failed` / `stopping` / `starting`), every other route fails
`module-unavailable` = 503 with "sec-monk is preparing its Python runtime (step N of 5: ...)", "sec-monk could not start:
..." (hint: the network and `<data_dir>/logs`) or "sec-monk is shutting down". The request checks (CSRF header, Host,
body limits, `actions` gate) run before the gate, so they answer as usual. The desktop scheme handler answers 503
"starting" before the router exists.

### Option policy (browser requests)

The modules do not enforce what the browser may choose; `secmonk_api::policy` does, before the engine sees the
request, with Python's sets and messages:

| Where | Rule | Failure |
|---|---|---|
| `POST /api/jobs`, `kind: scan` (single item `options`, or every `items[n].options`) | none of `WEB_FORBIDDEN_SCAN_OPTS` = `ssh_bin`, `transport`, `ssh_option`, `kubectl`, `ssh_config` | 400 `options: option not accepted from the browser: …` / `items[n]: …` + hint "Run scans that need a custom ssh binary… with the secmonk CLI." |
| same | **fail closed**: options must be a list of strings (or lines of one string) of `key=value`; `items` must be a list of objects | 400 `options: options must be a list of key=value strings`, `<where>: <collector>: expected key=value, got '…'`, `items: expected a non-empty list…`, `items[n]: expected an object…` |
| `GET /api/discover` `opt` | keys within `DISCOVER_WEB_OPTS` (identity, known_hosts, insecure_host_key, connect_timeout, probe_timeout, context, host, tls_ca, tls_cert, tls_key, tls_verify, kubeconfig, namespace, sudo) | 400 `opt: not accepted here: …` + `Allowed: …` |
| `GET /api/docker/containers` `opt` | keys within `DOCKER_LIST_OPTS` (tls_ca, tls_cert, tls_key, tls_verify, identity, timeout, connect_timeout; no `socket`, no `ssh_bin`) | 400 `opt: not accepted here: …` + `Allowed: …; use the host, context and all parameters.` |
| both | each `opt` must be `key=value` | 400 `opt: expected key=value, got '…'` |

The `actions` gate stays first (403 on a non-loopback binding without `--allow-actions`). The loopback HTTP binding
reads each request within 10 s and refuses a header line beyond the 64 KiB head budget (400); a silent or trickling
client is dropped.

`not-implemented` (skeleton only) answers 501 with `code` kept; the real engine never answers it.

### Observed against the mock (e2e, 2026-11-11)

Differences between the real engine's payloads and `_design/mock/data.js`:

- `POST /api/assets/match` takes the asset `id` in the query string, not in a body.
- `/api/findings` returns a page object `{findings, limit, limit_reached}`.
- `match_stats` was absent from the asset detail.
- `osv:*` cursor rows of `/api/sources` report `records` 0.

## Parity test

**Not written yet** (2026-11-11; the payloads are only schema-checked in the engine tests). The planned acceptance check for this contract: run the Python server (`secmonk ui`, a v2 database built from the
fixtures) and the desktop router (a v3 store built from the same fixtures through the modules) and compare, per route
and for a list of queries, the JSON after normalizing volatile fields (timestamps, ids, `db.path`, `bind`). Every
response must also validate against its schema. The design mock stays the UI's reference data.
