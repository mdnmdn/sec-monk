---
title: Node API — the /node/v1 binding, the remote client and feed following
summary: The HTTP binding of the mirror-node services (routes, scopes, caps, error mapping, audit), the RemoteNode client (token exchange and renewal, chunking, limits, TLS trust) and FeedSource, which follows an upstream feed as a native source (localization, re-cut, full replace of snapshot sources, versions).
read_when: you change the /node/v1 routes, call a node from another node or a state node, wire [node] serve or [node.upstream] in the host, or debug a feed-follow sync
type: tech
context: tech
status: implemented
tags: [rust, distributed, api, auth, sync, mirror-node]
updated: 2026-11-13
verified: 2026-11-13
code: [rust/crates/secmonk-node/src/]
related: [plans/node-server-design.md, tech/api-contract.md, tech/data-model.md, decisions/0010-source-staging-adapter.md, decisions/0011-native-sources.md, decisions/0012-native-importer-row-reads-and-registry.md, tech/source-kev.md]
---

# Node API

Crate `secmonk-node` (depends on traits, model, `secmonk-api` for the `Mount` trait, `secmonk-auth` for `Scope`; never
on the store, the engine implementation or the module host: the host injects the services). Proposal:
[`_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md`](../../../_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md)
§3 and §5; design: [node-server-design §3, §6](../plans/node-server-design.md). Types: `secmonk_model::node`; traits:
`secmonk_traits::node` (`MatchService`, `VulnInfo`, `Feed`).

## Server: `NodeApi`

`NodeApi::new(Option<Arc<dyn MatchService>>, Option<Arc<dyn VulnInfo>>, Option<Arc<dyn Feed>>, Arc<dyn NodeInfoProvider>)`
(or `NodeApi::derived(.., node_id, mirror)`, which derives `GET info` from the services: roles = enabled services,
versions from `Feed::status`, else `MatchService::versions`) implements `secmonk_api::Mount` with prefix `/node/v1/`.
Only the services listed in `[node] serve` are `Some`. The server layer authenticates, rate-limits and caps the body
at 4 MiB (413) before the mount runs; the mount needs no `X-SecMonk-Request` header.

| Route | Scope | Request | Response | Count (audit) |
|---|---|---|---|---|
| `GET info` | any authenticated principal | | `NodeInfo` (node id, roles, matcher, mirror, sources) | 1 |
| `POST match/components` | `match` | `MatchComponentsRequest` `{components ≤ 1000, min_confidence?}` | `MatchComponentsResponse` | components |
| `POST match/changes` | `match` | `ChangesRequest` `{since: {source: "<importer>@<version>"} ≤ 256, matcher?}` | `ChangesResponse` | sources |
| `POST vulninfo/summaries` | `vulninfo:read` | `{ids ≤ 500}` | `{summaries, missing}` | ids |
| `GET vulninfo/detail?id=&raw=` | `vulninfo:read` | `id` required (≤ 256 bytes), `raw` = `1` / `true` / `yes` | the `vulns/show` payload | 1 |
| `GET vulninfo/search?…` | `vulninfo:read` | every query parameter, as a JSON object (a repeated name becomes an array; ≤ 32 parameters, values ≤ 1024 bytes) | the `vulns/search` payload | 1 |
| `GET feed/status` | `feed:read` | | `FeedStatus` | sources |
| `GET feed/since?source=&since=&page=&limit=` | `feed:read` | `source` required; `limit` an unsigned integer | `FeedPage` | batches |

With authentication off (loopback) the principal is `None` and every route is allowed. `admin` implies every scope.

Order of checks: route (404 `not found`) → method (405, `Allow` header) → scope (403 `forbidden`, hint names the scope) →
service enabled (404 `{"error":"service not enabled"}`) → body / query validation and caps → the call.

- **Bodies** are JSON of types with `deny_unknown_fields` (400 `invalid request body: …`); `min_confidence` outside
  0..1 is 400. Caps: more than `MAX_COMPONENTS` (1000) components or `MAX_IDS` (500) ids, or the other caps above:
  **413** `too many components: 1001 (at most 1000 per request)` with a hint to split. The service never sees an
  oversized request.
- **Responses** are JSON with `Cache-Control: no-store` (`json_response`).
- **Wire errors** from a service map to HTTP (`wire::status_of`, as [api-contract](api-contract.md#errors) extended); the
  body is `{error, hint?, code}` and **`code` always travels**, so the client maps it back:

| Wire code | HTTP |
|---|---|
| `invalid-params`, `protocol-error` | 400 |
| `unknown-asset`, `unknown-vuln`, `unknown-collector`, `unknown-source`, `no-db` | 404 |
| `busy`, `stale` | 409 |
| `unsupported-platform`, `collect-error`, `module-unavailable`, `module-crashed`, `timeout`, `cancelled` | 503 |
| `engine-unreachable`, `host-unreachable` | 502 |
| `unknown-method` | 501 |
| `internal`, any unknown code | 500, text replaced by `internal error` (the original goes to the log, never to the network) |

- **Audit** (proposal §5): one `tracing::info!(target: "audit", key, route, status, count)` per call, next to the server
  layer's per-request line. Never a body, a query or an id. **Data minimization**: request bodies are parsed, used and
  dropped; nothing in this crate stores them.

## Client: `RemoteNode`

`RemoteNode::new(RemoteConfig { base_url, api_key, ca_cert, timeout })` implements `MatchService`, `VulnInfo` and `Feed`
(plus `info()` for `GET info`).

- **URL**: `https://host:port` (a path prefix is kept, for a reverse proxy); plain `http://` only for a loopback host
  (`localhost`, `127.0.0.0/8`, `::1`); credentials in the URL, other schemes and an empty key are refused at `new`.
  Redirects are never followed (the token would travel with them).
- **TLS**: the workspace's `reqwest` (rustls). `ca_cert` is an extra PEM certificate added as a trust root
  (`add_root_certificate`; ≤ 1 MiB), for a self-signed or private-CA node; the system roots still apply.
- **Auth**: `POST {base}/auth/token` with `{"method":"api_key","api_key":…}`; the JWT is cached and renewed
  `REFRESH_MARGIN` (60 s) before `expires_at` (`with_refresh_margin` changes it), or on a 401, in which case the call is
  repeated **once** (a second 401 is the answer). One exchange at a time (the cache is behind an async mutex).
  The key goes only to `/auth/token`; the token header is marked sensitive; neither appears in `Debug`, logs or errors.
- **Limits**: response bodies are read in chunks and refused above `MAX_RESPONSE_BYTES` (32 MiB; error bodies 64 KiB),
  also by `Content-Length`. `timeout` is the connect and the total request timeout.
- **Chunking**: `match_components` above 1000 components and `summaries` above 500 ids are split; the answers are merged
  in request order. The merged `as_of` is the **first** chunk's (versions only move forward, so it is the oldest, the
  safe stamp for a client that later asks `changes`); `coverage` is the union. An empty request is one call.
- **Errors** (`WireError`): network failure or certificate refusal → `host-unreachable` (the text carries the cause
  chain, no URL); timeout → `timeout`; the node's body `code` when it is a known wire code; else by status: 400 / 413 →
  `invalid-params`, 401 → `unauthorized`, 403 → `forbidden`, 404 → `not-found` (these three are `ErrorCode::Other`:
  there is no permission code in the wire set), 409 / 429 → `busy`, 502 → `host-unreachable`, 503 → `module-unavailable`,
  504 → `timeout`, other → `internal`. A refused key is always "the node refused the API key" (the key is never echoed).
  The node's error text is kept (≤ 500 chars): it is the remote's text, not ours.
- `versions()` is `GET info` re-shaped as `Versions`.

## Feed following: `FeedSource`

`FeedSource::new(sources, feed, view, localizer, local_version)` is a native `Source` (`native() = true`) for the sources
of `[node.upstream] sources`; `feed` is a `RemoteNode`, `view` the engine's `MirrorView`. The host provides the other
two: `BatchLocalizer` (`async fn localize(&RowsBatch) -> StepResult<Vec<RowOp>>`, an adapter over
`MirrorNodeStore::localize_feed_batch`) and `LocalVersionFn` (`Fn(&str) -> Option<String>`, over
`MirrorNodeStore::source_versions()`; the plain version, `None` = everything).

`sync(source)` pages `Feed::since({source, since, page})` (`since` = the local version, repeated on every page; `options.since`
overrides, `options.full` sends none) and streams batches of generation `native-rust`, **numbered from the applied native
seq + 1** (1 after another generation), at most 5000 operations / about 2 MiB each. `ack` is a no-op and `export` is
refused, like every native importer ([ADR-0011](../decisions/0011-native-sources.md)).

- **Delta pages**: each upstream batch goes through the localizer (the `delete affected {source, vuln_id}` marker becomes
  one delete per local `affected` row plus deletes of stale aliases); the localized operations are re-cut, across page
  boundaries, into batches of ≤ 5000 operations.
- **Snapshot pages** (kev, epss, debian-tracker): upserts only. **The full replace is the mechanism of the native
  importers (kev.rs): a `delete` for every stored row of the source whose key the snapshot did not have**, found with
  `MirrorView::row_keys` after the last page (the tables are `kev`, `epss`, `distro_triage`, plus any keyed table the
  pages carry; the key columns are those of `mirror_schema`). The memory cost is one key text per row seen. The deletes
  come after the upserts, so a cut stream leaves old rows that the next sync removes. The snapshot guard of the Python
  sources applies unless `options.full`: an empty snapshot, or under half of the stored rows, deletes nothing and ends the
  run `error`. `raw_record` rows are upserted and never deleted (as kev.rs); `affected` rows in a snapshot page are
  refused (no natural key).
- **End**: the last operation is the `source_sync` row: `cursor` = the upstream version **of the first page** (records
  modified while the run pages come again next time through the overlap), `records` = the upstream's count, status
  `ok`; `source_versions()` then serves the same version further down. The `SyncEnd` entry's message names the upstream
  `<importer>@<version>`.
- **Failures**: an upstream failure (unreachable, refused, a page for another source, a repeated cursor, a refused
  snapshot) ends the run with an `error` entry and an `error` `source_sync` row (the version does not move), as
  native importers treat feed problems; failures of the local side (the mirror view, the localizer) are errors of
  the call. Batches already streamed stay applied; the next sync converges.
- **Chaining**: `Source::importer_version(source)` (also `upstream_importer`) returns the `version.importer` of the last
  page, so a follower serves the same importer version as its upstream; `None` before the first page.

## Not done

- No push: a follower polls (`feed/since`, `match/changes`). No signed rows, filtered replicas or Bloom-filtered changes
  (P5).
- A delta carries no record deleted upstream (resync); `FeedSource` with `options.full` re-reads every record but does not
  remove local records the upstream lost.
- A snapshot page of a *record* source (`affected` rows) is refused; only the key-diffable snapshot tables are replaced.
- The importer of the *local* rows is not compared with the upstream's: the host decides whether to pass a local version
  (a different importer means a resync, proposal §3.2 rule 2).
- `options.limit` and `options.ecosystems` are ignored by `FeedSource` (the upstream's pages are not a subset knob).

## Tests

`crates/secmonk-node/tests/e2e.rs`: `NodeApi` behind `secmonk_api::Server` with auth on over real sockets (every route,
scope enforcement, caps, 405 / 404, disabled service, error mapping), `RemoteNode` against it (every service, chunking,
token exchange and renewal after expiry, 401 retry, bad key, unreachable) and over TLS with the `secmonk-api` fixture
certificate as `ca_cert`. `tests/follow.rs`: `FeedSource` over a scripted feed, fake view and fake localizer (delta,
re-cut, seq, snapshot replace, guard, upstream failures). The test server uses `secmonk-engine`'s `SkeletonEngine` as the
router's engine (dev-dependency only).
