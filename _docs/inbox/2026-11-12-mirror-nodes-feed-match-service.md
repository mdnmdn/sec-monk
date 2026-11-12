---
title: Proposal — mirror nodes for the Rust version (feed, match service, vulnerability summaries)
summary: Rust only - nodes with a state part and an optional mirror; a mirror serves a feed to other mirrors and a batch match and summary service to state-only nodes; versions, APIs, data model, costs, security, effort.
read_when: you decide whether a vulnerability mirror is shared by several Rust engines, design the match or feed API between nodes, or plan the distributed mode (roadmap R5) of the Rust version
type: proposal
context: inbox
status: proposed
tags: [architecture, distributed, matching, data-model, security, rust]
updated: 2026-11-12
verified: 2026-11-12
related: [inbox/2026-11-08-port-to-compiled-stack.md, tech/data-model.md, tech/engine/matching.md]
---

# Proposal — mirror nodes for the Rust version (feed, match service, vulnerability summaries)

**Scope: the Rust version only** (`rust/`). The Python reference keeps one database per user and is not changed.

## Summary

Every node runs a **state** part (inventory, findings, run history) and may run a **mirror** part (the vulnerability
data). A node with a mirror can serve two things to other nodes:

- a **feed**: other mirrors follow it and receive its row batches instead of syncing the vulnerability sources themselves;
- a **match service**: a node without a mirror sends batches of components and gets back the vulnerabilities that
  match them, and asks for **summaries** of those vulnerabilities, which it keeps in its state.

A node with both parts talks to its own mirror through the same interface, in process. Every call between nodes is
authenticated and authorized.

The idea holds. It reuses what the Rust version already has: row batches with `seq` and `generation`,
`apply_rows`, repair, the ephemeral match. It also removes the two costs of a central mirror: every engine syncing
every source, and SQL joins between state and mirror. Five changes are recommended, detailed in §3:

1. **Versions name their origin**: `(origin node, generation, seq)` per source, plus the matcher version. A bare
   `seq` means nothing on another node.
2. **The match call stays stateless; a separate `changes` call drives re-matching.** "Only what is new since my
   version" cannot report a match that disappeared, and it makes the node send its whole inventory at every poll.
3. **Matching is per component, scoring is per asset.** The mirror returns matches per component key, and the state
   node computes priorities with the asset's own facts. Identical components on many assets are matched once.
4. **Every node keeps the summaries table, including a node with its own mirror.** Without it, reports follow two
   code paths, and state on PostgreSQL (roadmap R6) cannot join a SQLite mirror at all.
5. **Roles are declared, not inferred.** A node becomes a mirror for others only through configuration, never
   because its state happens to be empty.

Effort (estimate): about 14 to 18 person-weeks beyond the security base of roadmap R5 (§7). Phase P0 (§7) is worth
doing first even without a network: it makes a sync update existing findings, which no version does today.

## 1. Context

| Fact (2026-11-12) | Where |
|---|---|
| State and mirror are two SQLite files, with no foreign key and no Store query across them. | [rust data-model](../../rust/_docs/tech/data-model.md) R1 |
| The Python engine module opens state read-only and **ATTACHes** the mirror. Matching and reports join across the two in one connection. | `rust/python/src/secmonk_modules/db.py` `open_readonly` |
| Matching runs many small queries per component: `affected` by `(ecosystem, package)` and by `(product, vendor)`, then alias closure, `vulnerability`, `kev`, `epss` and `distro_triage` per match. | `src/secmonk/engine/match.py` |
| A match depends on the component alone: its identity and the identity keys of its `meta` (`source_package`, `source_version`, `product`, `product_source`, `product_alts`, `vendor_alts`, `vendor_hint`, `brew_kind`, `brew_name`, `patched_cves`, `confidence`). Scoring also reads the asset's `meta` (exposure). | `engine/match.py`, `engine/scoring.py` `priority` |
| Matching runs after a scan, on a cache reuse and on demand. **A sync never updates existing findings.** | `ops.py`, `POST /api/assets/match` |
| Sources emit `secmonk-mirror-rows/1` batches. `apply_rows` records `seq` and `generation` per source in `source_applied`, skips a batch already applied and answers `needs_repair` when a batch does not fit. `begin_repair` rewrites one source; `rows_page` reads a source page by page. | rust ADR-0010, 0011, 0012 |
| `engine.match` has an ephemeral mode: it matches an inventory held in TEMP tables and stores nothing. | [contracts](../../rust/_docs/tech/contracts.md) |
| Routes that read the mirror: overview, asset detail, SBOM with vulnerabilities, findings (joins), `vulns/show`, `vulns/search`, `sources`. | [api-contract](../../rust/_docs/tech/api-contract.md) |
| The earlier proposal plans "one mirror per engine, synced by that engine" and leaves export to another engine for later. | [port proposal §7](2026-11-08-port-to-compiled-stack.md#7-operations-across-hops) |

## 2. The idea, as proposed

- A node has a state part and may host a mirror. With an empty state it acts as a pure mirror.
- A node with a mirror offers a **mirror provider** (here: **feed**), which lets other mirrors use it as a source,
  and a **match service** for nodes with state only.
- `match`: the client sends components and its last version per source. The mirror returns, per component, the ids
  of the vulnerabilities that came after that version, and the new versions.
- `summary`: the client sends vulnerability ids and gets their summaries back in batch.
- A state-only node scans its own inventory, calls `match` and `summary`, and caches the summaries for the UI.
- Any mirror can sync from any other mirror by sending its last version per source.
- A node with both parts uses the same match approach internally and keeps no summary cache.
- Every call between nodes is authenticated and authorized.

## 3. Feedback and adjustments

### 3.1 Roles and names

| Role | Name | What it does |
|---|---|---|
| state | `state` | inventory, findings, jobs, node identity, credentials, audit log; present on every node |
| mirror | `mirror` | imports sources, or follows a feed |
| mirror → mirror | **`feed`** (a node *publishes* a feed; another node *follows* it, and the publisher is its *upstream*) | serves row batches and snapshots |
| mirror → state | **`match`** | matches batches of components |
| mirror → state | **`vulninfo`** | summaries by id, plus detail and search for `vulns/show` and `vulns/search` |

Roles are switched on in `sec-monk.toml` (`[node] serve = ["feed", "match", "vulninfo"]`, a listen address, the
allowed clients). A pure mirror is a node with a mirror and no scan targets. It still keeps a state database for its
jobs, its identity and its audit log. **An empty state never opens a listener by itself**: a fresh install of a
scanning node must not start serving.

### 3.2 Versions carry their origin

`seq` and `generation` are local to the node that applied them. Through a chain of followers they must stay
comparable, so a version names the node that ran the importer:

```
MirrorVersion = { matcher: "<match logic version>",
                  sources: { "<source>": { origin: "<node id>", generation: "<uuid>", seq: <n> } } }
```

- A follower **re-publishes batches unchanged**, with the origin, generation and seq it received. Any node that
  carries the same origin can then serve the same delta, so a follower can fail over between them.
- A generation is a new UUID at each repair or reset on the origin. Today's constant `native-rust` is not enough
  between nodes.
- A different `matcher` value (a fix in version comparison, a new matching rule) invalidates every earlier match.
  The data did not change, but the answers did. **Mirror data alone cannot express this.**
- Each source is followed from **one origin at a time** (a tree, not any-to-any). If two nodes import the same source,
  those are two origins, and a follower picks one per source. Switching origin means one resync of that source.

### 3.3 Stateless match plus a `changes` call

The proposed `match(components, since)` has three problems:

1. "Vulnerabilities after version V" cannot express a **removal**: a withdrawn or rejected record, a corrected
   `fixed` version, a narrowed range, a new distro triage that says `not-affected`.
2. Canonicalization crosses sources. A new OSV alias can change the canonical id of a match that came from cvelist.
   A per-source "since" does not tell which components changed.
3. Each poll sends the whole inventory. That is bandwidth, and it shows the mirror the full software list again every
   time.

Recommended shape:

| Call | Request | Response |
|---|---|---|
| `match.components` | up to 1 000 components: identity plus the allowlisted identity keys of §1, no asset id, no path, no user | per component key: the **complete** match set (`vuln_id`, `advisory_ids`, `matched_by`, `confidence`, `fixed_version`, `triage`, `triage_source`), the **lookup keys** used (`pkg:<ecosystem>/<package>`, `prod:<product>`), `as_of`, `coverage` |
| `match.changes` | `since: MirrorVersion` | the lookup keys touched since `since`, the vulnerability ids whose summary changed, `as_of`; or `resync` when an origin, generation or matcher differs or the log no longer reaches `since` |
| `vulninfo.summaries` | up to 500 ids, optional `since` | per id: aliases, summary, dates, `withdrawn`, severity, CVSS (score, vector, version), CWEs, KEV, EPSS, up to 20 references; with `since`, only the changed ones |
| `vulninfo.detail` / `vulninfo.search` | as routes 12 and 13 | as today's `vuln-detail` and `vuln-search-page`; passed through, not cached |
| `feed.status` | — | per source: origin, generation, seq, last sync, status, records; the oldest seq still in the log |
| `feed.batches` | `source`, `origin`, `generation`, `after_seq`, `limit` | a stream of `secmonk-mirror-rows/1` batches, unchanged; or `resync` |
| `feed.snapshot` | `source` | the source's rows page by page (`rows_page`) at one version, which the follower applies with `begin_repair` … `commit(high_water, generation)` |

Notes:

- **The server returns the lookup keys.** The state node stores them and intersects them with `match.changes`, so it
  never has to compute keys itself. Normalization (`purl.normalize_name`, product candidates, brew names, vendor
  alternatives) stays in one place, on the mirror.
- The client asks only with `confidence` returned, and applies `min_confidence` itself. A stored match then serves any
  threshold.
- **`coverage`** lists the sources and ecosystems the answer covers. A mirror that follows only some ecosystems must
  not let a client read "no match" as "not vulnerable".
- On the mirror, the change log is fed by `apply_rows`. In the batch's transaction it writes the lookup keys of every
  upserted `affected` or `distro_triage` row, and of every row a `{source, vuln_id}` delete removes (read before the
  delete). A `vulnerability` row whose `state` or `withdrawn` changes touches the keys of its `affected` rows. KEV and
  EPSS changes touch summaries only, never matches.

### 3.4 Matching per component, scoring per asset

A match depends on the component, not the asset (§1). Moving priority to the state side follows from that:

```
finding(asset, component, vuln) = component_match(component, vuln)      -- from the match service, per component key
                                  x vuln_summary(vuln)                    -- cvss, epss, kev, severity
                                  x scoring.priority(..., asset.meta)     -- on the state node, with the asset's exposure
                                  + lifecycle (open / fixed / suppressed) -- on the state node, as today
```

- Identical components across a fleet (the same Debian package on 500 hosts) are sent and matched **once**. A
  mirror can also cache answers by `(component identity hash, as_of)` across its clients.
- The lifecycle stays in state. Comparing an asset's new finding set with its open findings is a local step, as
  `match_asset` does today.

### 3.5 Every node keeps the summaries

The proposal leaves the summary cache out of a node that has both parts. Keeping it there is recommended:

| Without `vuln_summary` on a node with both parts | With it on every node |
|---|---|
| Reports join state and mirror (ATTACH) on that node, and read the cache on state-only nodes: two code paths and two behaviours | one report code path that reads state only |
| State on PostgreSQL (R6) cannot join a SQLite mirror | works |
| — | cost: one row per distinct vulnerability that findings refer to (thousands), filled in process on a node with both parts |

It is the state's own copy of the vulnerabilities it refers to, refreshed by `as_of`, not a network cache with a TTL.
`finding` already copies `severity`, `cvss_score`, `epss` and `kev`; the table adds what the views show (summary,
dates, aliases, vector, references).

### 3.6 One interface, two implementations

`MatchService`, `VulnInfo` and `Feed` are Rust traits in `secmonk-traits`, the same pattern as the Store traits:

- **in process** on a node with both parts: direct calls, no serialization;
- **remote** over the authenticated binding of §5.

One conformance suite runs against both implementations. That suite is what guarantees "the same behaviour with an
internal or an external mirror".

## 4. Flows

```
 mirror node M (feed upstream)          mixed node X                         state-only node S
 sources -> apply_rows -> feed_log  ==> follows M: feed.batches -> apply_rows
            + mirror_change            match/vulninfo in process             scan -> match.components (remote, X or M)
            serves feed/match/vulninfo  serves match/vulninfo to S  <======   vulninfo.summaries -> vuln_summary
```

| Flow | Pure mirror | Node with both parts | State-only node |
|---|---|---|---|
| Sync | imports sources (or follows a feed); writes `feed_log` and `mirror_change` | the same | — |
| Scan | — | collect → classify → save → `match.components` (in process) for keys without a current match → findings → summaries | the same, with remote calls |
| After a mirror update | — | `match.changes(since)` in process → re-match only the components whose lookup keys were touched → re-score findings whose summaries changed | `match.changes` polled or pushed → the same |
| Reports | `vulninfo` only | state only | state only, plus `vulninfo.detail` / `search` passed through |

## 5. Security

Every call between nodes is authenticated, authorized, limited and logged. This builds on the identities of the
[port proposal §6](2026-11-08-port-to-compiled-stack.md#6-security-model).

| Topic | Rule |
|---|---|
| Identity | A key pair per node with a stable id (`node:<hash of key>`). mTLS between nodes; the upstream's certificate is pinned. |
| Authorization | Scopes per client: `feed:read`, `match`, `vulninfo:read`, granted by the serving node's admin and revocable. There is no anonymous mode, and no listener opens without a configured client. |
| Limits | Per-client quotas (components per minute, calls per minute) and per-call caps: 1 000 components, 500 ids, a byte cap per frame. Requests are validated against JSON Schema like module input. |
| Data minimization | `match.components` carries only component identity and the allowlisted identity keys: no asset id, hostname, path, user or label. It still reveals a tenant's software set, so the serving node **never stores request bodies**; its audit log holds client, call, count and time. A tenant that does not accept this follows a feed instead (§6, option C). |
| Untrusted input both ways | The serving node treats requests as untrusted. A follower treats batches as untrusted: `apply_rows` keeps its allowlists, source binding and validation. |
| Integrity | TLS first. Later, each batch is signed by its origin's key so a relay cannot alter it. A trusted upstream can still **omit** data: trust is explicit, per upstream. |

## 6. Options and costs

| | A. Remote SQL from state | B. Match service only | C. Feed only (replica on every engine) | **B + C (this proposal)** |
|---|---|---|---|---|
| Scan latency | about 10 000 round trips for 2 000 components: seconds on a LAN, minutes on a WAN | one round trip per 1 000 distinct components | local, as today | in process on nodes with a mirror; one round trip per batch on state-only nodes |
| After a mirror update | everything again | everything again (whole inventory sent) | local `changes`, re-match only touched keys | the same as C, for state-only nodes too |
| Disk per engine | none | none | a replica (size **(verify)**: `raw_record`, verbatim JSON, is probably most of it and need not be replicated) | a replica only where a mirror is wanted |
| Inventory leaves the node | yes, as queries | yes | no | only from state-only nodes, to a mirror they trust |
| Upstream feed traffic | — | — | the first snapshot, then batches; EPSS replaces about 400 000 rows a day and dominates ([source-epss](../../rust/_docs/tech/source-epss.md)) | the same, for followers only |

Estimated steady cost of a state-only node (rough, to measure): each `match.changes` poll returns the keys touched
since the last one. Matching then covers only the intersecting components, a few KB to MB a day. Summary refresh
covers the node's own vulnerability ids: EPSS changes almost all of them every day, about 1 MB for a few thousand ids.
To keep EPSS off a feed, a follower can import EPSS from FIRST directly, or the feed can send only score changes
larger than a threshold.

## 7. Effort

Rough estimates in person-weeks, on top of the R5 security base (identities, mTLS, tokens, roles).

| Phase | Content | Estimate |
|---|---|---|
| P0, local split | `MatchService` / `VulnInfo` traits with the in-process implementation; state tables `component_match` (with lookup keys and `as_of`) and `vuln_summary`; a finding builder (component matches × summaries × scoring × lifecycle); `mirror_change` written by `apply_rows`; re-match after a sync. Prototype path: run `match.components` as an ephemeral match of a synthetic inventory and regroup by component key. Reports that join the mirror keep ATTACH until they are ported to read `vuln_summary`; a Rust port, because `src/` is not changed. | 4 to 5 |
| P1, versions | `origin` and a UUID generation in `source_applied`; the `matcher` version; `feed_log` with retention; `match.changes` | 2 |
| P2, binding | the authenticated binding for the `feed`, `match` and `vulninfo` methods, scopes, quotas, audit (service part only) | 2 |
| P3, state-only node | remote implementations, polling or push of `changes`, state-only configuration, the passed-through `vulns/show` / `search` / `sources` | 2 to 3 |
| P4, feed | `feed.status` / `batches` / `snapshot`, following with repair, re-publishing, per-source upstream in `sec-monk.toml` | 3 to 4 |
| P5, hardening | partial (ecosystem-filtered) replicas with `coverage`, a match cache on the mirror, signed batches | 2 to 3 |

Total: about 14 to 18 person-weeks. P0 and P1 need no network and help the single-process app. P2 to P5 belong to
roadmap R5, after its security base.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Lookup keys miss a case, so a change is not seen | keys come from the server (§3.3); a periodic full re-match (for example weekly) as a safety net; differential test: incremental against full match on the same fixtures |
| Version skew between nodes (matcher, row format) | `matcher` in `MirrorVersion`; the row format is a versioned contract, extended compatibly and validated on load |
| A trusted mirror hides vulnerabilities from its clients | explicit trust per upstream; signed batches (P5); `coverage` in every answer |
| The serving node learns tenants' inventories | identity allowlist, no stored bodies, feed-follow as the alternative |
| Redistributing feed data to other organizations | licences differ per source (some OSV sources ask for attribution): check each source before serving outside one organization |
| Two caches drift (`component_match`, `vuln_summary`) | both carry `as_of`; `match.changes` answers `resync` when it cannot cover the gap |

## Recommendation

Accept the B + C design with the adjustments of §3. Start with P0 and P1 inside the single-process app; they fix the
missing re-match after a sync and make the state database self-contained. Then add the network services with roadmap
R5. When accepted: one rust ADR for node roles and versions, one for the `match` / `vulninfo` / `feed` contract,
plan items in [rust roadmap](../../rust/_docs/plans/roadmap.md) and [backlog](../../rust/_docs/plans/backlog.md), and an
amendment to [rust data-model](../../rust/_docs/tech/data-model.md).

## Open questions

1. Names: `feed`, `match`, `vulninfo`? "Upstream" and "follower" for the feed?
2. May a mirror serve another organization (multi-tenant), or only nodes of the same organization (roadmap D5)?
3. Is a state-only node allowed to send its software list to a mirror, or must every engine follow a feed?
4. Should `raw_record` be part of the feed? It is needed for `vulns/show?raw=1` on a follower, and it is probably most
   of the volume.
5. Is `match.changes` polled by the client or pushed by the server? How long does `feed_log` keep batches before a
   follower must take a snapshot?
6. Should a mirror cache match answers across clients (§3.4), given that it would then keep inventory-derived data?
