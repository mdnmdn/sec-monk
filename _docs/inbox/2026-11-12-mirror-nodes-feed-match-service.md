---
title: Proposal — mirror nodes for the Rust version (feed, match service, vulnerability summaries)
summary: Rust only - nodes with a state part and an optional mirror; a mirror serves a feed to other mirrors and a batch match and summary service to state-only nodes; upstream source versions, APIs, flows, costs, security, effort.
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

- a **feed**: other mirrors follow it instead of syncing the vulnerability sources themselves;
- a **match service**: a node without a mirror matches batches of components and asks for **summaries** of the
  vulnerabilities found.

A node with both parts calls its own mirror through the same interface, in process. Every call between nodes is
authenticated and authorized.

The design reuses what the Rust version already has: the per-source cursors, the row batches, `apply_rows`, repair
and the ephemeral match. Settled points:

1. **A source's version is its upstream version**: the cursor each source already keeps (KEV `catalogVersion`, EPSS
   `score_date`, NVD `lastModified`, OSV `modified` per ecosystem, cvelist git HEAD, the Debian ETag or hash). It is
   the same on every node that imported the same upstream state, so it needs no node id. Conditions are in §3.2.
2. **Two match calls; the inventory is sent once.** `match.components` is stateless and returns, besides the matches,
   the lookup keys it used. `match.changes(since)` returns only what changed upstream. The client intersects that with
   its stored keys and matches again only the components hit (§3.3).
3. **Matching per component, scoring per asset.** Identical components on many assets are matched once.
4. **Summaries behind one interface**: `summaries(ids)` reads the local cache table on a state-only node and calls
   the mirror part on a node with both. The reports already read findings first and then vulnerabilities by id (§3.5).
5. **Roles are declared in configuration**, never inferred from an empty state.

Effort (estimate): about 12 to 16 person-weeks beyond the security base of roadmap R5 (§7). Phase P0 needs no network
and makes a sync update existing findings, which no version does today.

## 1. Context

| Fact (2026-11-12) | Where |
|---|---|
| State and mirror are two SQLite files, with no foreign key and no Store query across them. | [rust data-model](../../rust/_docs/tech/data-model.md) R1 |
| The Python engine module opens state read-only and ATTACHes the mirror. **Matching** joins both in one connection. **Reports** read findings and components from state, then vulnerability, KEV, EPSS and affected rows **by id** (`engine/queries.py`); only `vulns/search` and `vulns/show` query the mirror alone. | `rust/python/src/secmonk_modules/db.py` `open_readonly`, `src/secmonk/engine/queries.py` |
| Matching runs many small queries per component: `affected` by `(ecosystem, package)` and `(product, vendor)`, then alias closure, `vulnerability`, `kev`, `epss`, `distro_triage` per match. | `src/secmonk/engine/match.py` |
| A match depends on the component alone: its identity plus identity keys of its `meta` (`source_package`, `source_version`, `product`, `product_source`, `product_alts`, `vendor_alts`, `vendor_hint`, `brew_kind`, `brew_name`, `patched_cves`, `confidence`). Scoring also reads the asset's `meta` (exposure). | `engine/match.py`, `engine/scoring.py` `priority` |
| Matching runs after a scan, on a cache reuse and on demand. **A sync never updates existing findings.** | `ops.py`, `POST /api/assets/match` |
| Every source keeps an upstream-derived cursor in `source_sync` (catalog version, score date, ETag or content hash, git HEAD, NVD and OSV modified times). A `partial` run moves `last_sync` but not always the cursor. | `db.py` `set_sync_state`, `rust/_docs/tech/source-*.md` |
| Sources emit `secmonk-mirror-rows/1` batches; `apply_rows` records `seq` / `generation` per source and answers `needs_repair`; `begin_repair` rewrites one source; `rows_page` pages through a source. | rust ADR-0010, 0011, 0012 |
| `engine.match` has an ephemeral mode: it matches an inventory in TEMP tables and stores nothing. | [contracts](../../rust/_docs/tech/contracts.md) |

## 2. The idea, as proposed

- A node has a state part and may host a mirror; with an empty state it acts as a pure mirror.
- A node with a mirror offers a **mirror provider** (here: **feed**), a source for other mirrors, and a **match
  service** for nodes with state only.
- `match`: the client sends components and its last version per source; the mirror returns the vulnerability ids per
  component that came after that version, and the new versions.
- `summary`: vulnerability ids in, summaries out, in batch.
- A state-only node matches its inventory remotely and caches summaries for the UI. A node with both parts uses the
  same calls in process and reads summaries from its mirror part.
- Any mirror can sync from any other by sending its last version per source.
- Every call between nodes is authenticated and authorized.

## 3. Design

### 3.1 Roles and names

| Role | Name | What it does |
|---|---|---|
| state | `state` | inventory, findings, jobs, node identity, credentials, audit log; present on every node |
| mirror | `mirror` | imports sources, or follows a feed |
| mirror → mirror | **`feed`** (a node *publishes* a feed; another *follows* it; the publisher is its *upstream*) | serves source rows since a version |
| mirror → state | **`match`** | `match.components`, `match.changes` |
| mirror → state | **`vulninfo`** | `summaries` by id; `detail` and `search` for `vulns/show` and `vulns/search` |

Roles are switched on in `sec-monk.toml` (`[node] serve = ["feed", "match", "vulninfo"]`, a listen address, the
allowed clients). A pure mirror is a node with a mirror and no scan targets; it still has a state database for jobs,
identity and audit. **An empty state never opens a listener by itself.**

### 3.2 A source's version is its upstream version

The version of a source is what the upstream published, not a local counter:

| Source | Version | Kind | Delta "since V" |
|---|---|---|---|
| nvd | `lastModified` high-water | per record | records with `modified > V` |
| osv | `modified` high-water per ecosystem (`osv:<Eco>`) | per record | records of that ecosystem with `modified > V` |
| cvelist | `dateUpdated` high-water (git HEAD as the identity of the state) | per record | records with `modified > V` |
| euvd | `dateUpdated` high-water **(verify)** | per record | records with `modified > V` |
| msrc | latest monthly document and revision **(verify)** | per document | documents newer than V |
| kev | `catalogVersion` | snapshot | the whole catalog (about 1 500 entries) |
| epss | `score_date` (and model version) | snapshot | the whole file, or a diff (§6) |
| debian-tracker | ETag, else `Last-Modified`, else content hash | snapshot | a diff kept by the serving node (below) |

The version becomes `(source, upstream version, importer version)`, together with one `matcher` version for the node.
It is the same on every node that read the same upstream state, so **any node can serve any other**. A follower can
change upstream without a resync, and two nodes that import the same source on their own stay comparable. The
local `seq` and `generation` stay as they are, for batches inside one node.

Conditions:

1. **Only complete imports move the version.** On a `partial` run the version moves only up to the oldest skipped
   record; today `last_sync` moves on `partial`.
2. **The importer version is part of it.** Two importers can read the same upstream and write different rows (a
   Rust port, a normalization fix). A different importer version means a resync of that source.
3. **Upstream clocks are not exact.** A record can appear with a `modified` slightly below the high-water. Every
   delta reads from `V - overlap` (for example 1 hour). Records are replaced whole, so the overlap is harmless.
4. **Per-record deltas need no change log.** `vulnerability.modified` and `raw_record.modified` are stored per
   record; an index `(source, modified)` is added. A changed record is sent whole: a delete per `{source, vuln_id}`,
   then its rows, as `replace_children` already does.
5. **Snapshot sources keep a small diff log**, keyed by version, for the last few versions. The native importers
   compute that diff already (debian-tracker's paged compare). An older client gets the whole snapshot.
6. **A `matcher` change** (a fix in version comparison, a new rule) invalidates every earlier match even though no
   data changed.

### 3.3 Two match calls: the inventory is sent once

| Call | Request | Response |
|---|---|---|
| `match.components` | up to 1 000 components: identity plus the identity keys of §1, no asset id, no path, no user | per component key: the **complete** match set (`vuln_id`, `advisory_ids`, `matched_by`, `confidence`, `fixed_version`, `triage`, `triage_source`), the **lookup keys** used (`pkg:<ecosystem>/<package>`, `prod:<product>`), `as_of` (the versions), `coverage` (sources and ecosystems covered) |
| `match.changes` | `since`: the versions of the client's last answer | the **lookup keys** of the rows changed since then, the **vulnerability ids** changed since then, the new versions; `resync` for a source whose importer or matcher version changed |

**How the client avoids sending its inventory:**

```
first scan     client --components (distinct keys, once)--> match.components --> matches + lookup keys
               client stores: component_match (matches) and component_lookup (component -> lookup keys)

later          client --since (versions only, no component)--> match.changes --> changed keys K, changed vuln ids I
               client, locally:  hit = components whose lookup keys are in K
                                     + components that have a match on an id in I
               client --only the hit components--> match.components --> their new complete sets
```

- `changes` carries **no inventory**: the request holds versions only, and the intersection runs on the client.
- **Removals are covered.** A record that stops matching (withdrawn, range narrowed, `not-affected`) is in `I`, and the
  client already holds a match on it. A record that starts matching has an `affected` row whose key is in `K`.
- A new asset sends only component keys that have **no current match** at the current versions. Components shared
  with assets already scanned are not sent again.
- **The server returns the lookup keys.** The client never computes them, so normalization (`purl.normalize_name`,
  product candidates, brew names, vendor alternatives) lives only on the mirror. Coarse keys (`prod:<product>`
  without vendor) give a safe superset.
- Size: one `changes` answer is the keys and ids touched since the last poll, typically KB to a few hundred KB a day
  (to measure). A Bloom filter of the keys is an option if it grows.
- What the server still learns: the components the client sends on a first scan and on a hit. A stricter client
  can ask by **hash prefixes of lookup keys** and match locally on the rows returned (as password-breach range
  queries do). That puts the matcher on the client, which every node has anyway (py-engine). It is a later option, §6.
- The client asks with `confidence` included and applies `min_confidence` itself, so one stored match serves any
  threshold.
- `coverage` keeps a partial mirror's "no match" from being read as "not vulnerable".

### 3.4 Matching per component, scoring per asset

```
finding(asset, component, vuln) = component_match(component, vuln)     -- match service, per component key
                                  x summaries(vuln)                     -- cvss, epss, kev, severity
                                  x scoring.priority(..., asset.meta)   -- state node, the asset's exposure
                                  + lifecycle (open / fixed / suppressed), as today
```

The same Debian package on 500 hosts is sent and matched **once**. The lifecycle stays on the state node.

### 3.5 Summaries behind one interface

`VulnInfo::summaries(ids) -> [summary]` has two implementations, chosen by the node's configuration:

| Node | Implementation |
|---|---|
| state and mirror | a call to the mirror part; no copy |
| state only | the `vuln_summary` table in state, filled on a miss with remote `vulninfo.summaries`, refreshed for the ids in `match.changes` |

This fits the reports as they are: they read findings and components from state, then vulnerability, KEV and EPSS
rows **by id** (`engine/queries.py`); they never join across the two databases. Sorting and filtering use columns
`finding` already copies (`severity`, `cvss_score`, `epss`, `kev`, `priority`), and `summaries(ids)` serves the rows
of one page. The rule this keeps: **no report query joins state and mirror tables.** That rule is also what lets
state move to PostgreSQL (R6). `vulns/search` and `vulns/show` go to `vulninfo.search` / `detail`, uncached.

### 3.6 One interface, two implementations

`MatchService`, `VulnInfo` and `Feed` are Rust traits in `secmonk-traits` (the pattern of the Store traits): in
process on a node with both parts, remote over the binding of §5. **One conformance suite runs against both**; it is
what guarantees the same behaviour with an internal or an external mirror.

## 4. Flows

```
 mirror node M                          node X (state + mirror)               state-only node S
 sources -> apply_rows                  follows M: feed.since(versions)
 serves feed / match / vulninfo          -> apply_rows                        scan -> match.components (remote: X or M)
                                         match / vulninfo in process           summaries -> vuln_summary
                                         serves match / vulninfo to S <=====  match.changes -> re-match the hit components
```

| Flow | Pure mirror | Node with both parts | State-only node |
|---|---|---|---|
| Sync | imports sources, or follows a feed with its versions | the same | — |
| Scan | — | collect → classify → save → `match.components` (in process) for keys without a current match → findings | the same, remote |
| After a mirror update | — | `match.changes(since)` in process → re-match hit components → re-score findings whose summaries changed | `match.changes` polled or pushed → the same |
| Reports | `vulninfo` | state + `summaries(ids)` from the mirror part | state + `summaries(ids)` from `vuln_summary` |

## 5. Security

Builds on the identities of the [port proposal §6](2026-11-08-port-to-compiled-stack.md#6-security-model).

| Topic | Rule |
|---|---|
| Identity | A key pair per node with a stable id (`node:<hash of key>`); mTLS between nodes; the upstream's certificate is pinned. |
| Authorization | Scopes per client: `feed:read`, `match`, `vulninfo:read`, granted by the serving node's admin and revocable. No anonymous mode; no listener without a configured client. |
| Limits | Quotas per client (components and calls per minute); caps per call (1 000 components, 500 ids, bytes per frame); requests validated against JSON Schema like module input. |
| Data minimization | `match.components` carries component identity and the allowlisted identity keys only: no asset id, hostname, path, user or label. The serving node **never stores request bodies**; its audit log keeps client, call, count, time. |
| Untrusted input both ways | The server treats requests as untrusted; a follower treats rows as untrusted (`apply_rows` keeps its allowlists and source binding). |
| Integrity | TLS first. Later, rows signed by the node that imported them. A trusted upstream can still **omit** data: trust is explicit, per upstream. |

## 6. Options and costs

| | A. Remote SQL from state | B. Match service only | C. Feed only | **B + C (this proposal)** |
|---|---|---|---|---|
| Scan latency | about 10 000 round trips for 2 000 components: seconds on a LAN, minutes on a WAN | one round trip per 1 000 distinct components | local | in process with a mirror; one round trip per batch without |
| After a mirror update | everything again | the whole inventory again | local, touched keys only | `changes` + the hit components only |
| Disk per node | none | none | a replica (size **(verify)**; `raw_record` is probably most of it and is optional) | a replica only where a mirror is wanted |
| Inventory leaves the node | yes, as queries | yes, at every poll | no | on first match and on hits only; hash-prefix mode later |
| Feed traffic | — | — | records since the version; EPSS replaces about 400 000 rows a day ([source-epss](../../rust/_docs/tech/source-epss.md)) | the same, for followers |

EPSS on a feed: a follower can import EPSS from FIRST directly, or the feed sends only scores that moved more than a
threshold. On a state-only node, the summaries of its own ids change daily through EPSS: about 1 MB for a few
thousand ids (estimate).

## 7. Effort

Rough estimates in person-weeks, on top of the R5 security base (identities, mTLS, tokens, roles).

| Phase | Content | Estimate |
|---|---|---|
| P0, local split | `MatchService` / `VulnInfo` traits, in-process implementation; state tables `component_match`, `component_lookup`, `vuln_summary`; a finding builder (component matches × summaries × scoring × lifecycle); `match.changes` in process; re-match after a sync. Prototype path: `match.components` as an ephemeral match of a synthetic inventory, regrouped by component key. Reports read summaries through `VulnInfo`: a Rust port, since `src/` is not changed. | 4 to 5 |
| P1, versions | the upstream version per source with the importer version and the rules of §3.2; index `(source, modified)`; diff log for snapshot sources; the `matcher` version | 1 to 2 |
| P2, binding | authenticated binding for `feed`, `match`, `vulninfo`; scopes, quotas, audit | 2 |
| P3, state-only node | remote implementations, `vuln_summary` fill and refresh, polling or push of `changes`, passed-through `vulns/show` / `search` / `sources` | 2 to 3 |
| P4, feed | `feed.status` / `feed.since` from the tables, following, per-source upstream in `sec-monk.toml` | 2 to 3 |
| P5, hardening | ecosystem-filtered replicas with `coverage`, a match cache on the mirror, signed rows, the hash-prefix mode | 2 to 3 |

Total: about 12 to 16 person-weeks. P0 and P1 need no network and help the single-process app. P2 to P5 belong to
roadmap R5.

## 8. Risks

| Risk | Mitigation |
|---|---|
| An upstream `modified` goes backwards or is not set | the overlap window; a periodic full compare per source (weekly); a source with no reliable `modified` is treated as a snapshot |
| A lookup key misses a case, so a change is not seen | keys come from the server; a periodic full re-match as a safety net; a differential test of incremental against full matching on the same fixtures |
| Version skew (importer, matcher, row format) | importer and matcher versions in the version; the row format is a versioned contract, extended compatibly |
| A trusted mirror hides vulnerabilities | explicit trust per upstream; signed rows; `coverage` in every answer |
| The serving node learns tenants' software | identity allowlist, no stored bodies, components sent once; hash-prefix mode or feed-follow for stricter tenants |
| Redistributing feed data to other organizations | licences differ per source (some OSV sources ask for attribution): check each before serving outside one organization |

## Recommendation

Accept the B + C design as in §3. Start with P0 and P1 inside the single-process app: they add re-matching after a
sync and remove the joins between state and mirror. Add the network services with roadmap R5. When accepted: a
rust ADR for node roles and source versions, one for the `match` / `vulninfo` / `feed` contract, plan items in
[rust roadmap](../../rust/_docs/plans/roadmap.md) and [backlog](../../rust/_docs/plans/backlog.md), and an amendment
to [rust data-model](../../rust/_docs/tech/data-model.md).

## Open questions

1. Names: `feed`, `match`, `vulninfo`? "Upstream" and "follower" for the feed?
2. May a mirror serve another organization (multi-tenant), or only nodes of one organization (roadmap D5)?
3. Is the hash-prefix match mode needed from the start for some tenants, or is feed-follow enough for them?
4. Is `raw_record` part of the feed? It is needed for `vulns/show?raw=1` on a follower and is probably most of the
   volume.
5. Is `match.changes` polled by the client or pushed by the server?
6. Should a mirror cache match answers across clients (§3.4), given that it then keeps data derived from inventories?
