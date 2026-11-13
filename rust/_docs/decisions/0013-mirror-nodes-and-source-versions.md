---
title: ADR-0013 — Mirror nodes - state and mirror parts, upstream source versions, match / vulninfo / feed services
summary: "Accepts the 2026-11-12 mirror-nodes proposal (B + C) for the Rust app, phases P0-P4: roles declared in sec-monk.toml, a source's version is its upstream cursor plus the importer version, MatchService / VulnInfo / Feed traits with an in-process and an HTTP implementation, lowercase lookup keys, per-component matching, re-match after a sync."
read_when: you change node roles, source versions, the match / vulninfo / feed services or their binding, or need why a sync now re-matches stored assets
type: decision
context: decisions
status: accepted
tags: [architecture, distributed, matching, data-model, decision, rust]
updated: 2026-11-13
verified: 2026-11-13
related: [plans/node-server-design.md, decisions/0014-server-mode-auth-and-ui-transport.md, tech/data-model.md, tech/node-api.md, tech/engine-service.md, decisions/0010-source-staging-adapter.md, decisions/0011-native-sources.md]
---

# ADR-0013 — Mirror nodes

## Context

The proposal [mirror nodes](../../../_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md) (2026-11-12, Rust
only) splits a node into a **state** part (inventory, findings, jobs) and an optional **mirror** part (vulnerability
data). A mirror serves a **feed** to other mirrors and **match** / **vulninfo** to state-only nodes. On 2026-11-13 the
user asked to implement it, together with a server mode ([ADR-0014](0014-server-mode-auth-and-ui-transport.md)).

## Decision

Accept design B + C of the proposal, phases P0 to P4. P5 (ecosystem-filtered replicas, a match cache on the mirror,
signed rows, the hash-prefix mode, Bloom-filtered `changes`) is not built.

1. **Roles are configuration** (`[node] mirror`, `serve = ["feed", "match", "vulninfo"]`, `matcher = "local" |
   "remote"`, `[node.upstream]`); an empty state never opens a listener.
2. **A source's version is `(source, upstream version, importer version)`**, plus one `MATCHER_VERSION` per node.
   The upstream version is the source's cursor in `source_sync` (`status = 'ok'` only), or the value recorded in
   `source_version` after a complete sync. A `partial` run never moves it. The wire form is `<importer>@<version>`.
   Native importers declare `importer_version` in `secmonk_sources::IMPORTERS`; module sources are `python/1`; a
   followed source carries the upstream's importer, so a follower can serve the same versions further down.
3. **Three traits in `secmonk-traits::node`** (`MatchService`, `VulnInfo`, `Feed`) with two implementations: in process
   (`secmonk_engine::node::LocalNode`, over `MirrorNodeStore`, the py-engine `Matcher` and `Reporter`) and remote
   (`secmonk_node::RemoteNode`, HTTPS). The HTTP binding is `/node/v1` ([node-api](../tech/node-api.md)).
4. **`match.components`** is an ephemeral match of a synthetic inventory, regrouped by component key (the proposal's
   prototype path); it returns, per component, the complete match set and the **lookup keys**.
5. **Lookup keys are lowercase on both sides**: `pkg:<ecosystem>/<package>` and `prod:<product>`. The mirror derives
   the keys of changed records from `affected`; the server derives a component's keys as a superset of the matcher's
   candidates. A false positive costs one re-match, never correctness.
6. **`match.changes(since)`** answers per source: changed ids and keys, `unchanged`, or `resync` (new source, importer
   changed, too many changes, no diff log); a matcher change resyncs everything.
7. **Feed pages** reuse `secmonk-mirror-rows/1`: per-record replace units for record sources (delta since a version
   minus an overlap of one hour) and snapshot pages for kev, epss, debian-tracker. A follower localizes a delta
   (`MirrorNodeStore::localize_feed_batch`) before `apply_rows`; following is a native `Source` (`FeedSource`).
8. **A sync re-matches stored assets whose components it hits** (P0), through the in-process `changes`.
9. **A state-only node matches through `NodeMatcher`**, a `Matcher` over a `MatchService` + `VulnInfo` with the
   `component_match`, `component_lookup`, `vuln_summary` cache tables; scoring (`priority`) stays on the state node.

## Alternatives

- **Remote SQL from the state node** (proposal option A): thousands of round trips per scan, the inventory leaves the
  node as queries. Rejected.
- **A local change counter instead of upstream versions**: ties a follower to one upstream and makes two independent
  importers incomparable. Rejected (proposal §3.2).
- **mTLS identities between nodes now**: replaced by API keys exchanged for JWTs over TLS (ADR-0014), behind the
  auth-provider chain, so an mTLS provider can be added without changing the node API.

## Consequences

- Schema: mirror migration 0004 (`source_version`, `snapshot_diff`, index `vulnerability(source, modified)`), state
  migration 0002 (`component_match`, `component_lookup`, `vuln_summary`, `node_sync`) ([data-model](../tech/data-model.md)).
- Deleted upstream records are not propagated by a delta (no tombstones), only by a resync; per-document sources
  (msrc) and records without `modified` travel only in full copies.
- The served data of other organizations is subject to each source's licence (proposal §8): a node serves one
  organization until that is checked.
- Open questions 2–6 of the proposal stay open; `match.changes` is polled by the client.
