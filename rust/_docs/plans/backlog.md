---
title: Backlog beyond the prototype
summary: "Backlog after the prototype: Rust migration order, distributed mode, other databases, uv as crates, ingest hardening, data import, docs tooling, and what the prototype left over."
read_when: you plan the next phases after the prototype works, or look for where a deferred item went
type: plan
context: plans
status: open
platform: any
tags: [plan, rust, migration]
updated: 2026-11-11
verified: 2026-11-11
related: [plans/roadmap.md, tech/architecture.md, tech/component-lifecycle.md, decisions/0002-rust-core-python-modules.md]
---

# Backlog beyond the prototype

Phases, order, entry/exit criteria and milestones for these items are proposed in the [roadmap](roadmap.md); the
items themselves stay here. Order follows the proposal §15 and [architecture § 9](../tech/architecture.md#9-prototype-boundary-and-migration-order).
Every port follows the [standard process](../tech/component-lifecycle.md) (golden → differential → config selects Rust).

## 1. Engine core to Rust (first)

- [ ] `secmonk-versions`: all schemes of `engine/versions.py` (PyPI, semver, Maven, Go, RubyGems, NuGet, Composer,
      Debian, RPM, Alpine, generic) + OSV range evaluation; differential test against `versions.*` on `py-engine` over
      every range in a full OSV mirror.
- [ ] `secmonk-purl` (normalization, OSV ecosystems) and `classify` (alias table, brew seed).
- [ ] `match` + `scoring` in Rust on the Store traits; differential test of `engine.match` finding sets.
- [ ] `reports.*` payloads in Rust with the Store queries they need; API parity test stays green; then retire the
      read-only grant ([rust ADR-0006](../decisions/0006-python-read-only-db-access.md)) and drop the JSON copies of
      promoted columns.

## 2. Probe to Rust (what the static probe binary needs)

- [ ] `secmonk-safeio` complete: `read_within`, `resolve_within`, safe tar/zip, redaction; Python `collectors/base`
      as the reference.
- [ ] `secmonk-lang` (7 ecosystems, Go/Rust binary identity), `fs`, `rootfs`.
- [ ] Process backends (Linux, macOS), split `py-procmon` at the snapshot: probe `process.snapshot`, engine
      `procmon.analyse`.
- [ ] Image layers (`docker-image`), `docker-engine`; then macOS, Homebrew, Windows collectors.
- [ ] Re-redaction and caps of module output on ingest (as `snapshot.from_dict` does).

## 3. Sources

- [ ] Native row emitters per source (no staging copy); drop the staging adapter
      ([rust ADR-0010](../decisions/0010-source-staging-adapter.md)). Sources may stay Python for good. **Partly done.**
  - 2026-11-11: kev native (rust ADR-0011); others still on staging.
- [ ] Seed the staging database and the v3 mirror from an existing Python `secmonk.db` (skip the first full sync).
- [ ] Measure row-stream throughput on a full OSV + CVE List sync (millions of row ops over JSON stdio, staging copy included; not
      measured, only the `kev` fixture ran end to end); add a compressed codec if needed.

## 4. Distributed mode

- [ ] `secmonk-probe` binary (`serve --stdio`), static musl build, signed; SSH exec stdio transport.
- [ ] TLS/WSS dial-out probes with enrollment (engine CA, one-time tokens), headless server with auth and roles.
- [ ] Federation in the desktop UI (several engines); OS overlay clients documented; RDP / embedded overlay last.
- [ ] Job cancel from the UI (`jobs.cancel`), several jobs at once, event push instead of polling.

## 5. Databases

- [ ] PostgreSQL backend for state (mirror stays SQLite), migrations in `postgres/`, Store conformance suite via
      testcontainers.
- [ ] MySQL/MariaDB only on request (key hashing for long text keys, `utf8mb4_bin`).

## 6. Runtime and packaging

- [ ] uv linked as crates behind `PythonRuntime` (evaluate only; uv crate API not stable).
- [ ] Release packaging: static UI and Python project as Tauri resources, pinned module hashes (`trust = "pinned"`),
      offline bundle (uv archive + wheels).
- [ ] Verify uv checksums against GitHub attestations in the release pipeline.

## 7. Docs and tooling

- [ ] Teach `scripts/docs.py` a second root (`rust/_docs`) for lint, index and drift; until then INDEX is by hand.
- [ ] Contract check script and Rust `schemars` export compared to `rust/contracts/schemas`.
- [ ] An API parity test: `secmonk ui` on a v2 database vs the desktop router on a v3 store built from the same fixtures
      ([api-contract](../tech/api-contract.md#parity-test)).

## 8. Left over by the prototype (docs pass 2026-11-11)

- [ ] **Module integrity gaps.** The `secmonk-tree/1` hash does not cover the path-dependency `secmonk` package (`../..`, installed
      non-editable in pinned mode) or the venv contents. Manifests carry no `integrity` of their own, so `trust = "pinned"` needs
      the `[modules.pins]` block printed by `scripts/pins.py` (in `rust/python`) copied into the config at release time.
- [ ] **`hello.session.grants` is strict.** `Grants` is `deny_unknown_fields` and the envelope schema closes it, unlike the rest
      of `hello`; a second grant would break older peers. Relax it (additive minors) before the first new grant.
- [ ] **Three error-path differences from the Python server** ([engine-service](../tech/engine-service.md#the-service)): a failed
      history insert at job start answers 500 (Python 503); the engine's own disabled-actions refusal is 400 (Python 403, hidden by
      the API's gate); a `save: false` scan without a database answers 409 with the new code `busy`. Align or accept in the parity test.
- [ ] **Per-module log files.** `logs/modules/` and `jobs/` are created but unused: module stderr goes to the main
      `secmonk-desktop.log.<date>`. Add `logs/modules/<name>.log`; use or drop `jobs/`. (The instance lock `run/instance.lock` and the
      default module list are done.)
- [ ] **epss host-side apply is slow**: about 72 s for 400k rows. Measure and speed up (batching, staging copy).
  - 2026-11-11: remeasured on an Apple M2: py-sources 16-18 s, native importer 5.3 s for 400k rows
    ([source-epss](../tech/source-epss.md)). Remaining cost: `MirrorStore::apply_rows` at about 12 µs per upsert;
    multi-row statements could reduce it.
- [ ] **`MirrorView::row_keys` memory**: about 570 bytes per key (226 MiB for 400k keys). A large source that computes
      deletes needs a compact or streamed read.
- [ ] **Retire the `py-sources` epss path** one release after the native epss importer.
- [ ] **Live-feed check per native importer**: sync the live kev and epss feeds once by hand and compare row counts
      with py-sources (roadmap R1 exit criterion).
- [ ] **Repair holds the mirror write connection for a whole export.** Measure the effect on a full OSV mirror.
- [ ] **Staging restored from an older copy with the same generation repeats seqs.** Define how a restored staging copy is detected.
- [ ] **Missing tests**: L5 (the process group is killed on a failed handshake) and L2 (the loopback accept loop recovers from accept errors).
- [ ] **A well-known config for general settings.** Shared defaults (for example the module list, uv pin, UI options),
      separate from the per-instance `sec-monk.toml`, with a defined merge order and the same ownership checks.
- [ ] **cargo-deny is unrun** (not installed on the dev machine): run `cargo deny check bans` in CI.
- [ ] **Retire the `py-sources` kev path** one release after the native kev source ([ADR-0011](../decisions/0011-native-sources.md)).
- [ ] **Next source port: cursors through `MirrorView`.** Define how a delta source with cursors reads its cursor through
      the read-only `MirrorView` ([source-kev](../tech/source-kev.md) is the example for the snapshot case).
- [ ] Optional: list the native sources in `/api/meta` `engine.modules`.
- [ ] **CI runs the real-module tests.** Run `SECMONK_REQUIRE_VENV=1 cargo test --workspace` in CI and release checks, so the
      differential tests (native kev vs py-sources) fail instead of skipping when `rust/python/.venv` is missing.
- [ ] **`--path` FIFO swap.** A file swapped for a FIFO between the metadata check and the open can still block the native
      feed reader; close it with an `O_NONBLOCK` open (e.g. `rustix`) ([source-kev](../tech/source-kev.md)).
- [ ] **nvd against the live API**: request shapes and the `apiKey` header, rate limits behind the 0.6 s / 6 s pacing, real page
      sizes, the largest real record and CPE match count (caps 8 MiB, 50,000 rows) ([source-nvd](../tech/source-nvd.md)).
- [ ] **nvd parses each record twice** (page check, then emission); a single parse would cut about a third of the build time.
- [ ] **Retire the `py-sources` nvd path** one release after the native nvd importer.
