---
title: Possible roadmap after the Rust prototype
summary: "Proposed phases R0-R6 after the prototype (harden, native sources from kev, engine core, Rust probe, packaging, distributed, PostgreSQL): exit criteria, estimates, milestones M1-M7, decisions needed."
read_when: you decide what to port or build next in rust/, check the order of the phases, or look for the exit criteria of a phase
type: plan
context: plans
status: open
platform: any
tags: [plan, rust, roadmap, migration]
updated: 2026-11-11
verified: 2026-11-11
related: [plans/backlog.md, plans/prototype.md, tech/architecture.md, tech/component-lifecycle.md, decisions/0002-rust-core-python-modules.md, decisions/0010-source-staging-adapter.md]
---

# Possible roadmap after the prototype

**A proposal for the user to review, not a commitment.** Written 2026-11-11 at the user's request ("start with `kev`
as the first native connector; create a doc with a possible roadmap"). Details of every item stay in the
[backlog](backlog.md); this file only orders them and says when a phase is done. Effort figures are **estimates**
taken from the [compiled-stack proposal §12](../../../_docs/inbox/2026-11-08-port-to-compiled-stack.md#12-effort-breakdown)
(person-weeks, one senior Rust developer; "agents" = coding agents plus one reviewer) and the Python line counts
below; none was measured on this port.

## 1. Where we are

| Fact | Status (2026-11-11) | Source |
|---|---|---|
| Prototype works headless end to end on macOS arm64 | sync kev 1,779 + epss 402,773 + osv subset 29,925 vulns, scan of a fixture -> 40 findings, procmon from a snapshot | [prototype log](prototype.md#log) |
| Tests | cargo 202 passed, Python 226 passed, clippy `-D warnings` clean, contracts + golden OK | prototype log |
| API | 22 routes real in `secmonk-api`; parity test against `secmonk ui` is **planned, not written** | [api-contract](../tech/api-contract.md) |
| Not observed | the desktop window (no GUI session), Linux and Windows runs, Windows Job object kill, live `ps` | [on-macos](on-macos.md), [on-linux](on-linux.md), [on-windows](on-windows.md) |
| Rust today | shell, config, store (schema v3), module host, uv runtime, API router, jobs, scan/sync orchestration | [architecture](../tech/architecture.md) |
| Python today (modules over stdio) | collectors, sources (staging adapter), classify, match, scoring, versions, report payloads | [ADR-0002](../decisions/0002-rust-core-python-modules.md) |
| First native step in flight | W6.1: `kev` as a Rust source emitting mirror rows directly | [prototype W6.1](prototype.md) |

Python reference sizes (lines, `wc -l`, 2026-11-11): sources 3,150 (osv 537, cvelist 877, debian-tracker 422, nvd 398,
msrc 229, epss 172, euvd 158, kev 99, base 250); engine 1,427 (match 531, classify 235, versions 214, queries 167,
purl 133, inventory 96, scoring 51); collectors 15,220 (process 3,950, rootfs 991, docker 2,100, git 1,054, lang 2,480).

## 2. Guiding rules

1. **Python is the reference** (`../src`, `../_docs`); `rust/` is the target. The Python version keeps running and
   is not edited for the port.
2. **Every port follows one loop** ([component-lifecycle](../tech/component-lifecycle.md)):
   contract (schema) -> golden outputs recorded from Python -> Rust implementation -> **differential test** (same
   inputs, same outputs, Python vs Rust) -> **select** (config selects Rust; Python stays selectable) -> **retire** the
   Python path after one release with no differences.
3. **One writer**: only `secmonk-store` writes. Native sources emit row operations, they do not open the mirror.
4. **No regression in API parity**: every phase keeps the 22 routes returning payloads valid against
   `rust/contracts` and equal to `secmonk ui` on the same fixtures (the parity test, R0, becomes a gate).
5. **Selectable and reversible**: each selection is a config key per component (as W6.1 does for `kev`); the module
   stays installed until its retire step.
6. Probes never touch the store; scans never call vulnerability APIs; targets are untrusted (root
   [AGENTS.md](../../../AGENTS.md)).

## 3. Phases

Order in one line: **R0** then **R1 and R2 in parallel** (R1 first item `kev`, already started) then **R3**,
**R4**, **R5**, **R6**. R6 can run any time after R0 on a spare lane.

### R0 Harden the prototype

| | |
|---|---|
| Goal | Make the prototype a safe base: observed on real machines, parity proven, review leftovers closed. |
| Items | GUI check on a Mac (WKWebView scheme, CSP, SBOM download, quit leaves no Python); Windows Job object (`on-windows` M2); write the API parity test; `cargo deny check bans` in CI; instance-level items of [backlog §8](backlog.md#8-left-over-by-the-prototype-docs-pass-2026-11-11) (module integrity gaps, `grants` relaxation, per-module logs, seq repeat on restored staging); Linux headless run. |
| Order, why | First, and cheap: every later phase leans on the parity test and on real-machine runs. The parity test is the regression net for R1-R3. |
| Entry | Prototype committed (done, 0fbd780). |
| Exit | Parity test green on fixtures (v2 DB through `secmonk ui` vs v3 store through the router); [on-macos](on-macos.md) GUI items ticked with dates; Windows kill-on-exit verified; CI runs fmt, clippy, tests, deny on 3 OS (headless on Linux). |
| Effort (estimate) | M: 2-3 person-weeks; most needs a person at a real Mac and a Windows machine. |
| Risks | No Windows machine available (blocks the Job object and WebView2 items); WebView CSP surprises. |
| Dependencies | Real machines (user). Parallel with R1. |

### R1 Native sources

| | |
|---|---|
| Goal | Each source runs as Rust code emitting mirror rows directly; the staging copy of the mirror ([ADR-0010](../decisions/0010-source-staging-adapter.md)) disappears. |
| Items (order) | 1 `kev` (W6.1, Python 99 lines) **done 2026-11-11** ([source-kev](../tech/source-kev.md)); 2 `epss` (172) **done 2026-11-11** ([source-epss](../tech/source-epss.md); 400k rows: native 5.3 s vs py-sources 16-18 s, Apple M2); 3 `debian-tracker` (422), `euvd` (158), `msrc` (229) **done 2026-11-11** ([source-debian-tracker](../tech/source-debian-tracker.md), [source-euvd](../tech/source-euvd.md), [source-msrc](../tech/source-msrc.md); shared code: [ADR-0012](../decisions/0012-native-importer-row-reads-and-registry.md)); 4 `nvd` (398); 5 `cvelist` (877, git subprocess + bulk loader); 6 `osv` (537, ecosystem cursors, largest volume). Per source: schema + golden, Rust impl behind the `Source` trait, differential test of the row stream against `py-sources` on the same recorded feed, config selection. |
| Order, why | Smallest and most self-contained first to prove the loop and the row-stream contract (kev, epss); feeds with plain JSON/CSV next; the three that stress performance, state (cursors, git) and volume last. Python sources stay as fallback. |
| Entry | W6.1 differential test green and the row-stream contract frozen (additive only afterwards). |
| Exit per source | Differential test: identical mirror content (row set after apply) on recorded fixtures; sync of the live feed once by hand compared with a Python sync (counts equal). Exit of the phase: all eight native, ADR-0010 superseded by a new ADR, staging code deleted, `py-sources` kept only as opt-in fallback, then retired. |
| Effort (estimate) | L: about 5 person-weeks (proposal work package 5), calendar 1.5 weeks with agents; HTTP/TLS client, git for cvelist and bulk loaders are the new Rust ground. |
| Risks | Throughput of a full OSV + CVE List sync was never measured (backlog §3); feed format drift (differential tests use recorded feeds, so they do not catch it); `git` as subprocess on a locked-down host. |
| Dependencies | W6.1 (kev). Independent of R2 and R3 (the mirror schema is the contract). Network allowed only in sync. |

### R2 Engine core

| | |
|---|---|
| Goal | Version comparison, classification, matching, scoring and the report payloads run in Rust; Python engine modules lose their reason to exist. |
| Items (order) | 1 `secmonk-versions` (214 lines plus the `univers` library, about 1.5-2k lines of Rust; schemes: PyPI, semver, Maven, Go, RubyGems, NuGet, Composer, Debian, RPM, Alpine, generic) with property tests and a differential over every range of a full OSV mirror; 2 `secmonk-purl` + `classify` (368 lines, alias table, brew seed); 3 `match` (531) + `scoring` (51) on the Store traits, differential of finding sets; 4 `reports.*` payloads + the store queries they need (parity test stays green); 5 drop the read-only DB grant ([ADR-0006](../decisions/0006-python-read-only-db-access.md)) and the JSON copies of promoted columns; 6 `procmon.analyse` split from `py-procmon` (needs R3 snapshot). |
| Order, why | Versions are the hot, security-critical piece and everything else depends on them; match and scoring are small once versions exist; reports last because they carry the 22-route parity. |
| Entry | R0 parity test; full OSV mirror available as test data (R1 not required: a Python-synced mirror works). |
| Exit | Versions: zero differences against `univers` on all ranges of the mirror and on property tests; match: finding sets equal to `engine.match` on every fixture and on the full mirror; parity test green with Python modules switched off; scan wall time not worse than Python (measure, no target set yet). |
| Effort (estimate) | L: about 10 person-weeks (work packages 2, 4, part of 12), calendar 3-4 weeks with agents; the version schemes are the long pole (4 person-weeks alone). |
| Risks | Silent version-order differences (Maven, RPM, Debian) = missed vulnerabilities: differential coverage is the mitigation; reports payload shape drift. |
| Dependencies | Parallel with R1 (shared lane budget: they touch different crates). Step 6 needs R3 process snapshot. |

### R3 Probe in Rust

| | |
|---|---|
| Goal | A probe that needs no Python on the target: the static `secmonk-probe` for the common targets. |
| Items (order) | 1 `secmonk-safeio` complete (`read_within`, `resolve_within`, safe tar/zip, redaction; 460 lines, base 179); 2 `secmonk-lang` (7 ecosystems + Go/Rust binary identity, 2,480 lines) ; 3 `fs`, `rootfs` (161 + 991); 4 process backends Linux then macOS (1,237 + 1,047) with the probe/engine snapshot split; 5 `docker-image` layers, `docker-engine` (852 + 853, transport 414); 6 macOS + Homebrew (478 + 733); 7 Windows (872) and `ssh`/harvest (688 + 557); 8 re-redaction and caps of module output on ingest. `git`, `k8s` and `discover` stay Python until asked for. |
| Order, why | Safeio and lang are the shared base and the most security-sensitive parser surface; fs/rootfs reuse them; process and image work are the largest and need real machines; macOS/Windows last (only verifiable on their OS). |
| Entry | Inventory contract frozen (done in prototype); parity test. R2 step 2 (classify) is not required: classify sits in the engine. |
| Exit per collector | Inventory differential: same components (purl, version, location) as the Python collector on every fixture under `tests/fixtures/`; malformed/hostile inputs from the Python tests (symlink escape, zip bomb, huge files) refused equally; on-platform run compared by hand for macOS, Windows, Linux. |
| Effort (estimate) | L-XL: about 20 person-weeks (work packages 1, 6-11), calendar 6-8 weeks with agents. |
| Risks | Security of untrusted parsers in a new language (fuzz targets planned per parser); Docker/OCI registry client volume; real-machine verification cost. |
| Dependencies | Independent of R1; R2 only for the process split. Collectors can be ported one by one in parallel lanes. |

### R4 Distribution and packaging

| | |
|---|---|
| Goal | Installable, signed, offline-capable artifacts. |
| Items | Static musl `secmonk-probe` (`serve --stdio`); code signing and notarization (macOS), Windows signing; release packaging (static UI and Python project as Tauri resources, pinned module hashes `trust = "pinned"`, offline bundle with uv archive and wheels); uv checksum vs attestations in the pipeline; CI release matrix (3 OS); uv-as-crates evaluation; docs tooling second root. |
| Order, why | Can start with the Python modules still inside (a signed desktop app earlier than R3); the static probe lands after R3 step 4. |
| Entry | R0 done. Probe artifact needs R3 items 1-4. |
| Exit | A signed macOS app opens on a clean Mac without Gatekeeper warnings; Windows installer passes SmartScreen reputation steps (as far as testable); offline install of the bundle works with the network unplugged; `trust = "pinned"` start succeeds with printed pins. |
| Effort (estimate) | M: 3-5 person-weeks (Tauri signing/updater) + 2 (probe packaging); needs signing certificates (user). |
| Risks | Certificates and notarization accounts; pinned mode currently covers only the module tree ([backlog §8](backlog.md#8-left-over-by-the-prototype-docs-pass-2026-11-11)). |
| Dependencies | Certificates; part parallel with R1-R3. |

### R5 Distributed mode

| | |
|---|---|
| Goal | Probes on other hosts, one or several engines. |
| Items | `secmonk-probe` over SSH exec stdio; TLS/WSS dial-out probes with enrollment (engine CA, one-time tokens); headless server with authentication and roles; job cancel from the UI, several jobs at once, event push; federation in the desktop UI; OS overlay clients documented. Embedded overlay and RDP only on request. |
| Order, why | SSH stdio first (no new trust root); dial-out next; auth before any non-loopback listener; federation last. |
| Entry | R3 probe binary (items 1-4), R4 signed probe, R2 step 3 (engine-side classify/match on ingest from remote probes). |
| Exit | A scan of a remote Linux host through SSH stdio returns the same inventory as a local run; enrollment, revocation and a compromised-probe test pass; two engines visible in one desktop window with namespaced assets. |
| Effort (estimate) | XL: about 19 person-weeks (proposal packages 18-24), calendar 6-8 weeks with agents. |
| Risks | Security model errors (identities, CA, tokens); multi-tenant questions (decision D5). |
| Dependencies | R3, R4; R2 partly. Sequential after them. |

### R6 Other databases

| | |
|---|---|
| Goal | PostgreSQL for state (mirror stays SQLite). |
| Items | `postgres/` migrations, Store conformance suite via testcontainers, concurrency checks, re-test of the Python read-only access story ([ADR-0006](../decisions/0006-python-read-only-db-access.md)); MySQL/MariaDB only on request. |
| Order, why | Needed only for a shared headless server (R5); Store traits are already the seam. |
| Entry | R0; R2 step 5 (no Python readers of the state DB left) makes it simpler. |
| Exit | The Store conformance suite passes on SQLite and PostgreSQL; parity test green on PostgreSQL. |
| Effort (estimate) | M: 5-7 person-weeks incl. MySQL, about 3-4 for PostgreSQL only. |
| Risks | Dialect differences in promoted columns and sort/collation; sea-query coverage. |
| Dependencies | Parallel lane from R0 on; needed before R5 goes multi-user. |

### Parallelism

| Lane | Can run together | Must wait for |
|---|---|---|
| A | R0 (needs real machines) | nothing |
| B | R1 sources | W6.1 |
| C | R2 engine core | R0 parity test |
| D | R3 probe (one lane per collector family) | R0 |
| E | R4 signing/packaging (desktop part) | R0 |
| F | R6 PostgreSQL | R0 |
| G | R5 distributed | R3, R4, part of R2 |

Realistic limit: one reviewer. Lanes B, C and D together are three streams of differential reviews; the proposal's
agent calendar assumes this review work does not shrink.

## 4. Milestones

| M | After | What the user can do | Rough calendar with agents (estimate) |
|---|---|---|---|
| M1 | R0 + `kev` native | Run the desktop app on Mac/Windows, sync kev from Rust with no staging copy, trust that routes match `secmonk ui`. | 2-3 weeks |
| M2 | R1 half (kev, epss, debian, euvd, msrc) | Sync the small feeds without Python; Python still needed for nvd, cvelist, osv. | +2 weeks |
| M3 | R1 complete | Sync everything natively; staging copy gone; Python only for scans. | +2 weeks |
| M4 | R2 complete | Match and report fully in Rust; Python needed only for collectors. Desktop app signed (R4 desktop part) and distributable. | +4 weeks |
| M5 | R3 items 1-4 + R4 probe | Scan files, language packages, rootfs and processes on Linux/macOS with a static probe; no Python needed on the machine for these. | +6 weeks |
| M6 | R3 complete | No Python at all in the default install; collectors for images, macOS, Windows are Rust. | +4 weeks |
| M7 | R5 | Scan remote hosts (SSH, dial-out), headless server with roles, several engines in one window. | +6-8 weeks |

Sum of the calendar column is about 5-6 months with agents (estimate; the proposal's full-port figure is 5-6 months
with the distributed core, for the Python-to-Rust port; sources-in-Python-for-good would cut M2/M3).

## 5. Decisions needed from the user

| # | Question | Proposed default |
|---|---|---|
| D1 | After `kev`, continue with sources (R1) or jump to the engine core (R2)? The architecture doc said "engine core first". | **Decided 2026-11-11 (user): continue with the sources (R1).** R2 waits. |
| D2 | Do sources have to become Rust at all (cvelist, osv, nvd are about 1,800 lines of mostly I/O)? | Port `kev`, `epss`, `debian-tracker`, `euvd`, `msrc` now; decide nvd/cvelist/osv after measuring throughput (may stay Python for good). |
| D3 | Who is the target user: single analyst laptop, team server, provider (proposal open question 1)? Sets the order of R5/R6. | Single laptop first; R5 after M6. |
| D4 | May Python stay in the default install until M6? May modules ever run on targets? | Yes until M6; never on targets. |
| D5 | One engine per tenant (default) or multi-tenant? | One engine per tenant. |
| D6 | Does a ported module's Python binding stay a fallback, or is it retired after one release? | Retire after one release with no differential differences. |
| D7 | Real machines and certificates: who provides a Windows machine, Linux desktop and signing accounts, and when? | Needed by R0 (machines) and R4 (certificates). |
| D8 | May sec-monk push a probe binary over SSH, or must SSH stay write-free? | Write-free; harvest remains the fallback. |
| D9 | Performance target for scans (Python is the baseline). | Not worse than Python; no stricter target until measured in R2. |
| D10 | Federation in the browser UI too, or desktop only? | Desktop only. |

## 6. Backlog items each phase consumes

| Phase | Backlog |
|---|---|
| R0 | [§8 left over](backlog.md#8-left-over-by-the-prototype-docs-pass-2026-11-11), [§7 parity test](backlog.md#7-docs-and-tooling), platform plans [macOS](on-macos.md), [Linux](on-linux.md), [Windows](on-windows.md) |
| R1 | [§3 sources](backlog.md#3-sources); §8 epss apply, seq repeat on restored staging, repair connection |
| R2 | [§1 engine core](backlog.md#1-engine-core-to-rust-first) |
| R3 | [§2 probe](backlog.md#2-probe-to-rust-what-the-static-probe-binary-needs) |
| R4 | [§6 runtime and packaging](backlog.md#6-runtime-and-packaging); §7 docs tooling |
| R5 | [§4 distributed mode](backlog.md#4-distributed-mode) |
| R6 | [§5 databases](backlog.md#5-databases) |

Nothing here duplicates the item text; when a phase changes, edit the backlog item and this table only.
