---
title: ADR-0002 — Rust core, Python modules for this phase (classify in the engine)
summary: Rust holds the central parts (shell, config, store, module host, API router, orchestration); probes, sources, classify, match, scoring and versions stay Python modules this phase; classify sits in the engine.
read_when: you decide whether something is written in Rust or Python now, or where classification happens
type: decision
context: decisions
status: accepted
tags: [rust, python, modules, architecture, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/architecture.md, tech/contracts.md, tech/component-lifecycle.md]
---

# ADR-0002 — Rust core, Python modules for this phase

## Context

User direction 2026-11-11 (plan assumptions A2b, A5): Rust holds only the central parts this phase; the full
migration comes after the prototype works and is well tested. The proposal (§9.1) wanted versions, classify, match and
scoring as non-pluggable Rust from the start; the user chose to keep them Python for now.

## Decision

| Rust (in-process) | Python modules (child stdio, unchanged `secmonk` package) |
|---|---|
| Tauri shell, config, store + schema v3 + migrations, module host (protocol, registry, `PythonRuntime` = uv), API router, jobs and orchestration (scan loop, image reuse rule, run history, redaction helpers) | `py-probe` (collectors, discovery, docker/k8s listings), `py-sources` (8 feeds), `py-engine` (classify, match, scoring, versions, `reports.*`), `py-procmon` (process monitor state) |

- **One interface for both languages**: the engine calls `Collector`, `Source`, `Classifier`, `Matcher`, `Reporter`
  traits; a Rust implementation is linked in, a Python one is an adapter over a stdio session. The engine cannot tell
  them apart.
- **Classification sits in the engine, on ingest**: probe modules return unclassified inventories; the host calls
  `engine.classify` before save or match (today `ops.collect` classifies inside collect).
- Python modules import `secmonk` through a uv path dependency on the repo root (`rust/python`); no copy of the code.
- **As built (W2.2)**: all four modules (`py-probe` 8 methods, `py-sources` 3, `py-engine` 16, `py-procmon` 3 = the 30 of the
  catalog) run on macOS, Linux and Windows except `py-procmon` (macOS and Linux: it has no Windows backend). Probe output is
  unclassified; `engine.classify` equals `engine/classify.classify` and is idempotent; `versions.*` and `scoring.priority`
  equal the Python functions (the oracle the Rust port will be tested against, `tests/test_engine.py`).

## Consequences

- The prototype reuses ~18k lines of tested Python; the Rust work is the host only.
- Hot paths (match over large inventories) pay a process hop and JSON; acceptable at collector/asset granularity.
- Versions/match become **the first Rust ports** after the prototype (security-critical, differential-tested against
  the Python `univers` oracle); see [backlog](../plans/backlog.md).
- Moving classify out of collect changes the order of operations; golden tests compare saved inventories with the
  Python version's.
