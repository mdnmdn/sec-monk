---
title: ADR-0001 — Rust workspace in rust/ and a single-process Tauri app first
summary: The Rust prototype lives in rust/ as a Cargo workspace whose crate graph enforces the probe/engine/ui boundaries; the first deliverable is one Tauri desktop process holding ui, engine, module host and the local probe.
read_when: you wonder why the Rust code is in rust/, why there is one process, or why a crate may not depend on another
type: decision
context: decisions
status: accepted
tags: [rust, tauri, architecture, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/architecture.md, decisions/0002-rust-core-python-modules.md]
---

# ADR-0001 — Rust workspace in rust/ and a single-process Tauri app first

## Context

The user approved the strangler path of the proposal
[`_docs/inbox/2026-11-08-port-to-compiled-stack.md`](../../../_docs/inbox/2026-11-08-port-to-compiled-stack.md)
(§9, §15 step 4) on 2026-11-11 and asked for a Rust version in `rust/`, developed next to the Python version in
`src/`, which others keep editing. The first target is a desktop app with today's UI and probes. Probe, engine and ui
must be separable across processes and hosts later.

## Decision

- All Rust code, its docs (`rust/_docs/`), contracts and the Python module adapters live under `rust/`; nothing in
  `src/` or `_docs/` changes for the prototype.
- A Cargo workspace (`rust/crates/*`, `rust/apps/desktop/src-tauri`) with the crates and dependency rules of
  [architecture § 2](../tech/architecture.md#2-cargo-workspace): probes cannot depend on the store, only
  `secmonk-store` depends on SQL crates, the API cannot reach the store, the engine sees traits only.
- The first binary is `secmonk-desktop` (Tauri v2): ui binding, engine, module host and local probe in **one OS
  process** (topology (a) of the proposal), no TCP listener. Python modules are child processes of it.
- Other topologies (SSH probes, daemons, headless server, federation) are not built now; the session layer is written
  over any byte stream so they can reuse it.

## Consequences

- The boundaries are compile-time facts from the first commit; CI adds a `cargo tree` check and `cargo deny` bans for
  transitive leaks.
- One process keeps the prototype simple (no auth, no ports); the price is that a module or webview bug can stall the
  app, mitigated by modules being separate processes with timeouts.
- Two codebases evolve in parallel; the shared contracts and golden outputs ([component lifecycle](../tech/component-lifecycle.md))
  keep them comparable.

## Implementation notes (2026-11-11, W2.1)

- `rust/Cargo.toml`: members `crates/*` and `apps/desktop/src-tauri` (listed by path: cargo treats a member glob
  with no match as a literal path and fails); `default-members = ["crates/*"]`, so a plain `cargo build` /
  `cargo test` never compiles Tauri. Edition 2024, `rust-version` 1.94 (sqlx 0.9), toolchain pinned to 1.98.0,
  `unsafe_code = "forbid"` workspace-wide, release profile at the root (cargo ignores member profiles).
- Platform targets refined by the user the same day (macOS and Windows ship probe, engine and ui; Linux ships engine
  and probe, the ui where possible): cargo features `ui` / `engine` / `probe` on the desktop crate, design in
  [architecture § Build features per platform](../tech/architecture.md#build-features-per-platform).
- `rust/deny.toml` encodes the dependency rules; not run yet (cargo-deny not installed) **(verify)**.

## Implementation notes (2026-11-11, W4.2)

- The workspace has 12 crates under `crates/` plus the desktop app. `secmonk-host` (W3.2) is the composition root; the
  desktop app and the headless binary `secmonk-headless` are thin shells over it, so the single-process decision holds
  for both ([architecture §3](../tech/architecture.md#3-composition-secmonk-host-and-the-desktop-app)).
- `rust/deny.toml` now lists `secmonk-host` among the wrappers of `secmonk-store` and `secmonk-modhost`, and
  `secmonk-engine` as a **dev-only** wrapper of `secmonk-modhost` (the gated real-module test). It is still unrun:
  cargo-deny is not installed **(verify)**. `cargo tree` (2026-11-11) confirms that only `secmonk-store` reaches `sqlx`.
