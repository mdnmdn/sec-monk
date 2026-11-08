---
title: ADR-0007 — Process / executable monitor
summary: Decision to build the process monitor as a collector with its own process:<host> asset, platform-neutral core plus per-OS backends, a snapshot file format and polling-based watch.
read_when: you are about to change the process monitor design, add an OS backend or question why it polls and uses a separate asset
type: decision
context: decisions
status: accepted
tags: [process, collector, architecture, macos]
updated: 2026-11-07
verified: 2026-11-07
related: [tech/collectors/process.md, features/process-monitor.md, tech/architecture.md, decisions/0005-prototype-scope-nov-2026.md]
code: src/secmonk/collectors/process/, src/secmonk/procmon.py
---

# ADR-0007 — Process / executable monitor

## Context
The collectors inventory what is **installed**. Analysts also ask what is **running**: which processes, started by
what (persistence), which exact version of which software, and where the binary came from. The target differs (a moving
process tree, not a filesystem) but most of the work is shared with the inventory: identifying software (bundles,
Homebrew, Go binaries) and matching it. It must start on macOS and later cover Linux and Windows.

## Decision
- **A collector, not a separate tool.** `process` is a registered collector producing an `Inventory`; its components
  reuse the existing identity code (`MacOSCollector._read_bundle`, `homebrew._keg_component`, the `lang` binary parsers)
  and are matched by the unchanged engine. The monitor UI (`secmonk procs`, `--watch`) is a view over the same analysis.
- **Its own asset `process:<host>`** (type `host-processes`). A process snapshot is a subset of the installed software;
  sharing `macos:<host>` would mark everything not running as removed (fixed findings) on every run.
- **Platform-neutral core + per-OS backends.** `Snapshot` (processes, launch items, OS, optional per-executable facts) is
  the boundary. Launch classification, risk flags, components and the CLI are shared; a backend contributes
  `take_snapshot()`, an `Inspector` (identity + provenance) and `PlatformHints`.
- **A snapshot file format** (`secmonk-process-snapshot/1`): offline analysis, fixtures, and the hand-off format for
  future agents/scripts (the Windows PowerShell script can emit one with identities precomputed). A foreign snapshot is
  analysed from paths alone unless `-o root=` points at a copy of its filesystem.
- **New category `executable`** for binaries without a package identity: kept for the view, never matched.
- **Read-only, fixed commands** (`ps`, `launchctl list`, `codesign -dv`, `pkgutil --file-info`, opt-in `spctl`), command
  lines redacted, only interpreter script paths stored.
- **Polling, not event subscription.** `--watch` diffs snapshots; Endpoint Security / eBPF / ETW need a privileged,
  signed agent and are out of scope for the prototype.

## Consequences
- Running software gets findings, provenance and launch context with no change to the schema or the matcher.
- `component` rows are shared with the installed-software assets; process facts live under `meta.process`.
- Short-lived processes between two ticks are missed; login items from the BTM database are not parsed.
- Linux/Windows support is a backend each (mapping in the tech doc); until then those platforms can only analyse snapshots.
