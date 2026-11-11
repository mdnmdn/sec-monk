---
title: "ADR-0009 — Platform targets: macOS and Windows ship probe, engine and ui; Linux ships engine and probe, and the ui if possible"
summary: macOS and Windows ship probe, engine and ui; Linux ships engine and probe, and the ui if possible; api, engine and probe are Tauri-free; a part missing on an OS is reported, never a crash.
read_when: you write platform-specific code, decide that a feature skips an OS, or plan real-machine verification
type: decision
context: decisions
status: accepted
tags: [platform, macos, linux, windows, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/architecture.md, plans/on-macos.md, plans/on-linux.md, plans/on-windows.md]
---

# ADR-0009 — Platform targets

## Context

User direction 2026-11-11 (A2d): targets macOS, Linux and Windows; where a platform is a real problem a part may be
unavailable there. Refined the same day:

- **macOS and Windows** ship all components (probe, engine, ui), with per-platform features enabled or disabled
  (for example the live process monitor is off on Windows).
- **Linux** ships engine and probe, and the ui if possible (WebKitGTK).

## Decision

- CI builds and runs the Rust tests on the three OSes. The desktop app (ui) is the primary artifact on macOS and
  Windows; on Linux it is built when WebKitGTK is available.
- **`secmonk-api`, `secmonk-engine` and `secmonk-probe` never depend on Tauri** (`cargo tree` check). The API's
  loopback HTTP binding (`secmonk_api::serve_http`, example `serve`) answers the same router with the Python
  server's Host rules, so a Linux headless build is engine + probe + that binding, with no desktop app. Only
  `secmonk-desktop` (webview, scheme registration, window) is Tauri.
- **Features of the desktop crate** (W3.2): `ui` (Tauri window; implies `engine`), `engine` (stores, engine, API
  binding), `probe` (py-probe wired into the probe service), all default. macOS and Windows build the defaults; a
  Linux machine without WebKitGTK builds `cargo build -p secmonk-desktop --no-default-features --features
  engine,probe`, which compiles no Tauri crate at all (`cargo tree` shows none) and runs the loopback server of
  `secmonk-host` (Host check, loopback addresses only). `build.rs` runs `tauri-build` only when `CARGO_FEATURE_UI`
  is set; `tauri`, `tauri-build` and `opener` are optional dependencies. A build without `engine` is the probe-only
  shape of later remote probes and serves nothing yet (exit 2 with a message).
- **Composition lives in `secmonk-host`**, the only crate that names both the module host and the engine; the
  desktop crate and the headless binary are thin shells over it.
- Platform facts live in one place each: uv asset table (config), scheme URL form (desktop crate), spawn details
  (`secmonk-modhost`), default paths (`secmonk-config`). See the [platform matrix](../tech/architecture.md#8-platform-matrix).
- A module declares `platforms`; elsewhere its methods answer `unsupported-platform` and the UI shows the feature as
  unavailable (as the process monitor does on Windows today).
- Windows specifics: no console window for children, Job Object kill-on-close (not implemented: it needs a safe
  wrapper crate, verify on a Windows machine; today only the module process is killed there), binary stdio, no `.bat`/`.cmd` spawns,
  paths with spaces and non-ASCII names tested.

## Consequences

- Development happens mostly on macOS/Linux; what needs a real Windows or macOS machine is in
  [plans](../plans/README.md).

## Implementation notes (2026-11-11, W4.2)

- The Linux headless graph was checked with `cargo tree --offline -p secmonk-desktop --no-default-features --features
  engine,probe`: no Tauri, wry or WebKit crate. It was not built on Linux.
- Unix kill of a module's whole process group is implemented and tested (`secmonk-modhost` `kill_group`); the Windows Job
  object is still open, as are `PR_SET_PDEATHSIG` on Linux and the Windows items listed in the plans.
