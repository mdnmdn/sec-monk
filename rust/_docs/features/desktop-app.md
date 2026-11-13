---
title: Desktop app (Rust prototype)
summary: "What the user gets from the single-process desktop app: today's UI and scans, first-run setup of the Python runtime, data location, per-OS behaviour, acceptance criteria and their status."
read_when: you decide what the prototype must do for a user, test it end to end, or explain how it differs from `secmonk ui`
type: feature
context: features
status: implemented
tags: [desktop, tauri, web-ui, rust]
updated: 2026-11-13
verified: 2026-11-11
code: [rust/apps/desktop/src-tauri/src/, rust/crates/secmonk-host/src/]
related: [tech/architecture.md, tech/api-contract.md, tech/configuration.md, plans/backlog.md]
---

# Desktop app (Rust prototype)

## What the user gets

- A desktop window with **the same interface as `secmonk ui`**: overview, assets, findings, vulnerabilities,
  processes, sources and sync, scans (single target and host mode), run history.
- The same probes (all collectors of the Python version) and the same sources, matching and priorities.
- No browser, no open port, no terminal: the app starts its own Python modules in the background.
- Its own data, separate from the Python version: both can be installed and used side by side.

## Platforms

| OS | Ships | Notes |
|---|---|---|
| macOS, Windows | probe, engine and ui (the desktop app) | Features switch per platform: live process monitor on macOS, off on Windows (503 as today); `macos`, `homebrew` collectors on macOS, `windows` on Windows. |
| Linux | engine and probe; the ui when possible | The desktop app needs WebKitGTK. Without it, the headless build serves the same UI and `/api` over the loopback HTTP binding (`cargo run -p secmonk-host --bin secmonk-server`, or `cargo run -p secmonk-desktop --no-default-features --features engine,probe`; the Host check of `secmonk ui`; loopback without a login, any other address with API-key authentication and TLS, see Server mode below). |

The `secmonk-api`, `secmonk-engine` and `secmonk-probe` crates do not depend on Tauri
([ADR-0009](../decisions/0009-platform-targets.md)).

## Usage

```bash
cd rust && cargo tauri dev                      # dev: config ./sec-monk.toml (debug build), data in rust/_data/
cargo run -p secmonk-desktop                    # the same without the Tauri CLI
secmonk-desktop --config ~/work/sec-monk.toml   # another config (or SECMONK_CONFIG; otherwise ./sec-monk.toml of the current directory, in every build)
secmonk-desktop --set log.level=debug --data-dir ~/sec-monk-test   # options of the shared command line also apply to the window
cargo run -p secmonk-host --bin secmonk-server -- serve --listen 127.0.0.1:8765   # no window, no WebKit
rm -rf rust/_data                               # reset the dev data (quit the app first)
```

### Server mode from the app binary

`secmonk-desktop serve [options]` (or `--serve`) runs exactly the server mode of `secmonk-server`: no window, Tauri is
never initialised, the same options (`--config`, `--set`, `--data-dir`, `--listen`, `--tls-cert`, `--tls-key`,
`--allow-actions` / `--no-actions`, `--auth`). `secmonk-desktop apikey create|list|revoke` and `config show` work the
same way and never start the engine. A build without the `ui` feature behaves like `secmonk-server` for every
subcommand (serving when none is given). The Windows release app is a GUI-subsystem program (no console is attached;
attaching to the parent console needs `unsafe`, which the workspace forbids), so on Windows use `secmonk-server.exe` for
the command line: the installers ship it next to the app executable (a Tauri sidecar). An installed app finds its UI
and its own copy of the Python project in its resource directory (on Windows the install directory) and installs the
modules into `data_dir` on first start; a `sec-monk.toml` of the user still overrides those defaults
([release](../tech/release.md)). Details: [README](../../README.md#server-mode-secmonk-server), [architecture §3](../tech/architecture.md#3-composition-secmonk-host-and-the-desktop-app).

### How the window reaches the engine

The page loads from the custom scheme (`secmonk://localhost`, on Windows `http://secmonk.localhost`). Plain requests go
through the scheme handler; the overlay's transport (`rust/ui/transport.js`) instead calls the Tauri command
`secmonk_api({method, path, headers, body})` (`window.__TAURI_INTERNALS__.invoke`, `withGlobalTauri` is false), which
runs `secmonk_api::handle_bridge` on the same router: no network, no authentication, `/api/` paths only. The command
exists only for the `main` window: `capabilities/main.json` grants the generated permission `allow-secmonk-api` and
nothing else. Tauri 2.12 treats the origin of a registered custom scheme as local (`is_local_url`), so IPC from it is
allowed. Status: compiled and ACL-validated on Linux (2026-11-13); not exercised in a running window. Open point: the
page's CSP (`connect-src 'self'`) may block Tauri's `ipc:` fetch channel, in which case Tauri falls back to
`postMessage`; check on a real window ([on-macos](../plans/on-macos.md)).

The configuration must list the modules (`[modules] enabled`); the repo's `rust/sec-monk.toml` does
([configuration](../tech/configuration.md)).

Developer tools of the webview open only in a debug build with `[ui] devtools = true`; a release build ignores the
setting.

First start: the app downloads the pinned uv (checksum-verified), installs the pinned Python and the module
environment into its data directory (38 s on a Mac with a good network, observed 2026-11-11; most of it is `uv sync`). The window opens at once and every
screen shows its normal error panel with "sec-monk is preparing its Python runtime (step N of 5: downloading uv /
installing Python / installing the module environment / opening the databases / starting the modules)" and a hint
(HTTP 503 from the same scheme handler; `/api/meta` answers with `engine.schema = "preparing"`); reload when it is
done. The server side is verified (headless run, 2026-11-11); how the UI renders the panel is not observed yet
([on-macos](../plans/on-macos.md)). A failed start (no network, a pinned checksum mismatch) keeps answering 503 with the reason and the log
directory instead of a blank window. Later starts reuse the installation. Offline machines use
`[python] offline = true` with a local uv archive and a wheel directory.

## Behaviour & rules

| Topic | Rule |
|---|---|
| Data | Everything in `data_dir` ([configuration](../tech/configuration.md)): databases, uv, Python, caches, logs, webview data (Windows, Linux). Nothing in `~/.cache/uv`, `~/.local/share/uv` or the Python version's `secmonk.db`. macOS exception: WKWebView has no data-directory option and keeps its state under `~/Library/WebKit/<id>` and `~/Library/Caches/<id>` (observed: the app starts and WebKit tries to create them, 2026-11-11). |
| Actions | Scans, syncs, discovery and docker listings are allowed in the window (no network listener). One job at a time, as today. |
| Processes view | Live on macOS and Linux; on Windows it answers "not available on this OS" as today; any OS can open a snapshot file (`[ui] snapshot`). |
| Security | Same rules as the web UI: CSP without inline scripts, `X-SecMonk-Request` on every API call, browser-sent scans cannot choose `ssh_bin`, `transport`, `ssh_option`, `ssh_config`, `kubectl`; modules run only from the configured, pinned set. |
| Errors | The UI's existing messages (no database yet, unknown asset, engine unreachable); module failures show as a 503 with a hint to the module log. |

## Acceptance criteria

1. On macOS, Linux and Windows the app (on Linux: engine and probe, and the ui where WebKitGTK exists) starts, installs its runtime into `data_dir`, and shows the overview with
   no database ("create the mirror first").
2. `sync kev epss osv` (and every other source, with `--path` fixtures in tests) fills the mirror; the Sources page
   shows the same status as `secmonk status`.
3. A scan of each collector that runs on the OS produces the same assets, components and findings as `secmonk scan`
   on the same target and mirror (API parity test, [api-contract](../tech/api-contract.md#parity-test)).
4. All 22 `/api` routes answer with payloads that validate against their schemas and equal the Python server's.
5. A filesystem audit after first start and a full scan finds no file written outside `data_dir` by the app, uv or the
   modules (except ssh's own `known_hosts` when the user's ssh writes it, and on macOS WKWebView's `~/Library/WebKit/<id>` and
   `~/Library/Caches/<id>`, a known exception). The W1.2 spike passed this audit for uv and Python on macOS arm64.
6. Killing the app leaves no Python process behind, and none of what the modules started (ssh, docker, kubectl): on Unix a module's whole process group is killed (tested); on Windows the Job Object that would do the same is not implemented ([on-windows](../plans/on-windows.md)).

Status on 2026-11-11: (1) observed with the headless server on macOS arm64 only, the window was built but not seen;
(2) a `kev` sync from the repo fixture is tested through the real modules (`secmonk-engine/tests/real_modules.rs`), the
other sources are not; (3) and (4) the API parity test is not written yet, the payloads are schema-checked in tests;
(5) only the uv and Python install was audited (`uv_audit`), not a full scan; (6) tested on Unix. Linux and Windows
were not run: see [on-linux](../plans/on-linux.md) and [on-windows](../plans/on-windows.md).

## App icon

The icon is `assets/logo-orange.png` (single origin). `python3 scripts/make_icons.py` (stdlib plus the `cargo tauri`
CLI) turns its black rounded tile into `assets/app-icon.png` (outside corners transparent, radius measured from the
image, about 20% of the tile) and runs `cargo tauri icon` into `apps/desktop/src-tauri/icons/` (committed: Tauri needs
it at build time; the mobile sets are dropped). `bundle.icon` in `tauri.conf.json` lists the 32/128/256 PNGs, `.icns`
and `.ico`. Rerun the script when the logo changes.

## Implemented by

[architecture](../tech/architecture.md) · [contracts](../tech/contracts.md) · [api-contract](../tech/api-contract.md) ·
[data-model](../tech/data-model.md) · [configuration](../tech/configuration.md) ·
[component-lifecycle](../tech/component-lifecycle.md)
