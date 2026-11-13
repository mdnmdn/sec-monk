---
title: Plan — Rust desktop app on Linux desktops
summary: "Linux verification items: headless build and run, WebKitGTK scheme and CSP, glibc/musl uv assets (Alpine gcompat), noexec data mounts, PR_SET_PDEATHSIG, packaging."
read_when: you are on a Linux desktop and want to verify the Rust desktop app
type: plan
context: plans
status: open
platform: linux
tags: [plan, linux, rust]
updated: 2026-11-13
verified: 2026-11-11
related: [plans/README.md, decisions/0009-platform-targets.md]
---

# Plan — Rust desktop app on Linux

- [ ] WebKitGTK 4.1: `secmonk://localhost/` origin, relative `/api` fetches, CSP `'self'` covers the scheme.
- [ ] uv asset choice: gnu archive on glibc distros, musl archive on Alpine; python-build-standalone picks the right
      libc in both cases.
- [ ] A `noexec` mount for `data_dir` breaks the managed Python (spike notes): detect it and report a clear error.
- [ ] Webview data directory set inside `data_dir`; nothing in `~/.local/share/<id>`.
- [ ] Filesystem audit after first start (`~/.cache/uv`, `~/.local/share/uv`, `~/.local/bin` untouched).
- [ ] Modules die with the app: stdin EOF and `PR_SET_PDEATHSIG` on a `kill -9` of the app.
- [ ] Live process snapshot (Linux backend) through `py-procmon` equals `secmonk procs`.
- [ ] AppImage / deb on Debian 12, Ubuntu 24.04, Fedora (WebKitGTK versions differ).

## Added by the W4.2 docs pass (2026-11-11)

- [ ] **Headless build and run on a real Linux machine.** `cargo build -p secmonk-desktop --no-default-features --features
      engine,probe` (and `cargo build -p secmonk-host --bin secmonk-headless`) on a host without WebKitGTK; the dependency
      graph was checked on macOS only (no Tauri crate). Then `secmonk-headless --listen 127.0.0.1:8765`: first start installs
      into the data dir, `preparing` answers 503 meanwhile, SIGTERM stops the modules.
- [ ] **Alpine + gcompat detection.** `secmonk-runtime` picks the musl uv build when `/lib/ld-musl-*` exists and no real glibc
      loader does; a glibc name that resolves to musl's loader or to `libgcompat` does not count (ADR-0004, unit-tested
      with fake trees only). Check on Alpine with and without `gcompat` and on Debian/Fedora: asset, `uv python install`
      and the module venv.
- [ ] **`noexec` data mounts.** Mount `data_dir` (or its parent) `noexec` and start: the managed Python cannot run. The app does
      not detect it yet: decide on a clear start-up error (a `Failed` state with a hint) and test it.
- [ ] **`PR_SET_PDEATHSIG` / parent death.** Modules run in their own process group and exit on stdin EOF; the Unix group kill
      covers a clean stop. After `kill -9` of the app a module busy in a long call (and its ssh/docker children) keeps running
      until it finishes: measure, then decide whether `PR_SET_PDEATHSIG` (needs `unsafe` `pre_exec`) is worth it.
- [ ] **The ui where possible.** WebKitGTK 4.1 window: `secmonk://localhost/` origin, the preparing panel, `data_dir/webview`
      created 0700 and nothing under `~/.local/share/<id>`, external links through `opener` (xdg-open), devtools in a debug build.

## Added by the server-mode and IPC work (2026-11-13)

- [ ] **Server mode on a real Linux box.** `secmonk-server` with TLS from a real certificate (`tls_cert`, `tls_key`), a systemd unit (user, `Restart`, `NoNewPrivileges`; sample not written **(verify)**), the release archive from [release](../tech/release.md) unpacked and started, API key creation and the `/auth/token` login from a browser and from `curl` ([ADR-0014](../decisions/0014-server-mode-auth-and-ui-transport.md)).
- [ ] **A real two-node follow over TLS.** A mirror node serving `feed` and a state-only or follower node with `[node.upstream]` (`ca_cert` for a private CA): sync, `feed/since` after a gap, `resync`, `match` through `RemoteNode` ([ADR-0013](../decisions/0013-mirror-nodes-and-source-versions.md), [node-api](../tech/node-api.md)); only loopback and in-process tests ran **(verify)**.
- [ ] **Shared `[paths] tools` first-download race.** Two processes (server and desktop, or two nodes) pointing `[paths] tools` at one directory start with no uv installed: check that the first download does not corrupt or double-install the pinned uv **(verify)**.
