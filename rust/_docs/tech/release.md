---
title: Release workflow — desktop bundles and server archives
summary: How to run .github/workflows/release.yml, its inputs, the matrices, the archives it produces and the release job; what is not done (signing, notarization, known gaps).
read_when: you cut a release of the Rust prototype, change the release workflow, or package secmonk-server or the desktop app
type: tech
context: tech
status: implemented
tags: [release, ci, github-actions, tauri, server, packaging]
updated: 2026-11-13
verified: 2026-11-13
code: [.github/workflows/release.yml]
related: [plans/node-server-design.md]
---

# Release workflow

Workflow: [`.github/workflows/release.yml`](../../../.github/workflows/release.yml) ("Release"). Two products are
built from `rust/`: the **desktop** app (`secmonk-desktop`, Tauri, via `cargo tauri build`) and the **server**
(`secmonk-server`, plain `cargo build --release --locked`). Design of the server mode: [node-server design §1, §7](../plans/node-server-design.md).

## Run it

| Trigger | Builds | Release |
|---|---|---|
| Actions → Release → Run workflow | the checked products and platforms | only when `tag` is set |
| push of a tag `v*` | everything | always, as a **draft**, never a prerelease |

## Inputs (workflow_dispatch)

| Input | Type | Default | Meaning |
|---|---|---|---|
| `desktop` | bool | true | build the Tauri bundles |
| `server` | bool | true | build the server archives |
| `linux` / `macos` / `windows` | bool | true | include that platform's targets |
| `tag` | string | empty | release tag (e.g. `v0.1.0`); empty = artifacts only |
| `draft` | bool | true | create the release as a draft (tag set only) |
| `prerelease` | bool | true | mark it as a prerelease (manual runs only) |

## Jobs

| Job | Runs | Output |
|---|---|---|
| `plan` | always | `desktop` and `server` matrices (`{"include":[…]}`), with counts |
| `build-desktop` | matrix non-empty | artifacts `desktop-<triple>` |
| `build-server` | matrix non-empty | artifacts `server-<triple>` |
| `release` | `tag` set or tag push; no job failed | downloads all artifacts, publishes with `softprops/action-gh-release@v2` |

Matrix targets:

| Target | Runner | Desktop | Server |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | ubuntu-22.04 | deb, AppImage | yes |
| `aarch64-unknown-linux-gnu` | ubuntu-24.04-arm | — | yes |
| `aarch64-apple-darwin` | macos-14 | app, dmg | yes |
| `x86_64-apple-darwin` | macos-13 | app, dmg | yes |
| `x86_64-pc-windows-msvc` | windows-latest | msi, nsis | yes |

Version: `rust/Cargo.toml` `[workspace.package] version`. Toolchain: `dtolnay/rust-toolchain@stable`, pinned by `rust/rust-toolchain.toml`. `tauri-cli` ^2 is cached.

## Archives (in `dist/`, then attached to the release)

| File | Contents |
|---|---|
| `secmonk-server-<ver>-<triple>.tar.gz` (Windows: `.zip`) | `secmonk-server[.exe]`, `README.md`, `sec-monk.toml`, `python/` (no `.venv`, `__pycache__`, `tests`), `static/` (from `src/secmonk/web/static`), `rust-ui/` if `rust/ui` exists; each with a `.sha256` file |
| desktop bundles | `.dmg`, `.app.tar.gz` (tarred to keep symlinks), `.msi`, `*-setup.exe`, `.deb`, `.AppImage` |

Constraints: whole repo checked out (`tauri.conf.json` bundles `src/secmonk/web/static`); `bash` on every step.

## Not done

| Item | State |
|---|---|
| Code signing (macOS, Windows) and notarization | not configured; placeholders (commented) in `build-desktop` |
| Tauri updater signatures (`TAURI_SIGNING_PRIVATE_KEY`) | not configured |
| `secmonk-server` binary | **missing**: `secmonk-host` has only `secmonk-headless` today; the `build-server` step fails until the bin exists ([node-server design §1](../plans/node-server-design.md)) |
| `rust/ui/` | does not exist; the step skips `rust-ui/` with a notice |
| Server archive run-time paths | `rust/python/pyproject.toml` has a uv path source `../..` (the repo root), which is outside the archive; the archive is not self-contained yet |
| Cancelled runs | `release` runs on `always()`; cancelling a run can still publish the partial set as a draft |
| Verification | YAML parsed, actionlint clean, plan and archive steps run locally; no GitHub run yet |
