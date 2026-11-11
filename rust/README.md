# sec-monk — Rust prototype

A single-process **Tauri desktop app** that runs today's sec-monk UI and probes over a Rust host. The Python version
in `../src/` stays as it is and is developed side by side; this folder never edits it.

| Rust (this phase) | Python modules (unchanged `secmonk` package, over stdio) |
|---|---|
| Tauri shell, `secmonk-host` composition, `sec-monk.toml`, store (schema v3, SQLite), module host (protocol, registry, pinned uv), engine (jobs, sync, scan), API router serving the current UI | collectors, sources, classify, match, scoring, versions, report payloads |

Start here: [`_docs/INDEX.md`](_docs/INDEX.md), then [architecture](_docs/tech/architecture.md),
[contracts](_docs/tech/contracts.md) and the status in [plans/prototype.md](_docs/plans/prototype.md).

## Layout

```
Cargo.toml, deny.toml, crates/, apps/desktop/src-tauri
                                              Rust workspace (12 crates + the desktop app), dependency bans in deny.toml
python/                                       uv project "secmonk-modules": `serve --stdio` adapters
contracts/                                    JSON Schemas, catalogs, examples (README inside)
golden/                                       shared golden outputs (conformance, differential tests)
sec-monk.toml                                 dev config: data_dir = "_data"
_data/                                        everything written at run time (gitignored)
_docs/                                        documentation (follows ../_docs/_meta rules)
```

## Rules that matter here

- **Do not edit `../src/` or `../_docs/`.** Python modules import `secmonk` through a uv path dependency.
- **The UI is served in place** from `../src/secmonk/web/static` through the `secmonk://` scheme; no copies.
- **Everything uv writes stays in `data_dir`** (binary, cache, interpreters, venvs); see
  [configuration](_docs/tech/configuration.md).
- **One writer**: only `secmonk-store` writes the database; Python engine modules read it read-only.
- **Probes never touch the store; only `secmonk-store` speaks SQL** (enforced by crate dependencies).
- The security rules of [`../AGENTS.md`](../AGENTS.md) apply unchanged: untrusted targets, redaction, no vulnerability
  APIs during scans, CSP without inline scripts, `X-SecMonk-Request` on every `/api/` call.

## Quick start

Prerequisites: Rust (the toolchain in `rust-toolchain.toml`) and a network for the first start (uv and Python are
downloaded once). Nothing else is installed on the machine: uv, the Python interpreter and the module venv all land
in `data_dir`.

```bash
cd rust
cargo tauri dev                           # dev window (cargo install tauri-cli --version "^2"); same as:
cargo run -p secmonk-desktop              # macOS, Windows, Linux with WebKitGTK 4.1
cargo run -p secmonk-host --bin secmonk-headless -- --listen 127.0.0.1:8765   # no window: API + UI on loopback
```

- **Config.** Every build (`cargo run`, `cargo tauri dev`, release) reads `./sec-monk.toml` of the current directory
  unless `--config FILE` or `SECMONK_CONFIG` is given; otherwise the per-user file is used. Start sec-monk only from
  directories you trust. The config must list `[modules] enabled`, which this folder's file does ([configuration](_docs/tech/configuration.md)).
- **Where data goes.** With this folder's config `data_dir` is **`rust/_data/`** (gitignored): `db/`, `tools/uv-*`,
  `python/`, `venvs/`, `uv-cache/`, `cache/`, `logs/secmonk-desktop.log.<date>` and the rest of the
  [layout](_docs/tech/configuration.md#data-directory-layout). The per-user default is `~/Library/Application Support/sec-monk`,
  `$XDG_DATA_HOME/sec-monk` or `%LOCALAPPDATA%\sec-monk`.
- **Reset.** Quit the app, then `rm -rf rust/_data` (everything, including the uv download and the databases), or
  remove only `rust/_data/db` to keep the Python runtime and start with empty databases.
- **First start.** The window (or the server) comes up at once and answers "sec-monk is preparing its Python runtime
  (step N of 5: ...)" while uv, Python and the module environment install (38 s observed on a Mac, mostly `uv sync`);
  reload when it is done. Later starts are ready after a few seconds. The headless server prints
  `listening http://127.0.0.1:<port>` on stderr and stops cleanly (modules stopped) on Ctrl-C.

### Build features per platform

`secmonk-desktop` features (all on by default): `ui` (Tauri window, implies `engine`), `engine` (stores, engine, API
binding), `probe` (py-probe collectors). `cargo build` and `cargo test` at this folder's root build the core crates
only (`default-members`), so a machine without WebKitGTK builds and tests everything except the window.

| Platform | Build |
|---|---|
| macOS, Windows | `cargo build -p secmonk-desktop` (all features) |
| Linux desktop | the same, with WebKitGTK 4.1 installed |
| Linux headless | `cargo build -p secmonk-desktop --no-default-features --features engine,probe` (no Tauri in the graph; runs the loopback server) |

## Checks

```bash
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test                                   # core crates (default-members), offline
cargo test -p secmonk-desktop                # the window crate, with Tauri
node apps/desktop/tests/nodeapi.cjs ../src/secmonk/web/static http://127.0.0.1:8765/   # UI scripts against a running headless server

cd python                                    # the Python modules (uv project secmonk-modules)
uv run pytest -q                             # protocol, conformance, golden, safety; offline
uv run ruff check .
uv run python scripts/check.py               # contracts, manifests, golden outputs
```

Contracts: every schema must be valid draft 2020-12 and every example must validate (`scripts/check.py`, procedure in
[`contracts/README.md`](contracts/README.md)). Real-module Rust tests (`secmonk-engine/tests/real_modules.rs`) run only
when `python/.venv` exists. What needs a real Windows, Linux or macOS machine: [`_docs/plans/`](_docs/plans/README.md).
