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
                                              Rust workspace (13 crates + the desktop app), dependency bans in deny.toml
python/                                       uv project "secmonk-modules": `serve --stdio` adapters
contracts/                                    JSON Schemas, catalogs, examples (README inside)
golden/                                       shared golden outputs (conformance, differential tests)
sec-monk.toml                                 dev config: data_dir = "_data"
_data/                                        everything written at run time (gitignored)
_docs/                                        documentation (follows ../_docs/_meta rules)
```

Crates worth naming: `secmonk-sources` holds the native (Rust) vulnerability sources. `kev` and `epss` run natively by
default (no Python, no staging copy: [source-kev](_docs/tech/source-kev.md), [source-epss](_docs/tech/source-epss.md),
[ADR-0011](_docs/decisions/0011-native-sources.md)); `[sources.implementation] kev = "python"` (or `epss = "python"`)
in `sec-monk.toml` switches a source back to the Python module.

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
cargo run -p secmonk-host --bin secmonk-server -- serve --listen 127.0.0.1:8765   # no window: API + UI (server mode)
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
  reload when it is done. Later starts are ready after a few seconds. The server prints
  `listening http://127.0.0.1:<port>` on stderr and stops cleanly (modules stopped) on Ctrl-C.

### Server mode (`secmonk-server`)

`secmonk-server` serves the UI and the API over HTTP(S), with no window. `secmonk-headless` is the same command line
and `secmonk-desktop serve` (or `--serve`) runs the same code; every build of the app also has the admin commands
below (on Windows the release app has no console: use `secmonk-server.exe`).

```bash
secmonk-server help                                   # all commands and options
secmonk-server                                        # = serve: 127.0.0.1:8765, no login on loopback
secmonk-server serve --listen 0.0.0.0:8765 --tls-cert cert.pem --tls-key key.pem   # reachable: login required
secmonk-server serve --listen 0.0.0.0:8080 --set server.insecure_http=true         # behind a TLS-terminating proxy
secmonk-server serve --no-actions                     # read-only: no scans or syncs through the API
secmonk-server config show                            # the effective configuration (file + environment + options)
```

- **Authentication.** On a non-loopback address (or `--auth required`) `/api/*` needs an API key or a token. The server
  starts without keys but warns: create the first one **on the machine that runs the server, as the same user**:

  ```bash
  secmonk-server apikey create --name admin --scope admin               # prints smk_... once on stdout
  secmonk-server apikey create --name ci --scope ui:read --scope match --expires-days 90
  secmonk-server apikey list                                            # id, name, scopes, created, expires, revoked
  secmonk-server apikey revoke ci                                       # by id or name; a running server notices
  ```

  Scopes: `ui:read`, `ui:actions`, `feed:read`, `match`, `vulninfo:read`, `admin` (implies all). The key is shown once
  and only its hash is stored (`<data_dir>/auth/api_keys.toml`, 0600). The UI shows a login form that exchanges the key
  for a one-hour token; scripts use `Authorization: ApiKey smk_...` or `POST /auth/token` ([contract](_docs/tech/api-contract.md#server-mode-authentication-scopes-mounts)).
  The token signing secret is `SECMONK_JWT_SECRET` (hex or base64, at least 32 bytes) or the file `<data_dir>/auth/jwt.key`
  (created on first start).
- **TLS.** `--tls-cert` and `--tls-key` (PEM chain and key, set together) make the server speak HTTPS. A non-loopback
  address without TLS is refused (exit 2) unless `[server] insecure_http = true`, for a proxy that terminates TLS; add
  the public name with `[server] allow_hosts = ["scan.example"]`.
- **Overrides.** Precedence: options (`--set`, `--listen`, ...) > `SECMONK_*` environment > file > defaults, so a server
  needs no file: `SECMONK_DATA_DIR=/var/lib/sec-monk SECMONK_SERVER__LISTEN=0.0.0.0:8443 secmonk-server serve --tls-cert ... --tls-key ...`
  or `secmonk-server --data-dir /var/lib/sec-monk --set log.level=debug serve`
  ([rules](_docs/tech/configuration.md#overrides)).
- **Release archive.** `secmonk-server-<ver>-<triple>.tar.gz` keeps the repository layout the Python modules need
  (`pyproject.toml`, `src/secmonk/`, `rust/python/`) next to the binary and a generated `sec-monk.toml`; run it from the
  archive root ([release](_docs/tech/release.md)).

### Build features per platform

`secmonk-desktop` features (all on by default): `ui` (Tauri window, implies `engine`), `engine` (stores, engine, API
binding), `probe` (py-probe collectors). `cargo build` and `cargo test` at this folder's root build the core crates
only (`default-members`), so a machine without WebKitGTK builds and tests everything except the window.

| Platform | Build |
|---|---|
| macOS, Windows | `cargo build -p secmonk-desktop` (all features) |
| Linux desktop | the same, with WebKitGTK 4.1 installed |
| Linux headless | `cargo build -p secmonk-host --bin secmonk-server`, or `cargo build -p secmonk-desktop --no-default-features --features engine,probe` (no Tauri in the graph; the same command line) |

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
