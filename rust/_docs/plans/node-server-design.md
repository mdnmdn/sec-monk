---
title: Design brief — server mode, API-key/JWT auth, mirror nodes (feed, match, vulninfo)
summary: Working design for the server mode of the Rust app (secmonk-server, secmonk-desktop --serve), API keys exchanged for JWTs, TLS, the UI transport abstraction (Tauri IPC or HTTPS), config overrides (SECMONK_*, --set) and paths, tool reuse, and the mirror-node services of the 2026-11-12 proposal.
read_when: you work on the server mode, authentication, the node API (/node/v1), the UI transport, config overrides or the release workflow of the Rust app
type: plan
context: plans
status: done
tags: [rust, server, auth, distributed, config, release]
updated: 2026-11-13
verified: 2026-11-13
related: [tech/architecture.md, tech/configuration.md, tech/api-contract.md, decisions/0013-mirror-nodes-and-source-versions.md, decisions/0014-server-mode-auth-and-ui-transport.md]
---

# Design brief — server mode, auth, mirror nodes

> Implemented 2026-11-13. Normative details live in [tech/node-api.md](../tech/node-api.md), [tech/api-contract.md](../tech/api-contract.md#server-mode-authentication-scopes-mounts) ("Server mode"), [tech/configuration.md](../tech/configuration.md), [tech/release.md](../tech/release.md) and ADR-0013 / ADR-0014; this brief is the original working design and is not kept in sync.

Source: the proposal [`_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md`](../../../_docs/inbox/2026-11-12-mirror-nodes-feed-match-service.md)
(Rust only) plus the user request of 2026-11-13: run headless with API-key-authenticated APIs, serve the UI over
HTTP(S) with API-key login exchanged for a JWT, a UI transport that uses Tauri IPC in the window and HTTPS in a
browser, config paths overridable by `--set` / `SECMONK_*`, a server-only executable and a `--serve` flag on the
desktop app, reuse of installed tools, and a release workflow.

## 1. Executables and modes

| Executable | Crate | Contains | Modes |
|---|---|---|---|
| `secmonk-server` | `secmonk-host` (bin, feature `engine`) | no Tauri | `serve` (default), `apikey create|list|revoke`, `config show`, `version` |
| `secmonk-headless` | `secmonk-host` (bin) | alias of `secmonk-server serve`, kept for scripts | as before plus the new flags |
| `secmonk-desktop` | `apps/desktop/src-tauri` | Tauri window (feature `ui`) | window (default); `--serve` / `serve` runs exactly `secmonk-server` (no window is created) |

Both parse the same command line (`secmonk_host::cli`): `--config FILE`, `--listen ADDR`, `--set key=value`
(repeatable), `--data-dir DIR`, `--tls-cert FILE`, `--tls-key FILE`, `--allow-actions`, `--no-actions`, `--auth MODE`.

## 2. Configuration: overrides and paths (secmonk-config)

Precedence, highest first: **command line** (`--set section.key=value`, convenience flags) > **environment**
(`SECMONK_*`) > **file** > built-in defaults. Overrides are merged into the TOML document **before** it is
deserialized, so the `deny_unknown_fields` rules apply to them too (a typo in an override is an error).

- Environment: `SECMONK_<KEY>` for a top-level key (`SECMONK_DATA_DIR`), `SECMONK_<SECTION>__<KEY>` for a nested key
  (`SECMONK_SERVER__LISTEN`, `SECMONK_PATHS__TOOLS`, `SECMONK_NODE__UPSTREAM__URL`); names are lower-cased,
  `__` separates levels. Reserved, not overrides: `SECMONK_CONFIG`, `SECMONK_STATIC`, `SECMONK_API_KEY`,
  `SECMONK_UPSTREAM_API_KEY`, `SECMONK_JWT_SECRET`, `SECMONK_LOG`. An unknown `SECMONK_` name that is not reserved
  and does not map to a key is refused like an unknown key.
- Values are parsed as a TOML value when they parse (`true`, `8`, `["a","b"]`), else taken as a string.
- Relative paths given by an override resolve against the **current directory** (file values keep resolving against
  the file's directory).

New sections:

```toml
[paths]            # every directory below data_dir can be moved; unset = data_dir/<default>
tools = "…"        # uv releases (tools/uv-<version>); share it between data dirs to download uv once
python = "…"       # uv-managed interpreters (UV_PYTHON_INSTALL_DIR)
venvs = "…"        # module environments
uv_cache = "…"     # UV_CACHE_DIR
cache = "…"        # SECMONK_CACHE of modules (cvelist clone, image blobs)
logs = "…"
db = "…"           # default directory of state/mirror sqlite files ({db_dir} in [database] URLs)
auth = "…"         # api_keys.toml, jwt.key

[uv]
path = "…"         # use this uv binary (must report [uv] version unless uv.any_version = true); "auto" = uv on PATH
any_version = false

[server]
listen = "127.0.0.1:8765"
tls_cert = "…"     # PEM chain; with tls_key the server speaks HTTPS
tls_key = "…"
trusted_proxies = []   # reverse proxies whose X-Forwarded-For is trusted (IPs / CIDRs)
allow_hosts = []   # extra Host header names accepted (public DNS name of the server)
insecure_http = false   # allow plain HTTP on a non-loopback address (behind a TLS-terminating proxy)
allow_actions = true    # scans and syncs through the API (still needs the `ui:actions` scope)
auth = "auto"      # "auto": required on non-loopback, off on loopback; "required"; "off" (loopback only)
serve_ui = true

[auth]
keys_file = "…"    # default {paths.auth}/api_keys.toml
jwt_ttl_s = 3600
rate_per_minute = 600   # token bucket per key id
jwt_secret_file = "…"   # default {paths.auth}/jwt.key, created 0600 with 32 random bytes

[node]
mirror = true                  # this node has a mirror part
serve = []                     # any of "feed", "match", "vulninfo"; empty = no node API
matcher = "local"              # "local" | "remote" (state-only node: match through node.upstream)
[node.upstream]
url = "https://mirror.example:8765"
api_key_env = "SECMONK_UPSTREAM_API_KEY"
ca_cert = "…"                  # optional PEM to trust (self-signed upstream)
sources = []                   # sources followed from the upstream feed instead of their own importer
```

## 3. Authentication (crate `secmonk-auth`, no I/O beyond the keys file)

- **API key** format `smk_<id>_<secret>`: `id` 8 lowercase hex chars (public, used in logs), `secret` 32 bytes
  base64url without padding. Only `sha256(secret)` is stored, in `api_keys.toml` (0600):
  `[[key]] id, name, hash, scopes, created, expires (optional), revoked (bool)`. Comparison is constant time.
- **Scopes**: `ui:read` (every GET of `/api`), `ui:actions` (POST `/api/jobs`, match, save), `feed:read`,
  `match`, `vulninfo:read`, `admin` (implies all). `ui` is shorthand for `ui:read` + `ui:actions`.
- **JWT** HS256 (`hmac` + `sha2`), claims `iss = "secmonk"`, `sub = key id`, `scp` (scopes, space separated),
  `iat`, `exp` (now + `jwt_ttl_s`), `jti`. Secret from `SECMONK_JWT_SECRET` or `jwt.key`. Revoking a key also
  rejects its JWTs (the verifier checks the key is still active).
- **Exchange**: `POST /auth/token` with `{"method": "<name>", ...}` (`api_key` is the default method, so `{"api_key": "smk_…"}` works; or `Authorization: ApiKey smk_…`) →
  `{"token", "token_type": "Bearer", "expires_at", "scopes"}`. Failed attempts are rate-limited per client address.
- **Requests**: `Authorization: Bearer <jwt>` or `Authorization: ApiKey <key>` (machine clients). The CSRF header
  `X-SecMonk-Request: 1` stays required on `/api/*`; `/node/v1/*` and `/auth/token` are not browser routes and do
  not need it.
- **What is public**: static UI files (`/`, `/static/*`, `/rust-ui/*`), `GET /auth/info` (`{auth, providers, login_methods}`). Everything
  else needs a principal when auth is on.
- **Quotas**: a token bucket per key id (calls per minute, `[auth] rate_per_minute`, default 600) and per-call caps
  (1 000 components, 500 ids). Audit: one `tracing` line per authenticated call (target `audit`: key id, route,
  status, count), never the body.

## 4. HTTP server (secmonk-api)

`serve_http` gains a TLS acceptor (`tokio-rustls`, PEM files) and an `AuthLayer` in front of the router:
`/auth/*` handled there, `/node/v1/*` dispatched to a mounted `NodeApi` (trait object, implemented in
`secmonk-node`), the rest to the existing `Router`. A non-loopback listen address needs auth on and either TLS or
`insecure_http = true`; otherwise the start is refused with exit 2. The Host check accepts the bind address,
`localhost` and `[server] allow_hosts`.

## 5. UI transport (rust/ui overlay, no edit of src/)

The UI under `src/secmonk/web/static` calls `fetch("/api/…")` through `ApiSource`. The Rust app serves an overlay
(`rust/ui/`, embedded with `include_str!`): `/` → `rust/ui/index.html` (same scripts plus
`/rust-ui/transport.js` before `secmonk-views.js` and `/rust-ui/boot.js` instead of `static/js/boot.js`).
`transport.js` defines `window.SecMonkTransport`:

- **tauri**: `window.__TAURI_INTERNALS__` present → `invoke("secmonk_api", {method, path, headers, body})`, answered
  by the router in process (command allowed for the main window only, capability `rust/apps/desktop/src-tauri/capabilities/main.json`).
- **http**: otherwise `fetch` with `Authorization: Bearer <jwt>`; a JWT is kept in `sessionStorage`; `GET /auth/info`
  tells whether a login is needed; a 401 shows the login form (API key → `POST /auth/token`); the token is renewed
  before expiry while the page is open; "Sign out" clears it.

`transport.js` installs a `fetch` wrapper for same-origin `/api/` URLs only, so the unchanged `ApiSource` works in
both modes (SBOM download included). No inline script or style (CSP).

## 6. Mirror nodes (the proposal, scoped)

Model types in `secmonk-model::node`; traits `MatchService`, `VulnInfo`, `Feed` in `secmonk-traits::node`;
in-process implementations in `secmonk-engine::node` over the stores and the `Matcher`; HTTP binding and remote
clients in the new crate `secmonk-node`.

| Proposal item | Done here |
|---|---|
| P0 traits, in-process implementation, `component_match` / `component_lookup` / `vuln_summary` tables, `match.changes` in process | yes; `match.components` is an ephemeral match of a synthetic inventory regrouped by component key |
| P1 source versions `(source, upstream version, importer version)`, index `(source, modified)`, `matcher` version | yes (version = `source_sync.cursor` + the importer version; `partial` runs do not move the served version) |
| P2 authenticated binding, scopes, quotas, audit | yes (API keys + JWT over TLS instead of mTLS: ADR-0014) |
| P3 state-only node (remote matcher, `vuln_summary` fill, polling `match.changes`) | yes, polling |
| P4 feed: `feed.status`, `feed.since`, following an upstream as a `Source` | yes for per-record sources and snapshot sources (whole snapshot) |
| P5 hardening (filtered replicas, match cache, signed rows, hash-prefix mode, Bloom-filtered `changes`) | no |

HTTP binding (`/node/v1`, JSON, `POST` for calls with a body):

| Route | Scope | Request → response |
|---|---|---|
| `GET /node/v1/info` | any | node id, roles, matcher version, source versions |
| `POST /node/v1/match/components` | `match` | `{components: [≤1000]}` → `{results: [{key, matches, lookup_keys}], as_of, coverage}` |
| `POST /node/v1/match/changes` | `match` | `{since: {source: version}}` → `{sources: {src: {changed_keys, changed_ids} | {resync: reason}}, as_of}` |
| `POST /node/v1/vulninfo/summaries` | `vulninfo:read` | `{ids: [≤500]}` → `{summaries: [...]}` |
| `GET /node/v1/vulninfo/detail?id=&raw=` · `GET /node/v1/vulninfo/search?<params>` | `vulninfo:read` | the `vulns/show` / `vulns/search` payloads |
| `GET /node/v1/feed/status` | `feed:read` | per source: version, importer version, kind, records |
| `GET /node/v1/feed/since?source=&since=&page=&limit=` | `feed:read` | a page of `secmonk-mirror-rows/1` batches since that version, or `resync` (full snapshot pages) |

## 7. Release workflow

`.github/workflows/release.yml`, `workflow_dispatch` with checkboxes: `desktop`, `server`, `linux`, `macos`,
`windows`, plus `tag` / `draft`. Desktop bundles via `tauri-cli`; the server is `cargo build --locked --release -p
secmonk-host --bin secmonk-server`. Artifacts are uploaded per job; a release is created only when `tag` is set.
