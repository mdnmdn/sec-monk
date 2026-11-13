---
title: ADR-0014 — Server mode - secmonk-server, auth provider chain (API keys to JWT), TLS, UI transport over Tauri IPC or HTTPS
summary: "The host runs headless as secmonk-server (or secmonk-desktop --serve) with API and UI behind an auth provider chain (API keys exchanged for HS256 session JWTs first), optional TLS, scopes and rate limits; the UI reaches the router through Tauri IPC in the window and authenticated HTTPS in a browser; config keys are overridable by --set and SECMONK_*."
read_when: you change authentication, add an auth strategy, expose the server beyond loopback, change how the UI reaches the API, or add a config override
type: decision
context: decisions
status: accepted
tags: [security, server, auth, ui, config, decision, rust]
updated: 2026-11-13
verified: 2026-11-13
related: [plans/node-server-design.md, decisions/0007-serve-current-ui-custom-protocol.md, decisions/0008-config-file-and-data-dir.md, decisions/0013-mirror-nodes-and-source-versions.md, tech/api-contract.md, tech/configuration.md, tech/release.md]
---

# ADR-0014 — Server mode, auth, UI transport

## Context

Until 2026-11-12 the Rust app served its API on a custom scheme (the window) and, for development, on a loopback port
with no login ([ADR-0007](0007-serve-current-ui-custom-protocol.md)). On 2026-11-13 the user asked for: a headless
mode exposing the APIs authenticated with API keys; the UI served by that web server behind the same keys; a UI that
uses Tauri APIs when they are there and HTTPS otherwise, with an API key exchanged for a JWT; config paths overridable
by arguments and `SECMONK_*` variables; a Tauri-free server executable and a flag on the desktop app; reuse of
installed tools; and readiness for more auth strategies later.

## Decision

1. **Executables**: `secmonk-server` (crate `secmonk-host`, no Tauri) and `secmonk-desktop --serve` run the same
   server mode; both share one CLI (`serve`, `apikey create|list|revoke`, `config show`, `version`).
2. **Auth is a provider chain** (`secmonk_auth::AuthProvider`): a provider authenticates a request directly, accepts
   named login methods and revalidates its subjects. The `Authenticator` owns the chain, issues **session JWTs**
   (HS256, `prv` = issuing provider, revalidated on every request, so revocation ends sessions) and applies per-subject
   rate limits and a failed-login throttle. **API keys** (`smk_<id>_<secret>`, sha-256 hashes in `api_keys.toml`,
   0600) are the first provider. OIDC, mTLS between nodes or a trusted proxy header are later providers; the HTTP
   layer does not change.
3. **Scopes**: `ui:read`, `ui:actions`, `feed:read`, `match`, `vulninfo:read`, `admin` (implies all).
4. **Exposure rules**: auth is on by default on a non-loopback address (`[server] auth = "auto"`); a non-loopback
   listener needs auth **and** TLS (rustls, PEM files) unless `insecure_http = true` (a TLS-terminating proxy).
   `X-SecMonk-Request` stays required on `/api/*`; static UI files and `/auth/*` are public.
5. **UI transport**: the host serves an overlay (`rust/ui`, embedded) whose `transport.js` wraps `fetch` for same-origin
   `/api/` calls: in the window it calls the Tauri command `secmonk_api` (the router in process; the only command,
   granted to the main window only); in a browser it adds the session JWT and shows a login form. `src/` is unchanged.
6. **Configuration**: `--set section.key=value` > `SECMONK_<SECTION>__<KEY>` > file > defaults, merged before the
   schema check so unknown keys stay refused; `[paths]` moves every data directory (a shared `tools` downloads uv once).
7. **Tool reuse**: `[uv] path` (a file or `auto` = `PATH`) uses an installed uv of the pinned version; the managed uv
   is verified, not re-downloaded; `uv python find` is skipped when a module venv records the interpreter.

## Amends

- ADR-0007 "the window gets no Tauri IPC": the window now has exactly one command, `secmonk_api`, which answers what
  the custom scheme answers (same router, same checks). The scheme stays for static files.
- ADR-0008 lookup order: overrides apply after the file is read.

## Alternatives

- **A JWT crate** (`jsonwebtoken`): more surface than HS256 needs; ~150 lines with `hmac` + `sha2`, `alg` pinned.
- **Opaque server-side sessions**: needs a session store shared by nodes; JWTs revalidated against the provider give
  revocation without one.
- **mTLS only**: does not serve browsers; kept as a future provider.

## Consequences

- The JWT secret (`auth/jwt.key`, or `SECMONK_JWT_SECRET`) must be shared by nodes behind one load balancer.
- Static UI files are public on an exposed server (they carry no data).
- Windows release builds of the desktop app have no console: use `secmonk-server.exe` for the CLI there.
