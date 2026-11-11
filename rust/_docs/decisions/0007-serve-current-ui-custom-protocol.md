---
title: ADR-0007 — Serve the current UI in place through a Tauri custom scheme that also answers /api
summary: The webview loads src/secmonk/web/static in place through the secmonk:// scheme, which also answers /api in-process with today's CSP and CSRF header; no copies, no port, no Tauri IPC.
read_when: you change how the desktop app loads the UI or answers API calls, or touch CSP, navigation or the static files
type: decision
context: decisions
status: accepted
tags: [web-ui, tauri, security, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/architecture.md, tech/api-contract.md]
---

# ADR-0007 — Current UI through a custom scheme

## Context

AGENTS.md: one component library, never copied; no build step, no network (Python ADR-0009). `ApiSource(base="")`
uses relative fetches. The proposal (§11.1) suggested a custom URI scheme handler that calls the engine catalog.

## Decision

- Register scheme `secmonk` (the spike used `register_uri_scheme_protocol`; the asynchronous variant is preferred).
  Window URL: `secmonk://localhost/` on macOS/Linux, `http://secmonk.localhost/` on Windows. `frontendDist` is an
  empty directory.
- `/`, `/index.html`, `/static/*` read from `ui.static_dir` (dev: `../src/secmonk/web/static` or `$SECMONK_STATIC`;
  release: `resource_dir()/static`, bundled through Tauri `resources`, a copy made at bundle time) with traversal and
  symlink checks; SPA fallback to `index.html`; `/api/*` go to `secmonk-api` in-process.
- Response headers = `server.py`'s (same CSP: `script-src 'self' 'unsafe-eval'`, no inline scripts or styles);
  Tauri's `app.security.csp` does not apply to custom scheme responses, so this header is the policy. `X-SecMonk-Request: 1` required on `/api/*`. No TCP port, so no Host check beyond the authority;
  the optional dev HTTP binding keeps the full Host check.
- No Tauri commands/capabilities granted to the window; external navigation refused, `http(s)` links opened in the
  system browser **(verify)**.

## Implementation (W2.3, 2026-11-11)

- `secmonk-api` (Tauri-free) holds the router: `Router::handle(http::Request<Vec<u8>>) -> http::Response<Vec<u8>>`.
  `secmonk-desktop` registers it with `register_asynchronous_uri_scheme_protocol` (spawned on Tauri's async
  runtime). The same router runs over loopback in `secmonk_api::serve_http` (headless harness, `[ui] http_listen`).
- Static files: percent-decoded, any `..`, absolute path, backslash or NUL is refused, then canonicalized and required
  inside the canonical root and a regular file (symlinks out are refused). Unknown `GET` paths without a file
  extension fall back to `index.html`; with one they answer 404.
- Authority check on the scheme: `localhost` (or `<scheme>.localhost`), no port; anything else is 421. Both the URI
  authority and a `Host` header are checked when present.
- Window: no capabilities (`app.security.capabilities = []`, no `capabilities/` files), so no IPC command is
  allowed. `on_navigation` allows only the own origin; `http(s)` links and `target=_blank` open in the system
  browser through the Rust-side `opener` crate (no plugin permission); everything else is refused.
- Static dir: debug builds use `$SECMONK_STATIC`, then `[ui] static_dir`, then the bundle; **release builds use only
  the bundled `static` resource** (a config file or variable cannot swap the code the webview runs).
- Webview data: `data_dir/webview` through `data_directory` on Windows and Linux; no option on macOS (documented).

## Consequences

- The UI and `_design` stay one codebase; a UI change is visible in both apps.
- Packaging later must ship the static directory as a resource (still not a copy in the repo).
- Downloads (SBOM blob) and `target=_blank` links need webview-specific handling **(verify)**.
- Spike evidence (2026-11-11): the handler sends the exact CSP, rejects traversal, answers 403 without
  `X-SecMonk-Request`; the unchanged `ApiSource("")` worked against it with the real Vue files in Node. A real
  webview render was not possible in the sandbox: **(verify on a GUI session)**.
- WKWebView keeps its state in `~/Library/WebKit/<id>` and `~/Library/Caches/<id>`, outside `data_dir`: a known
  exception on macOS (Tauri's data-directory option covers Windows and Linux).

## Implementation notes (2026-11-11, W4.2)

- The asynchronous scheme handler is what `apps/desktop/src-tauri/src/lib.rs` registers
  (`register_asynchronous_uri_scheme_protocol`, the router in a `OnceLock`; 503 "starting" before it is set).
- While `secmonk-host` starts, the router sits on the preparing `Gate`, so the page loads and the API answers 503
  "preparing" (step N of 5) instead of a blank window.
- The headless server (`secmonk-headless`) serves `ui.static_dir` in every build; only the window's release build is
  restricted to the bundle.
- Still unobserved in a real webview: rendering, CSP, the preparing panel, SBOM download and external links
  ([on-macos](../plans/on-macos.md)).
