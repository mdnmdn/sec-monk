---
title: ADR-0008 — Local web interface stack
type: decision
context: decisions
status: superseded
tags: [web-ui, architecture, security]
updated: 2026-11-07
related: [features/web-ui.md, tech/web-ui.md, decisions/0001-language-python-uv-mise.md, decisions/0007-process-monitor.md]
code: src/secmonk/web/
---

# ADR-0008 — Local web interface stack

> Superseded by [ADR-0009](0009-web-ui-vendored-libraries.md): same stack, but Vue and Vue Router are vendored in the package (no CDN, no external origin in the CSP).

## Context
sec-monk needs a graphical interface, starting with the process monitor and later hosting every feature. It runs on the
analyst's machine next to the CLI. The project is a Python prototype managed with uv (ADR-0001); adding a Node toolchain
or a web framework dependency for a local tool would be a large cost for little gain.

## Decision
- **Server: Python stdlib** (`http.server.ThreadingHTTPServer`) inside the package (`src/secmonk/web/`), started by
  `secmonk ui`. It serves static files and a small JSON API (`/api/...`) that calls the same modules the CLI calls
  (collectors, `procmon`, `engine`). No new dependency.
- **Client: Vue 3 + Vue Router from a CDN, pinned exact versions, no bundling.** Classic `<script>` files exposing globals
  (`SecMonkUI`), templates compiled in the browser. No `npm`, no build, editable with any editor; the design pages also work
  from `file://`.
- **One component library.** `src/secmonk/web/static/css/secmonk.css` (design tokens + component styles),
  `js/secmonk-ui.js` (base components and formatting), `js/secmonk-views.js` (views, store, data sources, router) are
  loaded unchanged by the app, by the `_design/` sample pages (with a mock data source) and by the storybook.
- **Data-source abstraction**: views talk to a store backed by `ApiSource` (the server) or `MockSource` (fixture-derived
  JSON for design and storybook). The mock is generated from the real fixtures by `scripts/design_mock.py`, so design and
  app render the same payload shape.
- **Local, no authentication**, with mitigations: bind `127.0.0.1` by default (non-loopback needs `--host` explicitly and
  prints a warning), `Host` header allow-list (DNS rebinding), mutating requests require `POST` + `X-SecMonk-Request: 1`
  (not sendable cross-origin without a CORS preflight, which is never granted), strict CSP, no `v-html`.

## Consequences
- The browser needs the CDN reachable (or a cached copy). CSP must allow `'unsafe-eval'` for Vue's in-browser template
  compiler; acceptable for a loopback-only tool serving no third-party content. A later step can vendor the two files.
- Single-user server state (current snapshot, watcher) lives in the process; a restart forgets it.
- Adding a feature = API handlers in `web/api.py`, views registered in `secmonk-views.js`, components reused from the
  storybook; see [tech/web-ui.md](../tech/web-ui.md).
