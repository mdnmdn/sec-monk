---
title: Web interface — architecture
type: tech
context: tech
status: implemented
tags: [web-ui, architecture, security, cli]
updated: 2026-11-07
code: src/secmonk/web/, scripts/design_mock.py, scripts/design_screenshots.js
related: [features/web-ui.md, decisions/0008-web-ui-stack.md, tech/collectors/process.md, features/process-monitor.md, tech/architecture.md]
---

# Web interface — architecture

What the user gets, the views and the navigation: [features/web-ui.md](../features/web-ui.md). Why this stack:
[ADR-0008](../decisions/0008-web-ui-stack.md). Design system, sample pages and storybook: [`_design/`](../../_design/README.md)
([storybook](../../_design/storybook/index.html), [screenshots](../../_design/screenshots/)).

## Layout

```
secmonk ui ──> web/server.py  ThreadingHTTPServer (stdlib)          browser
                 │  GET /                -> static/index.html  ───────────>  Vue 3.5.13 + Vue Router 4.5.0 (unpkg, pinned)
                 │  GET /static/*        -> css/secmonk.css               secmonk-ui.js     base components (sm-*)
                 │                          js/secmonk-ui.js              secmonk-views.js  store, sources, views, router
                 │                          js/secmonk-views.js           boot.js           mountApp(ApiSource())
                 │  GET /api/meta, /api/processes[?refresh=1],
                 │      /api/processes/watch, POST /api/processes/save   <── ApiSource (fetch)
                 v
               web/api.py  ProcessMonitor ──> collectors/process (analyse) ──> procmon.snapshot_payload / event_dict
                                         └──> engine (match in a temporary overlay; save() persists)

_design/pages/*.html, _design/storybook ──> the same css/js by relative path + MockSource(mock/data.js)
scripts/design_mock.py ──> runs ProcessMonitor on the fixtures ──> _design/mock/data.js
```

| File | Role |
|---|---|
| `src/secmonk/web/server.py` | HTTP server: routing, static files, security headers, Host / CSRF checks, JSON errors |
| `src/secmonk/web/api.py` | `ProcessMonitor`: current analysis, overlay matching, watch state, save |
| `src/secmonk/procmon.py` | payload builders shared with the CLI: `snapshot_payload`, `tree_rows`, `software_rows`, `launch_item_rows`, `event_dict`, `match_inventory` |
| `static/index.html`, `js/boot.js` | app entry (no inline script: the CSP forbids it) |
| `static/css/secmonk.css` | design tokens (light / dark) + every component style |
| `static/js/secmonk-ui.js` | vocabulary (launch kinds, flags, methods, events), formatting, toasts, theme, base components |
| `static/js/secmonk-views.js` | `ApiSource` / `MockSource`, store, `NAV`, `ROUTES`, views, `mountApp()` |
| `cli.py` `ui` | `secmonk ui [--host] [--port] [--snapshot F] [--open] [-o k=v] [--db]` |

## API (phase 1)

All responses are JSON; errors are `{"error": "...", "hint": "..."}` with a meaningful status.

| Method | Path | Returns | Notes |
|---|---|---|---|
| GET | `/api/meta` | `{version, mode, platform, db{path, exists}, bind, features[]}` | `features` tells the client which areas are live |
| GET | `/api/processes` | snapshot payload (below) | cached; `?refresh=1` takes a new snapshot; a watch tick marks it stale and the next call re-matches |
| GET | `/api/processes/watch` | `{events[], taken_at, baseline}` | first call primes the watcher (no events); each later call = one tick |
| POST | `/api/processes/save` | `{asset, scan_id, stats}` | needs `X-SecMonk-Request: 1`; persists `process:<host>` + findings, creates the DB if needed |

Snapshot payload (`procmon.snapshot_payload`): `asset, host, platform, os, taken_at, source (live | snapshot), matched,
summary{processes, components, launch_kinds{}, with_findings, flagged, launch_items, missing_programs}, processes[]`
(tree order, `procmon.view_row` + `depth`), `software[]` (one per identity: findings, pids, executables, launch kinds,
flags), `launch_items[]` (with `kind`, `running_pids`, `missing_program`), `warnings[]`. Watch events are
`procmon.event_dict` (the same JSON as `secmonk procs --watch -f json`).

Errors: live snapshot not available on this OS -> 503 with a hint to use `--snapshot`; collector errors -> 503;
anything unexpected -> 500 with the exception type and message (never a traceback page).

## Security (local, no authentication)

| Threat | Mitigation |
|---|---|
| Other machines on the network | bind `127.0.0.1` by default; `--host` elsewhere prints a warning |
| DNS rebinding (a web page resolving its name to 127.0.0.1) | `Host` must be `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>` or the bind address, else 421 |
| CSRF (a web page posting to localhost) | mutations are POST + `X-SecMonk-Request: 1`; a custom header forces a CORS preflight, which the server never answers |
| XSS from collected data (process names, paths, plist values) | only `{{ }}` / attribute bindings; the single `v-html` renders static icon paths from `secmonk-ui.js`; CSP `script-src 'self' 'unsafe-eval' https://unpkg.com` (no inline), `style-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'` |
| Path traversal on static files | resolved under `static/` only, else 404 |
| Leaking secrets | payloads come from the collector, which already redacts command lines and URLs (see [process collector](collectors/process.md)) |

`'unsafe-eval'` is required by Vue's in-browser template compiler (ADR-0008). Tested in `tests/test_web.py`.

## Frontend structure

- **Components** (`secmonk-ui.js`, prefix `sm-`): icon, button, badge, priority, findings summary, launch badge, flag(s),
  event badge, chip(s), search, switch, segmented, select, card, stat, key/value, copy, table (slots per cell), drawer,
  section, callout, empty, spinner, chain, feed item, page header, toasts, theme toggle, nav. Each has a story in
  `_design/storybook/stories.js`.
- **Vocabulary** lives in one place (`LAUNCH`, `FLAGS`, `METHODS`, `EVENTS` in `secmonk-ui.js`) and mirrors
  `collectors/process` (launch kinds, `risk_flags`, resolution methods, watch events): change both together.
- **Store** (`createStore(source)`): `snap`, `meta`, loading / saving / error, `watch{on, interval, events, unseen}`,
  `stale` (events since the snapshot). Views read it through `inject("store")`.
- **Sources**: `ApiSource()` (server) and `MockSource(data)` (design / storybook). Both return the same shapes.
- **Routing**: hash history; list filters in the query (`useQueryState`), details as route params, so every state is a
  URL. Planned areas are routes too, rendered by `PlannedView` with the CLI command to use today.
- **Styling**: tokens on `:root`, dark theme via `prefers-color-scheme` or `data-theme`; BEM-like `sm-block__el--mod`
  and `is-*` states; no inline styles beyond a few layout one-offs.

## Adding a feature (later phases)

1. **API**: a handler object like `ProcessMonitor` in `web/api.py` (or a new module) that calls the existing engine /
   queries; routes in `server.py` (GET for reads, POST + CSRF header for actions); payload builders next to the
   CLI code so `--format json` and the UI share them; tests in `tests/test_web.py`.
2. **Client**: methods on `ApiSource` and `MockSource`; store state if the data is shared across views; a view component
   in `secmonk-views.js` following the page anatomy (page header → context → toolbar → content → drawer); add the route
   to `ROUTES` and flip `planned` off in `NAV`; add the feature name to `/api/meta` `features`.
3. **Design**: extend `scripts/design_mock.py` so the mock carries the new payload, add sample pages in `_design/pages/`
   and stories for any new component, regenerate screenshots.
4. **Docs**: views table in [features/web-ui.md](../features/web-ui.md), API table here.

## Development

```bash
uv run secmonk ui --snapshot tests/fixtures/collectors/process/snapshot.json   # any OS (paths only)
uv run secmonk ui                                                             # this Mac, live
uv run python scripts/design_mock.py                                          # regenerate _design/mock/data.js
python3 -m http.server -d . 8000    # then http://localhost:8000/_design/ (or open the files directly)
node scripts/design_screenshots.js  # _design/screenshots/*.png; needs Node + playwright
uv run pytest -q tests/test_web.py
```

Vue is pinned in `static/index.html`, every `_design` page and the storybook (`vue@3.5.13`, `vue-router@4.5.0`): bump
all of them together and re-run the screenshots (they fail on any console error).

## Limitations

- Needs the CDN (unpkg.com) in the browser; offline the page shows a message. Vendoring the two files is a later step.
- Single-user state in the server process; a restart forgets the current snapshot and the watch baseline.
- The watch is client-driven polling (one tick per request); a closed tab stops it.
- No pagination: fine for a few thousand processes; later views (findings across assets) will need server-side paging.
