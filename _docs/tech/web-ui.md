---
title: Web interface — architecture
type: tech
context: tech
status: implemented
tags: [web-ui, architecture, security, cli]
updated: 2026-11-07
code: src/secmonk/web/, src/secmonk/reports.py, src/secmonk/ops.py, scripts/design_mock.py, scripts/design_screenshots.js, scripts/vendor_web.py
related: [features/web-ui.md, decisions/0009-web-ui-vendored-libraries.md, decisions/0008-web-ui-stack.md, tech/collectors/process.md, features/process-monitor.md, tech/architecture.md]
---

# Web interface — architecture

What the user gets, the views and the navigation: [features/web-ui.md](../features/web-ui.md). Why this stack:
[ADR-0009](../decisions/0009-web-ui-vendored-libraries.md). Design system, sample pages and storybook: [`_design/`](../../_design/README.md)
([storybook](../../_design/storybook/index.html), [screenshots](../../_design/screenshots/)).

## Layout

```
secmonk ui ──> web/server.py  ThreadingHTTPServer (stdlib)          browser
                 │  GET /                -> static/index.html  ───────────>  Vue 3.5.13 + Vue Router 4.5.0 (static/vendor)
                 │  GET /static/*        -> css/secmonk.css               secmonk-ui.js     base components (sm-*)
                 │                          js/secmonk-ui.js              secmonk-views.js  store, sources, views, router
                 │                          js/secmonk-views.js           boot.js           mountApp(ApiSource())
                 │  GET /api/meta, /api/processes…, /api/overview, /api/assets…, /api/findings,
                 │      /api/vulns/…, /api/sources, /api/collectors, /api/jobs[/<id>]
                 │  POST /api/processes/save, /api/assets/match, /api/jobs              <── ApiSource (fetch)
                 v
               web/api.py   ProcessMonitor ──> collectors/process (analyse) ──> procmon.snapshot_payload / event_dict
                                          └──> engine (match in a temporary overlay; save() persists)
               web/data.py  DataApi (reads, re-match) ──> reports.* ──> engine/queries.py (SQL)
               web/jobs.py  JobRunner (thread, one job) ──> ops.sync_source / ops.collect + save_and_match
                            (the same functions `secmonk sync` / `secmonk scan` call)

_design/pages/*.html, _design/storybook ──> the same css/js by relative path + MockSource(mock/data.js)
scripts/design_mock.py ──> runs ProcessMonitor on the fixtures ──> _design/mock/data.js
```

| File | Role |
|---|---|
| `src/secmonk/web/server.py` | HTTP server: routing, static files, security headers, Host / CSRF checks, JSON errors |
| `src/secmonk/web/api.py` | `ApiError` (status, message, hint, `code`); `ProcessMonitor`: current analysis, overlay matching, watch state, save |
| `src/secmonk/web/data.py` | `DataApi`: database reads (overview, assets, asset detail, unmatched, findings, vulnerability show / search, sources, collectors) with the CLI's parameter validation; `match()` |
| `src/secmonk/web/jobs.py` | `JobRunner`: background `sync` / `scan` jobs (validation in the request, work in a thread, log + result), one at a time, last 20 kept |
| `src/secmonk/reports.py` | JSON payloads shared with the CLI's `--format json` (`finding_dict`, `findings`, `asset_rows`, `asset_detail`, `component_rows`, `unmatched_rows`, `status_payload`, `vuln_detail`, `vuln_search`, `overview`) |
| `src/secmonk/ops.py` | steps shared by the CLI and the jobs: `parse_opts`, `expand_sources`, `sync_source`, `collect`, `save_and_match` |
| `src/secmonk/procmon.py` | payload builders shared with the CLI: `snapshot_payload`, `tree_rows`, `software_rows`, `launch_item_rows`, `event_dict`, `match_inventory` |
| `static/index.html`, `js/boot.js` | app entry (no inline script: the CSP forbids it) |
| `static/css/secmonk.css` | design tokens (light / dark) + every component style |
| `static/js/secmonk-ui.js` | vocabulary (launch kinds, flags, methods, events), formatting, toasts, theme, base components |
| `static/js/secmonk-views.js` | `ApiSource` / `MockSource`, store, `NAV`, `ROUTES`, views, `mountApp()` |
| `static/vendor/` | Vue and Vue Router global builds + LICENSE, `MANIFEST.json` (sha256), README; written by `scripts/vendor_web.py` |
| `cli.py` `ui` | `secmonk ui [--host] [--port] [--allow-host NAME] [--allow-actions/--no-actions] [--snapshot F] [--open] [-o k=v] [--db]` |
| `errors.py` | `COLLECT_ERRORS`, the collector error group shared by the CLI (exit 1) and the API (503) |

## API

All responses are JSON; errors are `{"error": "...", "hint": "..."}` with a meaningful status. **Every** `/api/`
request must send `X-SecMonk-Request: 1` (403 otherwise), reads included: `watch` and `refresh` change server state.

| Method | Path | Returns | Notes |
|---|---|---|---|
| GET | `/api/meta` | `{version, mode, platform, db{path, exists}, bind, features[]}` | `features` tells the client which areas are live |
| GET | `/api/processes` | snapshot payload (below) | cached; `?refresh=1` takes a new snapshot; a watch tick marks it stale and the next call re-matches |
| GET | `/api/processes/watch` | `{events[], taken_at, baseline}` | first call primes the watcher (no events); each later call = one tick. A refresh while watching is diffed against the watch baseline and its changes are delivered on the next tick |
| POST | `/api/processes/save` | `{asset, scan_id, stats}` | persists `process:<host>` + findings, creates the DB if needed |
| GET | `/api/overview` | `reports.overview`: `{db, totals{assets, components, open_findings, fixable, P1..P4, kev}, assets[], top_findings[], sources[], tables{}}` | |
| GET | `/api/assets` | `reports.asset_rows` = `inventory assets -f json` (+ `findings_by_priority`) | |
| GET | `/api/assets/detail?id=` | `reports.asset_detail`: `{asset{…, meta (large values summarized)}, scans[], components[] (with open finding counts), findings[] (all statuses), summary, partial, warnings}` | 404 `unknown-asset` |
| POST | `/api/assets/match?id=` | `{asset, stats}` | `secmonk match`; this and `/api/processes/save` answer 409 while a job runs (one writer at a time) |
| GET | `/api/unmatched` | `inventory unmatched -f json` rows | |
| GET | `/api/findings?priority&asset&all&fixable&hide_minor&hide_deferred&limit` | `{findings[] (= findings -f json), limit, limit_reached}` | 400 on a bad priority / limit (1..5000); 404 unknown asset |
| GET | `/api/vulns/show?id=[&raw=1]` | `reports.vuln_detail` = `vuln show -f json`: `{id (canonical), query, aliases, summary, severity, cvss_score, records[], kev, epss, affected[], findings[], raw[]?}` | 404 `unknown-vuln` |
| GET | `/api/vulns/search?package&ecosystem&product&version&limit` | `{results[] (= vuln search -f json), limit, limit_reached}` | 400 without package / ecosystem / product |
| GET | `/api/sources` | `{db{path, exists}, registry[{name, description, in_all}], sync_all_order[], status (= status -f json) or null}` | works without a database |
| GET | `/api/collectors` | `[{name, description}]` | |
| POST | `/api/jobs` | the new job (202) | JSON body: `{kind: "sync", sources[], ecosystems[], since, full, limit, path}` or `{kind: "scan", collector, target, options (key=value list or lines), save, min_confidence}`; 400 invalid, 403 actions off, 409 a job is running, 413 / 415 body |
| GET | `/api/jobs`, `/api/jobs/<id>` | jobs newest first (no log) / one job `{id, kind, title, params, status (running, ok, partial, error), started, finished, error, result, log[]}` | scan result `{asset, saved, scan_id, stats, warnings, partial, findings[], counts}`; sync result `{sources[{source, status, records, seconds, message}]}` |

Database reads never create the database: without one they answer 404 with `code: "no-db"`, which the client turns
into a "create the mirror first" state (`/api/sources` still answers, so the first sync can start there).

Snapshot payload (`procmon.snapshot_payload`): `asset, host, platform, os, taken_at, source (live | snapshot), matched,
summary{processes, components, launch_kinds{}, with_findings, flagged, launch_items, missing_programs}, processes[]`
(tree order, `procmon.view_row` + `depth`), `software[]` (one per identity: findings, pids, executables, launch kinds,
flags), `launch_items[]` (with `kind`, `running_pids`, `missing_program`), `warnings[]`. Watch events are
`procmon.event_dict` (the same JSON as `secmonk procs --watch -f json`).

Errors: live snapshot not available on this OS (`UnsupportedPlatformError`) -> 503 with a hint to use `--snapshot`; collector errors -> 503;
anything unexpected -> 500 with the exception type and message (never a traceback page).

## Security (local, no authentication)

| Threat | Mitigation |
|---|---|
| Other machines on the network | bind `127.0.0.1` by default; `--host` elsewhere (IPv4 or IPv6) prints a warning |
| DNS rebinding (a web page resolving its name to 127.0.0.1) | `Host` (name and port) must be a loopback name, the bind address, a name given with `--allow-host`, or, when bound to a wildcard (`0.0.0.0`, `::`), any IP literal or this machine's hostname; else 421. A rebinding page always sends its own domain name |
| CSRF / cross-site requests to localhost | every `/api/` request needs `X-SecMonk-Request: 1` (GETs too: a page could otherwise advance the watcher and steal its events, or force snapshots); a custom header forces a CORS preflight, which the server never answers; mutations are also POST |
| XSS from collected data (process names, paths, plist values) | only `{{ }}` / attribute bindings; the single `v-html` renders static icon paths from `secmonk-ui.js`; CSP `script-src 'self' 'unsafe-eval'` (no inline, no external origin), `style-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'` |
| Tampered or swapped third-party code | libraries vendored from the npm registry after sha512 integrity verification; sha256 per file in `static/vendor/MANIFEST.json`, checked by the tests |
| Path traversal on static files | resolved under `static/` only, else 404 |
| Leaking secrets | payloads come from the collector, which already redacts command lines and URLs (see [process collector](collectors/process.md)) |
| Running collectors / syncs for someone else | jobs read local paths, connect to SSH hosts, pull images and download feeds as the user running `secmonk ui`: allowed by default only on a loopback bind; otherwise `--allow-actions` is required (403). Body: JSON object only, `Content-Type: application/json`, at most 64 KiB; every field validated like the CLI options |
| Untrusted links (advisory references) | rendered as links only when `fmt.safeUrl` accepts them (`http:` / `https:`), with `rel="noopener noreferrer"`; anything else is text |

`'unsafe-eval'` is required by Vue's in-browser template compiler (ADR-0009). Tested in `tests/test_web.py`.

## Frontend structure

- **Components** (`secmonk-ui.js`, prefix `sm-`): icon, button, badge, priority, findings summary (list or counts),
  severity, priority bar, launch badge, flag(s), event badge, chip(s), search, switch, segmented, select, tabs, field,
  job, card, stat, key/value, copy, table (slots per cell), drawer, section, callout, empty, spinner, chain, feed item,
  page header, toasts, theme toggle, nav. Each has a story in `_design/storybook/stories.js`.
- **View-level pieces** (`secmonk-views.js`): `data-gate` (loading / no-db / error around a resource), `findings-table`,
  `finding-detail`, `job-result`, `job-list`, `process-detail`; the reusable ones have stories under *Patterns*.
- **Vocabulary** lives in one place (`LAUNCH`, `FLAGS`, `METHODS`, `EVENTS`, `SEVERITY`, `PRIORITY_TEXT`, `MATCHED_BY`,
  `JOB_STATUS`, `COLLECTOR_TARGETS` in `secmonk-ui.js`) and mirrors `collectors/process`, `engine/match.py`,
  `engine/scoring.py` and `web/jobs.py`: change both together.
- **Store** (`createStore(source)`): `snap`, `meta`, loading / saving / error, `watch{on, interval, events, unseen}`,
  `stale` (events since the snapshot), `jobs{list}` with `startJob()` / polling, and `dataVersion`, bumped when a job ends.
  Views read it through `inject("store")`.
- **Data loading**: `useResource(fetcher, deps)` -> reactive `{data, error, loading, reload}`; reloads when `deps()`
  changes (dropping the old data) and when `dataVersion` changes (keeping it visible).
- **Sources**: `ApiSource()` (server) and `MockSource(data)` (design / storybook). Both return the same shapes.
- **Routing**: hash history; list filters in the query (`useQueryState`, re-read whenever the query changes, so sidebar
  links and back / forward update the filters), details as route params with stable keys (pid, `name@version@category`,
  `label|plist`, `asset|component_id|vuln` for findings, the asset id and the vulnerability id for their pages), so
  every state is a URL. Server-side filters (findings) are query parameters too, re-fetched when they change.
- **Styling**: tokens on `:root`, dark theme via `prefers-color-scheme` or `data-theme`; BEM-like `sm-block__el--mod`
  and `is-*` states; spacing utilities (`sm-mt-*`, `sm-mb-*`, `sm-ml-*`). No static `style=""` attributes; `:style`
  bindings only for computed values (tree depth custom property, column widths), applied through the CSSOM.

## Adding a feature

1. **API**: SQL in `engine/queries.py`, the payload in `reports.py` (used by the CLI's `--format json` too), a handler in
   `web/data.py` (reads) or a job kind in `web/jobs.py` (long actions; steps in `ops.py`, shared with the CLI); the route
   in `server.py` (`GET_ROUTES` for reads, POST for actions; the CSRF header is enforced for all of `/api/`); tests in
   `tests/test_web.py`.
2. **Client**: methods on `ApiSource` and `MockSource`; store state only if shared across views (otherwise
   `useResource`); a view component in `secmonk-views.js` following the page anatomy (page header → context → toolbar →
   content → drawer); the route in `ROUTES`, the entry in `NAV`; the feature name in `/api/meta` `features`.
3. **Design**: extend `scripts/design_mock.py` so the mock carries the new payload, add sample pages in `_design/pages/`
   and stories for any new component, regenerate screenshots.
4. **Docs**: views table in [features/web-ui.md](../features/web-ui.md), API table here.

## Development

```bash
uv run secmonk ui --snapshot tests/fixtures/collectors/process/snapshot.json   # any OS (paths only)
uv run secmonk ui                                                             # this Mac, live
uv run python scripts/design_mock.py                                          # regenerate _design/mock/data.js
python3 -m http.server -d . 8000    # then http://localhost:8000/_design/ (or open the files directly)
node scripts/design_screenshots.js  # _design/screenshots/*.png; needs Node + playwright; blocks all external requests
uv run python scripts/vendor_web.py --check   # vendored libraries match MANIFEST.json
uv run pytest -q tests/test_web.py
```

Upgrading Vue / Vue Router: change the version in `scripts/vendor_web.py`, run it (needs the npm registry), delete the old
`static/vendor/<pkg>@<old>` directory, update the script tags in `static/index.html`, every `_design` page and the
storybook (`tests/test_web.py` fails on a mismatch), re-run the screenshots (they fail on any console error).

## Limitations

- Single-user state in the server process; a restart forgets the current snapshot, the watch baseline and the job list.
- One job at a time and no cancel (Python threads cannot be interrupted): stop the server to abort a long sync.
- The watch is client-driven polling (one tick per request); a closed tab stops it.
- No pagination: processes and components are filtered client side (fine for a few thousand); findings use the CLI's
  `limit` (up to 5000) instead of paging; vulnerability pages show the first 200 affected entries.
