---
title: Web interface (local)
summary: Requirements for the local web UI `secmonk ui` with functional tables mapped to CLI commands, views and routes, navigation, actions, security stance and acceptance criteria.
read_when: you add or change a web UI view, action or route, or need to know what the UI covers and how it is secured
type: feature
context: features
status: implemented
tags: [web-ui, cli, process, findings, sync, design]
updated: 2026-11-11
verified: 2026-11-11
code: src/secmonk/web/, src/secmonk/cli.py
related: [tech/web-ui.md, decisions/0009-web-ui-vendored-libraries.md, features/process-monitor.md, features/scan-and-findings.md, features/vuln-sync.md, features/README.md]
---

# Web interface (local)

`secmonk ui` starts a local web interface on `http://127.0.0.1:8765` covering everything the CLI does: a dashboard,
assets and their inventories, scanning a target, findings, the vulnerability mirror (search, one page per id), sources
and sync, background jobs, and the [process monitor](process-monitor.md). It reads the same database as the CLI and
runs the same code: what `secmonk findings -f json` prints is what the Findings page shows.

Design system, sample pages and the component storybook: [`_design/`](../../_design/README.md)
([storybook](../../_design/storybook/index.html)). How it is built: [tech/web-ui.md](../tech/web-ui.md).

## Requirements

### Who and where

| | |
|---|---|
| User | One analyst on their own machine (security engineer, IT admin, developer checking a laptop). |
| Deployment | Local only: bound to `127.0.0.1`, **no authentication**, no multi-user state. The same Python process that runs the CLI serves it. |
| Data | Only the local mirror (SQLite) and local collectors, like the CLI. The browser never calls anything external: Vue and Vue Router are vendored in the package. The server reaches the network only for what the CLI would (a sync job, a scan of a remote target). |

### Functional (process monitor)

| # | Requirement | CLI equivalent |
|---|---|---|
| F1 | See every running process as a parent/child **tree** or a flat list, with user, launch kind, identity (software + version), findings summary and flags. | `secmonk procs`, `--flat` |
| F2 | **Filter**: free text (name, path, label, identity, user, script), launch kind, "suspicious only" (findings or flags). Filters survive reload (URL). | `--suspicious` |
| F3 | Open a **process detail**: launch explanation (kind, mechanism, label, plist, evidence, ancestry chain), identity (method, all components incl. embedded runtimes / Go modules), findings with priority, KEV, fixed version, provenance (download URL, browser, time, signature, hash), flags with an explanation each. | `procs -f json` |
| F4 | See **running software** grouped by identity (one row per app/formula/package), process count, users, launch kinds, findings. | `inventory show process:<host>` |
| F5 | See **launch items** (persistence): label, mechanism, program, plist, scope, run-at-load / keep-alive, whether it is running, programs that no longer exist. | `asset.meta.launch_items_missing_program` |
| F6 | **Refresh** the snapshot; **save** it (asset `process:<host>` + findings) to the database. | re-run, `--save` |
| F7 | **Watch**: start/stop periodic re-snapshots and get an **activity feed** of new / changed executables and new / changed / removed launch items, with their findings and flags. | `--watch N` |
| F8 | Show the **context**: host, OS, snapshot time, source (live / snapshot file), database present and matched or not, collector warnings. | notes on stderr |

### Functional (database areas)

| # | Requirement | CLI equivalent |
|---|---|---|
| D1 | **Dashboard**: open findings across assets by priority, KEV and fixable counts, the most urgent findings, assets ranked by risk, freshness of each source; every number links to the filtered list. | `status`, `findings`, `inventory assets` |
| D2 | **Assets**: every scanned target (type, OS, components, open findings per priority, last scan); filter by text, type, "with findings". | `inventory assets` |
| D3 | **Asset detail**: findings (incl. fixed), components (with their findings, category filter), scans (partial, warnings), collector facts; **re-match** against the current mirror; rescan. | `inventory show`, `findings ASSET --all`, `match` |
| D4 | **Unmatched identities** (alias-table candidates). | `inventory unmatched` |
| D5 | **Scan a target**: collector, target, `-o` options, save or match-only, minimum confidence; runs as a background job, result = one entry per target (asset, stats, warnings, findings, error) with totals. The equivalent CLI command is shown. | `scan` |
| D5a | **Docker engine** (collector `docker-engine`): choose the engine (auto = current context / `DOCKER_HOST` / local socket, a Docker context from `docker context ls`, or a host `ssh://user@host`, `tcp://host:2376`, `unix:///path`), include stopped containers, re-collect images already scanned (`rescan=true`; by default an image Id already inventoried is only rematched), and under *Advanced* only TLS file paths (`tls_ca`, `tls_cert`, `tls_key`), `tls_verify` and an SSH key (`identity`); the target is a selector: comma-separated names / ids, globs (`web-*`), `re:<regex>`, `image:<ref>`, `image:*` (every tagged image), `image:<glob>`, `image:re:<regex>` (images are scanned once per image Id). **Preview containers** lists the engine's containers and highlights what the selector picks ("N of M match"). The fields become `-o` options in the CLI command shown. | `scan docker-engine -o host=… -o context=… -o all=true`, `containers` |
| D5c | **Host (auto) mode**: a host field (blank = this machine, or `[ssh://]user@host[:port]`; SSH key, known_hosts, connect timeout under *Advanced*), **Explore** (`GET /api/discover`, loading state: an ssh probe can take up to a minute) shows the host (name, OS and version, architecture, local / ssh) and a checkbox panel of candidates (macOS: applications, processes, Homebrew, home folder, Docker containers / images; Linux: its packages, Homebrew, Docker…; over ssh: the remote software and its Docker), each with collector, description, reason (unavailable ones cannot be ticked), details (containers, images per Id, prefixes) and, for Docker and folders, an editable target (`web-*`, `image:nginx:*`). Select all / none; **Scan selected (N)** (at most 20) runs one batch job. The CLI command shown is `secmonk scan-host <host> --only <ids>` (approximate when targets were edited). Each item carries its candidate id (stored in the history). Result rows carry the collector, an image's tags (and the aliases folded into one Id) and a *reused* badge for images whose stored inventory was rematched. | `discover`, `scan-host` |
| D5b | **Run history**: scans and syncs from the UI *and* the CLI are kept in the database (origin `ui` / `cli`, status, time, outcome, log, result) and survive restarts; **Run again** fills the form from a run's settings (never starts it); for a host-mode run it switches to host mode and shows the stored items ticked with their candidate ids (the `scan-host --only` command uses them), without exploring (Explore again for a fresh look). Secrets are stored masked and ssh user names are not stored: the form says what to type again. Earlier targets and hosts are offered as suggestions. | `history` |
| D6 | **Findings** across assets with the CLI filters (priority, asset, fixable, hide minor / deferred, include fixed, limit) plus text search and KEV only; **finding detail**: why this priority, match method and confidence, distro triage, timeline, matched advisories, the vulnerability's KEV / EPSS. | `findings` |
| D7 | **Vulnerability search** by package (ecosystem, name, version) or product (name, version); **vulnerability page** per id (aliases resolve): every source's record, affected ranges, findings on your assets, KEV, EPSS, references, raw records. | `vuln search`, `vuln show [--raw]` |
| D8 | **Sources & sync**: table sizes, each source's last sync / records / status (OSV per ecosystem); **sync** selected sources (or `all`) with ecosystems, since, full, limit, or import from a local file; runs as a job. | `sources`, `status`, `sync` |
| D9 | **Jobs**: the run history (UI and CLI) filtered by kind and origin, with status, duration, outcome; a run's log, result and settings; Run again; one job at a time (a CLI run in progress does not block the UI); a toast when one ends and every page reloads its data. | `history`, `history show` |

Suppression of findings is not in the UI because the CLI has no command for it yet (the engine keeps `suppressed`
sticky; VEX ingestion is planned in [engine-and-quality](../plans/engine-and-quality.md)).

### Non-functional

- **No build step, works offline**: Vue 3 + Vue Router vendored in the package (`static/vendor`, checksummed), plain CSS,
  classic scripts; the design pages work from `file://`. No Node toolchain needed to run or change it.
- **One component library**: the CSS and the Vue components used by the app are the very files used by the design sample
  pages and the storybook (no copies).
- **Secure by default for a local tool**: loopback bind, `Host` header check (DNS rebinding; `--allow-host` for extra
  names when bound to another interface), every API request needs a custom header (CSRF), strict Content-Security-Policy,
  all data rendered as text (no `v-html`), links only for `http(s)` URLs. Scans and syncs (which read local paths and use
  the network) are refused when the server listens on a non-loopback address, unless `--allow-actions`.
- Responsive down to a laptop split screen (1024 px); usable at phone width for reading. Light and dark themes
  (`prefers-color-scheme`, manual toggle). Keyboard reachable (focus styles, `Esc` closes the drawer, `/` focuses search).
- Long lists: up to ~2000 processes without pagination (tree collapse, filtering client side); findings are limited
  server side like the CLI (`limit`, 200 by default, up to 5000) with a note when the limit is reached.

## Overall structure (view perspective)

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ Top bar:  ◆ sec-monk │ breadcrumb: Monitor / Processes │ host · macOS 14.5 · 10:02 │ DB ● │ ◐ │
├──────────────┬───────────────────────────────────────────────────────────────────────────────┤
│ Sidebar      │ Page header: title, one-line description, primary actions (Refresh, Save,     │
│              │              Watch ▸)                                                         │
│ MONITOR      ├───────────────────────────────────────────────────────────────────────────────┤
│  Processes   │ Context strip: stat cards (processes, with findings, flagged, launch kinds)   │
│  Software    │ + warnings callout                                                            │
│  Launch items├───────────────────────────────────────────────────────────────────────────────┤
│  Activity    │ Toolbar: search · filter chips · toggles · view switch                         │
│ INVENTORY    ├───────────────────────────────────────────────────────────────┬───────────────┤
│  Assets      │ Main content: data table (tree / flat), cards, tabs, feed,     │ Detail drawer │
│  Scan        │ forms, job cards                                              │ (row click;   │
│  Unmatched   │                                                               │  deep link)   │
│ RISK         │                                                               │               │
│  Findings    │                                                               │               │
│ DATA         │                                                               │               │
│  Vulns       │                                                               │               │
│  Sources     │                                                               │               │
│ SYSTEM       │                                                               │               │
│  Jobs, About │                                                               │               │
└──────────────┴───────────────────────────────────────────────────────────────┴───────────────┘
```

- **App shell** (always present): top bar, sidebar, main area, toast area. Each feature contributes routes and sidebar
  entries. The top bar shows the snapshot context on monitor pages, the database state elsewhere, and the running job.
  The app opens on the dashboard; the process snapshot is taken only when a monitor page is first opened.
- **Page anatomy** (every view): page header -> optional context strip -> toolbar -> content -> optional drawer.
  New features follow the same anatomy and reuse the components.

## Views

| Route | View | Content | Main interactions |
|---|---|---|---|
| `#/processes` | **Processes** | stat cards (total, with findings, flagged, by launch kind); table: pid, user, launch, process (tree indent, collapse toggle, interpreter script), identity, findings badges, flags | search, launch-kind chips, suspicious toggle, tree / flat switch, expand / collapse all, row click -> drawer, Refresh, Save, Watch |
| `#/processes/:pid` | **Process detail** (drawer over the list; full page on narrow screens) | header (name, pid, user, started); sections: Launch (kind badge, mechanism, label, plist path, evidence, ancestry chain clickable), Identity (method, components table), Findings table, Provenance (quarantine / download URL / agent / time, signature, sha256, file times), Flags (pill + explanation) | click an ancestor -> its detail; copy path / hash; `Esc` / close -> back to list with filters kept |
| `#/software` | **Running software** | table: identity, version, category, resolution method, processes, users, launch kinds, findings, flags | search, category chips, "with findings" toggle, row expand -> executables + processes (links to process detail) |
| `#/launch-items` | **Launch items** | table: label, mechanism (kind badge), scope, program, plist, run-at-load / keep-alive, running pids, missing-program warning | search, mechanism chips, "running only" / "problems only" toggles, link running pid -> process detail |
| `#/activity` | **Activity** | watch controls (interval, start / stop, last tick); event feed newest first: time, event type badge, process / item, identity, findings, flags | start / stop watch, interval select, clear feed, click event -> process detail / launch item |
| `#/overview` | **Dashboard** (start page) | stat cards (open, P1, P2, KEV, fixable, components), most urgent findings, assets at risk (priority bar), mirror freshness (stale > 7 days in amber) | every stat opens the filtered findings / assets; row click -> finding, asset, sources |
| `#/assets` | **Assets** | table: name + id, type, OS / platform, components, open findings by priority, priority bar, last scan | search, type chips, "with open findings", row -> asset page; Scan a target, Unmatched |
| `#/assets/:id` | **Asset detail** (page) | id, last scan; partial / warning callouts; stats; tabs Findings / Components / Scans / Details | priority chips, include fixed, finding -> drawer (`?f=`); component row -> its findings; Re-match, Rescan |
| `#/scan` | **Scan** | mode switch *Single collector* / *Host (auto)* (`?mode=host`); host mode: host + SSH options, Explore, host summary, warnings, candidate checkbox panel, save, minimum confidence, Scan selected, the `scan-host` command; single mode: form (collector with its description, target with a per-collector hint and earlier targets, minimum confidence, save, options; for docker-engine the Engine fields and the container preview) and the equivalent CLI command; **Scan history** (10 newest, origin badge, outcome) with the open run's log and result: totals, then one collapsible row per target (findings, partial / failed, warnings, top findings, asset link) | Run scan (disabled while a job of this server runs or actions are off); Preview containers; row -> its card; Run again -> form filled; `?again=<job id>` fills the form from that run |
| `#/unmatched` | **Unmatched identities** | name, version, category, normalized product, bundle id | search |
| `#/findings/:key?` | **Findings** + **finding detail** drawer | table: priority + KEV, vulnerability, component + version + match method, asset, fixed in, severity + CVSS, EPSS, triage, status | search, priority segmented, asset select, KEV / fixable / hide minor / hide deferred / include fixed, limit; drawer -> asset, vulnerability, advisories |
| `#/vulns` | **Vulnerability search** | package (ecosystem, name) or product search with version; id lookup; examples | results -> vulnerability page |
| `#/vulns/:id` | **Vulnerability** (page) | severity, KEV, EPSS, open findings; on your assets; records by source (summary, details, CVSS vector, CWE, dates, state); affected ranges; raw records on demand; exploitation; aliases; references | alias -> its page (canonical), finding -> drawer |
| `#/sources` | **Sources & sync** | table sizes; per source: description, last sync, records, status, message, OSV ecosystems | row / chip selects sources; sync form (ecosystems, since, limit, local file, full) with the CLI command; sync history with Run again (`?again=<job id>`) |
| `#/jobs/:id?` | **Jobs** | run history of the UI and the CLI (newest 100): #, status, title + error, origin, started, duration, outcome; filters kind (`?kind=`) and origin (`?origin=`) | row -> drawer with log, result and settings (the items of a host-mode run); Run again -> Scan / Sources form filled |
| `#/about` | **About** | version, database path and status, actions on/off, bind address, links to docs / storybook | — |

## Navigation paradigm

- **Persistent left sidebar, grouped by domain** (Monitor, Inventory, Risk, Data), the same groups the CLI help uses; the
  active route is highlighted; the sidebar collapses to icons under 1100 px.
- **Hash routing** (`#/…`): every view and every detail is deep-linkable and works with back / forward, with no server
  routing. Filters live in the query string (`#/processes?q=slack&kind=agent&suspicious=1&mode=flat`).
- **List -> detail in a drawer**: the list keeps its scroll position and filters; the drawer has its own URL; on narrow
  screens it becomes a full page.
- **Cross-links between views**: identity -> software row, launch label -> launch item, pid -> process detail, ancestor
  -> process detail; asset -> finding -> vulnerability -> its findings on other assets; alias -> vulnerability;
  component -> its findings; scan result -> asset; dashboard numbers -> filtered lists.
- Breadcrumb in the top bar: `Group / View [/ Item]`.

## Actions and interactions

| Action | Where | Behaviour | Feedback |
|---|---|---|---|
| Refresh | page header (Processes, Software, Launch items) | new snapshot + match (`GET /api/processes?refresh=1`); button shows a spinner, the table stays visible (stale) until data arrives | toast "Snapshot 10:02:13 — 412 processes"; error callout on failure |
| Save | page header | persist asset + findings (`POST /api/processes/save`) | toast with the stats line; disabled when there is no snapshot |
| Watch start / stop | page header (all monitor views) and Activity | client polls `GET /api/processes/watch` every N s (5, 10, 30, 60); first call sets the baseline | live badge in the top bar ("watching · 10 s"); new events increment a counter on the Activity nav entry; a toast for events with P1/P2 findings or risk flags |
| Filter / search | toolbar | instant, client side; `/` focuses search; chips toggle; state written to the URL | result count "37 of 412" |
| Tree controls | Processes | caret per row with children; expand all / collapse all; filters show matching rows with their ancestors | — |
| Open detail | row click / Enter on focused row | drawer opens, URL changes | — |
| Copy | detail values (paths, hashes, URLs) | copy button next to mono values | toast "Copied" |
| Theme | top bar | light / dark / system, remembered in `localStorage` | — |
| Run scan / sync | Scan, Sources & sync | `POST /api/jobs`; the client polls the job every second; one job at a time (409 otherwise) | job card with live log; badge in the top bar and count on Jobs; toast when it ends; every data view reloads |
| Preview containers | Scan (docker-engine) | `GET /api/docker/containers` with the engine fields and the target as selector; contexts from `GET /api/docker/contexts`; refused like jobs when actions are off | table with matched rows highlighted, "N of M match", engine label; engine errors with a hint |
| Explore a host | Scan (host mode) | `GET /api/discover?target=&opt=k=v` (refused like jobs when actions are off; 400 bad target / option, 502 with a hint) | spinner and "probing over ssh" note; host summary and candidates, or the error with its hint |
| Run again | Scan / Sources history, Jobs drawer | fills the form from the run's stored `params` (docker engine options back into the Engine fields) | toast; warns when a secret was masked or an ssh host lost its user name |
| Re-match | asset page | `POST /api/assets/match` (like `secmonk match`) | toast with the stats; the page reloads |

Empty and error states are explicit: no database (data pages show what to do first with links to Sources & sync and
Scan; the process findings column is hidden), live snapshots not supported on this OS (callout with the snapshot-file
alternative), no asset / finding / result, nothing matches the filters, limit reached, actions disabled on this server.

## Acceptance criteria

- `secmonk ui --snapshot tests/fixtures/collectors/process/snapshot.json` serves the app on any OS; on a Mac `secmonk ui`
  shows the live machine.
- Every view in the table above is reachable from the sidebar and by URL; every CLI command except `procs --watch`
  in a terminal and `windows-script` has a page (`containers` is the container preview of the Scan page, `discover` / `scan-host` its host mode, `history` the Jobs page).
- A scan and a sync started from the UI produce the same database content as the CLI commands shown next to the button.
- The storybook renders every shared component from the same `secmonk-ui.js` / `secmonk.css` the app loads.
- API and security behaviour covered by `tests/test_web.py`.
