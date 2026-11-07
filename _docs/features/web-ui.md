---
title: Web interface (local)
type: feature
context: features
status: implemented
tags: [web-ui, cli, process, design]
updated: 2026-11-07
code: src/secmonk/web/, src/secmonk/cli.py
related: [tech/web-ui.md, decisions/0009-web-ui-vendored-libraries.md, features/process-monitor.md, features/scan-and-findings.md, features/README.md]
---

# Web interface (local)

`secmonk ui` starts a local web interface on `http://127.0.0.1:8765`. Phase 1 hosts the
[process monitor](process-monitor.md); the shell (navigation, layout, components, API conventions) is built to host every
other sec-monk feature later (assets and inventories, findings, vulnerability mirror, sync).

Design system, sample pages and the component storybook: [`_design/`](../../_design/README.md)
([storybook](../../_design/storybook/index.html)). How it is built: [tech/web-ui.md](../tech/web-ui.md).

## Requirements

### Who and where

| | |
|---|---|
| User | One analyst on their own machine (security engineer, IT admin, developer checking a laptop). |
| Deployment | Local only: bound to `127.0.0.1`, **no authentication**, no multi-user state. The same Python process that runs the CLI serves it. |
| Data | Only the local mirror (SQLite) and local collectors, like the CLI. No external call at all: Vue and Vue Router are vendored in the package. |

### Functional (phase 1: process monitor)

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

### Functional (later phases: reserved in the navigation)

| Area | Views to come | CLI today |
|---|---|---|
| Overview | dashboard: open findings by priority across assets, KEV hits, freshness of the mirror | `status`, `findings` |
| Inventory | assets list, asset detail (components, scans, partial flags), unmatched identities, run a scan | `inventory *`, `scan`, `collect` |
| Risk | findings list (filters as CLI), finding detail, suppress | `findings` |
| Vulnerability data | vulnerability search / detail across sources, source status and sync | `vuln show/search`, `sources`, `status`, `sync` |

### Non-functional

- **No build step, works offline**: Vue 3 + Vue Router vendored in the package (`static/vendor`, checksummed), plain CSS,
  classic scripts; the design pages work from `file://`. No Node toolchain needed to run or change it.
- **One component library**: the CSS and the Vue components used by the app are the very files used by the design sample
  pages and the storybook (no copies).
- **Secure by default for a local tool**: loopback bind, `Host` header check (DNS rebinding), state-changing requests
  need a custom header (CSRF), strict Content-Security-Policy, all data rendered as text (no `v-html`).
- Responsive down to a laptop split screen (1024 px); usable at phone width for reading. Light and dark themes
  (`prefers-color-scheme`, manual toggle). Keyboard reachable (focus styles, `Esc` closes the drawer, `/` focuses search).
- Long lists: up to ~2000 processes without pagination (tree collapse, filtering client side).

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
│ INVENTORY ⋯  ├───────────────────────────────────────────────────────────────┬───────────────┤
│  Assets      │ Main content: data table (tree / flat), cards, feed            │ Detail drawer │
│ RISK ⋯       │                                                               │ (row click;   │
│  Findings    │                                                               │  deep link)   │
│ DATA ⋯       │                                                               │               │
│  Vulns       │                                                               │               │
│  Sources     │                                                               │               │
│ ─────────    │                                                               │               │
│ About        │                                                               │               │
└──────────────┴───────────────────────────────────────────────────────────────┴───────────────┘
```

- **App shell** (always present): top bar, sidebar, main area, toast area. Each feature contributes routes and sidebar
  entries; planned areas are visible but marked *planned* and open a placeholder that names the CLI command to use today.
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
| `#/overview`, `#/assets`, `#/findings`, `#/vulns`, `#/sources` | **Planned** placeholders | what the view will show + the CLI command that does it today | link to the docs |
| `#/about` | **About** | version, database path and status, server bind address, links to docs / storybook | — |

## Navigation paradigm

- **Persistent left sidebar, grouped by domain** (Monitor, Inventory, Risk, Data), the same groups the CLI help uses; the
  active route is highlighted; the sidebar collapses to icons under 1100 px.
- **Hash routing** (`#/…`): every view and every detail is deep-linkable and works with back / forward, with no server
  routing. Filters live in the query string (`#/processes?q=slack&kind=agent&suspicious=1&mode=flat`).
- **List -> detail in a drawer**: the list keeps its scroll position and filters; the drawer has its own URL; on narrow
  screens it becomes a full page.
- **Cross-links between views**: identity -> software row, launch label -> launch item, pid -> process detail, ancestor
  -> process detail. Later phases add component -> finding -> vulnerability.
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

Empty and error states are explicit: no database (findings column hidden, callout with `secmonk sync` command), live
snapshots not supported on this OS (callout with the snapshot-file alternative), no process matches the filters.

## Acceptance criteria

- `secmonk ui --snapshot tests/fixtures/collectors/process/snapshot.json` serves the app on any OS; on a Mac `secmonk ui`
  shows the live machine.
- Every view in the table above is reachable from the sidebar and by URL; planned views explain what to use instead.
- The storybook renders every shared component from the same `secmonk-ui.js` / `secmonk.css` the app loads.
- API and security behaviour covered by `tests/test_web.py`.
