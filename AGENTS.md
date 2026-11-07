# AGENTS.md — working on sec-monk

Guide for coding agents (and humans) changing this repository. Read it before editing; it is short on purpose and
points to the docs that hold the details.

## What this is

A prototype **holistic vulnerability scanner** in Python: one local vulnerability mirror (SQLite), many inventory
collectors, one shared matching engine. *Different collectors, one shared engine* is the design rule
([vision](_docs/product/vision.md), [architecture](_docs/tech/architecture.md)).

```
sources/     vulnerability feeds -> SQLite (osv, cvelist, nvd, kev, epss, euvd, msrc, debian-tracker)
collectors/  targets -> Inventory(Asset, [Component]) ; never touch the DB, never match
             macos homebrew rootfs docker-image docker-engine fs ssh windows process
             lang/     shared language-dependency parsers (7 ecosystems)
             process/  process monitor: platform-neutral core + per-OS backends (macOS now)
engine/      classify -> versions -> match (osv-package | cve-product | cpe-product) -> scoring P1..P4
procmon.py   `secmonk procs` views (process tree + findings, --watch differ); payload builders shared with web/
web/         local web UI (`secmonk ui`): stdlib server + JSON API, static Vue app (static/css, static/js)
cli.py       Typer CLI (`secmonk ...`)
_design/     interface design: sample pages, storybook, screenshots (loads web/static files, never copies)
data/        product_aliases.yaml, brew_cpe_seed.csv, windows/secmonk-inventory.ps1
_docs/       all documentation, organized by context with YAML frontmatter
tests/       offline tests on fixtures (tests/fixtures/)
```

## Setup and checks

```bash
mise install && uv sync            # Python 3.13 + uv (any Python >= 3.12 + uv works)
uv run pytest -q                   # must stay green; runs fully offline
uv run ruff check src tests scripts
uv run python scripts/docs_index.py          # regenerate _docs/INDEX.md after any doc change
uv run python scripts/docs_index.py --check  # frontmatter, paths, links, anchors, INDEX up to date
```

`mise run lint` runs ruff + the docs check. Run all three before committing.

## Rules of the codebase

- **Collectors only collect.** A collector returns an `Inventory`; persistence is `engine/inventory.save_inventory`,
  matching is `engine/match`. Register new collectors with `@register` and import them in `collectors/__init__.py`.
- **Reuse identity code.** App bundles: `MacOSCollector._read_bundle`; Homebrew: `homebrew._keg_component`; language
  packages and binaries: the `collectors/lang` registry (`walk_dir`, `parse_file`, Go/Rust binary parsers). Do not
  write a second parser for something that already has one.
- **Scans never call external vulnerability APIs**: only the local mirror. Network is for `sync` and for pulling
  images that are themselves the target.
- **Targets are untrusted.** Read scanned trees through `collectors/base.read_within` / `resolve_within` (no symlink
  escapes, size caps); never extract archives blindly; redact secrets in anything stored (`redact_command`,
  `strip_url_secrets`, `redact_labels`). Commands run on a target are fixed, read-only and documented.
- **State is per-user, never CWD-relative** ([ADR-0006](_docs/decisions/0006-per-user-state-locations.md)). Tests are
  isolated by an autouse fixture; never point them at a real database.
- **Schema** is the integration contract: `db.py` and [data-model](_docs/tech/data-model.md) change together.
- **CLI conventions**: exit 0 ok / 1 runtime error / 2 usage / 3 `--fail-on`; `--format table|json|csv` with JSON/CSV on
  stdout and notes on stderr; collector warnings are always shown; untrusted strings go through `_t()` / `_e()`.
- Style: ruff, line length 110, `from __future__ import annotations`, dataclasses for records, no new dependencies
  without a reason in the commit message.

## Process monitor specifics

`collectors/process/` is split so that new platforms only add a backend
([tech doc](_docs/tech/collectors/process.md), [ADR-0007](_docs/decisions/0007-process-monitor.md)):

- `model.py` / `snapshot.py` / `launch.py` / `collector.py` are **platform-neutral**. Put OS facts in a backend or in
  `launch.PlatformHints`, not in shared code.
- A backend = `take_snapshot(root, opts) -> Snapshot` + an `Inspector` subclass (identity `Resolution` + provenance
  facts), registered in `backend.BACKENDS`. Pure parsers (command output -> data) live in the backend module and get
  fixture tests; live commands are wrapped in `_run` so tests can replace them.
- The `secmonk-process-snapshot/1` format is a public contract (offline analysis, agents, fixtures): extend it
  compatibly, validate on load.

## Web interface specifics

Feature: [web-ui](_docs/features/web-ui.md); architecture and "Adding a feature": [tech/web-ui](_docs/tech/web-ui.md);
design system and storybook: [`_design/`](_design/README.md); stack: [ADR-0008](_docs/decisions/0008-web-ui-stack.md).

- **No build step**: Vue 3 + Vue Router from unpkg (pinned in `static/index.html`, every `_design` page and the
  storybook: bump together), classic scripts exposing `window.SecMonkUI`. No npm dependency in the app.
- **One component library**: `static/css/secmonk.css`, `static/js/secmonk-ui.js`, `static/js/secmonk-views.js` are used
  by the app, the `_design` pages and the storybook. Never copy them; a new component gets a story, a new view gets a
  sample page; regenerate `_design/mock/data.js` (`scripts/design_mock.py`) when a payload changes.
- **Security rules**: render data only with `{{ }}` / bindings (no `v-html`), no inline scripts or styles (CSP), reads are
  GET, actions are POST with `X-SecMonk-Request: 1`, keep the `Host` check. The server stays stdlib-only.
- Payloads are built by functions shared with the CLI's JSON output (`procmon.snapshot_payload`, `event_dict`), not
  re-shaped in the server.

## Tests and fixtures

- Every parser gets a fixture under `tests/fixtures/<area>/` with a README stating provenance (real, trimmed and
  anonymized, or synthetic). Prefer building fixture trees at test time over committing binaries; reuse existing
  binaries (`tests/fixtures/lang/go`, `lang/rust`).
- Fixtures never contain real hostnames, user names, serials, tokens or `/Users/<real-name>` paths.
- macOS, Windows and live Docker code is developed on Linux against fixtures; what still needs a real machine is listed
  in [`_docs/plans/`](_docs/plans/README.md), one file per platform. Add unverifiable assumptions there.

## Documentation

All docs live in `_docs/` ([how they are organized](_docs/_meta/README.md), [frontmatter schema](_docs/_meta/frontmatter.md)):
`features/` what the user gets, `tech/` how it is built, `references/` external systems (from real probes),
`decisions/` ADRs (immutable; supersede with a new one), `plans/` open work per platform.

When you change behaviour: update the feature and tech docs, the CLI-at-a-glance block in
[`_docs/features/README.md`](_docs/features/README.md#cli-at-a-glance) for CLI changes, bump `updated:`, regenerate
`INDEX.md`. Use absolute dates. Evidence over memory: say `sample: synthetic` when it is.

## Git

Small commits with descriptive messages; no generated files other than `_docs/INDEX.md`; never commit databases
(`*.db`) or caches.
