---
title: How the sec-monk docs are organized
type: meta
context: meta
status: reference
tags: [docs, conventions]
updated: 2026-11-08
---

# How the documentation is organized

All project documentation lives in `_docs/`. Docs explain *why* and *what*; the code in
`src/secmonk/` is the *how*. Everything about the docs themselves (this file, the frontmatter
schema, templates) lives in `_docs/_meta/`.

## Folders = context

| Folder | Context | What goes there | Typical `type` |
|---|---|---|---|
| `_meta/` | meta | Docs about docs: structure, frontmatter schema, templates. | `meta` |
| `product/` | product | Vision, goals, scope, roadmap, glossary, personas. The *why*. | `product` |
| `features/` | features | One file per user-visible capability (a CLI command family, a scan target). Behaviour, usage, acceptance criteria. Links to the tech docs that implement it. | `feature` |
| `tech/` | tech | Internal design: architecture, data model, CLI internals. Sub-folders per area: `tech/collectors/` (how each target is inventoried), `tech/engine/` (classification, versions, matching, scoring). | `tech` |
| `references/` | references | Knowledge about **external** systems we depend on, written from real probes: `references/vuln-sources/` (CVE List, OSV, NVD, KEV, EPSS, EUVD…). Facts about the outside world, not our design. | `reference` |
| `decisions/` | decisions | Architecture Decision Records `NNNN-short-title.md`. Immutable once accepted; supersede with a new ADR. | `decision` |
| `inbox/` | inbox | Proposals not yet decided: large changes written up for discussion (effort, options, risks). Accepted ones are turned into ADRs in `decisions/` and checklists in `plans/`; the proposal stays as the record. | `proposal` |
| `plans/` | plans | Work still to do, **organized by the platform you need to be on** to do it (macOS, Linux/Docker host, Windows, open network) plus the source-integration backlog. Checklists, kept current. | `plan` |

Outside `_docs/`: the interface design (design system, sample pages, component storybook, screenshots) lives in
[`_design/`](../../_design/README.md), because it is made of runnable HTML that loads the app's own CSS/JS.

Rule of thumb when placing a doc: *Is it about the outside world?* → `references/`.
*About what the user gets?* → `features/`. *About how we build it?* → `tech/`.
*About a choice we made?* → `decisions/`. *About why the project exists?* → `product/`.
*A large change not decided yet?* → `inbox/`. *About what is left to do / verify?* → `plans/` (pick the file for the platform it needs).

A folder may contain a `README.md` acting as its index (and as the template holder for
homogeneous doc families such as vuln sources or collectors).

## Frontmatter

Every doc starts with YAML frontmatter — see [frontmatter.md](frontmatter.md) for the schema.
It makes docs filterable by tooling (e.g. `uv run python scripts/docs_index.py` regenerates
[`../INDEX.md`](../INDEX.md) grouped by context, status and tag).

## Conventions

- GitHub-flavored Markdown; diagrams as ASCII or Mermaid.
- **Evidence over memory:** `references/` docs are written from real samples; samples are saved
  (trimmed) in `tests/fixtures/` and referenced via the `fixtures:` key, so docs and tests share
  the same truth. If a sample is hand-made, say `sample: synthetic`.
- Absolute dates (`2026-11-07`), never "last week". Bump `updated:` when editing.
- Relative links between docs; `related:` paths are relative to `_docs/`.
- Templates: [templates/](templates/).

## Reading order

1. [product/vision.md](../product/vision.md)
2. [decisions/](../decisions/)
3. [tech/architecture.md](../tech/architecture.md)
4. [features/](../features/)
5. [references/vuln-sources/](../references/vuln-sources/) and [tech/collectors/](../tech/collectors/)
