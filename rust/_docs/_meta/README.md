---
title: How the rust/_docs tree is organized
summary: States that rust/_docs follows the _docs/_meta rules of the Python tree, and lists the few local differences (link base, no docs.py tooling yet, hand-maintained INDEX).
read_when: you add or edit a document under rust/_docs and want to know which conventions apply
type: meta
context: meta
status: reference
tags: [docs, conventions, rust]
updated: 2026-11-11
verified: 2026-11-11
---

# How the rust/_docs tree is organized

`rust/_docs/` documents the Rust prototype (`rust/`). It **follows the rules of the Python tree's
[`_docs/_meta/`](../../../_docs/_meta/README.md)** without copying them:

- placement, folders = context, the two verbs (amend, append): [authoring.md](../../../_docs/_meta/authoring.md);
- frontmatter keys, legal `type` / `status` values and lifecycles: [frontmatter.md](../../../_docs/_meta/frontmatter.md);
- templates: [`_docs/_meta/templates/`](../../../_docs/_meta/templates/).

## Local differences

| Topic | Rule in rust/_docs |
|---|---|
| Link base | `related:` paths are relative to `rust/_docs/`. A link into the Python tree is a relative markdown link (from a folder of this tree: `../../../_docs/...`); never put it in `related:`. |
| `code:` / `fixtures:` | Repo-relative paths, as in `_docs/`. Omitted while the code does not exist (`status: draft`). |
| ADR numbers | Start at 0001 in this tree, independent of `_docs/decisions/`. Cite them as "rust ADR-0003" when the context is ambiguous. |
| INDEX | [`../INDEX.md`](../INDEX.md) is maintained **by hand** until `scripts/docs.py` learns a second root (see [plans/backlog.md](../plans/backlog.md)). Add a row when you add a document. |
| Tooling | `scripts/docs.py` scans `_docs/` only and takes no root argument. Its lint (L1, L2 links and anchors, L12) was run on this tree on 2026-11-11 by a throwaway wrapper that imports `docs.py` and points `ROOT` here (not committed; `docs.py` unchanged); L12 (INDEX up to date) is expected to fail because the INDEX header differs. The contracts have their own check ([contracts README](../../contracts/README.md)). |
| Markers | **(verify)**: a claim nobody has checked yet. **(spike)**: a detail waiting for the feasibility spike (wave W1.2). The spike reported on 2026-11-11; its results are folded in, settled points carry no mark, and what it could not run is marked **(verify)**. |
| Owner rule | [plans/prototype.md](../plans/prototype.md) belongs to the coordinator; other agents report instead of editing it. |

Folders: `tech/` (how it is built), `features/` (what the user gets), `decisions/` (ADRs), `plans/` (open work).
`references/`, `product/` and `inbox/` stay in the Python tree: the product, the external systems and the proposals
are shared by both implementations.
