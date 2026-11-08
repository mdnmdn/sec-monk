---
title: Docs tooling reference
summary: Every command of scripts/docs.py and its mise task — what each checks or writes, which L-check it serves, and its limits.
read_when: you want to know which docs command to run before a commit, on a maintenance pass, or after changing code
type: meta
context: meta
status: reference
tags: [docs, tooling]
updated: 2026-11-08
verified: 2026-11-08
code: [scripts/docs.py, mise.toml, tests/test_docs_tool.py]
related: [_meta/librarian.md, _meta/authoring.md]
---

# Docs tooling reference

One script, `scripts/docs.py` (stdlib + PyYAML, already a project dependency), wrapped by `mise` tasks. Either form
works:

```bash
mise run docs-lint                          # the task
uv run python scripts/docs.py lint          # the same command
```

The checks it runs are defined in [librarian.md](librarian.md#6-revision-checklist); nothing in the library depends on
the tool (plain markdown, relative links), it only makes the mechanical half cheap.

## Which command you want

| If you are about to | Run |
|---|---|
| Commit any change that touched docs | `mise run docs` (index, then lint) |
| Find the documents a code change affects | `mise run docs-touched [files]` |
| Add a document | `mise run docs-new <kind> <slug>` |
| Record that you checked a document against its code | `mise run docs-verify <paths>` |
| Repair forgotten `updated` dates | `mise run docs-stamp` |
| Start a maintenance pass | `mise run docs-stats`, `mise run docs-lint`, `mise run docs-drift` |
| Close a pass | `uv run python scripts/docs.py log --scope ... --counts ... --notes ...` |

## Reading commands (write nothing)

| Command | Does |
|---|---|
| `lint [paths] [--json] [--strict]` | Checks L1, L2, L4, L5, L7, L8, L9, L10, L11, L12. Errors exit 1; warnings print; `--strict` fails on warnings too. With paths, only those documents (and no INDEX check) |
| `index --check` | Fails if `INDEX.md` is stale (L12) |
| `touched [files]` | Inverts `code` + `fixtures`: documents covering the given files. Without arguments: uncommitted files plus the branch diff against `origin/main`. Also lists changed `src/` files no document anchors |
| `changed [days]` | Documents whose file changed more than `days` (default 2) after `updated` (L11). `changed 0` is strict |
| `drift` | Documents whose anchored files changed after `verified` (L3). Detects the *possibility* of drift; a reader decides |
| `review` | Documents whose `verified` is older than their `review_cycle` (default quarterly: 91 days) |
| `stats` | Counts per folder and status, lengths, documents without anchors, oldest verification, open plan items, inbox, last logged pass |
| `inbox` | Proposals with status, age and how many documents cite them; flags undecided ones older than 14 days (L7) |

File dates: today for uncommitted changes, else the last git commit, else the mtime.

## Writing commands (each narrow on purpose)

| Command | Writes | Guard |
|---|---|---|
| `index` | `_docs/INDEX.md` | Generated file; never edit by hand |
| `stamp [--check]` | The `updated:` line of documents L11 flags | Rewrites that one line only. `--check` shows the plan. Notes when `updated` passes `verified` |
| `verify <paths>` | The `verified:` line of the named documents | Refuses to run without paths: no flag stamps the whole library |
| `new <kind> <slug> [--template F] [--title T]` | A file from [templates/](templates/) with today's date; ADRs get the next number, proposals a date prefix | Refuses to overwrite |
| `log --scope S [--checks] [--counts] [--notes]` | One row appended to [review-log.md](review-log.md) | Append only |

**`stamp` never touches `verified`.** `updated` is a fact about the file a machine can read; `verified` is a claim
that someone compared the page with its sources, so it moves only when you name the document.

## Where the tool stops

It has no opinion on whether a claim is true. A reader owes L3 (does the page still hold after the code change),
L6 (one fact, one home) and the prescribe/describe decision of [authoring.md](authoring.md#6-verification).
A document without `code`/`fixtures` cannot be drift-checked; `stats` counts them.

`tests/test_docs_tool.py` runs `lint` on the repository, so `uv run pytest` fails when the docs are malformed or the
INDEX is stale.
