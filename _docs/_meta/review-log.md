---
title: Review log
summary: Append-only record of documentation maintenance passes — date, scope, checks run, counts and notes.
read_when: you start a maintenance pass and need to know what the last one did
type: meta
context: meta
status: reference
tags: [docs, maintenance]
updated: 2026-11-08
verified: 2026-11-08
related: [_meta/librarian.md, _meta/feedback.md]
---

# Review log

One row per pass; "nothing to change" is a result and gets its row. Cite checks by their ids from
[librarian.md](librarian.md#6-revision-checklist). Append with `uv run python scripts/docs.py log`.

| date | scope | checks run | counts | notes |
|---|---|---|---|---|
| 2026-11-08 | setup: maintenance scheme | L1–L12 | 68 docs given `summary`, `read_when`, `verified`; 6 `_meta` docs added; 0 errors, 16 warnings (14 L8 → F1, 2 L5) | Scheme adapted from aiheroes-2026-splitwise-sample. `verified` seeded from `updated` (the pages were written against the code on that date, not re-checked in this pass). `summary`/`read_when` written by agents from each page's content |
