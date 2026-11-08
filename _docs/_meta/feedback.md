---
title: Proposal ledger
summary: Append-only ledger of documentation changes the librarian cannot make alone — splits, moves, rule changes, contradictions — with their status.
read_when: you want to propose a split, merge, move, rename or rule change, report a contradiction, or check whether a proposal was already rejected
type: meta
context: meta
status: reference
tags: [docs, maintenance]
updated: 2026-11-08
verified: 2026-11-08
related: [_meta/librarian.md, _meta/review-log.md]
---

# Proposal ledger

The channel for everything a contributor or the librarian cannot do alone ([librarian.md](librarian.md#51-powers-and-limits)).

- At most five open entries; when full, report the finding instead of appending.
- One sentence of rationale per entry. A proposal that needs a paragraph goes to `inbox/`.
- A rejection keeps its reason, so the next pass does not raise it again.
- The librarian executes an accepted entry, then closes it with what it did.

`kind`: `split · merge · move · rename · rule-change · gap · drift`.

| id | date | target | kind | rationale | status |
|---|---|---|---|---|---|
| F1 | 2026-11-08 | `references/vuln-sources/*.md`, `tech/collectors/dependencies.md`, `tech/engine/matching.md`, `product/vision.md` | move | 14 "TODO" / "Known gaps" / "Open questions" sections (L8) hold open work that belongs in `plans/` items; moving them is a large edit across plans, so it needs a dedicated pass | open |
