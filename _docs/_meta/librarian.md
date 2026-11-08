---
title: Librarian — maintenance rulebook
summary: How the library is shaped and kept current — placement, document anatomy per folder, balance bands, the librarian's powers and triggers, and the revision checklist L1–L12.
read_when: you run a documentation maintenance pass, reshape documents (move, split, merge), or a docs.py check fails and you need to know what it means
type: meta
context: meta
status: reference
tags: [docs, conventions, maintenance]
updated: 2026-11-08
verified: 2026-11-08
code: scripts/docs.py
related: [_meta/authoring.md, _meta/tools.md, _meta/guidelines.md, _meta/review-log.md, _meta/feedback.md]
---

# Librarian — maintenance rulebook

The operative rules for keeping `_docs/` correct and findable. Contributors need only
[authoring.md](authoring.md); this page is for a **maintenance pass** and for anyone who must reshape the library.
The principles behind each rule are in [guidelines.md](guidelines.md); the commands in [tools.md](tools.md).

## 1. The library

Folders encode the **kind of knowledge** (table in [README.md](README.md#folders--context)); frontmatter encodes
**stability** (`status`, `updated`, `verified`, see [frontmatter.md](frontmatter.md)). `INDEX.md` is generated and is
the entry point: one row per document with its `summary` and `read_when`.

## 2. Where a document goes

In order:

1. Undecided large change → `inbox/` (a proposal; a human accepts or rejects it).
2. About the documentation → `_meta/`.
3. Work to do or verify → an item in the `plans/` file for the platform it needs. Not a new document.
4. A choice between alternatives → a new ADR in `decisions/`. Accepted ADRs are immutable; supersede them.
5. Facts about the outside world, from real samples → `references/`.
6. Otherwise the placement rule: **delete the capability from the product — if the document goes too, it belongs in
   `features/`; if it survives, it belongs in `tech/`.** The why of the project → `product/`.

Prefer extending an existing document. A new file needs a reader who cannot find the material where it is.

When a proposal in `inbox/` is decided, set its `status` (`accepted` / `rejected`), keep it as the record, and
turn an accepted one into ADRs and `plans/` items that link back to it.

## 3. Document anatomy

Each kind has a fixed section order, given by its template in [templates/](templates/) (`docs.py new` copies it).
An agent skims to the part it needs and stops.

| Folder | Template | Prescribes or describes |
|---|---|---|
| `features/` | `feature.md`: What the user gets · Usage · Behaviour & rules · Acceptance criteria · Implemented by | Behaviour and acceptance criteria **prescribe** |
| `tech/` | `tech.md` (generic) or `tech-collector.md`: Summary · Where the data lives · Data format · Classification · Limitations | **Describe**; yield to the code |
| `references/` | `reference.md` or `reference-vuln-source.md`: Summary · Access · Data format · Mapping · Quirks · Limitations | **Describe** the outside world, from probes |
| `decisions/` | `decision.md`: Context · Decision · Consequences | **Prescribe**; immutable once accepted |
| `plans/` | `plan.md`: checklist items with commands, what to verify, which doc to update | **Describe** open work |
| `inbox/` | `proposal.md`: Summary · Options · Effort · Risks · Recommendation · Open questions | Neither until decided |

Open work never lives in a feature, tech or reference page as a `TODO` / "Open questions" / "Known gaps" heading: it
goes to `plans/` (L8). A *Limitations* section that states what the code does not do is fine.

## 4. Balance

- **Length**: aim for 80–400 lines; the ceiling is 500. Above it, split by reader intent (who opens it for which
  task), never into `part-2` files. Folder `README.md` indexes and catalogues are exempt (L4).
- **Fences**: at most 45 lines each. ASCII diagrams belong; long code or JSON listings do not — name the fixture or
  source file instead (L4).
- **Links**: one target at most three times per document; `plans/` and folder indexes are exempt (L9).
- **Timelessness**: `features/` and `tech/` describe the current state; history is in git and ADRs (L5).

## 5. The librarian

### 5.1 Powers and limits

The librarian (an agent or human on a maintenance pass) may: move, split, merge and rename documents and fix every
link that breaks; rewrite `summary` / `read_when`; repair frontmatter; fix descriptive drift (L3) where the code is
unambiguous; regenerate INDEX; tick a plan item that is provably done; execute an accepted [feedback.md](feedback.md)
entry.

The librarian may not: change a prescriptive claim (feature behaviour, an ADR, product scope) to match the code;
accept or reject an `inbox/` proposal; delete a document whose subject still exists; edit an accepted ADR. Those go to
[feedback.md](feedback.md) for a human.

### 5.2 Triggers

Run a pass when any of these holds:

- `docs.py drift` lists more than ~5 documents (code moved under the docs).
- `docs.py review` lists documents past their `review_cycle`.
- A large merge landed (new collector, new source, schema change).
- The proposal ledger has accepted entries waiting.
- Before a release or a demo.

### 5.3 A pass, step by step

1. Read the last rows of [review-log.md](review-log.md) so you do not repeat a pass.
2. `docs.py stats`, then `docs.py lint` and fix every error.
3. `docs.py drift`: for each listed document read the anchored change, fix descriptive claims, `docs.py verify` the
   page; queue prescriptive mismatches in the proposal ledger.
4. `docs.py review`, `docs.py inbox`: re-check or flag.
5. Work the warnings (L4, L5, L8, L9) as far as the pass allows.
6. `docs.py index`, `docs.py lint` green, then `docs.py log --scope ... --counts ... --notes ...` and commit.

## 6. Revision checklist

`docs.py lint` runs the mechanical checks; errors fail, warnings are reported. A reader owes the judgement checks.

| Id | Check | Kind | What to do when it fails |
|---|---|---|---|
| **L1** | Frontmatter parses; required keys present; `type`/`status`/`context` legal for the folder; `platform`/`sample`/`reachable`/`review_cycle` values; dates valid and not in the future; `summary`/`read_when` one line | error | Fix the field |
| **L2** | Every markdown link and `#anchor` resolves; every `code`, `fixtures`, `related`, `supersedes` path exists | error | Fix the reference; if the source moved, update the anchor and re-verify |
| **L3** | No `code`/`fixtures` file changed after `verified` (`docs.py drift`) | report | Read the change, fix descriptive claims, `verify`; queue prescriptive ones |
| **L4** | ≤ 500 lines; fences ≤ 45 lines | warning | Split by reader intent, or name the file instead of the listing |
| **L5** | No "previously / currently / used to / will be / has been added / was changed" in implemented `features/` and `tech/` | warning | Rewrite in the present tense |
| **L6** | No fact outside its owning document | judgement | Replace the copy with a link |
| **L7** | Plans: `done` has no unchecked item, `open` has at least one; inbox: no proposal undecided for > 14 days | error / warning | Fix the status; ask a human to decide the proposal |
| **L8** | No `TODO` / "Open questions" / "Known gaps" headings in features, tech, references, product | warning | Move the items to the right `plans/` file |
| **L9** | No link target more than three times in one document | warning | Delete the surplus |
| **L10** | `AGENTS.md` points to `_docs/_meta/authoring.md` | error | Restore the pointer first |
| **L11** | No document file changed more than 2 days after its `updated` | error | `docs.py stamp`; if `updated` passes `verified`, check the page |
| **L12** | `INDEX.md` matches the frontmatter | error | `docs.py index` |

A green lint means the library is well formed, not that it is right: L3 and L6 need a reader.

## 7. Reporting

Every pass appends one row to [review-log.md](review-log.md) (`docs.py log`), including "nothing to change".
Structural changes the librarian cannot make alone go to [feedback.md](feedback.md), one sentence of rationale each.
