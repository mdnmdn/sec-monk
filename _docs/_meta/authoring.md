---
title: Writing and updating docs
summary: The duty of every agent or human who changes code or a claim — find the touched docs, amend them in the same commit, fill frontmatter, verify, and where to put what does not fit.
read_when: your change touched behaviour, a collector, a source, the schema, a payload or the CLI, and you are not on a maintenance pass
type: meta
context: meta
status: reference
tags: [docs, conventions]
updated: 2026-11-08
verified: 2026-11-08
related: [_meta/frontmatter.md, _meta/librarian.md, _meta/tools.md, _meta/guidelines.md]
---

# Writing and updating docs

This page is for everyone who is **not** on a documentation maintenance pass: agents and humans who change code or
decide something. It is self-sufficient: it holds the placement rule, the fields and the edits you may make.
The full rulebook is [librarian.md](librarian.md); the reasons are in [guidelines.md](guidelines.md).

If you read nothing else:

1. If your change touched a claim, update the owning document **in the same commit**.
2. Edit in place. Do not move, split, rename or reorganize documents.
3. Match the document you edit: its section order and level of detail are already right.
4. `features/` and `tech/` are written in the present tense and describe the current state.
5. Bump `updated`; bump `verified` only after you compared the page with its code (§6).
6. Run `mise run docs` (regenerates INDEX, then lints) before committing.
7. If you cannot place something, use `plans/`, `inbox/` or the proposal ledger (§7).

## 0. Find the documents your change touched

In this order:

1. `mise run docs-touched` (or `uv run python scripts/docs.py touched [files]`): every document whose `code:` or
   `fixtures:` covers a changed file. With no arguments it reads the working tree and the branch diff.
2. [INDEX.md](../INDEX.md): the `read_when` column names the task each document serves.
3. `grep -rn '<module, command or table name>' _docs/`: documents that mention what you changed.

Change-type checklist (sec-monk specifics):

| Your change | Documents you owe |
|---|---|
| CLI command, option, exit code or output | the feature doc + the CLI-at-a-glance block in [features/README.md](../features/README.md#cli-at-a-glance) |
| Collector (new, or what it reads) | `tech/collectors/<name>.md`, the `features/inventory-*.md` page, [architecture](../tech/architecture.md) module table if a module appears |
| Vulnerability source | `references/vuln-sources/<name>.md`, [vuln-sync](../features/vuln-sync.md) |
| Schema (`db.py`) | [data-model](../tech/data-model.md) in the same commit (the schema is the integration contract) |
| Matching, versions, scoring | [matching](../tech/engine/matching.md) or [classification](../tech/engine/classification.md) |
| Web payload or view | [web-ui](../tech/web-ui.md); regenerate `_design/mock/data.js` |
| Something only a real machine can confirm | an unchecked item in the right `plans/on-*.md` |
| A choice between alternatives | a new ADR (`docs.py new decisions <slug>`), never an edit of an accepted one |

## 1. Two verbs

You **amend** an existing document, or **append** a row, a bullet or a plan item to one.

| You can | You cannot |
|---|---|
| Edit any section of an existing document | Move, split, merge or rename a document |
| Append a table row, a plan checkbox, a feedback row | Change the section order of a document |
| Tick a plan item with the date and result | Edit an accepted ADR (write a new one that supersedes it) |
| Stamp `verified` after checking (§6) | Decide a proposal in `inbox/` (humans do) |
| Create a document in the cases of §2 | Leave `TODO` or "Open questions" headings in features/tech/references |

Content is yours; structure belongs to the librarian ([librarian.md](librarian.md)); substance decisions to humans.

## 2. When you can create a document

Only when the subject has no home. Prefer extending an existing page.

- **Placement rule.** Delete the capability from the product: if the document goes too, it belongs in `features/`;
  if it survives, it belongs in `tech/`. Facts about the outside world (a feed, a file format, a vendor API, observed
  from real samples) go to `references/`. A choice between alternatives goes to `decisions/`. Work still to do or to
  verify goes to `plans/`. A large undecided change goes to `inbox/` as a proposal. The why of the project goes to
  `product/`.
- Never create a folder. Never create a second document for a subject that has one.
- Scaffold with `uv run python scripts/docs.py new <kind> <slug>` (`features tech references plans decisions
  inbox`); it copies the template from [templates/](templates/) with today's date, numbers ADRs and dates
  proposals. Then fill `summary`, `read_when`, `tags` and the sections, and run `mise run docs`.

## 3. When you must update a document

Documentation is part of the change, not follow-up work. If a change touched a file in a document's `code` or
`fixtures`, read that document's claims about it and fix what no longer holds. If a change altered something a reader
acts on (a command, a rule, a table, a payload), update its owner. If you left something open, add a plan item.

## 4. Frontmatter

The schema and the legal values are in [frontmatter.md](frontmatter.md). When you amend a document:

1. Set `updated` to today (`docs.py stamp` repairs it if you forget: L11).
2. If §6 applies, set `verified` to today (`docs.py verify <path>`).
3. If the document now depends on a new module or fixture, add it to `code` or `fixtures`.

When you create one, fill every required key. `summary` says what is inside; `read_when` names the reader's
task ("you change how the SSH collector extracts the harvest"), not the subject ("SSH").

## 5. Writing constraints

1. **Present tense, current state** in `features/` and `tech/`: no "previously", "currently", "will be",
   "has been added". History is in git; the *why* of a choice is in its ADR.
2. **Cite code as a path plus a symbol** (`engine/match.py` `_triage`), never a line number.
3. **One fact, one home.** Everywhere else, link to it. Link one target at most three times per page.
4. **Evidence over memory.** `references/` are written from real probes; say `sample: synthetic` when it is.
5. **Absolute dates** (`2026-11-08`), never "last week".
6. Long listings belong in the source file: keep fenced blocks short (ASCII diagrams are fine).
7. A page past 500 lines: make your edit, then file a split in [feedback.md](feedback.md).

## 6. Verification

`verified` means: someone compared this document with its sources (`code`, `fixtures`, the probe or the decision) and
it held. It does not mean "edited" — that is `updated`. The tool repairs `updated`; it never writes `verified` on its own.

1. **Per change (required).** You changed a file in a document's `code`/`fixtures`, or a claim it owns: read the
   claims, fix what does not hold, then `docs.py verify <path>`.
2. **Periodically.** `docs.py drift` lists documents whose anchored files changed after `verified` (L3).
3. **When you used a page and it held**, you may stamp it.

**If a document and the code disagree, decide which one is authoritative before editing either.**
`product/`, ADRs and a feature's behaviour and acceptance criteria **prescribe**: the code is wrong, or a human
decides (file it in the proposal ledger as `drift`). `tech/` implementation detail, `references/` and `plans/`
**describe**: fix the document.

## 7. When you cannot comply

- **Open work, an unverified assumption, a gap**: an item in the right `plans/` file (one place per gap).
- **A large change that needs a decision**: a proposal in `inbox/` (`docs.py new inbox <slug>`).
- **A structural problem** (needs a split, two documents contradict each other, a page should not exist): one row in
  [feedback.md](feedback.md). For a contradiction, state both sides; do not pick a winner.

Humans have one more power: they change the rules in `_meta/`.
