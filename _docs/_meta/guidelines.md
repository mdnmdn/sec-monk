---
title: Documentation guidelines
summary: What `_docs/` is for and the principles (G1–G10) behind its rules; maps each principle to the rule and check that enforce it.
read_when: you question a documentation rule, want to add one, or decide what belongs in the library
type: meta
context: meta
status: reference
tags: [docs, conventions]
updated: 2026-11-08
verified: 2026-11-08
related: [_meta/authoring.md, _meta/librarian.md, _meta/tools.md]
---

# Documentation guidelines

This page states what the documentation is *for* and the principles that produce its rules. It holds no
procedures: [authoring.md](authoring.md) says what a contributor does, [librarian.md](librarian.md) what a
maintenance pass does, [tools.md](tools.md) what to type. Read it when a rule feels wrong or when you want to add one.

The approach is adapted from the *LLM wiki* pattern (a plain-markdown knowledge base that a model reads and a
model maintains), as used in the `aiheroes-2026-splitwise-sample` repository. What was adopted and what was not is
in [§6](#6-what-was-adopted-and-what-was-not).

## 1. The premise

An agent arrives with no memory. Everything it knows about sec-monk in the first minute comes from files:
`AGENTS.md`, then `_docs/`. Conversations are ephemeral; the library is the durable working memory, and it
compounds: every change that is distilled into the right document makes the next task cheaper.

Agents are the first audience and also the main maintainers, which makes a strict scheme affordable: an agent does
not tire of bookkeeping or forget the index. Humans are the second audience, and a document must be trustworthy for
them too. A stated purpose, one fact in one place and an explicit *read when* serve both.

## 2. Goals, in priority order

1. **Time to context.** A fresh agent reaches the two or three documents its task needs from one read of
   [INDEX.md](../INDEX.md) (each row has a `summary` and a `read_when`).
2. **Trust.** A reader can believe a document without opening its source. Without trust agents read the code
   anyway and the library is dead weight.
3. **Coverage without sprawl.** Every collector, source, engine stage and user-visible feature has a document, and
   there is one document per subject.
4. **Low maintenance cost.** Upkeep is mechanical enough for a script (`scripts/docs.py`) or a cheap model; the
   judgement left to a reader is small and named.

## 3. Principles

**G1. Compiled, not re-derived.** Knowledge is processed once, when it arrives, into the document that owns it.
A probe result goes into `references/`, a design choice into `decisions/`, a gap into `plans/`.

**G2. Write for a reader with no memory.** No "as discussed", no dependence on reading another page first. The
first two sentences say what the document is about.

**G3. Organize for lookup, not for reading through.** Predictable folders, one-line `summary`, a task-shaped
`read_when`, fixed section orders, templates. A rule nobody is pointed at does not exist: the duty is reachable
from `AGENTS.md` (check L10).

**G4. Know which side is the source of truth.** `product/`, `decisions/` and a feature's behaviour and acceptance
criteria **prescribe**: if the code disagrees, the code is wrong or a human decides. `tech/` implementation detail,
`references/` probes and `plans/` **describe**: they yield when the code or the outside world changes. Getting this
backwards makes the library ratify whatever the code does.

**G5. One fact, one home.** A claim stated twice soon disagrees with itself. Link instead of copying; derived
material (`INDEX.md`, the CLI help) is generated or not kept.

**G6. Present tense, current state** in `features/` and `tech/`. History lives in git and in ADR rationale, not in
prose ("previously", "currently", "will be": check L5).

**G7. Record contradictions; do not resolve them silently.** If two documents disagree, or a document disagrees
with the code in a prescriptive section, write an entry in [feedback.md](feedback.md) naming both sides.

**G8. Everyone amends; the librarian reshapes; humans decide.** Whoever changes code or thinking updates the
documents it touched, in the same commit. Structure (moves, splits, merges, renames) belongs to a maintenance pass.
Substance (scope, ADRs, accepting a proposal) belongs to a human. An agent never turns a guess into a decision.

**G9. Documentation is part of the change.** A stale document is worse than a missing one: absence sends the
reader to the source, a stale page is believed. `updated` moves with the file (L11); `verified` moves when someone
compares the page with its `code`/`fixtures` (L3).

**G10. A document earns its tokens.** Length, repetition and ceremonial prose cost on every read. Cut before you
grow; split by reader intent above 500 lines (L4).

## 4. Non-goals

- Not a handbook or tutorial: the README has the quick start, the docs have the contracts.
- Not an API reference: documents name the module and the symbol and stop.
- Not a history: git holds it. ADRs keep only *why*.
- Not project management: `plans/` lists what is open per platform; no assignees, no sprints.

## 5. How principles become rules

| Principle | Enforced by |
|---|---|
| G1, G2 | Placement rule and templates in [librarian.md](librarian.md#2-where-a-document-goes) |
| G3 | `summary` / `read_when` in [frontmatter.md](frontmatter.md) · generated INDEX (L12) · duty pointer (L10) |
| G4 | The mismatch rule in [authoring.md](authoring.md#6-verification) · `verified` + `code`/`fixtures` (L3) |
| G5 | Links instead of copies (L6, by a reader) · generated INDEX |
| G6 | Banned phrases (L5) |
| G7 | [feedback.md](feedback.md) · no TODO / open-question headings outside `plans/` (L8) |
| G8 | The two verbs in [authoring.md](authoring.md#1-two-verbs) · powers in [librarian.md](librarian.md#5-the-librarian) |
| G9 | Same-commit duty · `docs.py touched` · L3 drift · L11 freshness |
| G10 | Length and fence bands (L4) · link repeats (L9) |

A rule with no principle here is a preference and can be dropped; a principle with no rule is decoration.

## 6. What was adopted and what was not

Adopted from the reference scheme: the contributor/librarian split, `summary` + `read_when` + `verified`, the
L-numbered checklist, the narrow write commands (`stamp` repairs `updated`, only `verify` writes `verified`), the
review log and the proposal ledger.

Kept from sec-monk: the folder taxonomy (`features/ tech/ references/ decisions/ plans/ inbox/`), the existing
frontmatter keys, paths instead of ids in `related`, and `code`/`fixtures` as the source anchors (no separate
`source_anchors` field: one fact, one home).

Not adopted: the Simplified Technical English dialect and a glossary (the vocabulary lives in the vision and the
data model), phases (the project has one phase, the prototype), and a hand-written `Home.md` (the INDEX is
generated and carries the reading triggers).
