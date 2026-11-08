---
title: Frontmatter schema
summary: Every frontmatter key, its legal values per folder, the status lifecycle of each document kind and the common tags; what docs.py lint enforces.
read_when: you create a document, fill or change frontmatter, or a docs.py L1/L2 error names a field
type: meta
context: meta
status: reference
tags: [docs, conventions, frontmatter]
updated: 2026-11-08
verified: 2026-11-08
---

# Frontmatter schema

```yaml
---
title: CVE List v5           # required — human title
summary: CVE List v5 records…  # required — one line: what is inside (the INDEX row)
read_when: you change the …    # required — one line: the reader's task that should open this doc
type: reference              # required — meta | product | feature | tech | reference | decision | plan | proposal
context: references          # required — top-level folder: meta | product | features | tech | references | decisions | plans | inbox
status: draft                # required — see below
tags: [vuln-source, cve]     # required — free-form, lowercase, kebab-case; reuse existing tags
updated: 2026-11-07          # required — the file changed (docs.py stamp repairs it: L11)
verified: 2026-11-07         # required — someone compared the page with its code/fixtures and it held (docs.py verify)
# optional
review_cycle: quarterly      # monthly | quarterly | yearly (default quarterly): docs.py review
platform: macos              # plans: macos | linux | windows | open-network | any
sample: real                 # references/collectors: real | synthetic | mixed
reachable: partial           # references: yes | partial | no  (from the dev sandbox network)
fixtures: tests/fixtures/sources/cvelist/   # repo-relative paths only (one, comma-separated, or a YAML list; globs ok)
code: src/secmonk/sources/cvelist.py        # implementing module(s): paths only, prose belongs in the body
                                            # code + fixtures are the source anchors: docs.py drift and touched read them
related: [references/vuln-sources/osv.md]   # paths relative to _docs/
supersedes: decisions/0001-…                # decisions only
---
```

`uv run python scripts/docs.py lint` enforces this page (checks L1, L2 and L12 of [librarian.md](librarian.md#6-revision-checklist)): required keys;
`context` = the folder (`_meta/` = `meta`); `type` and `status` legal for the folder (table below); `platform` only on plans; `sample` / `reachable` /
`review_cycle` values; dates valid and not in the future; `summary` and `read_when` one line each; every `code`, `fixtures`, `related` and `supersedes`
path exists; relative markdown links and `#anchors` resolve; `INDEX.md` is current. (`reachable: no` is read as the string `no`, not YAML false.)

**`summary` vs `read_when`.** `summary` says what is inside ("KEV feed fields, mirror fallback, mapping to the `kev`
table"); `read_when` names the task that should lead a reader to it ("you change the KEV importer or debug a KEV
sync"), never just the subject ("KEV").

**`updated` vs `verified`.** `updated` is a fact about the file; `verified` is a claim that someone looked. When a
change in `code`/`fixtures` lands after `verified`, the page shows up in `docs.py drift` until someone re-checks it.

## `status` values

| Value | Meaning | Used by |
|---|---|---|
| `draft` | Being written; may be incomplete. | all |
| `reference` | Stable informational doc (also a source doc without an importer). | product, meta, references |
| `implemented` | Describes something that exists in code and is tested. For a vuln source: an importer exists; how far it was validated is `sample` + `reachable`. | feature, tech, references |
| `blocked` | Cannot proceed; reason in the doc. Not used for sources whose importer exists but whose host is unreachable from the sandbox (that is `reachable: no`). | references, features |
| `proposed` / `accepted` / `superseded` | ADR lifecycle. | decisions |
| `proposed` / `accepted` / `rejected` | Inbox proposal lifecycle (an accepted proposal becomes ADRs and plans). | inbox |
| `open` / `done` | Plan checklist state (a plan stays `open` while any item is unchecked). | plans |

## Common tags

`vuln-source`, `collector`, `engine`, `cli`, `data-model`, `macos`, `docker`, `linux`, `cve`,
`osv`, `purl`, `cpe`, `kev`, `epss`, `prioritization`, `matching`, `versions`.
