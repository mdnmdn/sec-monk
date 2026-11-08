---
title: Frontmatter schema
type: meta
context: meta
status: reference
tags: [docs, conventions, frontmatter]
updated: 2026-11-08
---

# Frontmatter schema

```yaml
---
title: CVE List v5           # required — human title
type: reference              # required — meta | product | feature | tech | reference | decision | plan | proposal
context: references          # required — top-level folder: meta | product | features | tech | references | decisions | plans | inbox
status: draft                # required — see below
tags: [vuln-source, cve]     # required — free-form, lowercase, kebab-case; reuse existing tags
updated: 2026-11-07          # required — last meaningful edit
# optional
platform: macos              # plans: macos | linux | windows | open-network | any
sample: real                 # references/collectors: real | synthetic | mixed
reachable: partial           # references: yes | partial | no  (from the dev sandbox network)
fixtures: tests/fixtures/sources/cvelist/   # repo-relative paths only (one, comma-separated, or a YAML list; globs ok)
code: src/secmonk/sources/cvelist.py        # implementing module(s): paths only, prose belongs in the body
related: [references/vuln-sources/osv.md]   # paths relative to _docs/
supersedes: decisions/0001-…                # decisions only
---
```

`uv run python scripts/docs_index.py --check` enforces this page: required keys; `context` = the folder (`_meta/` = `meta`); `type` and `status` legal for
the folder (table below); `platform` only on plans; `sample` / `reachable` values; every `code`, `fixtures`, `related` and `supersedes` path exists; relative
markdown links and `#anchors` resolve; `INDEX.md` is current. (`reachable: no` is read as the string `no`, not YAML false.)

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
