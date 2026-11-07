---
title: Frontmatter schema
type: meta
context: meta
status: reference
tags: [docs, conventions, frontmatter]
updated: 2026-11-07
---

# Frontmatter schema

```yaml
---
title: CVE List v5           # required — human title
type: reference              # required — meta | product | feature | tech | reference | decision | plan
context: references          # required — top-level folder: meta | product | features | tech | references | decisions | plans
status: draft                # required — see below
tags: [vuln-source, cve]     # required — free-form, lowercase, kebab-case; reuse existing tags
updated: 2026-11-07          # required — last meaningful edit
# optional
platform: macos              # plans: macos | linux | windows | open-network | any
sample: real                 # references/collectors: real | synthetic | mixed
reachable: partial           # references: yes | partial | no  (from the dev sandbox network)
fixtures: tests/fixtures/sources/cvelist/   # where the samples / test fixtures live
code: src/secmonk/sources/cvelist.py        # implementing module(s)
related: [references/vuln-sources/osv.md]   # paths relative to _docs/
supersedes: decisions/0001-…                # decisions only
---
```

## `status` values

| Value | Meaning | Used by |
|---|---|---|
| `draft` | Being written; may be incomplete. | all |
| `reference` | Stable informational doc. | product, meta, references |
| `implemented` | Describes something that exists in code and is tested. | feature, tech, references |
| `blocked` | Cannot proceed (e.g. source unreachable); reason in the doc. | references, features |
| `proposed` / `accepted` / `superseded` | ADR lifecycle. | decisions |
| `open` / `done` | Plan checklist state (a plan stays `open` while any item is unchecked). | plans |

## Common tags

`vuln-source`, `collector`, `engine`, `cli`, `data-model`, `macos`, `docker`, `linux`, `cve`,
`osv`, `purl`, `cpe`, `kev`, `epss`, `prioritization`, `matching`, `versions`.
