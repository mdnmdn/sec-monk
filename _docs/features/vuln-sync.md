---
title: Vulnerability data sync
type: feature
context: features
status: implemented
tags: [cli, vuln-source, sync]
updated: 2026-11-07
code: src/secmonk/sources/
related: [references/vuln-sources/README.md, tech/data-model.md]
---

# Vulnerability data sync

## What the user gets
A local, queryable mirror of public vulnerability data (CVE List v5, OSV incl. GHSA and distro
advisories, CISA KEV, EPSS, NVD, EUVD), refreshed incrementally, so scans run offline and fast.

## Usage
```bash
secmonk sources                                 # list sources
secmonk sync kev epss                           # small snapshots
secmonk sync osv -e PyPI -e npm -e Debian -e Alpine   # OSV bulk per ecosystem (delta on re-run)
secmonk sync cvelist --since 2024               # sparse git mirror of recent years
secmonk sync cvelist --id CVE-2021-44228        # single records
secmonk sync cvelist --id @referenced           # CVEs referenced by OSV aliases / KEV but missing
secmonk sync nvd --since 2026-10-01             # NVD delta (NVD_API_KEY recommended)
secmonk sync osv --path ./Alpine-all.zip        # offline import
secmonk status                                  # freshness + table sizes
secmonk vuln show CVE-2021-44228                # merged view across sources
secmonk vuln search --ecosystem PyPI --package django --version 4.2.1
```

## Behaviour & rules
- Each source records last sync, status and a delta cursor (`secmonk status`).
- A failing source does not stop the others; errors are shown and stored.
- KEV falls back to the `cisagov/kev-data` GitHub mirror when cisa.gov is unreachable.

## Acceptance criteria
- `sync` of each source works from fixtures (tests) and from the network where reachable.
- `vuln show` merges a CVE with its GHSA/distro/EUVD aliases, KEV and EPSS.
