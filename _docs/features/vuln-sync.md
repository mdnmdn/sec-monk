---
title: Vulnerability data sync
summary: The eight vulnerability sources (osv, cvelist, kev, epss, nvd, euvd, msrc, debian-tracker) with sync commands, delta cursors, offline --path import and sync behaviour.
read_when: you refresh the local vulnerability mirror, pick a source or sync option, import data offline, or check what sync all includes
type: feature
context: features
status: implemented
tags: [cli, vuln-source, sync, osv, cve, kev, epss, nvd, euvd, msrc]
updated: 2026-11-11
verified: 2026-11-11
code: src/secmonk/sources/
related: [references/vuln-sources/README.md, tech/data-model.md, tech/architecture.md, features/README.md, references/probes.md]
---

# Vulnerability data sync

## What the user gets
A local, queryable mirror of public vulnerability data, refreshed incrementally, so scans run offline and fast.
Eight sources are registered (`secmonk sources`):

| Source | Command | Provides | Delta / cursor | Offline import (`--path`) |
|---|---|---|---|---|
| `osv` | `sync osv -e <Ecosystem>` | Package-ecosystem and distro advisories (incl. GHSA, PyPA, Go, RustSec, Debian, Ubuntu, Alpine, Red Hat, Rocky, Alma) | per-ecosystem `modified_id.csv` cursor (`osv:<Eco>`); > 5000 changes falls back to the full zip | zip or JSON |
| `cvelist` | `sync cvelist [--since YEAR] [--id CVE-..] [--id @referenced]` | CVE List v5 + CISA ADP (SSVC): vendor/product ranges for apps, brew, Windows | git commit SHA of a sparse clone; `--id` per-record raw fetch | file or directory of `CVE-*.json` |
| `kev` | `sync kev` | CISA KEV exploited flag (cisa.gov, falls back to the `cisagov/kev-data` mirror) | full snapshot replace | JSON |
| `epss` | `sync epss [--id CVE-..]` | EPSS score/percentile (daily bulk CSV, or API by id in batches of 100) | CSV `score_date` | `.csv` / `.csv.gz` |
| `nvd` | `sync nvd [--since DATE] [--api-key K]` | CVSS, CWE, CPE applicability | end of the last window (119-day windows); `NVD_API_KEY` recommended | API-shaped JSON file or dir |
| `euvd` | `sync euvd` | ENISA exploited/recent views, EUVD to CVE aliases, EPSS fallback | none (small views pulled whole) | JSON list/object |
| `msrc` | `sync msrc [--since DATE] [--limit N]` | Microsoft CVRF: fixed builds and KBs per product (Windows, Office, .NET) | `CurrentReleaseDate` filter | CVRF JSON file or dir |
| `debian-tracker` | `sync debian-tracker` | `distro_triage`: not-affected, no-dsa/postponed/ignored, urgency per Debian release | HTTP `ETag` / content hash; snapshot replace | tracker JSON (`.gz/.bz2/.xz`) or security-tracker repo checkout |

## Usage
```bash
secmonk sources                                 # list sources
secmonk sync kev epss                           # small snapshots
secmonk sync osv -e PyPI -e npm -e Debian -e Alpine   # OSV bulk per ecosystem (delta on re-run)
secmonk sync cvelist --since 2024               # sparse git mirror of recent years
secmonk sync cvelist --id CVE-2021-44228        # single records
secmonk sync cvelist --id @referenced           # CVEs referenced by OSV aliases / KEV but missing
secmonk sync nvd --since 2026-10-01             # NVD delta (NVD_API_KEY recommended)
secmonk sync euvd ; secmonk sync msrc --since 2024-01-01
secmonk sync debian-tracker                     # or --path tracker.json / --path security-tracker/
secmonk sync osv --path ./Alpine-all.zip        # offline import
secmonk sync all                                # kev epss osv cvelist nvd euvd (NOT msrc, debian-tracker)
secmonk status                                  # freshness + table sizes
secmonk vuln show CVE-2021-44228                # merged view across sources
secmonk vuln search --ecosystem PyPI --package django --version 4.2.1
secmonk windows-script > secmonk-inventory.ps1  # not a source: the Windows inventory script (see inventory-windows.md)
```
Other options: `--full` (ignore the stored cursor), `--limit N` (debug cap), `--db`.

## Behaviour & rules
- Each source records last sync, status and a delta cursor (`secmonk status`).
- A failing source does not stop the others; errors are shown and stored (`status=error`, existing rows kept).
- KEV falls back to the `cisagov/kev-data` GitHub mirror when cisa.gov is unreachable.
- Raw records are stored verbatim (`SECMONK_OSV_STORE_RAW=0` skips OSV raw storage to keep the DB small).
- Syncing `msrc` or `debian-tracker` is explicit: `sync all` does not include them.
- `sync osv` without `-e` syncs the default ecosystems: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist,
  Pub, SwiftURL, Debian, Alpine, Red Hat, Rocky Linux, AlmaLinux (`sources/osv.DEFAULT_ECOSYSTEMS`); Ubuntu and the
  others are opt-in with `-e`.
- Which sources are reachable from the dev sandbox, and which were validated on real data: [vuln-sources index](../references/vuln-sources/README.md), [probe log](../references/probes.md).

## Acceptance criteria
- `sync` of each source works from fixtures (tests) and from the network where reachable (osv, cvelist, kev on 2026-11-07; epss, nvd, euvd, msrc, debian-tracker only from fixtures: hosts blocked).
- `vuln show` merges a CVE with its GHSA/distro/EUVD aliases, KEV and EPSS.
- OSV delta: a repeat sync takes the delta path (Alpine: 0 changes) - measured 2026-11-07, see [osv reference](../references/vuln-sources/osv.md).

## Implemented by
[architecture](../tech/architecture.md), [data model](../tech/data-model.md), [references/vuln-sources](../references/vuln-sources/README.md).
