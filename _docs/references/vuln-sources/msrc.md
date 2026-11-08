---
title: Microsoft MSRC CVRF
summary: Microsoft MSRC CVRF monthly documents for Windows KB and fixed-build data, the assumed (unverified) response shape, mapping, quirks and review fixes.
read_when: you change the MSRC importer, debug Windows KB or fixed-build matching or need the CVRF structure and what is unverified
type: reference
context: references
status: implemented
tags: [vuln-source, msrc, windows, cve]
updated: 2026-11-07
verified: 2026-11-07
sample: synthetic
reachable: no
fixtures: tests/fixtures/sources/msrc/
code: src/secmonk/sources/msrc.py
related: [references/windows-inventory.md, references/vuln-sources/cvelist-v5.md]
---

# Microsoft MSRC CVRF

## Summary

MSRC publishes every monthly "Security Updates" release as a CVRF document: per vulnerability, per affected product, the **KB
article and the fixed build**. The CVE List's Microsoft CNA records already carry per-build ranges (see
[windows-inventory.md](../windows-inventory.md)), so MSRC is a second, richer source for the same data (KBs, supersedence, exact fixed build per
product ID), not the only one. **Status blocked**: `api.msrc.microsoft.com` is not reachable from the dev sandbox; the schema below and the fixture are
from knowledge (**synthetic**, marked as such in the file). Validate from an unrestricted network.

## Access

- `GET https://api.msrc.microsoft.com/cvrf/v3.0/updates` -> list of months (`ID` like `2024-Aug`, `CurrentReleaseDate`, `CvrfUrl`).
- `GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{ID}` with `Accept: application/json` -> the month's document (several MB). No key needed for v3.0 CVRF.
- `secmonk sync msrc` downloads every month (`--since 2024-01-01` filters on `CurrentReleaseDate`, `--limit N` keeps the newest N); `secmonk sync msrc --path <file|dir>` imports downloaded CVRF JSON.
- Monthly cadence (second Tuesday) plus out-of-band updates (`CurrentReleaseDate` changes when a month is revised).

## Data format (unverified)

`DocumentTracking.Identification.ID.Value` (`2024-Aug`), `ProductTree.FullProductName[] {ProductID, Value}` (flat list; nested `Branch` also handled),
`Vulnerability[] {CVE, Title.Value, Notes[] (Title "Description"), CVSSScoreSets[] {BaseScore, Vector, ProductID[]}, Threats[], Remediations[]}`,
remediation `{Type: 2 (Vendor Fix), Description.Value: "5041585", URL, ProductID[], Supercedence, RestartRequired, SubType, FixedBuild: "10.0.22631.4037"}`.
Fixture: `tests/fixtures/sources/msrc/cvrf-2024-Aug.synthetic.json` (CVE-2024-38063 with the real fixed builds of the CNA record, plus an Office CVE without `FixedBuild`).

## Mapping

| CVRF | Our tables |
|---|---|
| `Vulnerability.CVE` | `vulnerability(source='msrc', id=CVE)`; no aliases (ids are CVEs) |
| `Title.Value`, Description note, `CVSSScoreSets` (max `BaseScore`) | summary, details, `cvss_score`/`severity`/`cvss_vector` |
| Remediation x `ProductID` with `FixedBuild` | `affected(vendor='microsoft', product=<normalized FullProductName>, range_type='CVE', version_type='custom', events=[{introduced:'0'},{fixed:FixedBuild}])`; one row per (product, fixed build); `extra`: `kb[]`, `product_ids`, `full_names`, `supersedes` |
| KB numbers | `vulnerability.extra.kbs` |
| whole `Vulnerability` object | `raw_record` |

**Product normalization** (`msrc.normalize_product_name`): lowercase, strip ` for x64-based Systems` / ` for ARM64-based Systems` / ` for 32-bit Systems` and
` (Server Core installation)`, so `Windows 11 Version 23H2 for x64-based Systems` becomes `windows 11 version 23h2` = the CNA spelling the Windows
collector emits (arch variants share one fixed build; CNA lists the base Server product for Core hosts). Exception: `Windows Server, version 23H2 (Server Core installation)` becomes
CNA's `windows server 2022, 23h2 edition (server core installation)`.

## Quirks & pitfalls

- `introduced: 0` is safe only because the product already encodes the Windows release; an old build of the *same* release is correctly below `FixedBuild`.
- Remediations without `FixedBuild` (Office Click-to-Run, SharePoint, Dynamics) produce no `affected` rows (vulnerability + KBs only).
- Windows 10 21H2 / 22H2 and 1809 / Server 2019 share fixed builds; CNA lists them as separate products, so does CVRF.
- Revised months overwrite per CVE (`replace_children`), so re-sync is idempotent.

## TODO

- Validate the JSON shape against the real API; handle `Supercedence` chains to derive "first KB containing the fix".
- Office build tables (channel to fixed build) from the Microsoft release-notes pages; MSRC Update Guide API (`/sug/v2.0`, needs an API key).

## Implementation notes (review fixes)

- Rows are replaced per **document**: importing a month deletes only `affected` rows with the same `extra.document`, so a CVE fixed for Windows 10 in January and Windows 11 in February keeps both. The `vulnerability`/raw row belongs to the newest document (an older one never overwrites it, but its KBs are merged into `extra.kbs`).
- Local `--path` files are sorted by `DocumentTracking.CurrentReleaseDate` (not by file name). Downloads skip months whose release date is not newer than the stored cursor (unless `--full`); the cursor only advances over documents imported before the first failure.
- The source no longer writes `source_sync` (the CLI does, from `SyncResult.records/total/cursor`).
