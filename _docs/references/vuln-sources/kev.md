---
title: CISA KEV
type: reference
context: references
status: implemented
tags: [vuln-source, kev, exploited, prioritization]
updated: 2026-11-07
sample: real
reachable: partial
fixtures: tests/fixtures/sources/kev/
code: src/secmonk/sources/kev.py
related: [references/vuln-sources/epss.md, references/vuln-sources/nvd.md, references/vuln-sources/euvd.md]
---
# CISA KEV

## Summary

The Known Exploited Vulnerabilities (KEV) catalog is published by CISA. Each entry is a CVE with
evidence of active exploitation in the wild, plus a remediation due date for US federal agencies.
We use it as a boolean "exploited" signal and as a prioritization input. It is not a severity
score.

## Access

- **Canonical:** `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` (JSON at
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, CSV beside it).
  Blocked from the sandbox (`www.cisa.gov`, proxy 403).
- **Mirror used (verified 2026-11-07):** GitHub `cisagov/kev-data`, updated shortly after cisa.gov
  on weekdays. Raw files:
  - `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`
  - `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.csv`
  - `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities_schema.json`
- **Auth:** none. Public domain (CC0).
- **Rate limits:** none on the static file. Fetch at most once per run; use `If-Modified-Since`/ETag
  against the raw URL (not verified).
- **Cadence:** on change, weekdays US Eastern. Snapshot cadence is enough for us (daily).
- **Delta:** none. The feed is a full snapshot. Diff by `cveID` and `dateAdded`, or use git history of
  `cisagov/kev-data` (commit = change).

## Data format

Verified from the mirror on 2026-11-07 (real, not synthetic).

Top level: `title`, `catalogVersion` (`2026.11.06`), `dateReleased` (`2026-11-06T19:44:45.1797Z`),
`count` (1769 at probe time), `vulnerabilities[]`. Schema is `..._schema.json` (draft-07).

| Field | Type | Notes |
|---|---|---|
| `cveID` | string | `CVE-YYYY-NNNN+` (schema allows 4 to 19 digits) |
| `vendorProject` | string | |
| `product` | string | |
| `vulnerabilityName` | string | |
| `dateAdded` | date `YYYY-MM-DD` | |
| `shortDescription` | string | |
| `requiredAction` | string | Long; includes BOD 26-04 wording in 2026 entries |
| `dueDate` | date `YYYY-MM-DD` | |
| `knownRansomwareCampaignUse` | `"Known"` / `"Unknown"` | 361 Known, 1408 Unknown at probe |
| `forensicTriage` | `"Yes"` / `"No"` | **Not in older docs.** Present in the 2026 schema. 97 Yes at probe |
| `notes` | string | `" ; "`-joined URLs, sometimes empty |
| `cwes` | string[] | e.g. `["CWE-308"]`; may be empty |

Fixture: `tests/fixtures/sources/kev/known_exploited_vulnerabilities.json`. Trimmed to 9 entries
(includes `CVE-2021-44228`, Apache Log4j2, `dateAdded` 2021-12-10, `dueDate` 2021-12-24). The
top-level `count` is rewritten to the trimmed length (9). The real count was 1769. Entries are
unmodified from the feed.

CSV (`known_exploited_vulnerabilities.csv`) has the same fields in this header order:
`cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,forensicTriage,notes,cwes`.
`cwes` is one string, comma+space separated (e.g. `CWE-306, CWE-862, CWE-345`; 112 rows have more
than one). Prefer JSON.

## Mapping

| KEV field | Our table / column |
|---|---|
| `cveID` | `kev.cve_id` (PK, joins `vulnerability.cve_id`) |
| `dateAdded` | `kev.date_added` |
| `dueDate` | `kev.due_date` |
| `knownRansomwareCampaignUse` | `kev.ransomware` (`'Known'` → 1, else 0) |
| `vendorProject` | `kev.vendor` |
| `product` | `kev.product` |
| `vulnerabilityName` | `kev.name` |
| `forensicTriage` | not stored in the prototype schema (ignore, or add a column later) |
| `requiredAction`, `shortDescription`, `notes` | not stored (linked from reports only) |

Exploited flag for a finding: a row exists in `kev` for the finding's CVE ID.

## Quirks & pitfalls

- A CVE can be added and then have its `dueDate` or `requiredAction` updated. Re-import replaces rows
  by `cveID`; do not append.
- `knownRansomwareCampaignUse` is `"Unknown"` for most entries, which is not `"No"`. Do not treat it
  as false.
- The JSON `count` can disagree with `len(vulnerabilities)` on a bad day. Trust the array and log it.
- The GitHub mirror lags cisa.gov by minutes, and can lag more on a bad day. Both are fine for us.
- This is not a source of CVE details. Join with NVD or CVE List v5 for descriptions and CVSS.

## Status / TODO

- Real sample fetched 2026-11-07 from the GitHub mirror. Reachable: mirror **yes**, cisa.gov **no**.
- Importer implemented (`sources/kev.py`, `tests/sources/test_kev.py` against the 9-row fixture).
- TODO: verify `www.cisa.gov` directly when run from an unrestricted network; check the feed's
  `count` against the array length.

## Implementation notes

- Source order: the official cisa.gov URL first. Any HTTP, network or JSON error falls back to the GitHub mirror. `SyncResult.message` records which URL served the data and why the official one failed.
- Each entry goes through `store_raw` (`modified` = `dateAdded`), so the feed can be re-normalized without a download.
- `kev.ransomware` is stored as 1/0. The column is `TEXT` in the schema, so it reads back as `'1'`/`'0'`.
- The full replace runs in one transaction (`DELETE FROM kev`, then inserts). A failure rolls back and keeps the previous snapshot.
- Guard (review S16): a snapshot with 0 entries or fewer than 50% of the stored rows is refused (status `error`, table untouched) unless `opts.full`. `--limit` upserts the first N entries without replacing the table (status `partial`, no cursor).
