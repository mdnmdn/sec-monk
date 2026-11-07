---
title: NVD API 2.0
type: reference
context: references
status: implemented
tags: [vuln-source, nvd, cve, cvss, cpe, cwe]
updated: 2026-11-07
sample: synthetic
reachable: no
fixtures: tests/fixtures/sources/nvd/
code: src/secmonk/sources/nvd.py
related: [references/vuln-sources/kev.md, references/vuln-sources/epss.md, references/vuln-sources/euvd.md]
---
# NVD API 2.0

## Summary

The National Vulnerability Database (NIST) publishes enriched CVE records: CVSS scores, CWE
weaknesses and CPE applicability (`configurations`). We use it for CVSS and CWE on the
vulnerability, and for CPE match ranges to decide whether an inventory component is affected.
CVE List v5 is the canonical CVE record. NVD adds the enrichment on top of it.

## Access

- **CVE endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`. **Blocked** from the
  sandbox (`services.nvd.nist.gov`). `nvd.nist.gov` also blocked.
- **CPE dictionary:** `https://services.nvd.nist.gov/rest/json/cpes/2.0`.
- **CPE match (virtual match):** `https://services.nvd.nist.gov/rest/json/cpematch/2.0`.
- **Auth:** optional API key sent in header `apiKey: <key>`. Free to request.
- **Rate limits (from memory, not verified):** about 5 requests per rolling 30 s without a key,
  about 50 with a key. Sleep 6 s between calls without a key.
- **Pagination:** `resultsPerPage` max **2000**, `startIndex` (0-based). Loop until
  `startIndex >= totalResults`.
- **Delta:** `lastModStartDate` / `lastModEndDate` (ISO-8601). Window max 120 days. Use it for
  incremental sync. Full sync = paginate without date filters (large, do it once).
- **Other filters:** `cveId`, `pubStartDate`/`pubEndDate`, `cvssV3Severity`, `cpeName`,
  `virtualMatchString`, `keywordSearch`, `noRejected`, `hasKev`.
- **Cadence:** continuous. Incremental sync daily is enough.

### April 2026 enrichment change (from memory, unverified)

Per the coordinator's brief, NVD changed its enrichment in April 2026: only prioritized CVEs
get CPE configurations, and a large backlog (about 29k) is marked as not scheduled for analysis.
Consequences for us: `configurations` may be empty for recent CVEs, so CPE-based matching will
miss them. Fall back to CVE List v5 `affected` (from CISA ADP / vendor) for those. Confirm the
`vulnStatus` values against a live response before coding against them.

## Data format

Shape of the **API 2.0 envelope** is verified from the NVD docs in memory and the fixture
structure. The fixture itself is **synthetic**.

Envelope: `resultsPerPage`, `startIndex`, `totalResults`, `format` (`"NVD_CVE"`), `version` (`"2.0"`),
`timestamp`, `vulnerabilities[]` where each item is `{"cve": {...}}`.

`cve` object:

| Field | Type | Notes |
|---|---|---|
| `id` | string | `CVE-YYYY-NNNN+` |
| `sourceIdentifier` | string | CNA email, e.g. `psirt@apache.org` |
| `published`, `lastModified` | string | `YYYY-MM-DDTHH:mm:ss.sss` (no `Z`) |
| `vulnStatus` | string | Observed: `Awaiting Analysis` (real, fkie-cad 2026 feed). Also: `Received`, `Undergoing Analysis`, `Analyzed`, `Modified`, `Deferred`, `Rejected` (memory). The `Not Scheduled` value is unverified |
| `cveTags` | array | |
| `descriptions[]` | `{lang, value}` | pick `lang == "en"` |
| `metrics.cvssMetricV31[]` | `{source, type, cvssData{version, vectorString, baseScore, baseSeverity, ...}, exploitabilityScore, impactScore}` | `cvssMetricV40`, `cvssMetricV2` similar; V2 has `baseSeverity` outside `cvssData` |
| `weaknesses[]` | `{source, type, description[{lang, value}]}` | `value` like `CWE-917`, `NVD-CWE-Other`, `NVD-CWE-noinfo` |
| `configurations[].nodes[].cpeMatch[]` | see below | |
| `references[]` | `{url, source, tags?}` | |

`cpeMatch[]` item: `vulnerable` (bool), `criteria` (CPE 2.3 string with wildcards),
`versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`
(all optional), `matchCriteriaId` (UUID). Use `matchCriteriaId` for CPE match lookups.

Fixture: `tests/fixtures/sources/nvd/cve-2021-44228.json`. **Synthetic**, wrapped in the API 2.0
envelope. Values for CVE-2021-44228 are the publicly known ones (CVSS 3.1 10.0, CWE-917, Log4j
2.0 to 2.15.0). The `matchCriteriaId` is a placeholder (all zeros). The `lastModified` is a
placeholder too.

**Note on the fkie-cad mirror:** `fkie-cad/nvd-json-data-feeds` (raw GitHub) has per-CVE JSON, but
the record there is **flattened** (top-level `id`, `affected[]` with `cpes`, `versions[]`, no
API envelope). Not an API 2.0 response. Probed 2026: `CVE-2026/CVE-2026-174xx/CVE-2026-17406.json`
returns 200 with `vulnStatus: "Awaiting Analysis"`. `CVE-2021/CVE-2021-44xxx/CVE-2021-44228.json`
returned 404 (the repo does not carry that year at the expected path). The GitHub API listing
for the repo is blocked (`GitHub access not enabled for this session`).

## Mapping

| NVD field | Our table / column |
|---|---|
| `id` | `vulnerability.cve_id` |
| `metrics.cvssMetricV31[0].cvssData.baseScore` | `vulnerability.cvss_score` |
| `…cvssData.vectorString` | `vulnerability.cvss_vector` |
| `…cvssData.baseSeverity` | `vulnerability.severity` |
| `weaknesses[].description[].value` (Primary first) | `vulnerability.cwe` (one per row in a join table if multiple) |
| `descriptions` (en) | `vulnerability.description` (fallback when CVE List lacks one) |
| `configurations[].nodes[].cpeMatch[]` | `cpe_match(vuln_id, criteria, vulnerable, version_start_incl, version_start_excl, version_end_incl, version_end_excl, match_criteria_id)` |
| `vulnStatus` | `vulnerability.nvd_status` (drives "no CPE data yet" handling) |

`cpe_match.vuln_id` joins `vulnerability.cve_id`. Matching in `04-engine/` uses the version range
columns, not the criteria string alone.

## Quirks & pitfalls

- Dates have no timezone. Treat as UTC.
- `lastModStartDate` and `lastModEndDate` must be given together, and the window is max 120 days.
- Empty `configurations` does not mean "not affected". It means "not analysed". Do not mark
  findings as clean from it.
- `cpeMatch` ranges: an entry with no version fields and a specific `criteria` version means
  exactly that version.
- Multiple `nodes` are AND/OR per `operator`. Model the logic, do not flatten it.
- A `Rejected` CVE can be returned with `noRejected` off. Filter it out.
- `cvssMetricV31` can have multiple entries (`Primary` from NVD, `Secondary` from CNA). Take Primary.

## Status / TODO

- Sample: **synthetic** (API 2.0 envelope and field structure; CVE-2021-44228 values public).
- Reachable from sandbox: **no** (`services.nvd.nist.gov`, `nvd.nist.gov` both failed).
  Real fkie-cad 2026 record fetched and inspected (flattened shape, not API 2.0).
- TODO: swap synthetic fixture for a real API response (`?cveId=CVE-2021-44228`) from an
  unrestricted network. TODO: confirm rate limits and `vulnStatus` values from a live response.
  TODO: confirm the April 2026 enrichment change against NVD's announcement.
- TODO: CPE dictionary API is not yet used. Document when we need product name resolution.

## Implementation notes

- Rejected records (`vulnStatus == "Rejected"`) update the vulnerability row (`state='REJECTED'`, `withdrawn = lastModified`) and drop their `affected` rows (`replace_children`); the matcher treats `withdrawn` rows as not applicable.
- Delta: the cursor is the end of the window, captured before any request is sent. Windows are 119 days long, under the 120-day cap. With no stored cursor (and no `--since`), the sync is a full pull. The end of every completed window is persisted in the internal row `nvd:progress`, and a failed run returns status `partial` with the records and cursor of the completed windows (no re-download on retry). `--since` accepts a year, month, date or timestamp and only advances the cursor when it re-covers the stored cursor (`since <= stored`); with no stored cursor or a later `since` the cursor is not moved (it would hide an unsynced gap). The source never writes the main `nvd` row (the CLI does).
- Each page is committed in its own transaction, so a failure keeps the progress already made. Re-running is idempotent (upserts, `replace_children`).
- CPE: a cpeMatch with version `-` and no bounds is skipped (no version applies). `*` with no bounds becomes `introduced: "0"`; an end-only bound (`versionEnd*`) gets a leading `introduced: "0"`; a CPE `update` field (beta/rc/pN) makes the row `CVE-UNPARSED` (`extra.cpe_update`) so stable releases do not match; `cpeMatch` entries are de-duplicated on `matchCriteriaId`.
- The `introduced_exclusive` event key is new. `db.py` lists only `introduced`, `fixed`, `last_affected` and `limit`. Matchers must handle it.
- Rate limit: one client paces all requests (6 s without a key, 0.6 s with). Per-request `apiKey` header.
- HTTP (review S12/SEC11): 403/429/5xx and transport errors are retried up to 5 times with exponential backoff (2 s base, 120 s cap), honoring `Retry-After` (seconds or HTTP date). Redirects are never followed, so the `apiKey` header cannot leave `services.nvd.nist.gov`.
- CVSS choice: Primary before Secondary, then 4.0 > 3.1 > 3.0 > 2.0. `--limit` stops after N stored records (status `partial`, no cursor).
- `nvd.renormalize(conn)` rebuilds all nvd rows from `raw_record` without downloading, so importer fixes reach an existing DB.
