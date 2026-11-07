---
title: ENISA EUVD
type: reference
context: references
status: implemented
tags: [vuln-source, euvd, enisa, exploited, alias]
updated: 2026-11-07
sample: synthetic
reachable: no
fixtures: tests/fixtures/sources/euvd/
code: src/secmonk/sources/euvd.py
related: [references/vuln-sources/kev.md, references/vuln-sources/epss.md, references/vuln-sources/nvd.md]
---
# ENISA EUVD

## Summary

The European Vulnerability Database (EUVD), run by ENISA under the EU Cybersecurity Act, is a
second vulnerability catalogue. Its identifiers are `EUVD-YYYY-NNNNN`. Each record carries a
`aliases` field that links to CVE IDs, so it works as a redundancy source and an alias bridge
between EUVD and CVE. It also carries an `exploited` flag and an `epss` value. We use it as a
cross-check and for the EU view.

## Access

- **Base:** `https://euvdservices.enisa.europa.eu/api/` (API host). **Not reachable** from the
  sandbox (`euvdservices.enisa.europa.eu` curl blocked). `euvd.enisa.europa.eu` (web UI and
  apidoc) failed DNS for WebFetch in this session.
- **Endpoints (from the coordinator's brief, unverified):**
  - `GET /api/vulnerabilities` with query params `fromScore`, `toScore`, `fromEpss`, `toEpss`,
    `product`, `vendor`, `assigner`, `exploited`, `page`, `size`.
  - `GET /api/exploitedvulnerabilities`: exploited set.
  - `GET /api/criticalvulnerabilities`: critical set.
  - `GET /api/lastvulnerabilities`: recent.
  - `GET /api/enisaid?id=EUVD-YYYY-NNNNN`: lookup by EUVD ID.
  - `GET /api/vulnerability?id=...`: single record.
  - `GET /api/advisory?id=...`: ENISA advisory (linked CSAF).
- **Auth:** none (public, from memory).
- **Rate limits:** unknown. Not verified.
- **Cadence:** continuous. Poll `lastvulnerabilities` or `exploitedvulnerabilities` hourly/daily.
- **Delta:** no date filter known. Use `lastvulnerabilities` for recent changes and compare
  `dateUpdated`.

## Data format

**Synthetic sample.** The field names come from the coordinator's brief and from memory of the
public API. The sample was not checked against a live response.

Vulnerability object fields:

| Field | Type | Notes |
|---|---|---|
| `id` | string | `EUVD-YYYY-NNNNN` |
| `enisaUuid` | string (UUID) | internal |
| `description` | string | |
| `datePublished`, `dateUpdated` | string (ISO-8601 with `Z`) | |
| `baseScore`, `baseScoreVersion`, `baseScoreVector` | number, string, string | CVSS |
| `references` | string | newline-separated URLs |
| `aliases` | string | **newline-separated** list, e.g. `CVE-2021-44228`. Parse, do not compare whole strings |
| `assigner` | string | CNA |
| `epss` | number or null | EPSS score when available |
| `exploited` | bool | ENISA exploited flag (not identical to KEV) |
| `enisaIdProduct[]`, `enisaIdVendor[]`, `enisaIdVulnerability[]` | string[] | ENISA internal IDs for product/vendor/vuln (memory) |

Fixture: `tests/fixtures/sources/euvd/exploited-sample.json`. **Synthetic.** Two items: one
Log4j-style record with a CVE alias, and one with no alias (exercises the "EUVD only" path). The
`total`/`items` envelope is also assumed, not verified.

## Mapping

| EUVD field | Our table / column |
|---|---|
| `id` | `alias.alias_id` (type `EUVD`) with `vulnerability.id` as the canonical record |
| `aliases` (each line matching `CVE-*`) | `alias` rows (type `CVE`), linking EUVD ↔ CVE |
| `baseScore`, `baseScoreVector` | `vulnerability` CVSS, only if no CVE-side score (EUVD is secondary) |
| `epss` | `epss` table, source `EUVD`, if we keep it separate. Prefer FIRST EPSS |
| `exploited` | flag `exploited_euvd` (not merged into KEV) |
| `enisaIdProduct[]` | not stored (prototype) |

## Quirks & pitfalls

- `aliases` is newline-separated inside one string. An empty string means no alias. Do not assume
  one CVE.
- An EUVD record can have **no** CVE alias. Keep it as an EUVD-only vulnerability.
- The `exploited` flag is ENISA's, not CISA's. Keep both, do not merge.
- `epss` may be `null`. Do not coerce to 0.
- `baseScore` may differ from the NVD/CNA score. Keep the source tag.
- The EUVD host and the web host differ (`euvdservices.` for API, `euvd.` for UI). Use the API
  host for code.

## Status / TODO

- Sample: **synthetic** (field names per brief and memory, values illustrative).
- Reachable from sandbox: **no** (`euvdservices.enisa.europa.eu` blocked by curl proxy;
  `euvd.enisa.europa.eu` DNS failed for WebFetch). No GitHub mirror probed (none known).
- Unverified: endpoint list, query parameters, response field names, envelope shape.
- TODO: verify endpoints and a real `vulnerabilities` response from an unrestricted network,
  then replace the synthetic fixture. TODO: confirm rate limits.

## Implementation notes

- Sync pulls `/exploitedvulnerabilities?size=100` and `/lastvulnerabilities`. With `opts.limit`, it also pages `/vulnerabilities` (`page` 0-based, `size=100`). All three endpoint shapes are unverified against the live API.
- Product entries: the fixture has none. The module reads an optional `products` list of `{vendor, product, version}` objects. Its real shape is unverified. `enisaIdProduct[]` strings are not stored.
- `exploited` = the record's own flag, OR the record came from the exploited view. It is stored in `vulnerability.extra` only and is not merged into `kev`.
- Only CVE aliases are stored (`alias.source = 'euvd'`). EUVD-only records get no alias rows.
- EPSS: when the record has an `epss` value, one `INSERT OR IGNORE` per CVE alias, with `date` = the `dateUpdated` day. EUVD never overwrites a FIRST score.
- No cursor is returned: the views are small and pulled whole.
