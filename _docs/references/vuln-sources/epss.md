---
title: FIRST EPSS
type: reference
context: references
status: implemented
tags: [vuln-source, epss, exploitation-probability, prioritization]
updated: 2026-11-07
sample: synthetic
reachable: no
fixtures: tests/fixtures/sources/epss/
code: src/secmonk/sources/epss.py
related: [references/vuln-sources/kev.md, references/vuln-sources/nvd.md, references/vuln-sources/euvd.md]
---
# FIRST EPSS

## Summary

The Exploit Prediction Scoring System (EPSS) is published by FIRST. For each CVE it gives the
estimated probability (`epss`, 0 to 1) that the CVE is exploited in the next 30 days, and its
`percentile` among all scored CVEs. We store the daily score and use it to rank findings. It is
complementary to KEV: KEV says "exploited already", EPSS says "likely soon".

## Access

- **Bulk (daily):** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (current day),
  and dated files `epss_scores-YYYY-MM-DD.csv.gz`. **Blocked from the sandbox** (connection
  failed, no response).
- **API:** `https://api.first.org/data/v1/epss` (JSON). **Blocked** (`api.first.org`, DNS/proxy).
- **Auth:** none.
- **Rate limits:** not verified. Public docs (from memory) suggest a request cap per IP and a
  maximum of 100 CVEs per API call. Confirm before relying on it.
- **Cadence:** one scoring run per day, with a `score_date` of the previous day (UTC).
- **Delta:** none. Use the daily full file. Diff by CVE.

## Data format

**Synthetic sample.** No mirror was reachable from the sandbox. The header and comment line were
written to match the published format, but the scores are illustrative. Replace with a real file
when reachable.

### Daily CSV (`epss_scores-YYYY-MM-DD.csv.gz`)

Line 1 is a comment carrying the model version and score date:

```
#model_version:v2023.03.01,score_date:2026-11-06T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.97431,0.99986
```

- Comment lines start with `#`. The importer must skip them, and must not assume line 1 is the header.
- Header (exact): `cve,epss,percentile`.
- `epss` and `percentile` are decimals with 5 digits in the daily file.
- Real file has about 250k rows.

Fixture: `tests/fixtures/sources/epss/epss_scores-sample.csv`. Has the real comment and header
(plus one extra `#SYNTHETIC SAMPLE` comment line, which importers skip) and 10 synthetic rows.

### API (`/data/v1/epss`)

Query: `cve=CVE-A,CVE-B` (comma-separated), `date=YYYY-MM-DD` (optional, defaults to latest),
`envelope`, `pretty`, `offset`, `limit`.

Response envelope:

| Field | Type | Notes |
|---|---|---|
| `status` | string | `"OK"` |
| `status-code` | int | `200` |
| `version` | string | API version |
| `total` | int | count matching the query |
| `offset`, `limit` | int | pagination |
| `data[]` | array | one per CVE |

`data[]` item: `cve` (string), `epss` (string, decimal), `percentile` (string, decimal), `date`
(`YYYY-MM-DD`). Numbers come back as strings. Parse explicitly.

Fixture: `tests/fixtures/sources/epss/api-sample.json` (synthetic, two rows).

## Mapping

| EPSS field | Our table / column |
|---|---|
| `cve` | `epss.cve_id` (joins `vulnerability.cve_id`) |
| `epss` | `epss.score` (REAL) |
| `percentile` | `epss.percentile` (REAL) |
| `date` / `score_date` | `epss.date` (`YYYY-MM-DD`; from the comment line for CSV) |

Primary key: `(cve_id, date)`. Keep history for trend views. Latest per CVE is a view.

## Quirks & pitfalls

- The CSV model comment line is not part of the CSV header. A plain CSV reader will mistake it for
  the header. Skip `#` lines first.
- The API returns numbers as strings. The CSV returns them as bare decimals.
- `score_date` in the comment is the day the scores describe, not the download date.
- Scores for newly published CVEs can be missing for a day. Treat missing as "unknown", not 0.
- EPSS is a probability model. It is not exploited-in-the-wild evidence. Keep it separate from
  the KEV flag.

## Status / TODO

- Sample: **synthetic** (format mirrors the published docs, values illustrative).
- Reachable from sandbox: **no** (`api.first.org` and `epss.empiricalsecurity.com` both failed).
  No GitHub mirror found. `raw.githubusercontent.com` probes for `jgamblin/EPSS` and
  `jgamblin/EPSS-Data` returned 404.
- TODO: replace the synthetic CSV with a real daily file from an unrestricted network; confirm the
  exact header and decimal width. TODO: confirm API rate limits and max `limit`.

## Implementation notes

- Schema: `epss.cve_id` is the only primary key in `db.py`, not `(cve_id, date)` as this doc says. The import keeps the latest score per CVE and no history. Trend views need a schema change.
- Precedence: a bulk FIRST import uses `INSERT OR REPLACE` (authoritative). EUVD-derived rows (`source='euvd'`) never overwrite FIRST rows but do refresh their own earlier euvd rows (upsert `WHERE epss.source='euvd'`).
- Cursor: the `score_date` from the CSV comment line (`YYYY-MM-DD`).
- API mode (`opts.ids`) sends batches of 100 with no pause between them. Values are parsed from strings to floats.
- Integrity (review S15/SEC18): gzip is decompressed incrementally with a 1 GiB cap (`epss.MAX_DECOMPRESSED`); a truncated/corrupt stream (no end-of-stream marker) is an `error` and the whole import rolls back; lines over 64 KiB are refused. A bulk file with 0 rows or fewer than 50% of the stored `source='epss'` rows is refused unless `opts.full`. `--limit` imports only the first N rows (status `partial`, no cursor).
