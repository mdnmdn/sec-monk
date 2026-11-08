---
title: CVE List v5 (+ CISA Vulnrichment)
summary: CVE List v5 git mirror and CISA Vulnrichment ADP, covering access paths, record format, mapping to tables, quirks, sync strategy and the sparse-clone implementation.
read_when: you change the CVE List importer, debug a cvelist sync or need the CVE 5.x record fields and quirks
type: reference
context: references
code: src/secmonk/sources/cvelist.py
status: implemented
tags: [vuln-source, cve, adp, ssvc]
updated: 2026-11-07
verified: 2026-11-07
sample: real
reachable: partial
fixtures: tests/fixtures/sources/cvelist/
related: [references/vuln-sources/osv.md, references/vuln-sources/nvd.md]
---

# CVE List v5 (CVEProject/cvelistV5) + CISA Vulnrichment ADP

## Summary

`CVEProject/cvelistV5` is the official git mirror of the CVE Record Format 5.x records, one JSON
file per CVE, published by the CVE Program (MITRE/CNA-LR). Each record has a **CNA container**
(`containers.cna`, written by the assigning CNA: vendor/product/version ranges, CVSS, CWE,
references) and optional **ADP containers** (`containers.adp[]`, third-party enrichment). The
important ADP is **CISA-ADP "CISA ADP Vulnrichment"**: SSVC decision points, KEV hints, and
CVSS/CWE filled in when the CNA left them out. It is our canonical, NVD-independent source for
CVE metadata and for **name-based (vendor/product) matching** of software that has no PURL (macOS
apps, desktop apps, appliances). Records are public domain-ish (CVE Terms of Use), no auth.

## Access

Probed 2026-11-07 from the dev sandbox.

| Endpoint | Result |
|---|---|
| `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<YYYY>/<NNN>xxx/CVE-<YYYY>-<N>.json` | OK, ~0.15 s, ~35 KB worst case (Log4Shell), typical 3-8 KB |
| `.../main/cves/delta.json` | OK, ~1 KB, latest delta only |
| `.../main/cves/deltaLog.json` | OK, **37.9 MB**, 2871 entries (2026-10-08 .. 2026-11-07), ~126k changes in the window |
| `git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git` | OK, **4.3 s, 53 MB `.git`**, tree objects for all 420,776 records, no blobs |
| `git sparse-checkout set cves/2025` (blobs fetched on demand) | OK, **26 s**, +40 MB `.git` (93 MB), **45,479 files / 424 MB** working tree |
| `git sparse-checkout set cves/2021/44xxx` | OK, 644 files, a few seconds |
| `github.com/.../releases` (and the `all_CVEs_at_midnight.zip.zip` release asset), `codeload`, `api.github.com`, `cveawg.mitre.org` (CVE Services API) | **403, blocked** by egress policy. The release zips (daily midnight snapshot, `_all_CVEs_at_midnight.zip`) are the upstream-recommended bulk path; validate from an open network. |
| `cves/` directory listing via raw | 404 (raw has no listings); use the sparse clone for listings |

Path rule: `cves/<year>/<floor(n/1000)>xxx/CVE-<year>-<digits>.json`, where the **folder** comes from the
numeric value `n` and the **file name keeps the id's digits verbatim, zero padding included**
(`CVE-2021-44228` -> `cves/2021/44xxx/CVE-2021-44228.json`, `CVE-2014-0160` ->
`cves/2014/0xxx/CVE-2014-0160.json`, `CVE-2026-119977` -> `cves/2026/119xxx/`). Note 2026 has 6-digit IDs and 86k
files already (CNA block allocations), so do **not** assume 4/5 digits.

**Cadence:** the repo is updated roughly every 7-20 minutes (deltaLog entries are ~15 min apart,
0..~100s of changes each). `delta.json` mirrors the newest entry; `deltaLog.json` is the
append-newest-first history. `dateUpdated` in `cveMetadata` is the per-record watermark.

**Delta format** (`tests/fixtures/sources/cvelist/delta.json`, `deltaLog.json`):
`{fetchTime, numberOfChanges, new:[{cveId, cveOrgLink, githubLink, dateUpdated}], updated:[...], error:[...]}`.
`githubLink` is a ready-to-use raw URL. deltaLog is an array of those objects. Because
`deltaLog.json` is 38 MB, use it only for catch-up after a gap; for steady-state use
`git fetch` on a sparse clone, or poll `delta.json` every few minutes (gap risk: if you miss
>1 poll you lose entries, fall back to deltaLog entries with `fetchTime` > last seen).

## Data format

Fixtures in `tests/fixtures/sources/cvelist/` (all real, complete records; fetched 2026-11-07):

| Fixture | Demonstrates |
|---|---|
| `CVE-2021-44228.json` | Log4Shell: `lessThan: "log4j-core*"` (non-version!), `changes[]`, CNA metric `other/unknown`, CISA-ADP CVSS 3.1 + SSVC + KEV, `CVE` ADP (refs only) |
| `CVE-2026-19868.json` | Recent KEV: CISA-ADP with `cvssV3_1`, `other.ssvc` (v2.0.3), `other.kev`, `timeline`; CNA `defaultStatus: unknown`, free-text versions ("7.3.3-7015 and older versions") |
| `CVE-2025-7783.json` | npm: `packageName` + `collectionURL` (`https://npmjs.com/form-data`) + `repo`; range *strings* in `version` ("< 2.5.4", "3.0.0 - 3.0.3"), CVSS 4.0 |
| `CVE-2025-24746.json` | WordPress plugin (Patchstack): `packageName`, `collectionURL`, `version: "0"` + `lessThanOrEqual` + `changes[]`, `versionType: custom`, `defaultStatus: unaffected` |
| `CVE-2025-1914.json` | Google Chrome: vendor/product, `version == lessThan`, `versionType: custom`, no `defaultStatus` |
| `CVE-2025-1013.json` | Mozilla Firefox/Thunderbird: only `unaffected` entries, `lessThanOrEqual: "128.*"` / `"*"`, `versionType: rpm` (!) |
| `CVE-2025-48709.json` | CISA-ADP container with its own `affected` + `cpes` (rare: 1 of 45k in 2025) |
| `CVE-2025-24077.json` | `cpeApplicability` (NVD-style nodes/cpeMatch, `dataVersion` 5.2), Microsoft macOS Office |
| `CVE-2025-24468.json` | `state: REJECTED`: no `descriptions`/`affected`, only `rejectedReasons` |
| `delta.json`, `deltaLog.json` | Delta feed (deltaLog trimmed to 3 entries x 2 ids) |

### Top level

| Field | Notes |
|---|---|
| `dataType` | `"CVE_RECORD"` |
| `dataVersion` | `5.1` or `5.2` (5.2 adds `cpeApplicability`, 2025+ records); accept any `5.x` |
| `cveMetadata.cveId` | `CVE-YYYY-N+` |
| `cveMetadata.state` | `PUBLISHED` or `REJECTED` (2025 sample: 43,686 / 1,793) |
| `cveMetadata.assignerOrgId` / `assignerShortName` | CNA UUID / short name (`apache`, `GitHub_M`, `Chrome`) |
| `cveMetadata.dateReserved`, `datePublished`, `dateUpdated`, `dateRejected` | ISO-8601 `...Z` with ms. `datePublished` absent on REJECTED-before-publish; `dateRejected` only when rejected. Use `dateUpdated` as `modified`. |

### `containers.cna`

| Field | Notes |
|---|---|
| `providerMetadata` | `{orgId, shortName, dateUpdated}` |
| `title` | optional (present in ~77% of 2025 records) |
| `descriptions[]` | `{lang, value, supportingMedia?}`; pick `lang` starting `en`, first |
| `affected[]` | see below. Present on every PUBLISHED record but may be `[{vendor:"n/a",product:"n/a",versions:[{version:"n/a"}]}]` |
| `metrics[]` | each element holds one of `cvssV2_0`, `cvssV3_0`, `cvssV3_1`, `cvssV4_0`, `other` (+ optional `format`, `scenarios[]` on 4.0 and some 3.x). Present in ~81% of 2025 records. |
| `problemTypes[]` | `descriptions[]: {type:"CWE", lang, cweId:"CWE-502", description:"CWE-502 ..."}`; sometimes `type` is free text with no `cweId` |
| `references[]` | `{url, name?, tags?[]}`; tags like `vendor-advisory`, `patch`, `exploit`, `issue-tracking` |
| `datePublic`, `dateAssigned`, `timeline[]`, `credits[]`, `solutions[]`, `workarounds[]`, `exploits[]`, `impacts[]` (CAPEC), `source`, `tags`, `x_*` | informational |
| `cpeApplicability[]` | 5.2: `[{operator?, nodes:[{operator, negate, cpeMatch:[{vulnerable, criteria, versionStartIncluding, versionEndExcluding, ...}]}]}]` (5,501 of 43,686 2025 records) |
| `rejectedReasons[]`, `replacedBy[]` | REJECTED records; `replacedBy` rare (40) |

### `affected[]` entry

| Field | Notes |
|---|---|
| `vendor`, `product` | free text, CNA-defined casing/spelling (`"Apache Software Foundation"`, `"Apache Log4j2"`, `"github"`/`"codeql-action"`, `"Daniel Iser"`/`"Popup Maker"`). Optional (269 entries without vendor in 2025). `"n/a"` is common (5,000 vendor, 4,168 product in 2025 sample). |
| `packageName` | ecosystem package name (`form-data`, `popup-maker`) |
| `collectionURL` | registry/repo root, **not** a PURL type: `https://npmjs.com/form-data`, `https://pypi.org/project/x/`, `https://repo1.maven.org/maven2`, `https://github.com/org/repo`, `https://wordpress.org/plugins`, `https://hub.docker.com`, GNOME/GitLab/Savannah URLs. Present with `packageName` in ~13.9k entries (2025). Sometimes with trailing `/`, `http://`, `npmjs.com` without `www`/`registry`. |
| `repo`, `programFiles[]`, `programRoutines[]`, `modules[]` | extra scope hints (`repo` 6.3k, `modules` 3k) |
| `platforms[]` | free text (`"Linux"`, `"Gen7"`, `"x64"`, `"macOS"`); 17k entries |
| `cpes[]` | CPE 2.3 strings, often one per version (Fortinet) or a wildcard (`cpe:2.3:a:bmc:control-m:*:*...`) |
| `defaultStatus` | `affected` / `unaffected` / `unknown`; missing = treat as `unknown` (2025: 30k unaffected, 10k affected, 4k unknown) |
| `versions[]` | see below |

### `versions[]` entry

| Field | Notes |
|---|---|
| `version` | required. Lower bound / exact version, or `"0"` (from start), `"unspecified"`, `"n/a"`/`"N/A"`, or a **range expression string** (`"< 2.5.4"`, `">= 3.26.11, <= 3.28.2"`, `"3.0.0 - 3.0.3"`, `"7.3.3-7015 and older versions"`) |
| `status` | `affected` / `unaffected` / `unknown` |
| `lessThan`, `lessThanOrEqual` | upper bound (exclusive / inclusive); may be `"*"`, a wildcard (`"128.*"`), a package label (`"log4j-core*"`), or even a URL/free text |
| `versionType` | absent on ~111k of ~250k entries (2025). Values: `semver` (30k), `custom` (40k), `git` (14.6k), `original_commit_for_fix` (2.6k), `rpm` (5k), `maven` (964), `python` (171), `date`, `cpe`, `dpkg`, `otp`, `osgi`, `go` + dirty values (`Custom`, `commercial`, `Patch`, `Firmware`, whole sentences). Lowercase before comparing; unknown -> custom fallback. |
| `changes[]` | `[{at, status}]` transitions after the base range, e.g. Log4Shell: affected from `2.0-beta9`, unaffected at 2.3.1, affected again at 2.4, unaffected at 2.12.2, ... Used by 4.3k 2025 entries. |

### Metrics

- `cvssV3_1` / `cvssV3_0`: `{version, vectorString, baseScore, baseSeverity, + exploded components}`.
- `cvssV4_0`: same plus `Automatable`, `Recovery`, `Safety`, `valueDensity`, ... all `NOT_DEFINED` placeholders; `scenarios[]`.
- `cvssV2_0`: `{version, vectorString, baseScore}` (no severity).
- `other`: `{type, content}`; CNA example `{type:"unknown", content:{other:"critical"}}` (Log4Shell), Red Hat SADP `"Red Hat severity rating"`.
- Numbers are JSON numbers (`10`, `9.4`); vectors start `CVSS:3.1/`, `CVSS:4.0/` (3.0 uses `CVSS:3.0/`, 2.0 has no prefix).

### `containers.adp[]`

Each: `{providerMetadata:{orgId, shortName, dateUpdated}, title, metrics?, references?, problemTypes?, affected?, timeline?}`.

| ADP shortName (2025 counts) | Content |
|---|---|
| `CISA-ADP` (42,218 of 45,479) | `metrics[]`: SSVC in **every** record; `cvssV3_1` (7.3k, only when the CNA gave none; rarely `cvssV4_0`), `problemTypes` CWE (7k), `references` (4.3k), `timeline` (KEV additions), `affected` + `cpes` (1 record). `title: "CISA ADP Vulnrichment"` |
| `CVE` (2,779) | CVE Program ADP: only `references`/`title` (reference fix-ups), no data we need |
| `siemens-SADP` (526), `redhat-SADP` (77) | vendor ADPs: `affected` + CVSS 3.1 / severity rating |

SSVC (`metrics[].other.type == "ssvc"`):
`content: {id, role:"CISA Coordinator", version:"2.0.3", timestamp, options:[{"Exploitation":"none|poc|active"},{"Automatable":"yes|no"},{"Technical Impact":"partial|total"}]}`.
`options` is a list of single-key objects (flatten to a dict).
KEV hint (`other.type == "kev"`, 189 in 2025): `content:{dateAdded, reference}` (+ ADP `timeline` entry "added to CISA KEV"). This is a convenience; the authoritative KEV source is KEV (kev.md, sibling doc).

## Mapping (design sketch) into our tables

> **Design sketch, written before the importer existed.** Table and column names below (`affected_range`, `ssvc` table`) are not the implemented schema. The tables that exist are in [tech/data-model.md](../../tech/data-model.md); what the importer really writes is under *Implementation notes*.


Use the **CNA container first**, fall back to ADP (CISA-ADP) for CVSS/CWE.

`vulnerability` (one row per CVE; skip or flag `state=REJECTED`):

| Column | Source |
|---|---|
| `id` | `cveMetadata.cveId` |
| `summary` | `cna.title` or first `en` `descriptions[].value` (keep both: title short, description long) |
| `published` | `cveMetadata.datePublished` |
| `modified` | `cveMetadata.dateUpdated` (sync watermark) |
| `rejected` / `withdrawn` | `state == REJECTED` -> `dateRejected` |
| `cvss_score/vector/version` | best of CNA `metrics[]`: prefer `cvssV4_0` > `cvssV3_1` > `cvssV3_0` > `cvssV2_0`, tie-break CNA over CISA-ADP; store all variants if schema permits (3.1 is what most policies use). |
| `severity` | `baseSeverity` of the chosen metric; v2.0 has none (derive); `other.content.other` is free text (Log4Shell "critical") |
| `cwe` | `problemTypes[].descriptions[].cweId` (CNA, else CISA-ADP); multi-valued, dedupe; ignore entries without `cweId` |
| `references` | `cna.references[]` + `adp[].references[]` |
| `assigner` | `cveMetadata.assignerShortName` |

`alias`: only `{CVE id}`; GHSA/OSV aliases come from OSV. Record `replacedBy` as an alias-like relation if present.

`affected_range` (name-based matching; one row per `affected[] x versions[]`):

| Column | Source |
|---|---|
| `source` / `cve_id` | `cvelist`, cveId; `container` = `cna` or ADP shortName |
| `vendor`, `product` | `affected[].vendor/product` (normalize: lowercase, strip, collapse `_`/space/punctuation; treat `n/a`, `unspecified`, empty as NULL) |
| `package_name`, `collection_url` | `packageName`, `collectionURL` (derive an ecosystem hint from `collection_url` host: npmjs.com, pypi.org/pypi.python.org, repo*.maven*, github.com, wordpress.org, hub.docker.com, crates.io...) |
| `cpe` | `affected[].cpes[]` and `cpeApplicability` criteria (vendor/product from CPE are the best normalized key) |
| `platform` | `platforms[]` |
| `version_type` | lowercased `versionType` (NULL if absent) |
| `introduced` | `version` if it is a plain version and not `0`/`unspecified`/`n/a`; `0` = from the start |
| `fixed` | `lessThan` (exclusive upper bound) |
| `last_affected` | `lessThanOrEqual` (inclusive upper bound) |
| `status` | `versions[].status`, defaulting to `affected[].defaultStatus` for unlisted versions |
| `changes` | expand into extra rows: each `at` with status `unaffected` closes the previous range (`fixed = at`), `affected` opens a new one (`introduced = at`) |
| `raw_version` | the original `version` string when it is an expression (kept for the fallback parser) |

SSVC is stored in `vulnerability.extra.ssvc` (no separate table; the columns would have been `cve_id, exploitation, automatable, technical_impact, version, timestamp, role` from `adp[CISA-ADP].metrics[other.type=="ssvc"].content`). `kev_hint`: `dateAdded` from `other.type=="kev"` (defer to the KEV source for truth).

## Quirks & pitfalls

1. **`lessThan` is not always a version.** Log4Shell has `lessThan: "log4j-core*"` and the real ranges live in `changes[]`. Validate bounds against the version parser; on failure drop the bound and fall back to `changes`/description, or mark the row `unparseable`.
2. **`*` wildcards**: `lessThanOrEqual: "*"` or `"128.*"` (Mozilla; all 8,449 in the 2025 sample). `"*"` = unbounded; `"128.*"` = "any 128.x". Mozilla lists **only unaffected** versions with `rpm` as versionType even though Firefox is not an RPM here: the implied affected set is "below `version`" when no `defaultStatus` is given (Chrome: `lessThan == version`, `custom`).
3. **`version: "0"` + `lessThan/lessThanOrEqual`** = "from the beginning up to"; the single most common pattern for package-based CNAs (Patchstack, GitHub, Red Hat).
4. **Range expressions inside `version`** (GitHub CNA & Vulncheck style): `"< 2.5.4"`, `">= 3.26.11, <= 3.28.2"`, `"3.0.0 - 3.0.3"`, `"7.3.3-7015 and older versions"`, `"prior to 9.2"`. Needs a small parser; otherwise unusable for matching. `versionType: semver` does not guarantee the string is a clean semver.
5. **`versionType` is optional and dirty**: absent in ~45%, `custom` is a catch-all (generic version-compare, not semver), plus free text in the field; `git` ranges (commit hashes, ~14.6k) and `original_commit_for_fix` (kernel) are **not** product versions: do not use them for installed-software matching.
6. `vendor`/`product` **`n/a`**, missing, or freeform (`"Apache Software Foundation"` vs CPE `apache`). Name matching needs the CPE dictionary / alias table; prefer `cpes`/`cpeApplicability` when present.
7. `collectionURL` is inconsistent (`npmjs.com/x` vs `registry.npmjs.org`, trailing slashes, `pypi.python.org`, GitHub repo URLs for non-GitHub-packaged products); map host -> ecosystem with a tolerant table, and treat as a hint, not PURL.
8. `cpeApplicability` `versionEndExcluding` can be a **URL** (Microsoft: `https://aka.ms/OfficeSecurityReleases`). Validate before use.
9. `defaultStatus` absent is common; `unknown` is not `unaffected`. Do not treat unlisted versions as safe when `defaultStatus != unaffected`.
10. REJECTED records have no `descriptions`/`affected`/`references`; the `cna` container contains only `providerMetadata` + `rejectedReasons`. `datePublished` may be missing. Remove existing rows on a transition PUBLISHED -> REJECTED.
11. ADP data are **not** in the CNA container: CVSS/CWE from `CISA-ADP` must be tagged with `container` provenance. CISA-ADP CVSS often supersedes a missing CNA score only; never overwrite CNA scores.
12. SSVC `options` is a list of one-key dicts; `timestamp` has no `Z`, uses `+00:00`. KEV additions update the file (ADP `dateUpdated` bump) without changing the CNA container.
13. Dates: `2025-10-21T23:25:23.121Z` (ms, `Z`); `dateUpdated` is the **max** over containers (the ADP update bumps it).
14. 6-digit and zero-free IDs: `CVE-2026-119977` lives in `119xxx`; never `zfill`.
15. Size: median record ~4-8 KB, outliers 100s KB (large `cpes`, many `versions`); don't assume < 1 MB blindly, stream/parse with the std `json`.
16. Untrusted free text in descriptions/versions: never `eval`, treat as data; escape on output.

## Recommended sync strategy

Given the sandbox (raw + git OK; releases zip, API, CVE Services blocked):

1. **Primary: sparse partial git clone, year-scoped.**
   `git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git && git sparse-checkout set --no-cone`-style paths or cone paths `cves/2024 cves/2025 cves/2026`.
   Measured: base clone 4 s / 53 MB, one year ~26 s / +40 MB `.git` / 424 MB tree (2025: 45k files; 2026 is 86k files so expect ~1 min). Full history is avoided by `--depth 1`; blobs for old years are never fetched.
   Initial seed = last 3 years (what is realistically installed and exploited); the older years can be added later with another `sparse-checkout set`/`add`.
   **Incremental**: `git fetch --depth 1 origin main` + `git diff --name-only <old> <new> -- cves` gives changed paths in seconds (blobs lazily fetched for just those). Persist the last commit SHA as the sync cursor; also store `max(dateUpdated)`.
2. **On-demand fallback (best for the prototype and for unrestricted-network-free dev): per-ID fetch** of `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<year>/<N//1000>xxx/CVE-<year>-<N>.json` for CVEs referenced by other sources (OSV aliases, KEV, NVD/EPSS ids, SSVC/KEV enrichment of already-matched findings). One ~0.15 s request per CVE; cache by `dateUpdated`; 404 -> unknown/withdrawn. Do not bulk-crawl raw for thousands (rate limits, politeness).
3. **Freshness without git**: poll `cves/delta.json` (1 KB) every 10-15 min and fetch only `new`/`updated` `githubLink`s; use `deltaLog.json` (38 MB) only for gap recovery. Good for a long-running daemon; for a CLI scan, a `git fetch` at scan start is enough.
4. **Unrestricted networks**: prefer the release zip `all_CVEs_at_midnight.zip` from GitHub Releases (one download, no git); blocked here, so untested. Keep the importer taking a directory of `CVE-*.json` so any of the above feeds it.

Importer rule: parse each file with `json` only, tolerate unknown `dataVersion`, upsert by `cveId` when `dateUpdated` is newer.

## Status / TODO

- [x] Probed access and measured sparse/partial clone (2026-11-07); fixtures saved and validated as JSON.
- [x] Format analysed on the full 2025 set (45,479 records).
- [x] Importer (directory walker + per-ID fetcher + git delta), `changes[]` expansion, version-expression parser and vendor/product normalization are implemented (see Implementation notes; alias table in `src/secmonk/data/product_aliases.yaml`).
- [ ] Validate release-zip bulk path and `cveawg` API from an unrestricted network (blocked: 403).
- [x] SSVC storage decided: JSON in `vulnerability.extra.ssvc`, no separate table.
- [ ] Cross-check the ADP KEV hints (`extra.adp_kev`) against the KEV table ([kev.md](kev.md)).

## Implementation notes

Code: `src/secmonk/sources/cvelist.py` (`CveListSource`, `import_record`, `parse_version_expression`,
`convert_version_entry`, `fetch_missing`, `cve_path`). Tests: `tests/sources/test_cvelist.py`.

### Sync modes

1. `opts.path`: one CVE JSON file, or a directory walked recursively for `CVE-*.json`.
2. `opts.ids`: per-id raw fetch from `raw.githubusercontent.com/.../cves/<year>/<n//1000>xxx/<id>.json`
   (file name = the id as written, so `CVE-2014-0160` stays zero padded; 6+ digit ids OK); 404 is skipped. `ids == ["@referenced"]` computes the ids from
   `alias` (`CVE-%`) and `kev` that have no cvelist row, capped by `opts.limit`
   (`fetch_missing`, for `secmonk sync cvelist --id @referenced`).
3. Default: sparse partial clone in the per-user cache `paths.cache_subdir("cvelistV5")`
   (`--depth 1 --filter=blob:none --sparse`), `git sparse-checkout add cves/<year>..` for the widest of
   `opts.since` year, the oldest year synced before (internal row `cvelist:years`, so a `--since` backfill
   is never abandoned by the next plain sync) and the last 2 years.
   Every sync with an existing cache **always** `git fetch --depth 1 origin main` and
   `git reset --hard FETCH_HEAD` (cache dir only), including `--full`. The stored cursor (internal row
   `cvelist:git`, validated `^[0-9a-f]{40,64}$`) only selects the *scope*: `git diff --name-only
   --end-of-options <cursor> <new>` limits the import to changed files; no/invalid cursor, `--full` or a
   failing diff (shallow history) walks all checked-out years (records with `dateUpdated` not newer than
   the stored row are skipped unless `opts.full`). Newly requested years are walked in full. The cursor and
   year range advance only after a run without `limit` truncation and without record errors.
   Hardening (security review): every git call runs with `GIT_CONFIG_NOSYSTEM=1`,
   `GIT_CONFIG_GLOBAL=/dev/null`, no `GIT_DIR`/`GIT_CONFIG_*` env, `-c core.fsmonitor= -c core.hooksPath=/dev/null`;
   before reuse the cache's `remote.origin.url` must equal `REPO_URL`, otherwise it is deleted and re-cloned.
4. Sync state: the source never writes the main `source_sync.cvelist` row (the CLI does, from
   `SyncResult.records/total/cursor`); internal rows `cvelist:git` / `cvelist:years` hold the cursor/year range.

### Mapping

`vulnerability`: summary = first English CNA description (REJECTED: first `rejectedReasons`, with
`withdrawn = dateRejected`); CVSS from the CNA (v4.0 > 3.1 > 3.0 > 2.0), else the first ADP with CVSS;
`extra.cvss_source` = `cna` | `adp:<shortName>`; severity = `baseSeverity` or derived; CWEs from CNA
(else ADP); `extra` = `ssvc` (Exploitation/Automatable/Technical Impact + version/timestamp/role),
`adp_kev`, `assigner`, `title`, first 20 reference urls. No aliases are written.

`affected` (CNA, plus ADP `affected`; none for REJECTED), `extra.container` = `cna` | `adp:<shortName>`:

| range_type | Meaning |
|---|---|
| `CVE` | CNA data with usable `events` (OSV-style) or `versions` (exact version) |
| `CPE` | from `cpeApplicability` cpeMatch (`cpe` set; vendor/product from the CPE string) |
| `GIT` | commit-based (`versionType` git/original_commit_for_fix or hash-looking bounds); matcher skips |
| `CVE-UNPARSED` | bounds not understood; raw entry in `extra.raw`; matcher skips |

Version entry conversion (one row per `affected` version entry):
- `version`+`lessThan` -> `[introduced v, fixed lt]`; `lessThanOrEqual` -> `last_affected`. `version`
  `0`/`*`/empty = introduced `0`; bound `*` = open-ended. `version == lessThan` (Chrome) -> introduced `0`.
- plain version without bounds -> `versions=[v]`; `n/a`/`unspecified` without bounds -> skipped.
- invalid bound (`log4j-core*`, `128.*`, URL, text): events from `changes[]` (`unaffected at X` -> fixed,
  `affected at X` -> introduced); otherwise `CVE-UNPARSED`. With valid bounds, `changes[]` only adds
  later `introduced` events.
- free-text `version` ("< 2.5.4", ">= a, <= b", "a - b", "x and older", "prior to x") via
  `parse_version_expression` (plain versions return None).
- status `unaffected` entries are only kept when an affected-less `affected[]` entry has no affected
  versions: one row `status="unaffected"`, `events` NULL, entries in `extra.unaffected_versions`
  (Mozilla pattern). `unknown` entries are ignored; `defaultStatus` goes to `extra.default_status`.
- `packageName` -> `package` (lowercased); `collectionURL` host mapped to ecosystem (npm, PyPI, Maven,
  RubyGems, crates.io, Packagist, NuGet, Go) when known. `cpes[]` of `affected` only in `extra.cpes`.
- `cpeApplicability`: events from versionStartIncluding/EndExcluding/EndIncluding. A non-version bound (e.g. a URL) is
  recorded in `extra.dropped_bounds` and the row becomes `CVE-UNPARSED` (never matched), so an unparseable bound cannot widen
  the range to all versions (`cvelist.py:_import_cpe_applicability`; earlier text of this doc said such rows stayed `CPE`).
5. Import robustness: every record is imported inside a SAVEPOINT; any exception (not only ValueError)
   rolls that record back (the previous version, children included, stays) and counts as an error
   (status `partial`, git cursor not advanced).
6. Mapping fixes: `versionStartExcluding` -> `introduced_exclusive`; an unparsable bound or a CPE `update`
   field (beta/rc/pN, stored in `extra.cpe_update`) -> `CVE-UNPARSED`; wildcard CPE with no bounds ->
   `[{"introduced":"0"}]`; end-only bounds get `introduced: 0`; `changes[]` inside a bounded entry are sorted,
   `unaffected` -> `fixed`, `affected` -> `introduced`, changes at/after the bound are dropped; `packageName` is
   normalized with `purl.normalize_name`; CPE strings are unescaped like nvd.py (`base.cpe_fields`);
   `defaultStatus: affected` without usable versions is kept as a `CVE-UNPARSED` row (`extra.default_status`);
   severity labels go through `base.normalize_severity`.
7. `cvelist.renormalize(conn)` rebuilds all cvelist rows from `raw_record` (no download) so fixes reach an
   existing DB.
