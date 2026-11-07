---
title: OSV.dev (bulk)
type: reference
context: references
status: implemented
tags: [vuln-source, osv, purl, distro, ghsa]
updated: 2026-11-07
sample: real
reachable: partial
code: src/secmonk/sources/osv.py
fixtures: tests/fixtures/sources/osv/
related: [references/vuln-sources/ghsa.md, tech/engine/matching.md]
---

# OSV.dev (bulk data)

## Summary

[OSV](https://osv.dev) aggregates ~45 upstream advisory databases (GHSA, PyPA/PYSEC, Go vulndb, RustSec,
Debian, Ubuntu, Alpine, Red Hat, Rocky, Alma, SUSE, Chainguard, Wolfi, OSS-Fuzz, ...) into one JSON
schema ([OSV schema](https://ossf.github.io/osv-schema/)). For sec-monk it is the primary source for
**package-ecosystem and distro-package matching** (PURL/ecosystem + version ranges) and covers GHSA
(see [ghsa.md](ghsa.md)). Probed 2026-11-07, schema versions seen: 1.4.0 - 1.9.2 (mixed, per upstream).

## Access

Reachability from the dev sandbox: bulk bucket works, `api.osv.dev` returns 403 (so the `/v1/query`
and `/v1/querybatch` APIs are not usable here; they are an option on an unrestricted network).

Bucket: `https://osv-vulnerabilities.storage.googleapis.com/` (public, no auth, `HEAD` and range requests work).

| Path | Content | Verified |
|---|---|---|
| `ecosystems.txt` | one ecosystem name per line (47 lines, one is the literal `[EMPTY]`) | yes (fixture `ecosystems.txt`) |
| `all.zip` (root) | every record, all ecosystems, **2,928,513,659 B (2.9 GB)** | HEAD only |
| `modified_id.csv` (root) | `<RFC3339 modified>,<Ecosystem>/<ID>`, newest first, **157,713,704 B**, all ~entire corpus (not a window) | yes |
| `<Eco>/all.zip` | flat zip, entries `<ID>.json` | yes |
| `<Eco>/<ID>.json` | single record | yes (e.g. `Maven/GHSA-jfh8-c2jp-5v3q.json`) |
| `<Eco>/modified_id.csv` | `<RFC3339 modified>,<ID>` (no ecosystem prefix), newest first | yes |
| `<Eco>:<release>/all.zip` | per-release zip exists for some (`Debian:12`, `Alpine:v3.20`, `Ubuntu:22.04:LTS`, `Ubuntu:Pro:22.04:LTS`) but see Quirks (stale, legacy) | yes |
| `<Eco>:<release>/modified_id.csv` | 404 for release-qualified paths | yes |

`modified_id.csv` sample (root; per-ecosystem files drop the `Eco/` prefix):
```
2026-11-07T08:45:03.213207645Z,PyPI/MAL-2026-18746
2026-11-07T08:45:03.084654453Z,Echo/ECHO-c3a5-5f6a-71f1
```
Timestamps have varying precision (`...Z` seconds, or 9 fractional digits). Sort and compare as parsed
datetimes, not strings. Fixtures: `modified_id.csv` (root, 20 lines), `PyPI.modified_id.csv`.
The file is the full index of every record with its `modified` (not just "recent"): fetching it for
delta means downloading the full CSV each time (PyPI 1.1 MB, npm 8.7 MB, Debian 3.7 MB; root 158 MB), so
fetch per-ecosystem CSVs; then GET only the IDs whose timestamp is newer than the last sync cursor
(`<Eco>/<ID>.json`). Use `If-None-Match`/`ETag` or `Last-Modified` from HEAD to skip an unchanged CSV.

### Ecosystem names (`ecosystems.txt`, 2026-11-07)
AlmaLinux, Alpaquita, Alpine, Android, Azure Linux, BellSoft Hardened Containers, Bitnami, CRAN,
Chainguard, CleanStart, Debian, Echo, GHC, GIT, GSD, GitHub Actions, Go, Hackage, Hex, Julia, Linux,
Mageia, Maven, MinimOS, NuGet, OSS-Fuzz, Packagist, Pub, PyPI, Red Hat, Red Hat Lightwell, Rocky Linux,
Root, RubyGems, SUSE, SwiftURL, TuxCare, UVI, Ubuntu, VSCode, Wolfi, `[EMPTY]` (the literal placeholder; skip), crates.io, npm, opam,
openEuler, openSUSE. **No `Homebrew`** (404). Paths with spaces must be URL-encoded (`Red%20Hat/all.zip`).

`ecosystems.txt` lists only the base names. Release-qualified names appear in `affected[].package.ecosystem`
inside records (see "Release encoding"); the base-name directory holds all releases.

### Sizes (Content-Length, 2026-11-07)

| Ecosystem | all.zip | modified_id.csv |
|---|---|---|
| PyPI | 37.7 MB | 1.15 MB |
| npm | 220 MB | 8.7 MB |
| Maven | 10.5 MB | 0.35 MB |
| Go | 12.8 MB (9,914 records, 43.8 MB unzipped) | 0.45 MB |
| crates.io | 3.8 MB | 0.14 MB |
| RubyGems | 5.2 MB | 0.25 MB |
| NuGet | 2.7 MB | 0.09 MB |
| Packagist | 11.1 MB | 0.36 MB |
| Hex / Pub / CRAN | 1.1 MB / 26 KB / 12 KB | small |
| GitHub Actions | 100 KB | 2.6 KB |
| Debian | 81.1 MB | 3.7 MB |
| Ubuntu | 809 MB | 3.6 MB |
| Alpine | 9.1 MB (10,697 records) | 0.56 MB |
| Red Hat | 27.7 MB (~20k records; 924 distinct ecosystem strings) | 0.9 MB |
| Rocky Linux | 5.5 MB (4,719 records, 28.3 MB unzipped) | 0.21 MB |
| AlmaLinux | 7.0 MB (6,399 records) | 0.28 MB |
| SUSE / openSUSE | 49.2 MB / 22.3 MB | 1.2 / 0.8 MB |
| Wolfi | 309 MB | 17.7 MB |
| Chainguard | 1,169 MB | 68 MB |
| MinimOS | 88 MB | 9.3 MB |
| GIT | 216 MB | 5.5 MB |
| Linux (kernel) | 59 MB | 1.5 MB |
| Release-qualified: `Debian:12` | 43.1 MB (stale, see Quirks) | 404 |
| `Debian:11` | 42.9 MB | 404 |
| `Alpine:v3.20` | 6.7 MB (stale) | 404 |
| `Ubuntu:22.04:LTS` / `24.04:LTS` | 149.9 MB / 142.4 MB | 404 |
| `Ubuntu:Pro:22.04:LTS` | 0.6 MB | 404 |
| `Alpine:v3.21`, `Rocky Linux:9`, `AlmaLinux:9`, `Red Hat:enterprise_linux:9` | 404 | 404 |

## Data format

Single JSON object per file. Fixtures (all real records, `tests/fixtures/sources/osv/`):

| Fixture | Shows |
|---|---|
| `pypi-GHSA-fhq3-2gf3-8f3j.json` | PyPI GHSA, `ECOSYSTEM` range + explicit `versions`, CVSS_V4 |
| `pypi-PYSEC-2021-375.json` | PYSEC with **both** a `GIT` and an `ECOSYSTEM` range in one affected entry |
| `pypi-OSV-2022-1074.json` | OSS-Fuzz style `GIT` range (`repo` + commit hashes), `versions` |
| `npm-GHSA-x4vh-j75g-268g.json` | `SEMVER` range, `database_specific.last_known_affected_version_range`, CVSS_V4 |
| `maven-GHSA-jfh8-c2jp-5v3q.json` | log4j; 10 `affected` entries, Maven `group:artifact`, `versions`, CVSS `E:H` |
| `go-GO-2024-2428.json` | Go vulndb: `SEMVER` with only `introduced:"0"` + `ecosystem_specific.custom_ranges` |
| `debian-DEBIAN-CVE-2024-2199.json` | Debian CVE record: `Debian:12`/`Debian:13`, source pkg, `ecosystem_specific.urgency` |
| `debian-DSA-5562-1.legacy.json` | old-format DSA from the stale `Debian:12/all.zip` (schema 1.6.0) |
| `ubuntu-UBUNTU-CVE-2024-58384.json` | `Ubuntu:Pro:*` releases, `severity` type `Ubuntu` (score `medium`), binaries in `ecosystem_specific` |
| `alpine-ALPINE-CVE-2024-3094.json` | `Alpine:v3.x`, `upstream`, no summary, `arch=source` purl |
| `redhat-RHSA-2026_39976.json` | `Red Hat:enterprise_linux:10.2`, rpm version with epoch `0:3.23.12-10.el10_2.5` |
| `rocky-RLSA-2019_0975.json` | `Rocky Linux:8`, rpm purl with `epoch`/`distro`, `ranges[].database_specific.yum_repository` |
| `git-CVE-2026-70659.json` | `GIT` ecosystem record: **no `package`**, only `ranges[type=GIT]` + `versions` (versions truncated to 8 in the fixture) |
| `sample-all.zip` | 6 of the above (flat `<ID>.json` entries, compact JSON) for the zip importer |

Top-level fields (as observed): `schema_version`, `id`, `modified`, `published`, `withdrawn` (rare; Go 183/9914, Maven 122/7253,
Alpine 67/10697), `aliases`, `related`, `upstream`, `summary` (optional: Alpine/Debian/Ubuntu CVE records lack it), `details`,
`severity[]`, `affected[]`, `references[]`, `credits[]`, `database_specific`.

| Field | Notes |
|---|---|
| `id` | Prefix identifies the source DB: `GHSA-`, `PYSEC-`, `GO-`, `OSV-` (OSS-Fuzz), `MAL-` (malware, huge share of npm/PyPI), `CVE-` (GIT ecosystem), `DEBIAN-CVE-`, `DSA-`, `DLA-`, `UBUNTU-CVE-`, `USN-`, `ALPINE-CVE-`, `RHSA-`/`RHBA-`/`RHEA-`, `RLSA-`, `ALSA-`/`ALBA-`, `CGA-` (Chainguard/Wolfi), `ECHO-`, `RUSTSEC-`, `GSD-`... |
| `modified`, `published` | RFC3339 UTC; `modified` has 0, 6 or 9 fractional digits. `modified` is the delta key. |
| `aliases` | Same-vuln IDs from other DBs (CVE, GHSA, PYSEC). Present for GHSA/Go/PYSEC, **absent for distro records** (they use `upstream`). |
| `upstream` | Distro records: the CVE(s) the distro advisory is about (Alpine, Debian, Ubuntu, Rocky, Red Hat). Treat like an alias for CVE linking, but the vuln id itself is distro-specific. |
| `related` | Weaker link (e.g. Go record lists a `CGA-...` id). Not an alias. |
| `severity[]` | `{type, score}`; types seen: `CVSS_V3` (score is the **vector string**, e.g. `CVSS:3.1/AV:N/...`; v3.0 vectors occur in Rocky), `CVSS_V4` (`CVSS:4.0/...`), `Ubuntu` (score is a word: `medium`, not a vector). No numeric base score is shipped; must be computed from the vector. May be absent (Go 50%, PYSEC, OSS-Fuzz). |
| `affected[]` | See below. One entry **per package per release** (Alpine 100+ entries/record; log4j GHSA: 10). |
| `references[]` | `{type: ADVISORY\|WEB\|FIX\|REPORT\|ARTICLE\|PACKAGE, url}` |
| `database_specific` | Source-specific. GHSA: `cwe_ids[]`, `github_reviewed`, `github_reviewed_at`, `nvd_published_at`, `severity` (`LOW\|MODERATE\|HIGH\|CRITICAL`). Go: `review_status`, `url`. GIT CVE records: `cwe_ids`, `cna_assigner`, `osv_generated_from`. Distros: usually absent at top level. |

`affected[]` entry:

| Field | Notes |
|---|---|
| `package.ecosystem` | See release encoding. May be a different ecosystem than the directory (Maven zip contains records that also affect npm/PyPI/NuGet; Go zip has GHSAs spanning Maven/crates.io...). **Always trust the entry, not the folder.** |
| `package.name` | Maven `group:artifact`; Go module path; npm may be scoped `@scope/name`; Debian/Ubuntu/Alpine: **source package name**; RPM distros: source rpm name. |
| `package.purl` | Present in all bulk records seen from ~2025 onward (GHSA reviewed, Go, distros). Absent from the raw `github/advisory-database` copy and from legacy distro dumps. Treat as optional; rebuild from ecosystem+name when missing. |
| (no `package`) | Allowed: `GIT` ecosystem records and OSS-Fuzz-derived ones have only `ranges` (GIT) + `versions`. 1,504 entries without package in the stale `Alpine:v3.20` zip. |
| `ranges[]` | `type` = `ECOSYSTEM` (distro/ecosystem version order), `SEMVER` (npm, Go, crates, GitHub Actions...), `GIT` (`repo` URL + commit-hash events; compare by commit graph, not by our version classes). |
| `ranges[].events[]` | One key each: `introduced`, `fixed`, `last_affected`, `limit` (event list is ordered; sort/pair by position). Observed in Maven: `introduced`, `fixed`, `last_affected` (1,868 of them). |
| `ranges[].database_specific` | Rocky: `yum_repository` (AppStream/BaseOS). GIT CVE: `extracted_events` provenance. |
| `versions[]` | Explicit affected version strings. Used heavily by PyPI/GHSA/Maven/Debian/Ubuntu; absent for Alpine, Go, Red Hat, Rocky. Not a complement of ranges (it is the enumeration of known-published versions in range); match on either. |
| `ecosystem_specific` | Debian: `urgency`; Ubuntu: `binaries[{binary_name,binary_version}]`; Go: `custom_ranges` (extra ranges the converter could not express as SEMVER) and often `{}`; OSS-Fuzz: `severity`. |
| `database_specific` | `source` (URL of upstream record), npm GHSA: `last_known_affected_version_range` (e.g. `<= 0.301.2`), GIT: `vanir_signatures`. |

Range semantics: `{introduced: "0"}` = from the beginning; `introduced` without a following `fixed`/`last_affected`
= **still vulnerable, no fix** (Go example, Ubuntu `Pro` records for EOL releases). `fixed` is exclusive, `last_affected`
inclusive. Multiple introduced/fixed pairs in one range are separate intervals.

### Release encoding (observed `package.ecosystem` strings)

| Source | Form | Examples |
|---|---|---|
| Debian | `Debian:<major>` | `Debian:11`, `Debian:12`, `Debian:13`, `Debian:14` (trixie=13, forky=14; purl `distro=trixie` codename) |
| Ubuntu | `Ubuntu:<ver>[:LTS]`; Pro/ESM: `Ubuntu:Pro:<ver>:LTS`; also `Ubuntu:Pro:FIPS:*`, `Ubuntu:Pro:FIPS-updates:*`, `Ubuntu:Pro:FIPS-preview:*`, `Ubuntu:Pro:Realtime:*`, `Ubuntu:Nvidia-BlueField:*` | `Ubuntu:22.04:LTS`, `Ubuntu:25.10`, `Ubuntu:26.04:LTS`, `Ubuntu:Pro:16.04:LTS` |
| Alpine | `Alpine:v<major.minor>` (v3.2 ... v3.24 present; `edge` not seen) | `Alpine:v3.20` |
| Red Hat | `Red Hat:<product>:<version>[::<repo>]` : 924 distinct strings; RHEL is `Red Hat:enterprise_linux:<N>[.<M>]::{baseos,appstream,crb,nfv,realtime,highavailability,...}`, or without `::repo` for 10.x; plus `rhel_eus`, `rhel_els`, `rhel_e4s`, `rhel_aus`, `rhel_tus`, `openshift`, `ansible_automation_platform`, ... | `Red Hat:enterprise_linux:9::appstream`, `Red Hat:enterprise_linux:10.2`, `Red Hat:rhel_eus:9.6::baseos` |
| Rocky | `Rocky Linux:<major>` | `Rocky Linux:8`, `:9`, `:10` |
| AlmaLinux | `AlmaLinux:<major>` | `AlmaLinux:8`, `:9`, `:10` |
| Wolfi / Chainguard | unversioned rolling | `Wolfi`, `Chainguard` |

Distro packages: **names are source packages**. Debian `pkg:deb/debian/xz-utils?arch=source&distro=trixie`; Ubuntu
`pkg:deb/ubuntu/python-tornado?arch=source&distro=esm-apps/bionic` (note `%2F`-encoded slash in the raw JSON);
Alpine `pkg:apk/alpine/xz?arch=source`; Ubuntu `ecosystem_specific.binaries[]` lists the binary packages built
from the source package. An installed `libssl3` (binary) must be mapped to its source package (`openssl`) before
lookup (dpkg `Source:` field; apk `o:` origin; rpm `SOURCERPM`). Debian version strings: `5.6.1+really5.4.5-1`;
Alpine: `5.6.1-r2`; RPM: `epoch:version-release` with explicit epoch (`0:3.23.12-10.el10_2.5`, `1:0.1.15-2.git...`).

## Mapping (design sketch)

> **Design sketch, written before the importer existed.** Table and column names below (`affected_range`, `ecosystem_base`, `package_name`) are not the implemented schema. The tables that exist are in [tech/data-model.md](../../tech/data-model.md); what the importer really writes is under *Implementation notes*.


**vulnerability** (one row per OSV `id`)

| Column | Source |
|---|---|
| `id` | `id` (primary; keep distro/GHSA ids as-is) |
| `source` | `osv` (+ ecosystem dir / id prefix) |
| `summary` | `summary` (NULL allowed) |
| `details` | `details` |
| `published`, `modified` | `published`, `modified` (parse as UTC; store ISO) |
| `withdrawn` | `withdrawn` (skip matching when set) |
| `severity_label` | `database_specific.severity` (GHSA) or `severity[type=Ubuntu].score` |
| `cvss_vector`, `cvss_type` | best of `severity[]` with type `CVSS_V4` > `CVSS_V3`; store all vectors (JSON column) |
| `cwe` | `database_specific.cwe_ids[]` (GHSA / GIT CVE) |
| `raw` | optional compressed original JSON |

**alias** (`vuln_id`, `alias`, `kind`): rows from `aliases[]` (kind `alias`), `upstream[]` (kind `upstream`),
`related[]` (kind `related`). Add the id itself for symmetric lookups. CVE-id lookup is the join key to NVD/KEV/EPSS.

**affected_range** (one row per `affected[] x ranges[]` interval, plus a synthetic row for explicit versions)

| Column | Source |
|---|---|
| `vuln_id` | record id |
| `ecosystem` | `package.ecosystem` verbatim (`Debian:12`) - also split into `ecosystem_base` (`Debian`) and `ecosystem_release` (`12`) |
| `package_name` | `package.name` (normalise per ecosystem at match time: PyPI PEP 503, etc.) |
| `purl` | `package.purl` (nullable) |
| `range_type` | `ECOSYSTEM`/`SEMVER`/`GIT` (GIT rows stored but not used for version matching) |
| `introduced`, `fixed`, `last_affected`, `limit` | consecutive event pairs; `introduced='0'` kept as `'0'`; NULL fixed/last_affected = open-ended |
| `repo` | `ranges[].repo` for GIT |
| `versions` | `affected[].versions` JSON array (a row-level column, or separate `affected_version` table) |
| `source_pkg` / `binaries` | Ubuntu `ecosystem_specific.binaries` (optional) |

Pairing algorithm: walk `events` in order; `introduced` opens an interval, the next `fixed`/`last_affected` closes it;
an interval left open stays unbounded. `limit` bounds GIT ranges only. Go: also ingest `ecosystem_specific.custom_ranges`.

## Matching notes

OSV ecosystem -> `univers` version class (verified with `univers.versions` in the probe project; class list: AllVersion, AlpineLinuxVersion,
ArchLinuxVersion, ComposerVersion, ConanVersion, DebianVersion, GentooVersion, GolangVersion, MavenVersion, NginxVersion, NugetVersion, OpensslVersion,
PypiVersion, RpmVersion, RubygemsVersion, SemverVersion, ...):

| OSV ecosystem | univers class | Note |
|---|---|---|
| PyPI | `PypiVersion` | |
| npm | `SemverVersion` | ranges are `SEMVER` |
| Maven | `MavenVersion` | name = `group:artifact` |
| Go | `GolangVersion` (or `SemverVersion`) | strip leading `v`; pseudo-versions; stdlib is package `stdlib`, toolchain `toolchain` |
| crates.io | `SemverVersion` | |
| RubyGems | `RubygemsVersion` | |
| NuGet | `NugetVersion` | |
| Packagist | `ComposerVersion` | |
| Debian, Ubuntu | `DebianVersion` | epoch, `~`, `+esm1` suffixes |
| Alpine | `AlpineLinuxVersion` | `-rN` |
| Red Hat, Rocky Linux, AlmaLinux (+SUSE, openSUSE, Azure Linux, Mageia, openEuler) | `RpmVersion` | include `epoch:` prefix; OSV always has epoch for Red Hat |
| Wolfi / Chainguard | `AlpineLinuxVersion` (apk) | |
| GIT | none | commit-graph; use `versions[]` list only |
| Hex, Pub, CRAN, Hackage, Julia, opam | `SemverVersion` fallback / `GenericVersion` | low priority |

PURL type <-> OSV ecosystem:

| PURL | OSV ecosystem | Name mapping |
|---|---|---|
| `pkg:pypi/<n>` | `PyPI` | normalise name (lowercase, `[-_.]+` -> `-`) |
| `pkg:npm/<n>`, `pkg:npm/%40scope/<n>` | `npm` | `@scope/name` |
| `pkg:maven/<g>/<a>` | `Maven` | `g:a` |
| `pkg:golang/<module>` | `Go` | module path as-is |
| `pkg:cargo/<n>` | `crates.io` | |
| `pkg:gem/<n>` | `RubyGems` | |
| `pkg:nuget/<n>` | `NuGet` | case-insensitive |
| `pkg:composer/<vendor>/<n>` | `Packagist` | `vendor/name` |
| `pkg:githubactions/<o>/<r>` | `GitHub Actions` | |
| `pkg:deb/debian/<src>?distro=debian-12` | `Debian:12` | source pkg; OSV purls use codename `distro=trixie` while scanners emit `debian-12`: map via a table |
| `pkg:deb/ubuntu/<src>?distro=ubuntu-22.04` | `Ubuntu:22.04:LTS` | derive `:LTS` from release (even-year .04 releases) |
| `pkg:apk/alpine/<pkg>?distro=alpine-3.20` | `Alpine:v3.20` | `distro=3.20.x` -> use `v3.20` |
| `pkg:rpm/redhat/<n>?distro=rhel-9.4` | `Red Hat:enterprise_linux:9[::repo]` | prefix match on `Red Hat:enterprise_linux:9`; also `:9.4` EUS strings |
| `pkg:rpm/rocky-linux/<n>`, `pkg:rpm/almalinux/<n>` | `Rocky Linux:<N>`, `AlmaLinux:<N>` | `distro=rocky-linux-8` / `almalinux-9` |

Distro ranges are ECOSYSTEM ranges in the *distro's* version space; never compare a Debian `fixed` with an
upstream version. Prefer distro records for OS packages (backport aware), upstream (GHSA/PYSEC) for language packages.
A matching query: `ecosystem = ?` (exact, or `LIKE 'Red Hat:enterprise_linux:9%'` / `Ubuntu%:22.04:LTS`) AND `package_name = ?`, then
version-compare, plus `versions[]` membership.

## Quirks & pitfalls

- **Stale per-release zips.** `Debian:12/all.zip` (`modified` newest 2024-10-04) and `Alpine:v3.20/all.zip` are frozen legacy dumps (entries
  `CVE-*.json`/`DSA-*.json`, schema 1.6.0, mixed releases inside). Do not use them; use `Debian/all.zip`, `Alpine/all.zip`
  (ids `DEBIAN-CVE-*`, `ALPINE-CVE-*`).
- Release-qualified paths have no `modified_id.csv` (404). Delta only per base ecosystem.
- Bulk is huge for Ubuntu (809 MB), Chainguard (1.2 GB), Wolfi (309 MB), GIT (216 MB). Skip unless needed.
- Ecosystem directory is not a filter on `affected[].package.ecosystem`: records can be listed in several folders.
- `[EMPTY]` in `ecosystems.txt` is not a valid directory.
- `withdrawn` records remain in the bulk; delete/skip them.
- Distro records: no `aliases`, use `upstream`. Some lack `summary`. A single Alpine record can have 100+ `affected` entries.
- `modified` timestamps differ in precision; do not compare as strings.
- `severity` has no numeric score and may be absent; `Ubuntu` type is a priority word.
- Red Hat ecosystem strings carry a repo suffix `::baseos`; versions need epoch.
- `affected[].versions` may be large (GIT CVE records have hundreds of commit-ish tags).
- Schema versions vary 1.4.0 - 1.9.2 in the same dump; parse defensively (unknown keys, missing `ranges`, missing `package`).
- Untrusted data: parse only, never eval; reject oversized entries when unzipping (zip bomb check by `file_size`).

## Status / TODO

- Fixtures + zip sample done (`tests/fixtures/sources/osv/`).
- Importer (zip + single JSON + delta) implemented in `sources/osv.py` (see Implementation notes).
- `api.osv.dev` not reachable here; `/v1/querybatch` could be an online fallback elsewhere.

### Recommended sync strategy (prototype)

1. Default ecosystems: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist (~303 MB zips), plus distro: Debian, Alpine, Red Hat, Rocky Linux, AlmaLinux
   (~130 MB). Total ~434 MB download, roughly 1.5 GB of JSON unzipped (zip ratios seen: 3.4x Go, 5x Rocky; estimate), ~0.6 - 1 GB SQLite after
   normalising (estimate; store `raw` compressed or not at all). Ubuntu (809 MB) opt-in (`--ecosystem Ubuntu`), skip Chainguard/Wolfi/GIT unless asked.
   Derive the list from the collected inventory (only sync ecosystems that appear in the scanned inventory) to keep it small; Docker image with Debian 12 ->
   Debian only.
2. First sync: download `<Eco>/all.zip` (resumable, `Range`), stream entries from the zip without extracting, upsert per record, store
   `max(modified)` as cursor per ecosystem.
3. Delta: GET `<Eco>/modified_id.csv` (conditional with ETag), read lines until `modified <= cursor` (file is newest first), GET
   `<Eco>/<ID>.json` for each, delete rows of `withdrawn`, replace the `affected` rows for that id wholesale. Fall back to full zip if > ~5k changes or cursor older than 30 days.
4. Run daily; the CSV is regenerated roughly every few minutes upstream.

## Implementation notes

Code: `src/secmonk/sources/osv.py` (`OsvSource`, `import_record`, `ids_modified_since`, `cvss3_score`); tests `tests/sources/test_osv.py`.

- **Ecosystem normalization** (`engine/purl.py`): `Ubuntu:Pro:18.04:LTS`/`Ubuntu:22.04:LTS` -> `Ubuntu:<ver>`; `Red Hat:enterprise_linux:9::appstream`/`:10.2`/`Red Hat:rhel_*:9.6::baseos` -> `Red Hat:<major>`, other Red Hat products (`Red Hat:openshift:4.14::el9`) stay verbatim; Ubuntu FIPS/Pro/realtime variants collapse to `Ubuntu:<rel>` with the variant kept in `extra.ecosystem_variant`; Rocky/Alma -> `<base>:<major>`; Debian/Alpine/others unchanged. Package names via `normalize_name` (PyPI PEP 503, Go/Maven as-is, else lowercase). The original string is kept in `extra.raw_ecosystem`. Purl is stored without qualifiers.
- **range_type**: `ECOSYSTEM`/`SEMVER` ranges -> one `affected` row each (events verbatim); Go `ecosystem_specific.custom_ranges` -> one row each (own type/events) and the open-ended `introduced: 0` placeholder range is dropped; `GIT` -> stored, never matched; `versions[]` -> a `VERSIONS` row only when the entry has no ECOSYSTEM/SEMVER range. Entries without `package` are skipped (GIT-only records yield no rows). Ubuntu binaries land in `extra.binaries`. `withdrawn` records keep their vulnerability row but get no affected rows. `aliases` become `alias` rows (`kind='alias'`); `upstream` ids are stored with `kind='upstream'` (NOT aliases: the matcher must not merge a downstream advisory with its upstream CVEs); `related` is ignored. Existing DBs get the `kind` column with default `alias` on open: re-sync OSV (or Ubuntu/Debian) to classify old `upstream` rows.
- **Severity/CVSS**: v3.x score computed from the vector (CVSS 3.1 formula); a v3 vector wins (the v4 vector goes to `extra.cvss_v4_vector`); a v4-only record stores the v4 vector, version `4.0` and, since there is no CVSS 4.0 calculator, a conservative score derived from the label (LOW 3.0, MEDIUM 5.5, HIGH 8.0, CRITICAL 9.5; `extra.score_derived = true`); label from `database_specific.severity`, the Ubuntu priority word, or derived from the score, normalized (MODERATE->MEDIUM, NEGLIGIBLE->LOW, UNTRIAGED->NULL).
- **Sync**: base ecosystem names only (release-qualified names rejected; those zips are stale). Per-ecosystem cursor in `source_sync` key `osv:<Eco>` = max record `modified` (original string). No cursor or `--full`: stream `<Eco>/all.zip` to a private temp file (`O_EXCL|O_NOFOLLOW`, 0600) in `paths.cache_subdir("osv")`, then `os.replace` it to `<Eco>.zip` (download capped at 4 GiB, env `SECMONK_OSV_MAX_ZIP_MB`; zip member reads capped), import every member under 50 MB. Otherwise fetch `<Eco>/modified_id.csv`, select ids with parsed timestamp > cursor (fractional digits vary), fetch each `<Eco>/<ID>.json`; more than 5000 changed ids falls back to the full zip. Commits every 2000 records; a malformed record is rolled back (savepoint) and logged. Raw JSON storage is **off by default** (it dominates DB size); enable with env `SECMONK_OSV_STORE_RAW=1`. The delta path is only taken when the stored `osv:<Eco>` status is `ok`; a `--limit`-truncated full sync stores status `partial` and no cursor, so the next run is a full one. Delta: a failing id (HTTP error, bad JSON) is skipped and counted (overall status `partial`) and the cursor advances only to the last success before the first failure. Overall status is `error` only when every ecosystem failed. The source never writes the main `osv` row (the CLI does, from `SyncResult.records/total/cursor`).
- **Measured (2026-11-07, raw stored)**: Alpine 10,697 records, 108,119 affected rows, 12.3 s, DB 90.7 MB; PyPI 26,812 records, 33,317 affected rows, 35,908 aliases, 11.3 s, DB 165.8 MB. A repeat Alpine sync took the delta path (0 changes).
