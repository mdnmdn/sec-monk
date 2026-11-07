---
title: Probe log (external endpoints and real-data runs)
type: reference
context: references
status: reference
tags: [probes, network, validation]
updated: 2026-11-07
sample: real
reachable: partial
related: [references/vuln-sources/README.md, references/homebrew.md, references/windows-inventory.md, references/package-formats/README.md, tech/collectors/docker-image.md, tech/collectors/ssh.md, tech/engine/matching.md, features/vuln-sync.md]
---

# Probe log

Every external endpoint probed while building sec-monk, plus the real-data validation runs. All probes were made on **2026-11-07** from the
dev sandbox, whose outbound HTTPS goes through an egress proxy with an allow-list. Meaning of results:

| Result | Meaning |
|---|---|
| `200`/`206`/`OK` | reachable |
| `401` | reachable; authentication required (anonymous token flow expected) |
| `403` | blocked by the sandbox proxy (egress policy), not necessarily by the service |
| `000` | no connection (DNS / proxy CONNECT refused); treated as blocked |
| `404` | reachable, resource does not exist (a finding, not a block) |

Columns: **Development probe** = what the docs record from the original probing. **Re-run** = HTTP status from `scripts/probe_sources.sh`
run at the end of the documentation pass (read-only HEAD / 1-byte range GET; `-` = not part of the script). A difference between the two
is noted; the sandbox allow-list is not static.

## 1. Vulnerability data

| Endpoint | Development probe | Re-run | What was learned | Doc / fixture |
|---|---|---|---|---|
| `raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<yyyy>/<n>xxx/CVE-*.json` | OK, about 0.15 s, 35 KB worst case (Log4Shell), typical 3-8 KB | 200 | Per-id raw fetch is a usable fallback; path has no zero padding, 6-digit ids exist | [cvelist-v5.md](vuln-sources/cvelist-v5.md); `tests/fixtures/sources/cvelist/`, `cvelist/microsoft/` (10 real records) |
| `.../cves/delta.json` | OK, about 1 KB | 200 | Latest delta only | cvelist-v5.md |
| `.../cves/deltaLog.json` | OK, 37.9 MB, 2871 entries (2026-10-08 to 2026-11-07), about 126k changes | 200 (HEAD) | Gap recovery only | cvelist-v5.md |
| `git clone --depth 1 --filter=blob:none --sparse` CVEProject/cvelistV5 | OK: 4.3 s, 53 MB `.git`, trees for 420,776 records | 200 (`info/refs`) | Sparse year-scoped clone is the primary sync path; `sparse-checkout set cves/2025`: 26 s, +40 MB, 45,479 files / 424 MB | cvelist-v5.md; `sources/cvelist.py` |
| GitHub Releases / `all_CVEs_at_midnight.zip`, `codeload`, `api.github.com` | 403 | 403 (releases, api) | Upstream-recommended bulk zip untestable here | cvelist-v5.md (TODO) |
| `cveawg.mitre.org` (CVE Services API) | 403 | 000 | Blocked | cvelist-v5.md (TODO) |
| `osv-vulnerabilities.storage.googleapis.com/ecosystems.txt` | OK, 47 lines (one `[EMPTY]`), no `Homebrew` | 200 | Ecosystem list for `sync osv -e` | [osv.md](vuln-sources/osv.md); fixture `ecosystems.txt` |
| `.../<Eco>/all.zip` (HEAD, range) | OK; sizes PyPI 37.7 MB, npm 220 MB, Debian 81.1 MB, Ubuntu 809 MB, Alpine 9.1 MB, root `all.zip` 2.9 GB | 200 (PyPI, Debian, Alpine) | Per-ecosystem zips are the bulk path; release-qualified zips (`Debian:12`) are stale legacy dumps; others 404 | osv.md (sizes table); `sample-all.zip` |
| `.../<Eco>/modified_id.csv` | OK (PyPI 1.15 MB, npm 8.7 MB, root 158 MB); release-qualified paths 404 | 200 (PyPI) | Delta key; newest first; mixed timestamp precision | osv.md; fixtures `modified_id.csv`, `PyPI.modified_id.csv` |
| `.../Maven/GHSA-jfh8-c2jp-5v3q.json` | OK | 200 | Single-record fetch | osv fixtures (`maven-GHSA-jfh8-c2jp-5v3q.json`, 13 real records) |
| `api.osv.dev` (`/v1/query`, `/v1/querybatch`) | 403 (refused by the sandbox classifier, not retried) | 000 | Only bulk is usable here; scans never call it anyway | osv.md, [distros.md](vuln-sources/distros.md) |
| `github/advisory-database` git (sparse) and `raw` files | OK: 37,571 reviewed + 363,332 unreviewed JSON files; raw files 200, directories 404 | 200 (raw, `info/refs`) | GHSA covered via OSV | [ghsa.md](vuln-sources/ghsa.md); `tests/fixtures/sources/ghsa/` |
| `www.cisa.gov/.../known_exploited_vulnerabilities.json` | 403 | 000 | Official URL tried first, mirror fallback implemented | [kev.md](vuln-sources/kev.md) |
| `raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` | OK, real (1769 entries, 361 `Known` ransomware, 97 `forensicTriage` Yes) | 200 | Mirror lags cisa.gov by minutes; `forensicTriage` is new in the 2026 schema | kev.md; `tests/fixtures/sources/kev/` (trimmed to 9) |
| `api.first.org/data/v1/epss`, `epss.empiricalsecurity.com/epss_scores-current.csv.gz` | blocked (failed) | 000 | Fixture is **synthetic**; format from published docs | [epss.md](vuln-sources/epss.md); `tests/fixtures/sources/epss/` |
| `raw.githubusercontent.com/jgamblin/EPSS`, `/EPSS-Data` | 404 | - | No GitHub mirror of EPSS found | epss.md |
| `services.nvd.nist.gov/rest/json/cves/2.0` (also `nvd.nist.gov`) | blocked | 000 | API 2.0 fixture is **synthetic** | [nvd.md](vuln-sources/nvd.md); `tests/fixtures/sources/nvd/` |
| `raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/CVE-2026/CVE-2026-174xx/CVE-2026-17406.json` | OK; the 2021 Log4Shell path 404; GitHub API listing blocked | 200 | Mirror record is flattened (not API 2.0), `vulnStatus: Awaiting Analysis` | nvd.md |
| `euvdservices.enisa.europa.eu/api/*`, `euvd.enisa.europa.eu` | blocked (curl proxy; DNS failed for the UI) | 000 | Endpoints and field names unverified; fixture **synthetic** | [euvd.md](vuln-sources/euvd.md) |
| `api.msrc.microsoft.com/cvrf/v3.0/updates`, `/cvrf/{ID}` | blocked | 000 | CVRF shape from knowledge; the CNA records in CVE List carry the same fixed builds | [msrc.md](vuln-sources/msrc.md); `tests/fixtures/sources/msrc/*.synthetic.json` |
| `security-tracker.debian.org/tracker/data/json`, `salsa.debian.org/.../security-tracker.git`, `www.debian.org` | 403 | 000 | Formats from documentation; fixtures **synthetic**; open-network validation steps recorded | [debian-tracker.md](vuln-sources/debian-tracker.md); `tests/fixtures/sources/debian-tracker/` |
| `ubuntu.com/security/cves.json`, `/cves/CVE-*.json`, `/notices.json` | 200 (one 503 on `cves.json?package=openssh`) | 206 (notices); `cves.json` 000 on the last run | Reachable but intermittent: retry before calling it an outage; sample saved, not ingested | distros.md; `tests/fixtures/sources/distros/` |
| `secdb.alpinelinux.org/v3.20/main.json` | 000 | 000 | Alpine covered via OSV; snippet synthetic | distros.md |
| `access.redhat.com/hydra/rest/securitydata/...`, `security.access.redhat.com/data/csaf/v2/vex/...` | 000 | 000 | Red Hat covered via OSV; CSAF snippet synthetic | distros.md |

## 2. Registries and package indexes

| Endpoint | Development probe | Re-run | What was learned | Doc / fixture |
|---|---|---|---|---|
| `registry-1.docker.io/v2/` + `auth.docker.io/token` | 401 with `WWW-Authenticate`, anonymous token works; then **429** (100 pulls / 6 h per IP) after 3 images; `HEAD` is not counted | 401; token 200 | Parse the challenge header, retry with backoff, suggest a mirror | [docker-image.md](../tech/collectors/docker-image.md); `tests/fixtures/collectors/docker/registry/alpine-3.20.*.json` |
| `mirror.gcr.io` | anonymous, no token; blobs redirect to Artifact Registry; used for `rockylinux:9-minimal`, `debian:12-slim`, `python:3.12-slim` | 401 on `/v2/` (token flow) | Good fallback for official images | docker-image.md; `rocky-9/rootfs` fixture |
| `ghcr.io` (`/v2/`, `/token`) | 401 then anonymous token OK; blob pull for generic images not exercised | 401; token 200 | Anonymous pull of public repos works | docker-image.md |
| `ghcr.io/v2/homebrew/core/<name>/tags/list`, manifests (`Authorization: Bearer QQ==`) | OK | - | Manifest annotations carry the full receipt (`sh.brew.tab`) and SBOM supplement | [homebrew.md](homebrew.md); `tests/fixtures/collectors/homebrew/` |
| ghcr blob `GET` (307 to `pkg-containers.githubusercontent.com`) | 403 CONNECT (blocked, not worked around) | 000 (host) | Receipts/SBOMs for fixtures are reconstructed from manifest annotations | homebrew.md |
| `public.ecr.aws` | token and manifests OK; blob redirect to `*.cloudfront.net` 403 | token 200 | Environment-specific | docker-image.md |
| `quay.io`, `registry.access.redhat.com`, `docker.io` | blocked (CONNECT 403) | 000 | Not usable here | docker-image.md |
| `pypi.org/pypi/<n>/<v>/json`, `files.pythonhosted.org` wheels | OK | 200 (pypi); host root 404 | Real `dist-info` METADATA for the Homebrew httpie fixture; `uv pip install requests==2.25.0` for the venv fixture | homebrew.md, [python.md](package-formats/python.md); `tests/fixtures/lang/python/`, `collectors/homebrew/` |
| npm registry (npm 10.9.9, yarn 1.22/4, pnpm 8+9, bun 1.2 resolved against it) | worked: lockfile fixtures generated registry-resolved | 200 | v1/v2/v3 lockfiles written on request | [javascript.md](package-formats/javascript.md); `tests/fixtures/lang/javascript/` |
| crates.io (`cargo generate-lockfile` for smallvec 1.6.0, time 0.1.43) | worked | 200 (sparse index) | Cargo.lock v4 fixture | [rust.md](package-formats/rust.md); `tests/fixtures/lang/rust/` |
| Maven Central (jars `commons-lang3`, log4j/jackson for the shaded jars) | worked (real jars, classes stripped) | 200 | Fat/shaded jar fixtures | [java.md](package-formats/java.md); `tests/fixtures/lang/java/` |
| Go module build (golang.org/x/text v0.3.7 fixture module) | worked | 200 (proxy.golang.org) | Real buildinfo in Go binaries | [go.md](package-formats/go.md); `tests/fixtures/lang/go/` |
| Public GitHub repos (.NET `*.deps.json`, gradle lockfile, jmeter verification metadata) | worked | - | Real files saved as fixtures | [dotnet.md](package-formats/dotnet.md), java.md |
| `repo.packagist.org`, `api.nuget.org` | not probed in development (formats read from OSV zips `Packagist/all.zip` 11 MB, `NuGet/all.zip`) | 200 | Added to the script for completeness | php.md, dotnet.md |

## 3. Vendor sites and source repositories

| Endpoint | Development probe | Re-run | What was learned | Doc / fixture |
|---|---|---|---|---|
| `formulae.brew.sh/api/*`, `repology.org`, github.com HTML/API | blocked | 000 / 000 / 403 | Formula API JSON shape taken from `Homebrew/brew` source, not observed live | homebrew.md |
| `raw.githubusercontent.com/Homebrew/homebrew-core/<sha-or-main>/Formula/...` | OK, any commit SHA works | 200 | Formula text at the bottle's commit | homebrew.md; fixture `.brew/*.rb` |
| sparse clones of `Homebrew/homebrew-core` (8,707 formulae, 281 aliases; 1.2 s + 4.0 s), `homebrew-cask` (7,818 casks), `Homebrew/brew`, `Homebrew/advisory-database` | OK | 200 (advisory-database raw) | Identity research corpus; `repology.json` 763 KB, 5,524 formulae | homebrew.md; `src/secmonk/data/brew_cpe_seed.csv` |
| `raw.githubusercontent.com/package-url/purl-spec/main/purl-types-index.json` | OK (checked: `brew` purl type exists) | - | purl convention for formulae | [macos.md](../tech/collectors/macos.md) |
| `nvd.nist.gov`, `euvd.enisa.europa.eu`, `www.debian.org` | blocked | 000 | See section 1 | nvd.md, euvd.md, debian-tracker.md |
| Microsoft CNA records through CVE List raw (10 records: CVE-2024-38063, 2025-21418, 2025-30400, 2024-38021, 2025-24057, 2024-43472, 2024-38229, 2025-21176, 2025-26682, 2023-24881) | OK | 200 (raw) | Per-build fixed versions for Windows, Edge, .NET, VS; Office bounds can be URLs | [windows-inventory.md](windows-inventory.md); `tests/fixtures/sources/cvelist/microsoft/` |

Not probed at all: `learn.microsoft.com` and other vendor documentation sites (Windows registry/Appx facts are from knowledge, marked unverified in
[windows-inventory.md](windows-inventory.md)); no real SSH, Windows, macOS or Docker-engine endpoint was available.

## 4. Real-data validation runs

Numbers below are copied from the referenced docs (measured 2026-11-07 unless stated). This section is the single home for measurements; tech and feature docs link here instead of repeating them.
Runs that report finding counts or component counts (image scans, `scan fs`, Debian urgency) were taken **before** the review-fix commit 97e72b9 (distinct-CVE canonicalization, withdrawn handling, Go buildinfo via section tables, jar/NuGet fixes) and have not been re-measured: expect small differences. Sync timings and fixture-based rows are unaffected.

| Run | Result | Where documented |
|---|---|---|
| OSV sync `Alpine` (raw stored) | 10,697 records, 108,119 affected rows, 12.3 s, DB 90.7 MB; a repeat sync took the delta path with 0 changes | [osv.md](vuln-sources/osv.md) |
| OSV sync `PyPI` (raw stored) | 26,812 records, 33,317 affected rows, 35,908 aliases, 11.3 s, DB 165.8 MB | osv.md |
| CVE List sparse clone | base clone 4.3 s / 53 MB `.git`; `cves/2025` 26 s, 45,479 files / 424 MB; format analysed on all 45,479 records | cvelist-v5.md |
| Real image `alpine:3.20` (registry) | 15 components: OS + 14 apk, ecosystem `Alpine:v3.20` | docker-image.md, [rootfs.md](../tech/collectors/rootfs.md) |
| Real image `mirror.gcr.io/library/debian:12-slim` | 89 components: OS + 88 deb (`Debian:12`) | docker-image.md |
| Real image `mirror.gcr.io/library/python:3.12-slim` | OS + 87 deb + `pip 25.0.1` (PyPI, streamed layers) | docker-image.md, [dependencies.md](../tech/collectors/dependencies.md) |
| Real image `registry:2` | Go binary `/bin/registry`, stdlib 1.20.8, 85 exact `osv-package` findings | dependencies.md |
| Fixture-dir dependency scan `scan fs tests/fixtures/lang` (real OSV data) | 453 components in 7 ecosystems, findings in all of them, e.g. log4j-core 2.14.1 to CVE-2021-44228 **P1 (KEV)**, golang.org/x/text 0.3.7 to CVE-2022-32149, smallvec 1.6.0 to CVE-2021-25900 | dependencies.md |
| Debian urgency measurement, `python:3.12-slim` (Debian 13), OSV urgency only | 193 findings, 46 labelled *unimportant* (now P4, hidden by `--hide-minor`), e.g. glibc CVE-2019-1010022 (CVSS 9.8, previously P3); 53.5k of 61k Debian 13 OSV ranges are *not yet assigned* | [matching.md](../tech/engine/matching.md) |
| Windows CVE end-to-end (real Microsoft CNA records, synthetic inventories; `tests/collectors/test_windows.py`) | Win11 23H2 at `10.0.22631.3880` gets CVE-2024-38063 with fixed `10.0.22631.4037`, none at 4037; Server 2022 `10.0.20348.2655` fixed `10.0.20348.2700`; Edge 126.0.2592.87 / CVE-2024-43472, .NET 8.0.8 / CVE-2024-38229, VS 17.12.2 / CVE-2025-26682 | [inventory-windows.md](../features/inventory-windows.md), windows-inventory.md |
| Homebrew identity (real record, fixture prefix) | jq CVE-2025-48060: `cve-product` finding at confidence 0.85 for jq 1.7.1, none for 1.8.2, none when patched | [inventory-homebrew.md](../features/inventory-homebrew.md) |
| Homebrew formula-to-CVE experiment (8,707 formulae x 43,686 CVE records, 2025) | name == product hits 427 formulae (4.9%); 298 also vendor-consistent (about 97% correct on spot check); truth set recall 62/74 (84%); seed `brew_cpe_seed.csv` 440 rows / 407 formulae | homebrew.md |

Still **not validated on real data**: EPSS, NVD, EUVD, MSRC and Debian tracker imports (hosts blocked); the Windows PowerShell script on a real
host; SSH against a real sshd, macOS or Windows host; Docker engine against a real socket; a scan of a real Mac.

## 5. How to re-probe

`scripts/probe_sources.sh` (executable, read-only) probes every endpoint above with `curl -I` (or a 1-byte `Range` GET where HEAD is refused) and prints
one line per URL: `<HTTP code> <group> <label> <url>`. Code `000` is a connection failure; `403` from a proxy means egress policy.

```bash
scripts/probe_sources.sh              # all groups
scripts/probe_sources.sh vuln         # or: registry | vendor
TIMEOUT=30 scripts/probe_sources.sh   # per-request timeout in seconds (default 15)
scripts/probe_sources.sh | awk '$1 !~ /^(200|206|401)$/'   # only what is not reachable
```

Core of the script (bash):

```bash
curl -sS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" -I  "$url"      # HEAD
curl -sS -o /dev/null -w '%{http_code}' -m "$TIMEOUT" -r 0-0 "$url"   # 1-byte range GET
```

After a source becomes reachable from an unrestricted network, run `secmonk sync <source>` and follow the "Validate from an open network" steps in the
source's doc, then update the [sources index](vuln-sources/README.md) (sample real, validated yes) and replace the synthetic fixture.
