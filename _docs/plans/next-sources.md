---
title: Plan - next vulnerability sources to integrate
summary: Prioritized backlog of vulnerability sources to add (Ubuntu, Red Hat, Alpine, SUSE, exploit feeds, VEX), with reachability probes, per-item checklists and distro triage vocabulary.
read_when: you add a new vulnerability source or choose which source to integrate next
type: plan
context: plans
status: open
platform: any
tags: [plan, vuln-source, distro, backlog, triage, exploit]
updated: 2026-11-11
verified: 2026-11-07
related: [references/vuln-sources/distros.md, references/vuln-sources/README.md, references/homebrew.md, tech/engine/matching.md, tech/data-model.md]
---

# Plan: source-integration backlog (prioritized)

Platform **any**: each item says where it can be **developed** (D) and where it must be **validated** (V). "sandbox" = the Linux cloud sandbox with the restrictive proxy
(allowed: `raw.githubusercontent.com`, `git` over https to GitHub/GitLab, `ubuntu.com` partially, the OSV bucket, `versionhistory.googleapis.com`;
everything else blocked). "open" = any unrestricted network. Development in the sandbox is possible with fixtures; **validation of the assumptions** is only on a real network
unless the source is reachable (then fetch a real fixture right away - do not write synthetic ones again).

Targets reuse the schema in [data-model.md](../tech/data-model.md): `vulnerability`, `affected`, `alias`, `distro_triage` (`ecosystem, package, cve_id, status, urgency, fixed_version, nodsa, note, advisory, source`), `kev`, `epss`.
Existing importers: `cvelist`, `osv`, `kev`, `epss`, `nvd`, `euvd`, `msrc`, `debian-tracker` (`src/secmonk/sources/`). Add a new module per source, a fixture dir under `tests/fixtures/sources/<name>/`, a reference doc under `references/vuln-sources/<name>.md`
and an entry in the table in [references/vuln-sources/README.md](../references/vuln-sources/README.md).

## Reachability probes (2026-11-07, from the dev sandbox)

Command: `curl -s -o /dev/null -w '%{http_code}' -m 15 -r 0-200 <url>` (read-only range request). `206` = reachable, `000` = proxy-blocked (connection refused), `404` = reachable but path wrong. A second run was done for flaky hosts.

| URL | Result |
|---|---|
| `ubuntu.com/security/cves.json?limit=1`, `ubuntu.com/security/notices.json?limit=1` | 206 on 2026-11-07 (000 once on the first run; flaky) |
| `ubuntu.com/security/cves/CVE-2021-44228.json` | 503 then 000 (per-CVE endpoint flaky; the list endpoint paginates) |
| `security.archlinux.org/issues/all.json`, `gitlab.archlinux.org` | 000 |
| `secdb.alpinelinux.org`, `security.alpinelinux.org`, `gitlab.alpinelinux.org` | 000 |
| `access.redhat.com/hydra/...`, `security.access.redhat.com/data/csaf/v2/...` | 000 |
| `cve.suse.com`, `www.suse.com/security/cve/*.json`, `ftp.suse.com/.../csaf/provider-metadata.json`, `download.opensuse.org`, `security.opensuse.org` | 000 |
| `alas.aws.amazon.com/AL2023/alas.rss`, `/AL2/alas.rss` | 000 |
| `linux.oracle.com/security/oval/...` | 000 |
| `security.gentoo.org/glsa/feed.rss`, `gitweb.gentoo.org/data/glsa.git` | 000; GitHub mirrors `gentoo/glsa`, `gentoo-mirror/glsa` -> 404 (not found) |
| `vuxml.freebsd.org/freebsd/vuln.xml` | 000 |
| `packages.vmware.com/photon/...` (Photon CVE metadata) | 000 |
| `raw.githubusercontent.com/NixOS/nixpkgs-security-tracker/...`, `nix-community/vulnix` | 404 (no such path; repo existence unverified) |
| `raw.githubusercontent.com/aquasecurity/vuln-list/main/...` and `git clone --filter=blob:none --sparse https://github.com/aquasecurity/vuln-list` | **206 / OK** (third-party mirror of many distro feeds, see "vuln-list" below) |
| OSV bucket `osv-vulnerabilities.storage.googleapis.com/{Ubuntu,Linux,SUSE,Wolfi,Mageia,openEuler,Azure Linux,Alpine}/modified_id.csv` | 206 |
| `raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2024/mfsa2024-01.yml` (+ `git ls-remote` of the repo) | **206 / OK** (the `.md` form 404; www.mozilla.org 000) |
| `raw.githubusercontent.com/github/advisory-database`, `.../Homebrew/advisory-database`, `.../Homebrew/homebrew-core`, `.../cisagov/vulnrichment`, `.../openvex/spec`, `.../chainguard-dev/vex`, `.../wolfi-dev/advisories` | 206 |
| `vulnerability.circl.lu/api/...`, `www.circl.lu` | 000 (the GitHub repo `vulnerability-lookup/vulnerability-lookup` raw: 206) |
| `support.apple.com/en-us/100100`, `.../HT201222` | 000 |
| `chromereleases.googleblog.com` | 000; `versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions` **200** |
| Vendor CSAF `provider-metadata.json`: Cisco `psirt.cisco.com`, Siemens `cert-portal.siemens.com`, SAP `security.sap.com`, CISA `www.cisa.gov`, BSI aggregator `wid.cert-bund.de` | 000 (all) |
| `www.exploit-db.com` | 000; **`gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` 206** (and `git ls-remote` OK); GitHub `offensive-security/exploitdb` 404 |
| `rapid7/metasploit-framework` `db/modules_metadata_base.json`; `projectdiscovery/nuclei-templates` `cves.json`; `nomi-sec/PoC-in-GitHub`; `trickest/cve` (raw) | 206 |
| `api.vulncheck.com` | 000 |
| `learn.microsoft.com/officeupdates/...` | 000 |
| `errata.rockylinux.org`, `errata.almalinux.org`, `mirrors.rockylinux.org` | 000 |
| `www.openwall.com/lists/oss-security`, `oss-security.openwall.org` | 000 |

Takeaway: **GitHub raw/git, GitLab raw, the OSV bucket and parts of ubuntu.com are the only usable channels from the sandbox**; sources hosted on their own domains need an open network.

## Backlog table (priority order)

Effort: S <= 1 day, M = 2-4 days, L = 1+ week. Priority reflects scan-quality gain per effort for Linux/Docker first (ADR-0005: macOS desktop, Docker images, SSH, Windows).

| # | Source | Adds | Format | Access / reachability (2026-11-07) | Target tables | Effort | Develop (D) / validate (V) |
|---|---|---|---|---|---|---|---|
| 1 | **Ubuntu CVE tracker** | triage (needed/ignored/deferred/not-affected/needs-triage, priority), fixed versions per release, ESM/Pro | JSON per CVE, paged list | `ubuntu.com/security/cves.json` reachable (flaky); sample exists | `distro_triage` (+ `affected` fixed via OSV already) | M | D sandbox, V sandbox/open |
| 2 | **Red Hat CSAF VEX** (+ Security Data API) | `known_not_affected`, `will not fix`/`affected` + `fix_state`, `under_investigation` -> triage; big noise reduction for RHEL/UBI/Rocky/Alma images | CSAF 2.0 JSON per CVE, `changes.csv`/`index.txt` | blocked (000) | `distro_triage` | M | D sandbox (fixture from spec), V open |
| 3 | **Homebrew advisory-database** (`BREW-*`, `repology.json`, `overrides.yml`) | backport detection for formula patches; formula -> distro source package bridge | OSV JSON + JSON + YAML | raw/git OK | `vulnerability`/`affected` (ecosystem `Homebrew`), alias; bridge table | S-M | D sandbox, V Mac ([on-macos.md](on-macos.md)) |
| 4 | **Exploit availability: Exploit-DB, Metasploit, nuclei, PoC-in-GitHub** | exploit signal for priority (P-level up) | CSV (`codes` column has CVEs), JSON | gitlab raw / raw OK | new `exploit(cve_id, source, kind, ref, date)` (proposed) -> `scoring.py` | S each | D sandbox, V sandbox |
| 5 | **Alpine secdb / tracker** | unfixed state (OSV has fixed only) | secdb JSON per branch+repo; unfixed per CVE | native blocked; **via vuln-list** `alpine-unfixed/` and `alpine/` OK | `distro_triage` (status `open`) | S | D sandbox via vuln-list, V open for native |
| 6 | **Amazon Linux ALAS** (not in OSV) | fixed advisories for AL1/AL2/AL2023 (an entire platform currently has no data) | ALAS JSON/RSS; `updateinfo.xml` | native blocked; **vuln-list** `amazon/{1,2,2022,2023}/ALAS-*.json` OK | `vulnerability`+`affected` (ecosystem `Amazon Linux:2023`, rpm), alias to CVE | M | D sandbox via vuln-list, V open (cross-check `dnf updateinfo` on an AL2023 box) |
| 7 | **Oracle Linux ELSA** (not in OSV) | fixed advisories OL7/8/9 | OVAL XML; vuln-list JSON | native blocked; **vuln-list** `oval/oracle/<year>/ELSA-*.json` OK | `vulnerability`+`affected` (`Oracle Linux:9`) | M | D sandbox via vuln-list, V open |
| 8 | **Debian: native tracker** | already implemented; validate | see [on-open-network.md](on-open-network.md) section 1 | blocked | `distro_triage` | (done, validate) | V open |
| 9 | **SUSE / openSUSE** (OSV + CSAF VEX/OVAL) | OSV gives fixed; CSAF/VEX adds not-affected, `under investigation` | OSV (present), CSAF VEX, OVAL | OSV bucket OK; SUSE hosts blocked; vuln-list `cvrf/suse/` OK (older CVRF) | `distro_triage` (VEX), `affected` (OSV) | M | D sandbox (OSV), V open (VEX) |
| 10 | **Rocky / AlmaLinux** | already in OSV (advisories `RLSA/ALSA`); consider vuln-list `rocky/`,`alma/` only if OSV lags; Rocky errata API for unfixed is not available | OSV | OSV OK | none new | - | verify only ([on-linux-docker.md](on-linux-docker.md) rpm items) |
| 11 | **Wolfi / Chainguard** | in OSV ecosystems `Wolfi` (309 MB), `Chainguard` (1.17 GB, check cost); `wolfi-dev/advisories` + `chainguard-dev/vex` give `not_affected`/`fixed` statements (OpenVEX-like) | OSV, advisory YAML, OpenVEX | OSV bucket OK; GitHub raw OK; `packages.cgr.dev` 000 | `affected`; VEX -> triage | S (OSV) / M (VEX) | D+V sandbox |
| 12 | **Other OSV distro ecosystems**: Azure Linux (`Azure Linux`), Mageia, openEuler, Echo, MinimOS, Root, Red Hat Lightwell, Alpaquita, BellSoft Hardened Containers, CleanStart, TuxCare; (**Photon is not in OSV**: `ecosystems.txt`) | coverage for more `os-release` IDs | OSV | bucket OK | `affected`; collector `os-release` ID -> ecosystem map in `engine/purl.py` | S | D+V sandbox. Photon: vuln-list `photon/<ver>/<pkg>/CVE-*.json` (`cve_id, pkg, aff_ver, res_ver`; "NA" values), S-M |
| 13 | **Arch Linux security tracker** | AVG records (status `Vulnerable/Fixed/Not affected`, severity, `affected`/`fixed`) | JSON | native blocked; **vuln-list** `arch-linux/AVG-*.json` OK | `vulnerability`/`affected` (ecosystem `Arch Linux`, pacman) + needs a pacman-DB reader in rootfs | M (+M for pacman DB) | D sandbox, V Arch container |
| 14 | **Linux kernel (OSV `Linux`) and Android** | kernel CVEs per host from `uname -r` / package `linux-image-*` | OSV | bucket OK | `affected`; component `kernel` from rootfs/ssh | M | D+V sandbox (+ Linux host) |
| 15 | **GHSA unreviewed advisories** | CVE descriptions for CVEs not yet reviewed; rarely has packages | OSV JSON in `advisories/unreviewed/` | raw/git OK; API blocked | `vulnerability`, `alias` | S | D+V sandbox |
| 16 | **Mozilla MFSA** (`announce/YYYY/mfsaYYYY-NN.yml`) | exact Firefox/Thunderbird/ESR fix versions + impact; complements Mozilla CNA "unaffected-only" records | YAML (observed: `announced`, `impact`, `fixed_in[]`, `title`, `advisories{CVE-x:{title,impact,description,bugs}}`) | raw/git OK | `affected` (vendor mozilla, product firefox/thunderbird, `fixed`) + `alias` | S | D+V sandbox |
| 17 | **CISA Vulnrichment standalone repo** | already consumed as ADP inside CVE List v5 (SSVC, KEV hint, CPE); only a faster feed | JSON (CVE v5 records) | raw OK | none new (decide SSVC storage, see [engine-and-quality.md](engine-and-quality.md) C) | S | sandbox |
| 18 | **Office / M365 release tables** | real matching of Click-to-Run builds (CNA bound is a URL) | HTML tables (`learn.microsoft.com/officeupdates/*`), or MSRC SUG `/sug/v2.0` (API key) | blocked (000) | `affected` (microsoft, `microsoft 365 apps for enterprise`, channel-specific builds) | L | D open (needs live pages), V Windows ([on-windows.md](on-windows.md) D) |
| 19 | **Vendor CSAF via provider-metadata** (Cisco, Siemens, SAP, Red Hat, SUSE, Oracle, CISA, BSI aggregator) | exact product/version/fix for network gear and ICS; `known_not_affected` | CSAF 2.0 (`product_tree`, `product_status`, `remediations`) | all probed provider-metadata URLs 000 | `affected` (CPE/purl identified products) + `distro_triage`-like VEX table | L | D sandbox with fixtures from the CSAF spec repo, V open |
| 20 | **Apple security releases** (HTML list + per-release pages) | OS/Safari/Xcode fix versions for macOS; Apple CNA records in CVE List v5 are coarse | HTML tables | blocked (000) | `affected` (apple, macos / safari / xcode) | M-L (fragile) | D open, V Mac ([on-macos.md](on-macos.md) A: Safari/macOS mapping) |
| 21 | **OpenVEX / CSAF VEX ingestion (user-supplied and vendor)** | suppress/annotate findings with justification | OpenVEX JSON, CSAF VEX | spec raw OK; engine side is in [engine-and-quality.md](engine-and-quality.md) B | `finding.suppressed` + new `vex_statement` | M | D sandbox |
| 22 | **VulnCheck KEV / NVD++** | superset of KEV with exploit refs; NVD-compatible CPE for most CVEs (answers the April-2026 gap) | JSON (API) | needs account/token; host blocked | `kev`-like, `affected`(CPE) | M | D open |
| 23 | **CIRCL vulnerability-lookup** | aggregated fallback + sightings; CVE-by-CVE API | JSON REST | host blocked | `vulnerability`, `alias` | M | D open |
| 24 | **Gentoo GLSA** | advisories for Gentoo hosts | XML in git (`gitweb.gentoo.org`) | blocked; GitHub mirror paths tried 404 | `affected` (`Gentoo`, ebuild versions: needs a new version scheme) | M + collector (portage `/var/db/pkg`) | D open |
| 25 | **FreeBSD VuXML** | BSD hosts | XML | blocked | `affected` (`FreeBSD`, pkg versions) | M + L collector (SSH refuses BSDs today) | D open |
| 26 | **NixOS** | Nix-managed software (pruned today: `/nix/store`) | no official feed found; `vulnix` scans store paths vs NVD; nixpkgs-security-tracker repo path unverified | blocked/unknown | `component` from store paths (name-version) -> CPE matching | L | D open |
| 27 | **Chrome / Edge release channels** | "outdated browser" signal (latest stable) - CVEs themselves come from the Chrome CNA records already in CVE List v5 | JSON (`versionhistory.googleapis.com`) | **200** | `meta` on components, not `affected` | S | D+V sandbox |
| 28 | **OSV ecosystems without a collector** (GitHub Actions, VSCode, Hex, CRAN, Hackage, Julia, opam, Bitnami, Android; Pub and SwiftURL got parsers 2026-11-11) | coverage per language/tool; VS Code extensions on macOS are listed in macos.md "Future" | OSV | bucket OK | `affected` (existing importer) | S per ecosystem + collector M | D sandbox |

## The vuln-list mirror (aquasecurity/vuln-list) - a way around blocked hosts

Probed 2026-11-07: `git clone --depth 1 --filter=blob:none --sparse https://github.com/aquasecurity/vuln-list.git` works from the sandbox (clone ~seconds, tree HEAD dated 2026-11-07). Top-level directories seen:
`alma alpine alpine-unfixed amazon arch-linux azure bottlerocket chainguard cvrf (suse) cwe echo echo-osv eoldates ghsa glad go kevc mariner minimos nvd openeuler osv oval (oracle) photon rocky rootio seal ubuntu wolfi`
(no `debian`, no `redhat`). It is the upstream of Trivy DB: **a third-party aggregator** - note licence and trust (it re-publishes vendor data; verify against native sources when reachable), JSON shapes samples fetched:
`alpine-unfixed/CVE-*.json` = `{id, state:[{fixed, published, repo, packageName, packageVersion}], cpeMatch}`; `arch-linux/AVG-*.json` = `{name, packages[], status, severity, type, affected, fixed, issues[], advisories[]}`;
`oval/oracle/<year>/ELSA-*.json` = `{Title, Description, Platform[], References[], Criteria...}`; `ubuntu/<year>/CVE-*.json` = `{Candidate, Priority, PublicDate, Patches{pkg:{release:{Status,Note}}}, ...}`;
`photon/<ver>/<pkg>/CVE-*.json` = `{os_version, cve_id, pkg, cve_score, aff_ver, res_ver}`. Use it as a **sandbox-friendly source for development and as a fallback**, not as the primary truth.

- [ ] Add a generic `vuln-list` reader (directory walker like the cvelist `--path`) producing the per-distro records above; clone with the sparse recipe and `sparse-checkout set alpine-unfixed amazon oval/oracle arch-linux photon ubuntu`.

## Per-item notes and checklists

### 1. Ubuntu CVE tracker (priority 1: reachable, verified shape, largest Linux userbase)

- Statuses (observed in `tests/fixtures/sources/distros/ubuntu-cve-2024-6387.json`: `released`, `not-affected`, `ignored`; from memory also `needed`, `needs-triage`, `deferred`, `pending`, `DNE`): `released` -> `description` is the fixed version; `not-affected` -> reason; `ignored` -> reason (e.g. end of standard support).
  Priorities `negligible|low|medium|high|critical|untriaged`. `pocket` `security|updates|esm-infra|esm-apps|...`.
- Mapping to `distro_triage` (see vocabulary table below): `ecosystem` = `Ubuntu:<ver>` (codename -> version map: jammy 22.04, noble 24.04, ...), `package` = source package, `status`, `urgency` = priority, `fixed_version` = `released` description, `nodsa` = `postponed` for `deferred`, `ignored` for `ignored`, `note` = description, `source` = `ubuntu-tracker`.
- **Ubuntu Pro / ESM**: a fix with pocket `esm-infra`/`esm-apps` (or version suffix `~esm1`) is **not available without Pro**. Policy to decide: report as `unfixed (fix needs Ubuntu Pro)` for assets without Pro (detect via `/etc/apt/sources.list.d/ubuntu-esm-*.list` or `pro status`), as fixed for Pro assets. OSV `Ubuntu:Pro:*` records are normalised away today (`Ubuntu:<ver>`): keep the Pro flag in `extra.raw_ecosystem`. Ubuntu releases out of standard support: `ignored` with reason `end of standard support`.
- Sync: `cves.json?limit=N&offset=M&order=descending&sort_by=updated` (verify param names) with `updated_at` cursor; per-CVE JSON is flaky (503) -> retry with backoff; full crawl size/time to measure. Alternative offline path: vuln-list `ubuntu/<year>/CVE-*.json` (same data, older field spelling).
- [ ] Probe pagination/params and measure a full crawl: `curl -s 'https://ubuntu.com/security/cves.json?limit=100&offset=0&order=descending' | jq '.cves|length, .offset, .total_results'`
- [ ] Implement `src/secmonk/sources/ubuntu_tracker.py`, fixture from the real list (`tests/fixtures/sources/ubuntu-tracker/`), tests, doc `references/vuln-sources/ubuntu-tracker.md`, extend `engine/match.py:_triage` to read `source='ubuntu-tracker'` rows.
- [ ] Validate on a real `ubuntu:22.04` and `ubuntu:24.04` image scan ([on-linux-docker.md](on-linux-docker.md)): findings count before/after, spot-check 10 `ignored`/`needed` cases against `ubuntu-security-status`/`pro security-status`.
- [ ] USN notices (`notices.json`, `release_packages`) for the binary-version map: only if source-version matching proves insufficient.

### 2. Red Hat CSAF VEX / Security Data API

- CSAF 2.0 `vulnerabilities[].product_status` buckets: `fixed`, `known_affected`, `known_not_affected`, `under_investigation`, `first_fixed`; `remediations[]` category `vendor_fix`/`no_fix_planned`/`none_available`; threat `impact` text. `product_tree` product ids `rhel-9:openssl-1:3.0.7-24.el9` style (verify).
  Map: `known_not_affected` -> `not-affected` (drop), `known_affected` + remediation `no_fix_planned` -> `no-fix` (will-not-fix: cap at P3/P4 like `no-dsa`), `under_investigation` -> `undetermined`, `fixed` -> resolved with fix NEVRA.
- Ecosystem: OSV `Red Hat:enterprise_linux:<major>[...]` normalised to `Red Hat:<major>`; Rocky/Alma images need the same data via the `Red Hat:<major>` mapping (decide; they follow RHEL fix states with their own advisories).
- Sync: `https://security.access.redhat.com/data/csaf/v2/vex/<year>/cve-*.json` + `changes.csv` / `index.txt` for deltas (paths from memory: verify). Full set is tens of thousands of files -> delta-only after first crawl, parallel with rate limiting.
- [ ] (open) Fetch 5 real VEX files, save fixtures, confirm product id grammar and `fix_state` naming; implement `redhat_vex.py`; test on `registry.access.redhat.com/ubi9/ubi-minimal` and `rockylinux:9`.

### 3. Homebrew advisory-database (see [references/homebrew.md](../references/homebrew.md))

- `data/*` `BREW-<formula>-<CVE>` OSV records: ecosystem `Homebrew`, purl `pkg:brew/<name>`, ranges `introduced 0 / fixed <pkg_version>` - only CVEs fixed by `patch ... resolves` (17 CVE/... in the doc). Importer: reuse `osv.py` `import_record` via `sync osv --path`, add ecosystem `Homebrew` scheme (generic) in `engine/versions.py:scheme_for_ecosystem`, match on `pkg:brew` components exactly.
- `data/repology.json` (5,524 formulae -> distro source package names) = bridge for matching brew formulae through OSV distro ecosystems at **medium-low** confidence; `overrides.yml` (`skip`, `registry_package`, `range_state`) as quality hints.
- [ ] `git clone --depth 1 https://github.com/Homebrew/advisory-database` -> `uv run secmonk sync osv --path <dir>`; verify the BREW records appear in `vuln show` and that a patched formula (e.g. `openssl@3` with a `patched_cves`) shows `patched` not a finding; test on a real Mac ([on-macos.md](on-macos.md) B).
- [ ] Compare with `patched_cves` suppression (collector) for double counting; document which wins.

### 4. Exploit signals (Exploit-DB, Metasploit, nuclei, PoC-in-GitHub)

- Exploit-DB `files_exploits.csv` (`id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,...`; `codes` = `CVE-2009-3699;OSVDB-58726`), Metasploit `db/modules_metadata_base.json` (module `references` incl. `CVE-...`), nuclei `cves.json` lines `{"ID":"CVE-...","Info":{Severity...},"file_path":...}` (a nuclei template means a remotely checkable, usually weaponised check), PoC-in-GitHub (public PoC repos per CVE; weak signal: filter by stars).
- Add table `exploit(cve_id, source, kind('exploit'|'module'|'template'|'poc'), ref, published)`; `scoring.py`: Metasploit/Exploit-DB verified -> treat like "public exploit" (+1 priority step, never above KEV rules), keep as a separate flag `finding.exploit_public`. Decide weights with the calibration in [engine-and-quality.md](engine-and-quality.md) C.
- [ ] Probed OK from sandbox: `curl -s -r 0-300 https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`; implement the three importers (S each), measure sizes (full CSV ~ 45k rows), license check (Exploit-DB GPLv2 data, Metasploit BSD).

### 5-7. Alpine, Amazon Linux, Oracle Linux

- Alpine: secdb `packages[].pkg.secfixes{<fixed-version>:[CVE...]}` carries **fixed only**; OSV Alpine already has the same. Real gain is *unfixed* (`alpine-unfixed/`, `state[].fixed=false`) -> `distro_triage.status='open'`. Low priority unless Alpine images dominate.
- Amazon Linux (OSV does not carry it): ecosystem string choose `Amazon Linux:2`, `:2023`, collector emits `distro` qualifier from `/etc/os-release` (`ID=amzn`, `VERSION_ID=2023`); rpm version scheme with epoch; ALAS record = advisory with CVE list + fixed package NEVRAs (vuln-list `amazon/<ver>/ALAS-*.json`; verify field names from a saved sample). Source package vs binary: ALAS lists binary RPMs -> match by binary name.
- Oracle Linux ELSA: OVAL-derived JSON with `Criteria` tree (package + `version less than`); extract (name, fixed EVR, CVEs); ecosystem `Oracle Linux:<major>`; UEK kernel vs RHCK separate.
- [ ] For each: `git clone --depth 1 --filter=blob:none --sparse https://github.com/aquasecurity/vuln-list && git sparse-checkout set <dir>` (sandbox OK), save 5 real files as fixtures, implement, validate with a real `amazonlinux:2023` / `oraclelinux:9` image scan ([on-linux-docker.md](on-linux-docker.md)) against `dnf updateinfo list security` / `yum updateinfo` output.
- [ ] (open) Replace with native feeds (ALAS RSS/`updateinfo.xml.gz`, `linux.oracle.com` OVAL bz2) and compare.

### 9-12. SUSE, Rocky/Alma, Wolfi/Chainguard, other OSV distros

- No new importer code needed for the OSV feeds, only: (a) ecosystem normalisation in `engine/purl.py` for `SUSE`, `openSUSE` (e.g. `SUSE:Linux Enterprise Server 15 SP5`? verify raw strings), `Wolfi`, `Chainguard`, `Azure Linux`, `Mageia`, `openEuler`; (b) `os-release` ID/VERSION_ID -> ecosystem in the collectors (rpm: `sles`, `opensuse-leap`, `azurelinux`, `mariner`, `openEuler`, `mageia`; apk: `wolfi`, `chainguard`); (c) cost check per bulk zip ([on-open-network.md](on-open-network.md) section 2).
- Chainguard/Wolfi OSV records: apk packages with distro `wolfi`; `fixed` + `database_specific`; Chainguard publishes `not_affected` statements in OpenVEX (`chainguard-dev/vex` reachable) -> ingest with item 21.
- [ ] `uv run secmonk sync osv -e Wolfi --limit 500` -> `scan docker-image cgr.dev/chainguard/python:latest` (anonymous pull allowed for `:latest`), check no false "unfixed" flood.

### 13-14, 24-26. Arch, Linux kernel, Gentoo, FreeBSD, NixOS

- Each needs **both** a source and a package-DB reader (pacman `/var/lib/pacman/local/*/desc`, portage `/var/db/pkg/*/*/`, `pkg info`, nix store names): schedule the source only together with the collector extension in [on-linux-docker.md](on-linux-docker.md) C (live rootfs). Until then rootfs reports "no package DB" for these.
- Kernel: OSV ecosystem `Linux` (kernel.org CNA, commit-range heavy, `GIT` ranges) -> needs the GIT-range fallback in [engine-and-quality.md](engine-and-quality.md) A to be useful; test first on `uname -r` of a Debian/Ubuntu host (distro kernels are covered by distro trackers, the OSV `Linux` feed is for mainline).

### 16. Mozilla MFSA

- Clone: `git clone --depth 1 --filter=blob:none --sparse https://github.com/mozilla/foundation-security-advisories && git sparse-checkout set announce`. Parse `announce/<year>/mfsa<year>-<nn>.yml`; `fixed_in` entries like `Firefox 122`, `Firefox ESR 115.7`, `Thunderbird 115.7`. Each CVE has `impact`.
- [ ] Map products to the macOS/Windows collector product strings (`mozilla firefox`, `firefox esr`); test with the installed Firefox on a Mac ([on-macos.md](on-macos.md) A) and Windows ([on-windows.md](on-windows.md) D); compare against Mozilla CNA records in CVE List v5.

### 18, 20. Office tables and Apple security releases

- Office: the Microsoft pages list per channel (`Current`, `Monthly Enterprise`, `Semi-Annual Enterprise`, `LTSC`) the build and release date; match = installed build < build of the release that fixed the CVE (MSRC release notes name the CVE -> KB/build). Needs an offline scraper script producing a static YAML table committed to `src/secmonk/data/` and refreshed by a script (do not scrape at scan time). Blocked until an open network is available.
- Apple: pages `support.apple.com/en-us/<id>` list "Impact/Description/CVE" per component (macOS, Safari, Xcode); parse the "released <date>" + product version header; the key is the (product, version) -> CVE mapping and fixing OS-version mapping of bundled Safari. Fragile HTML: keep a golden-file test per page layout.

### 21. VEX ingestion (source side)

- Vendor OpenVEX: `chainguard-dev/vex`, `wolfi-dev/advisories` (YAML), Red Hat CSAF VEX (item 2), SUSE CSAF VEX, Docker Scout attestations (`docker buildx imagetools inspect --format '{{json .Provenance}}'`, OCI referrers). Store statements keyed by (purl or product id, CVE) with status `not_affected|affected|fixed|under_investigation` + justification; user-supplied VEX goes through the CLI (see [engine-and-quality.md](engine-and-quality.md) B).

## Distro triage vocabulary (shared mapping; implement once in `engine/match.py`/`scoring.py`)

| Concept | Debian tracker | Ubuntu | Red Hat VEX | Alpine | Arch | Stored `distro_triage.status` / `nodsa` / `urgency` | Priority effect (existing rules) |
|---|---|---|---|---|---|---|---|
| Not affected | `<not-affected>`, fixed `0` | `not-affected`, `DNE` | `known_not_affected` | (absent) | `Not affected` | `not-affected` | finding dropped |
| Fixed | `resolved` + fixed_version | `released` | `fixed` | secfixes | `Fixed` | `resolved` + `fixed_version` | dropped if installed >= fixed |
| Open, will be fixed | `open` | `needed` | `known_affected` + vendor_fix pending | `alpine-unfixed` | `Vulnerable` | `open` | unchanged |
| Not yet triaged | `undetermined`, urgency `not yet assigned` | `needs-triage`, priority `untriaged` | `under_investigation` | - | - | `undetermined` | unchanged |
| Deferred / minor | `no-dsa`, `postponed` | `deferred` | (low impact + no fix planned) | - | - | `nodsa=postponed\|no-dsa` | at most P3 |
| Won't fix / ignored | `ignored`, `unimportant`, `end-of-life` | `ignored` (e.g. EOL) | `no_fix_planned` / `will not fix` | - | - | `nodsa=ignored`, urgency `unimportant`/`end-of-life` | P4 (KEV overrides) |
| Needs paid channel | - | `released` in `esm-*` pocket | (EUS/ELS repos) | - | - | new `note='requires Ubuntu Pro'` / `urgency` unchanged | decide: show as unfixed |

- [ ] Review this table once Ubuntu (1) and Red Hat (2) data exist; extend the `_triage` function and its tests (`tests/engine/test_triage.py`), then document the final vocabulary in [matching.md](../tech/engine/matching.md).
