---
title: Linux distribution security data sources
type: reference
context: references
status: reference
tags: [vuln-source, linux, distro, backports]
updated: 2026-11-07
sample: mixed
reachable: partial
fixtures: tests/fixtures/sources/distros/
related: [references/vuln-sources/debian-tracker.md, references/vuln-sources/nvd.md, references/vuln-sources/kev.md, references/vuln-sources/epss.md, references/vuln-sources/euvd.md]
---

# Linux distribution security data sources

## Summary

Distros ship their own security data because they backport fixes: `openssh` 8.9p1 on Ubuntu
jammy is patched for a CVE whose upstream fix is 9.8p1. Matching by upstream version gives
wrong answers in both directions. Each distro publishes per-release fix state, either in its own
tracker or through OSV. This doc records what we can reach, the formats, and the traps. The
prototype should use OSV as the primary source and native trackers for enrichment.

## Access

Probed 2026-11-07 with `curl -s -o /dev/null -w '%{http_code}' -m 15`:

| Host | Result | Used for |
|---|---|---|
| `ubuntu.com` (`/security/cves.json`, `/security/cves/CVE-*.json`, `/security/notices.json`) | 200 | Ubuntu CVE + USN data (sample saved) |
| `osv-vulnerabilities.storage.googleapis.com` | 200 | OSV bulk zips, `ecosystems.txt` |
| `raw.githubusercontent.com` | 200 | Not needed for distros |
| `security-tracker.debian.org` | 000 (blocked) | Debian tracker JSON |
| `secdb.alpinelinux.org` | 000 (blocked) | Alpine secdb |
| `access.redhat.com` | 000 (blocked) | Red Hat Security Data API |
| `security.access.redhat.com` | 000 (blocked) | Red Hat CSAF/VEX |

Notes:
- `ubuntu.com/security/cves.json?package=openssh` returned **503** once. Retry before treating it as
  an outage.
- A probe of `api.osv.dev` was refused by the sandbox classifier and not retried. Per-ID OSV lookups
  are therefore unverified here.

### Source inventory

| Distro | Native source (access URL) | Format | Cadence (as observed or from memory) | In OSV? (`ecosystems.txt`) | OSV ecosystem names |
|---|---|---|---|---|---|
| Debian | `https://security-tracker.debian.org/tracker/data/json` (blocked here) | One JSON, source package → CVE → release | Several updates a day (memory) | Yes | `Debian:11`, `Debian:12`, `Debian:13`, `Debian:14` (version major, not codename) |
| Ubuntu | `https://ubuntu.com/security/cves/CVE-YYYY-NNNN.json`, `https://ubuntu.com/security/cves.json?limit=N` (verified), `https://ubuntu.com/security/notices.json` (verified) | Per-CVE JSON, per-USN JSON | Continuous; `updated_at` per CVE allows delta sync | Yes (bulk zip 809 MB) | Not sampled; expected `Ubuntu:<ver>:LTS`, unverified |
| Alpine | `https://secdb.alpinelinux.org/v3.20/main.json` (blocked here) | One JSON per branch and repo | Continuous (memory) | Yes | `Alpine:v3.19` … `Alpine:v3.24` (observed) |
| Red Hat | Security Data API `https://access.redhat.com/hydra/rest/securitydata/cve/CVE-YYYY-NNNN.json`; CSAF VEX `https://security.access.redhat.com/data/csaf/v2/vex/YYYY/cve-YYYY-NNNN.json`; OVAL (all blocked here; paths from memory) | JSON (API), CSAF 2.0 VEX, OVAL XML | Daily (memory) | Yes | `Red Hat:enterprise_linux:<ver>::<variant>`, `Red Hat:rhel_eus`, `Red Hat:rhel_e4s`, … (110 observed) |
| Rocky Linux | Errata (`RLSA-*`) and OSV only in this probe | RPM NEVRA in OSV | Bulk zip regenerated within 24 h of probe | Yes | `Rocky Linux:8`, `:9`, `:10` |
| AlmaLinux | Errata (`ALSA/ALBA/ALEA-*`) and OSV only in this probe | RPM NEVRA in OSV | Bulk zip regenerated within 24 h of probe | Yes | `AlmaLinux:8`, `:9`, `:10` |
| SUSE / openSUSE | `https://cve.suse.com`, OVAL under `ftp.suse.com` (memory, unverified) | OSV, OVAL | Not sampled | Yes (`SUSE`, `openSUSE`) | Not sampled |
| Wolfi | Wolfi `security.json` (memory, unverified) | OSV | Not sampled (bulk zip 309 MB) | Yes | `Wolfi` |
| Chainguard | Not sampled (bulk zip 1.17 GB) | OSV | Not sampled | Yes | `Chainguard` |
| Amazon Linux | ALAS advisories (memory, unverified) | Advisory text / updateinfo | Not sampled | **No** | none |
| Oracle Linux | ELSA errata, OVAL on `linux.oracle.com` (memory, unverified) | OVAL, errata | Not sampled | **No** | none |
| Other OSV distros | Mageia, Echo, MinimOS, Root, Red Hat Lightwell (zips 0.35–88 MB) | OSV | Regenerated within 24 h of probe | Yes | `Mageia`, `Echo`, `MinimOS`, `Root`, `Red Hat Lightwell` |

OSV bulk zips (`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`) were all
regenerated in the 36 hours before the probe (`Last-Modified` header). A full `all.zip` is the
practical unit of sync. Some are large: Ubuntu 809 MB, Chainguard 1.17 GB, Wolfi 309 MB, Debian 81 MB.

## Data format

### Ubuntu CVE JSON (verified, real)

Fixture: `tests/fixtures/sources/distros/ubuntu-cve-2024-6387.json` (CVE-2024-6387 regreSSHion,
trimmed). Fields confirmed from the live record:

- Top level: `id`, `published`, `updated_at`, `priority` (own scale: `high`…), `cvss3` (float),
  `status` (`active`), `description`, `ubuntu_description`, `mitigation`, `notes[]`, `bugs[]`,
  `patches{}`, `notices_ids[]` (e.g. `USN-6859-1`), `tags{}`, `packages[]`.
- `packages[]`: `name` (**source** package), `statuses[]`, `debian`, `ubuntu`, `source`.
- `packages[].statuses[]`: `release_codename` (`trusty`, `xenial`, `bionic`, `focal`, `jammy`,
  `mantic`, `noble`, plus `upstream`), `status`, `description`, `pocket` (`security` observed),
  `component` (null in sample).
- Status values in the full live record (14 rows across both packages): `not-affected` (9),
  `released` (4), `ignored` (1). The fixture keeps a subset. Memory adds `needed`, `pending`, `deferred`,
  `DNE`, `needs-triage`; not seen here.
- `description` meaning depends on status: for `released` it is the **fixed version**
  (`1:8.9p1-3ubuntu0.10`); for `not-affected` it is free text (`introduced in v8.5p1`); for the
  `upstream` row it is the upstream fixed version (`9.8p1`); for `ignored` it is a reason
  (`frozen on openssh 7.5p`).

Subset of the statuses (from the fixture, `openssh` source package):

| Release | Status | description |
|---|---|---|
| jammy | released | `1:8.9p1-3ubuntu0.10` |
| noble | released | `1:9.6p1-3ubuntu13.3` |
| xenial | not-affected | `introduced in v8.5p1` |
| upstream | released | `9.8p1` |

### USN notices JSON (verified, real)

`https://ubuntu.com/security/notices.json?limit=N` returns `{"notices":[…]}`. Fields seen:
`id` (`USN-8952-2`), `title`, `summary`, `description`, `instructions`, `references[]`,
`published`, `cves_ids[]`, `is_hidden`, `type`, and `release_packages{codename: [ {name, version,
is_source, pocket?, description?, source_link?, version_link?} ]}`. The release map gives binary
package versions per release, including ESM pockets (`esm-apps`, `esm5` version suffix). Use it
to map CVE → fixed binary version, complementing the CVE statuses.

### OSV distro records (verified, real; four fixtures saved)

Shape is the standard OSV schema. Distro-specific bits:

- `affected[].package` has `name`, `ecosystem` (`Debian:12`, `Alpine:v3.20`, `Rocky Linux:9`,
  `AlmaLinux:9`, `Red Hat:enterprise_linux:…`), and `purl` (e.g. `pkg:deb/debian/<src>?arch=source`,
  `pkg:apk/alpine/<src>?arch=source`, `pkg:rpm/rocky-linux/<name>?distro=…`).
- `affected[].ranges[].events` uses `introduced` / `fixed`, with the fixed version in the
  distro's native format.
- Debian adds `affected[].ecosystem_specific.urgency` (`not yet assigned`, `unimportant`, `low`,
  `medium`, `high`, `end-of-life`). Debian `database_specific.source` links the DSA/DLA page.
- Some Debian affected entries carry an explicit `versions[]` list in addition to ranges
  (97,611 entries). A matcher must handle both.
- Rocky, Alma and Red Hat records are advisories (`RLSA-`, `ALSA-`, `RHSA-`), with the CVE in
  `upstream[]`. The `id` is the advisory, not the CVE.

Fixtures (real, from the OSV bulk zips, unmodified apart from pretty-printing):

| File | Record | What it shows |
|---|---|---|
| `osv-debian-open-range-cve-2001-1534.json` | `DEBIAN-CVE-2001-1534` (apache2, `Debian:12`) | Open range: `introduced: 0`, no `fixed` event; urgency `unimportant` |
| `osv-alpine-cve-2006-20001.json` | `ALPINE-CVE-2006-20001` | Per-branch `affected` entries, `arch=source` purl, `-r0` fixed versions |
| `osv-rocky-rlsa-2019-0975.json` | `RLSA-2019:0975` | RLSA advisory with CVE in `upstream`, `database_specific.yum_repository` |
| `osv-redhat-rhba-2007-0026.json` | `RHBA-2007:0026` | A bug-fix advisory (RHBA) that carries a CVE |

### Debian tracker JSON (blocked; synthetic snippet)

Not reachable from the sandbox. Shape from the brief and memory, **sample: synthetic**:

```json
{"openssh": {"CVE-2024-6387": {"releases": {"bookworm": {
  "status": "resolved", "fixed_version": "1:9.2p1-2+deb12u3",
  "urgency": "high", "repositories": {"bookworm": "1:9.2p1-2+deb12u3"}}}}}}
```

Memory-based status vocabulary (unverified): `resolved`, `open`, `undetermined`, `no-dsa`,
`postponed`, `unfixed`, `not-affected`. Keys are source packages and codenames.

Full treatment (both JSON and git text formats, field certainty): [debian-tracker.md](debian-tracker.md).
In the JSON, `no-dsa`/`postponed`/`ignored` are not statuses but `nodsa`/`nodsa_reason` fields;
status is only `resolved`/`open`/`undetermined` (assumption).

### Alpine secdb (blocked; synthetic snippet)

Shape from memory, **sample: synthetic**:

```json
{"distroversion": "v3.20", "reponame": "main", "packages": [
  {"pkg": {"name": "openssl", "secfixes": {"3.3.2-r0": ["CVE-2024-5535"]}}}]}
```

`secfixes` maps fixed version → list of CVEs. Memory says an `unfixed` key holds CVEs with no fix
yet. Unverified.

### Red Hat CSAF VEX (blocked; synthetic snippet)

From memory, **sample: synthetic**. CSAF 2.0 `vulnerabilities[].product_status` buckets:
`fixed`, `known_affected`, `known_not_affected` (with `flags` / `threats` justification),
`under_investigation`, `first_fixed`. Product IDs are CPE-like (`cpe:/o:redhat:enterprise_linux:9`)
joined to package PURLs (`pkg:rpm/redhat/openssh@…`).

## Mapping

Working map for the prototype's tables (distro-agnostic):

| Source concept | Our field |
|---|---|
| Source package (`packages[].name`, `purl ?arch=source`, Debian `src_pkg`) | `advisory_package.source_name` |
| Binary package (installed name, from dpkg/rpm/apk inventory) | joined to source via collector metadata; never matched directly |
| Distro release (`jammy`, `Debian:12`, `Alpine:v3.20`, `Rocky Linux:9`) | `distro_release` (normalised: `ubuntu:22.04`, `debian:12`, `alpine:3.20`) |
| Fixed version (native string) | `fixed_version` with `version_scheme` = `dpkg` / `rpm` / `apk` |
| Status (`released`, `not-affected`, `fixed`, `known_not_affected`, …) | `fix_state` enum (see below) |
| Open range (no fixed version) | `fix_state = unfixed` |
| Urgency / priority | `distro_priority` (kept separate from CVSS) |
| Advisory id (USN, RLSA, RHSA, DSA) | `advisory_id` (secondary; a CVE can have several) |

`fix_state` should be: `fixed` (version known), `unfixed` (no fix yet), `not_affected`
(distro says the package is not affected), `ignored` (distro decided to skip), `unknown`
(needs-triage / pending / deferred). Keep the raw status string.

## Quirks & pitfalls

1. **Backports break upstream ranges.** Ubuntu's openssh record says the jammy fix is
   `1:8.9p1-3ubuntu0.10`, while the upstream fix is `9.8p1`. A naive `< 9.8` check flags jammy
   correctly here, but the same check flags focal and xenial, which Ubuntu marks `not-affected`
   because the regression was `introduced in v8.5p1`. Never compare against upstream versions for
   a distro package.
2. **Source vs binary.** Advisories and trackers are keyed by source package (`openssh`). Installed
   packages are binaries (`openssh-server`, `openssh-client`). Map binary → source before matching.
   Debian and Alpine OSV use source names (`?arch=source`). For Red Hat and Rocky OSV, the sample
   does not show whether names are source or binary; check against a multi-binary package before
   relying on it.
3. **Version comparators differ.** Use `dpkg --compare-versions` semantics for Debian and Ubuntu
   (epochs `1:`, `+esm5`, `ubuntu0.10`), `rpmvercmp` (epoch:version-release, `.el9`) for RPM
   distros, and apk ordering for Alpine (`-r0` revisions). Do not use semver.
4. **Unfixed coverage varies by ecosystem.** In the OSV archives we sampled:
   - Debian: 25,721 open ranges (no `fixed` event), e.g. `DEBIAN-CVE-2001-1534`, mostly
     `urgency: not yet assigned`.
   - Alpine (10,697 records), Rocky (4,719), Alma (6,399), Red Hat (24,010): **zero** open ranges.
     Every range has a `fixed` event. This is absence in OSV, not proof the CVE is fixed.
   An open range with `introduced: 0` means "all versions affected, no fix". Decide whether to
   report it (policy flag), and keep it distinct from `fixed`.
5. **Advisory type is not severity.** `RHBA-2007:0026` (a bug-fix advisory) carries a CVE. Alma's
   `ALBA-` and `ALEA-` prefixes are bug-fix and enhancement advisories (980 and 222 records). Filter
   on the CVE list, not the prefix.
6. **Ubuntu `priority` is not CVSS.** `priority: high` for CVE-2024-6387 comes from Ubuntu's own
   scale. Keep `cvss3` separate.
7. **Ubuntu status values are per release**, and one CVE can be `released` for one codename and
   `not-affected` for another. Read per row, not per CVE.
8. **Release names vs versions.** OSV uses version numbers (`Debian:12`, `Rocky Linux:9`,
   `Alpine:v3.20`). Ubuntu uses codenames (`jammy`, `noble`). Map codename → version explicitly
   (jammy = 22.04, noble = 24.04, bookworm = Debian 12, trixie = Debian 13), and do not infer from
   string prefixes.
9. **Large bulk archives.** Ubuntu (809 MB) and Chainguard (1.17 GB) need streaming reads and
   `modified` tracking, not full re-downloads per run.
10. **Amazon Linux and Oracle Linux are not in OSV** (absent from `ecosystems.txt`). Those need
    native sources.

## TODO

- [ ] Re-probe the four blocked hosts from an unrestricted network; replace the synthetic snippets
      with real fixtures.
- [ ] Sample Ubuntu, Wolfi, SUSE and Chainguard OSV records (stream, do not download fully) and
      record their ecosystem names and open-range behaviour.
- [ ] Confirm Red Hat OSV source vs binary package naming with a multi-binary advisory.
- [ ] Confirm Debian tracker status vocabulary and `repositories` shape against a live file
      (importer implemented in `src/secmonk/sources/debian_tracker.py`; see
      [debian-tracker.md](debian-tracker.md) for formats and the validation checklist).
- [ ] Find a native source for Amazon Linux (ALAS) and Oracle Linux (ELSA/OVAL).

## Recommendation for the prototype

- **Primary:** OSV distro ecosystems, via the per-ecosystem bulk zips. Start with Debian,
  Ubuntu, Alpine, Rocky Linux, AlmaLinux, Red Hat (`Red Hat:enterprise_linux:*`), SUSE/openSUSE,
  Wolfi and Chainguard. Treat Mageia, Echo, MinimOS and Root as opt-in. Use `modified` for
  incremental sync. Matching is by source package name plus native version comparison.
- **Enrichment, later:**
  - Ubuntu CVE JSON (reachable and verified): per-release `not-affected` and `ignored`, plus
    `released` versions. Also the USN release map for binary versions.
  - Red Hat CSAF VEX for `known_not_affected` and `under_investigation` (blocked from the
    sandbox; test on an unrestricted network).
  - Debian tracker for `unfixed`, `no-dsa` and urgency (blocked from the sandbox; implemented as
    `debian-tracker`, see [debian-tracker.md](debian-tracker.md), tested on synthetic fixtures only).
- **Not covered by OSV:** Amazon Linux and Oracle Linux. Add native collectors when those targets
  are in scope.
- **Policy:** open ranges (no `fixed` event) are surfaced as `unfixed`, not silently dropped,
  and are kept separate from `fixed` in reports.
