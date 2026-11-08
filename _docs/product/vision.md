---
title: Holistic CVE Scanner — Project Notes
summary: Project notes from 2026-11 covering goals, identifiers, vulnerability and context sources, collector options, architecture, matching, prioritization, roadmap, risks and endpoints.
read_when: you need the original scope, design rationale, glossary or source landscape behind sec-monk
type: product
context: product
status: reference
tags: [vision, scope, roadmap, glossary]
updated: 2026-11-07
verified: 2026-11-07
---

# Holistic CVE Scanner — Project Notes

> Working document · Nov 2026 · Author: Marco De Nittis

---

## 1. Goal

Build a **single, holistic vulnerability scanner** that discovers the software running anywhere in the estate and tells us, with a prioritized list, which known vulnerabilities (CVEs and related advisories) affect it.

**In scope targets**

| Target | Examples | Collection mode |
|---|---|---|
| Container images | Registry images, running containers, K8s workloads | Agentless (registry / CI) |
| Source repositories | Git repos, lockfiles, manifests | Agentless (CI / git clone) |
| Servers | Linux VMs, bare metal, (later) Windows Server | Agent or SSH |
| Desktop / endpoint apps | Windows, macOS, Linux workstations | Agent (osquery) or MDM export |

**Design principle:** *different collectors, one shared engine.* Targets differ only in how software is discovered; normalization, matching, enrichment, prioritization and reporting are identical.

**Success criteria**
- One inventory and one findings view across all target types.
- Low false-positive rate on Linux (distro-backport aware).
- Usable coverage of desktop/commercial software despite reduced NVD CPE enrichment.
- Findings ranked by real risk (exploitation + exposure), not by CVSS alone.
- Track lifecycle: first seen → fixed → regression.

**Non-goals (for now)**
- Exploit verification / active pentesting.
- Misconfiguration scanning (CIS benchmarks, IaC) — possible later module.
- Auto-remediation (patching).

---

## 2. Key concepts and identifiers

| Term | What it is | Example |
|---|---|---|
| **CVE** | Global ID for a publicly disclosed vulnerability, assigned by a CNA | `CVE-2021-44228` |
| **CNA** | CVE Numbering Authority — org allowed to assign CVEs (vendors, CERTs, GitHub, etc.) | Red Hat, GitHub, MITRE |
| **ADP** | Authorized Data Publisher — adds data to a CVE record after the CNA (e.g. CISA Vulnrichment) | CISA ADP container |
| **CPE** | NIST naming scheme for products (vendor/product/version), used by NVD | `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` |
| **PURL** | Package URL — identifies a package within an ecosystem | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |
| **CWE** | Weakness category (root-cause type) | `CWE-502` (deserialization) |
| **CVSS** | Severity score 0–10 (v3.1, v4.0) — *severity, not risk* | `10.0 CRITICAL` |
| **EPSS** | Probability of exploitation in the next 30 days (FIRST.org) | `0.97` |
| **KEV** | Catalog of vulnerabilities known to be exploited in the wild (CISA) | yes/no + due date |
| **SSVC** | Decision-tree prioritization (Track / Attend / Act) used by CISA | `Exploitation: active` |
| **SBOM** | Software Bill of Materials — list of components | CycloneDX, SPDX |
| **VEX** | Statement that a product *is / is not* affected by a CVE | OpenVEX, CSAF VEX, CycloneDX VEX |
| **CSAF** | OASIS standard for machine-readable security advisories | Red Hat, Siemens, Cisco feeds |
| **OSV** | Open Source Vulnerability schema + database (Google) | `GHSA-jfh8-c2jp-5v3q`, `PYSEC-…` |
| **GHSA** | GitHub Security Advisory ID | `GHSA-jfh8-c2jp-5v3q` |
| **EUVD ID** | ENISA EU Vulnerability Database ID, mapped to CVE | `EUVD-2025-21128` |

**Rule of thumb:** PURL for ecosystem packages (libraries, distro packages) → precise matching. CPE for generic products (commercial/desktop software, OS, appliances) → fuzzy, name-based matching.

---

## 3. Vulnerability sources

Detailed, tested per-source notes (format, access, quirks) live in [`../references/vuln-sources/`](../references/vuln-sources/).

### 3.1 Core / authoritative CVE data

| Source | Content | Access | Notes |
|---|---|---|---|
| **CVE List (cve.org)** | Canonical CVE records, JSON 5.x. `containers.cna.affected` = vendor/product/versions, sometimes `packageName` + `collectionURL` | GitHub repo `CVEProject/cvelistV5` (bulk + deltas), CVE Services API | Always present for every CVE. Quality of `affected` depends on the CNA. Includes ADP containers (CISA Vulnrichment). |
| **NVD (NIST)** | CVE + CPE applicability configs, CVSS, CWE | REST API 2.0 (API key recommended), JSON feeds | Since **15 Apr 2026** NVD enriches only prioritized CVEs; pre-March-2026 unenriched backlog (~29k) set to "Not Scheduled". **Missing CPE ≠ not affected.** |
| **CISA Vulnrichment (ADP)** | SSVC decision points, CVSS, CWE, sometimes CPE added to CVE records | GitHub `cisagov/vulnrichment`, and inside cve.org records | Does not replace NVD CPE applicability at scale. |
| **ENISA EUVD** | EU vulnerability DB, mapped to CVE; critical / exploited / EU-coordinated views; EPSS included | REST API `https://euvdservices.enisa.europa.eu` | Launched 2025 under NIS2 / CRA. API has no delta fetch (full pulls). Good EU-side redundancy. |
| **GCVE** | Decentralized numbering (EU-led), GNA-based | Early stage | Monitor; not required for MVP. |

### 3.2 Open-source ecosystem sources (PURL-based, best for libraries)

| Source | Coverage | Access |
|---|---|---|
| **OSV.dev** | Aggregates GHSA, PyPA, RustSec, Go, npm, Maven, NuGet, Packagist, RubyGems, Hex, Pub, plus several Linux distros (Debian, Ubuntu, Alpine, Rocky, AlmaLinux…) | REST API (`/v1/query`, `/v1/querybatch`, `/v1/vulns/{id}`), bulk GCS zips per ecosystem |
| **GitHub Advisory Database (GHSA)** | Reviewed advisories for major ecosystems; feeds Dependabot | GraphQL API, GitHub repo `github/advisory-database` (OSV format) |
| **PyPA Advisory DB** | Python | GitHub (OSV format) |
| **RustSec** | Rust crates | GitHub (OSV format) |
| **Go Vulnerability DB** | Go modules, with symbol-level info | `vuln.go.dev` |
| **npm / Yarn audit** | npm (backed by GHSA) | npm registry audit endpoint |

### 3.3 Linux distribution sources (critical for servers & container base images)

Distros **backport** fixes — the upstream version number lies. Always match OS packages against the distro's own data.

| Distro | Source / format |
|---|---|
| Debian | Debian Security Tracker (JSON), DSA/DLA; also in OSV |
| Ubuntu | Ubuntu CVE Tracker, OVAL, USN; also in OSV |
| Red Hat / RHEL | Red Hat Security Data API, **CSAF + VEX** files, OVAL |
| Rocky / AlmaLinux / Oracle Linux | Errata (ALSA/ELSA), OVAL; Rocky/Alma in OSV |
| SUSE / openSUSE | OVAL, CSAF |
| Alpine | secdb (JSON); also in OSV |
| Amazon Linux | ALAS advisories |
| Wolfi / Chainguard | secdb / OSV |

### 3.4 Vendor / commercial sources (desktop, appliances, enterprise software)

| Vendor | Format / access |
|---|---|
| Microsoft | MSRC Security Update Guide API (CVRF/CSAF) — Windows, Office, Edge… |
| Apple | Security releases pages (HTML) — no structured feed; scrape or rely on CVE `affected` |
| Google Chrome / Mozilla Firefox | Release blogs / MFSA advisories |
| Adobe | APSB bulletins |
| Oracle | Critical Patch Update (quarterly) |
| Cisco, Fortinet, Palo Alto, Juniper | CSAF / openVuln APIs / PSIRT advisories |
| Siemens and ICS vendors | CSAF feeds; Siemens publishes **Supplier-ADP** data into CVE records (since Apr 2026) |
| VMware/Broadcom, SAP, Atlassian… | Vendor advisory portals |

**CSAF aggregator / provider metadata** (`/.well-known/csaf/provider-metadata.json`) lets you discover CSAF feeds automatically for vendors that support it.

### 3.5 Commercial / aggregated alternatives (optional)

- **VulnCheck** (NVD++ enrichment, VulnCheck KEV) — partially free tier.
- **Snyk, Sonatype OSS Index, Mend** — curated library intelligence.
- **Vulners, Vulnerability-Lookup (CIRCL)** — aggregators; CIRCL's tool also powers parts of EUVD.

---

## 4. Context / prioritization sources (beyond "is it vulnerable?")

| Source | Purpose | Access |
|---|---|---|
| **CISA KEV** | Known exploited in the wild → top priority | JSON/CSV feed |
| **VulnCheck KEV** | Broader exploited list | API (account) |
| **EUVD exploited view** | EU-side exploited list | EUVD API |
| **EPSS (FIRST)** | Exploitation probability, daily | CSV / API |
| **CVSS v3.1 / v4.0** | Severity baseline | CVE record, NVD, vendor |
| **SSVC (CISA ADP)** | Exploitation / automatable / technical impact | CVE ADP container |
| **Exploit-DB, Metasploit modules, Nuclei templates** | Public exploit availability | GitHub repos |
| **Vendor VEX** | "Not affected" statements → suppress false positives | CSAF VEX, OpenVEX |
| **Internal asset context** | Exposure (internet-facing), environment, owner, criticality | CMDB, cloud tags, K8s labels |

---

## 5. Discovery / collection sources (what is installed)

Detailed collector notes live in [`../tech/collectors/`](../tech/collectors/).

| Target | Data source | Tools |
|---|---|---|
| Container images | Image layers: OS package DB + language manifests + binaries | **Syft**, **Trivy** |
| Repos | Lockfiles & manifests (package-lock.json, yarn.lock, poetry.lock, requirements.txt, go.sum, Cargo.lock, pom.xml, gradle.lockfile, *.csproj, composer.lock, Gemfile.lock) | Syft, Trivy, **OSV-Scanner** |
| Linux servers | dpkg/rpm/apk DB, `/etc/os-release`, language runtimes, `/opt`, jars, binaries | Syft (filesystem), Trivy (rootfs), **osquery** |
| Windows | Registry `Uninstall` keys (HKLM/HKCU, 32/64-bit), MSI DB, winget/choco, KB/hotfix list | osquery, PowerShell, MDM (Intune) |
| macOS | `/Applications/*.app/Contents/Info.plist` (`CFBundleIdentifier`, `CFBundleShortVersionString`), Homebrew, pkgutil | osquery, MDM (Jamf) |
| Kubernetes | Running image digests per workload | Trivy Operator, kube API |

**Common output (vision; planned, not implemented):** **CycloneDX 1.6 JSON** SBOM + asset metadata envelope (asset id, type, hostname, OS, owner, environment, exposure, scan timestamp, collector version). *Prototype reality:* collectors emit an `Inventory` dataclass stored in SQLite (`collect -O` writes it as JSON); a CycloneDX exporter is deferred ([ADR-0005](../decisions/0005-prototype-scope-nov-2026.md)).

---

## 6. Architecture

```
  ┌───────────── Collectors ─────────────┐
  │ Image/Registry │ Repo/CI │ Server agent │ Desktop agent / MDM │
  └───────┬───────────────┬───────────────┬────────────┘
          │  CycloneDX SBOM + asset metadata
          ▼
  ┌──────────────── Shared Engine ────────────────┐
  │ 1. Ingest & normalize  (PURL / CPE, alias table) │
  │ 2. Match                                          │
  │    • PURL / distro pkgs → Grype or Trivy (SBOM)   │
  │    • CPE / desktop apps → custom matcher          │
  │      (NVD + CVE `affected` + vendor CSAF)         │
  │ 3. Enrich   (KEV, EPSS, CVSS, SSVC, VEX)          │
  │ 4. Score    (risk = vuln signals × asset context) │
  │ 5. Store    (assets, components, findings, history)│
  └──────────────────────┬────────────────────────┘
                         ▼
        API · Dashboard · Alerts · Ticketing (Jira) · Reports
```

**Vulnerability data sync** runs as a separate job: mirror CVE List, NVD, OSV bulk, distro feeds, KEV, EPSS, vendor CSAF into a local DB on a schedule (hourly/daily). Scans never hit external APIs directly.

### 6.1 Build vs reuse

| Layer | Reuse | Build |
|---|---|---|
| Image/repo/server inventory | Syft / Trivy | Orchestration, scheduling |
| Desktop inventory | osquery / MDM APIs | Collector → CycloneDX converter |
| PURL & distro matching | Grype / Trivy (`grype sbom:x.json`, `trivy sbom x.json`) | — |
| CPE / desktop matching | NVD CPE dictionary | **Name → CPE resolver + alias table** (core R&D) |
| Storage + UI (MVP) | **OWASP Dependency-Track** (ingests CycloneDX, has NVD/OSV/GHSA) | — |
| Prioritization | KEV/EPSS feeds | **Risk scoring with asset context** |

### 6.2 Minimal data model

- `asset` (id, type, name, os, owner, env, exposure, tags)
- `scan` (id, asset_id, collector, started_at, sbom_ref)
- `component` (id, purl, cpe, name, version, type, source_path)
- `asset_component` (asset_id, component_id, first_seen, last_seen)
- `vulnerability` (id, aliases[], cvss, epss, kev, cwe, published, sources[])
- `finding` (asset_id, component_id, vuln_id, status, fixed_version, vex_status, risk_score, first_seen, fixed_at)

---

## 7. Matching strategy

1. **Component has PURL**
   - OS package (`pkg:deb`, `pkg:rpm`, `pkg:apk`) → distro feed (with distro + release!), compare with distro version semantics.
   - Library (`pkg:npm`, `pkg:pypi`, `pkg:maven`…) → OSV / GHSA, ecosystem version ranges.
2. **Component has only name + version** (desktop / commercial)
   - Normalize name (strip edition, arch, year, "(x64)", etc.).
   - Look up alias table → CPE vendor:product.
   - Fallback: fuzzy match against NVD CPE dictionary (token similarity + vendor hint from publisher field); store confidence score.
   - Match versions against NVD configurations **and** CVE `affected` blocks **and** vendor CSAF.
3. **Apply VEX** to suppress "not affected".
4. **Deduplicate aliases** (CVE ↔ GHSA ↔ OSV ↔ distro IDs ↔ EUVD) into one vulnerability.

### Version comparison pitfalls
- Each ecosystem has its own semantics: Debian epochs (`1:2.3-4`), RPM `epoch:version-release`, semver, PEP 440, Maven ordering.
- Windows "DisplayVersion" may differ from marketing version (e.g. Office build numbers).
- Use the libraries the scanners already use rather than writing your own comparators.

---

## 8. Prioritization (draft)

```
priority =
    KEV listed                → P1 (always)
  else EPSS ≥ 0.1 AND exposed → P1
  else CVSS ≥ 9 AND exposed   → P2
  else EPSS ≥ 0.1             → P2
  else CVSS ≥ 7               → P3
  else                        → P4
modifiers: production +1 priority step, internet-facing +1 step (never above P1)   [implemented]
           VEX not_affected → suppress, fix available → flag "actionable"   [vision only:
           no VEX ingestion; use `findings --fixable` for "fix available"]
```

Implemented in `engine/scoring.py`: the production / internet-facing modifiers raise the priority (read from `asset.meta`, which nothing populates yet);
see [matching](../tech/engine/matching.md#prioritization).

Tune thresholds after the first real data set.

---

## 9. Roadmap

| Phase | Scope | Output |
|---|---|---|
| **0 – Foundations** | Vuln data sync (CVE List, OSV, NVD, KEV, EPSS), DB schema | Local vuln mirror |
| **1 – MVP** | Images + repos via Syft → Grype; Dependency-Track as UI | First findings dashboard |
| **2 – Servers** | Linux collector (agent/SSH), distro-aware matching | Server coverage |
| **3 – Prioritization** | Asset context, risk scoring, alerts, Jira integration | Ranked work queue |
| **4 – Desktops** | osquery/MDM collector, name→CPE resolver, alias table, vendor CSAF | Endpoint coverage |
| **5 – Hardening** | VEX support, reachability (optional), reporting, RBAC | Production-ready |

> The prototype ([ADR-0005](../decisions/0005-prototype-scope-nov-2026.md), which supersedes [ADR-0003](../decisions/0003-prototype-scope.md)) reorders this: macOS desktop first,
> then Docker images / live containers, SSH and Windows, with a native Python engine instead of Grype/D-Track and no CycloneDX output yet.

---

## 10. Known challenges and risks

- **NVD CPE gap:** many CVEs (especially pre-March-2026 backlog and non-prioritized new ones) will never get NVD CPE data → rely on CVE `affected`, vendor CSAF, OSV, and your own resolver.
- **Desktop app identification** is the main source of false positives/negatives.
- **Distro backports:** never match OS packages with upstream CVE ranges.
- **Vendored / statically linked code** (fat jars, Go binaries, bundled OpenSSL) — use scanners that inspect binaries and jar manifests.
- **Alias explosion:** same issue under CVE, GHSA, distro IDs, EUVD — dedupe early.
- **Data freshness:** feeds update at different cadences; record source + fetch time per finding.
- **Program stability:** the CVE program had funding uncertainty in 2025–2026 (reportedly since stabilized). Mirroring multiple sources (CVE List on GitHub, OSV, EUVD) adds resilience.
- **Rate limits:** NVD API (use API key), GitHub API; prefer bulk downloads.
- **Agent footprint & privacy** on desktops — keep collection to software inventory only.

---

## 11. Useful tools (open source)

| Tool | Role |
|---|---|
| Syft | SBOM generation (images, filesystems, archives) |
| Grype | Vulnerability matching on SBOMs |
| Trivy (+ Trivy Operator) | All-in-one scanner (images, fs, repos, K8s, SBOM) |
| OSV-Scanner | Lockfile/repo scanning against OSV |
| osquery (+ Fleet) | Endpoint/server inventory via SQL, fleet management |
| OWASP Dependency-Track | SBOM portfolio, vuln tracking, policy, UI |
| CycloneDX CLI | SBOM convert/merge/validate |
| Vulnerability-Lookup (CIRCL) | Self-hostable vuln aggregator |
| csaf_distribution / csaf tooling | Fetch & validate vendor CSAF feeds |

---

## 12. Quick reference — endpoints

```
# CVE record
https://cveawg.mitre.org/api/cve/CVE-2021-44228
https://github.com/CVEProject/cvelistV5

# NVD
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=log4j

# OSV
https://api.osv.dev/v1/vulns/CVE-2021-44228
POST https://api.osv.dev/v1/query  {"package":{"purl":"pkg:pypi/django@4.2.1"}}

# KEV
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# EPSS
https://api.first.org/data/v1/epss?cve=CVE-2021-44228

# EUVD
https://euvdservices.enisa.europa.eu/api/vulnerabilities
https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities

# CISA Vulnrichment
https://github.com/cisagov/vulnrichment
```

---

## 13. Open questions

- Fleet size and OS mix (how many Windows/macOS endpoints vs Linux servers)?
- Existing MDM / CMDB to reuse for inventory and asset context?
- Language for the engine (Go aligns with Syft/Grype/Trivy libraries; Python is faster to prototype)? → see [ADR-0001](../decisions/0001-language-python-uv-mise.md)
- Self-hosted only, or acceptable to use commercial feeds (VulnCheck, Snyk)?
- Where do findings go — Jira, ServiceNow, Slack, email?

---

## 14. References

- CVE Program — https://www.cve.org
- NVD — https://nvd.nist.gov
- CSA research notes on NVD enrichment triage (Apr 2026) — https://labs.cloudsecurityalliance.org
- OSV — https://osv.dev
- GitHub Advisory Database — https://github.com/advisories
- ENISA EUVD — https://euvd.enisa.europa.eu
- CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS — https://www.first.org/epss
- PURL spec — https://github.com/package-url/purl-spec
- CPE spec — https://nvd.nist.gov/products/cpe
- CycloneDX — https://cyclonedx.org · SPDX — https://spdx.dev
- CSAF — https://oasis-open.github.io/csaf-documentation/
- OpenVEX — https://github.com/openvex/spec
