---
title: Vulnerability data sources — index
type: reference
context: references
status: reference
tags: [vuln-source, index, validation, network]
updated: 2026-11-07
related: [references/probes.md, features/vuln-sync.md, tech/architecture.md, references/package-formats/README.md, references/homebrew.md, references/windows-inventory.md]
---

# Vulnerability data sources (external references)

One file per source. Docs are written from **real samples** fetched on the probe date where the host was reachable; where it was not, the sample is
**synthetic** (format from published docs) and the doc says so. Trimmed samples live in `tests/fixtures/sources/<source>/` and double as test fixtures. Every endpoint probed, with result and the doc
or fixture it produced, is in the [probe log](../probes.md) (re-run with `scripts/probe_sources.sh`).

## Index

| Source | Role in prototype | Integration | Sample | Reachable from dev sandbox | Validated on real data? | Doc |
|---|---|---|---|---|---|---|
| CVE List v5 (+ CISA Vulnrichment ADP) | Canonical CVE records, vendor/product ranges (apps, brew, Windows), CVSS, CWE, SSVC | implemented (`sources/cvelist.py`) | real | partial ([probe log](../probes.md)) | yes: format analysed on the 2025 set (45,479 records); real Microsoft CNA records drive the Windows e2e tests; real jq CVE-2025-48060 drives the Homebrew e2e test; release-zip and CVE Services paths untested | [cvelist-v5.md](cvelist-v5.md) |
| OSV.dev (bulk) | PURL/ecosystem + distro matching (incl. GHSA, PyPA, Go, RustSec, Debian, Ubuntu, Alpine, Red Hat, Rocky, Alma) | implemented (`sources/osv.py`) | real | partial ([probe log](../probes.md)) | yes: Alpine and PyPI syncs timed, real image scans (alpine, debian-slim, python-slim, registry:2), `scan fs` on the lang fixtures | [osv.md](osv.md) |
| GitHub Advisory DB | Covered by OSV (same OSV format) | doc-only (no importer, by design) | real | partial ([probe log](../probes.md)) | indirectly: GHSA records arrive via OSV | [ghsa.md](ghsa.md) |
| CISA KEV | Exploited-in-the-wild flag (P1) | implemented (`sources/kev.py`, mirror fallback) | real | partial ([probe log](../probes.md)) | yes via mirror: real 1769-entry sample inspected; KEV P1 observed in the real-data `scan fs` run; `www.cisa.gov` path untested | [kev.md](kev.md) |
| FIRST EPSS | Exploitation probability | implemented (`sources/epss.py`) | synthetic | no ([probe log](../probes.md)) | no | [epss.md](epss.md) |
| NVD 2.0 | CVSS, CWE, CPE applicability | implemented (`sources/nvd.py`) | synthetic (a real flattened fkie-cad record was inspected) | no ([probe log](../probes.md)) | no | [nvd.md](nvd.md) |
| ENISA EUVD | EU redundancy, exploited view, alias bridge | implemented (`sources/euvd.py`; endpoint shapes unverified) | synthetic | no ([probe log](../probes.md)) | no | [euvd.md](euvd.md) |
| Microsoft MSRC CVRF | Per-product fixed builds + KBs for Windows | implemented (`sources/msrc.py`; response shape unverified) | synthetic | no ([probe log](../probes.md)) | no for MSRC; the equivalent CNA data is validated (see CVE List row) | [msrc.md](msrc.md) |
| Debian Security Tracker | `distro_triage`: not-affected / no-dsa / urgency per release | implemented (`sources/debian_tracker.py`; formats from documentation, not seen live) | synthetic | no ([probe log](../probes.md)) | no for the tracker; the OSV-urgency path is measured on real `python:3.12-slim` (193 findings, 46 *unimportant*) | [debian-tracker.md](debian-tracker.md) |
| Distro trackers (Debian, Alpine secdb, Ubuntu, Red Hat) | Backport-aware OS matching (via OSV); research notes | doc-only (OSV carries the data; only Debian tracker has an importer) | mixed | partial ([probe log](../probes.md)) | no (Ubuntu sample saved, not ingested) | [distros.md](distros.md) |

Per-host reachability, HTTP results and dates live **only** in the [probe log](../probes.md) (single table; this index shows the frontmatter summary).

**Status vocabulary** (same as the `status` / `sample` / `reachable` frontmatter): `implemented` = an importer exists in code with offline tests; *how far it was
validated* is carried by the Sample (real | synthetic | mixed), Reachable (yes | partial | no) and Validated columns, never by a separate "partial" status. `reference` / doc-only =
research notes without an importer.

"No" in the reachable column means blocked by the **sandbox egress policy** used during development, not by the source. Implementations
exist for blocked sources too; they are exercised with fixtures and should be validated from an unrestricted network
(`scripts/probe_sources.sh` then `secmonk sync <source>`).

## Inventory-side references

External formats and sources behind the collectors (not vulnerability feeds):

| Doc | Covers |
|---|---|
| [package-formats/README.md](../package-formats/README.md) | Lockfile / manifest / binary formats read by the language parsers (Go, Rust, Java, .NET, JavaScript, Python, PHP) |
| [homebrew.md](../homebrew.md) | Homebrew on-disk layout, receipts, SBOM, bottle registry, formula-to-CVE identity research |
| [windows-inventory.md](../windows-inventory.md) | Registry/Appx/winget/Chocolatey/Scoop/osquery, Microsoft CNA record shapes, MSRC CVRF |

## Template

New source docs start from [`_meta/templates/reference-vuln-source.md`](../../_meta/templates/reference-vuln-source.md).
