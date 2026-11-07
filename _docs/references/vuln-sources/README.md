---
title: Vulnerability data sources — index
type: reference
context: references
status: draft
tags: [vuln-source, index]
updated: 2026-11-07
---

# Vulnerability data sources (external references)

One file per source. Each is written from **real samples** fetched on the probe date; trimmed
samples live in `tests/fixtures/sources/<source>/` and double as test fixtures.

## Index

| Source | Doc | Role in prototype | Reachable from dev sandbox (2026-11-07) |
|---|---|---|---|
| CVE List v5 (+ CISA Vulnrichment ADP) | [cvelist-v5.md](cvelist-v5.md) | Canonical CVE records, `affected`, CVSS, CWE, SSVC | ✅ via `raw.githubusercontent.com` / git |
| OSV.dev (bulk) | [osv.md](osv.md) | PURL / ecosystem + distro matching (incl. GHSA, PyPA, Go, RustSec, Debian, Ubuntu, Alpine…) | ✅ bulk zips on GCS · ❌ `api.osv.dev` |
| GitHub Advisory DB | [ghsa.md](ghsa.md) | Via OSV (same OSV format) | ✅ raw / git · ❌ REST API (403) |
| CISA KEV | [kev.md](kev.md) | Exploited-in-the-wild flag | ✅ via `cisagov/kev-data` mirror · ❌ `www.cisa.gov` |
| FIRST EPSS | [epss.md](epss.md) | Exploitation probability | ❌ (`api.first.org`, `epss.empiricalsecurity.com`) |
| NVD 2.0 | [nvd.md](nvd.md) | CPE applicability, CVSS | ❌ (`services.nvd.nist.gov`) |
| ENISA EUVD | [euvd.md](euvd.md) | EU redundancy, exploited view, EPSS | ❌ |
| Microsoft MSRC CVRF | [msrc.md](msrc.md) | Per-product fixed builds + KBs for Windows | ❌ (`api.msrc.microsoft.com`; CNA records of the same data via CVE List ✅) |
| Distro trackers (Debian, Alpine secdb, Ubuntu, Red Hat) | [distros.md](distros.md) | Backport-aware OS package matching | Ubuntu ✅ · others ❌ (covered via OSV) |

"❌" means blocked by the **sandbox egress policy** used during development, not by the source.
Implementations exist for blocked sources too; they are exercised with fixtures and should be
validated from an unrestricted network.

## Template

New source docs start from [`_meta/templates/reference-vuln-source.md`](../../_meta/templates/reference-vuln-source.md).
