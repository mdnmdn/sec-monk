---
title: Matching, enrichment and prioritization
type: tech
context: tech
status: implemented
tags: [engine, matching, versions, prioritization]
updated: 2026-11-07
code: src/secmonk/engine/match.py
related: [tech/engine/classification.md, tech/data-model.md]
---

# Matching

`engine.match.match_asset(conn, asset_id)` evaluates the components of the asset's latest scan.

## Strategies

| Strategy (`matched_by`) | Applies to | Lookup | Version semantics | Confidence |
|---|---|---|---|---|
| `osv-package` | `library`, `os-package` with an ecosystem | `affected.ecosystem = component.ecosystem AND package IN (name, meta.source_package)`; range types ECOSYSTEM / SEMVER / VERSIONS | ecosystem-specific via `univers` (Debian, RPM, Alpine, PEP 440, semver, Maven, Go…) on `meta.source_version` if present | 1.0 |
| `cve-product` / `cpe-product` | everything else (apps, brew, runtimes, OS) | `affected.product IN (meta.product, normalized name)` with range types CVE / CPE; vendor must match when both known | generic tolerant comparator | base by `meta.product_source`: `brew-seed` 0.85, `alias-table` 0.8, `brew-name-vendor` 0.7, `normalized-name` 0.5 (0.4 for brew formulae); −0.2 without vendor confirmation, −0.2 unparseable version; with `meta.vendor_hint` (no `vendor`): a row vendor consistent with the hint keeps the base, a different one is −0.4 |

Distro backports are handled by construction: OS packages only ever match distro ecosystems,
never upstream CVE ranges (vision §7).

RPM versions are compared as `epoch:version-release` (collectors always emit an epoch, `0:` by
default) because OSV RPM fixed versions carry an epoch.

Vendor handling: a known `vendor` drops rows of another vendor (any of `meta.vendor_alts` is accepted; `meta.product_alts`
extend the product lookup). A guessed `meta.vendor_hint` (brew formulae, bundle ids) never drops rows; it raises/lowers
confidence. "Consistent" = equal after removing punctuation, or one contains the other (>= 4 chars).

**Formula-patched CVEs**: `meta.patched_cves` (Homebrew `patch ... resolves "CVE-x"`, see
[homebrew collector](../collectors/homebrew.md)) removes the finding for those CVE ids (any alias); counted as `patched` in the
match stats. A Homebrew `3.6.4_1` can be fixed although upstream `3.6.4` is in the CVE range.

## Canonicalization & dedupe

Each matched advisory id is expanded over the `alias` graph; the canonical id is the lowest CVE
id among the aliases (else the advisory id). Findings are unique per
`(asset, component, canonical id)`; all advisory ids are kept in `advisory_ids`.
Withdrawn/REJECTED records drop the finding.

## Enrichment

Facts come from all aliases: CVSS/severity by source preference `nvd > cvelist > osv > euvd`,
`kev` from the KEV table, `epss` = max score across CVE aliases.

## Prioritization (vision §8, `engine/scoring.py`)

```
KEV                         → P1
EPSS ≥ 0.1 and exposed      → P1
CVSS ≥ 9   and exposed      → P2
EPSS ≥ 0.1                  → P2
CVSS ≥ 7                    → P3
else                        → P4
modifiers: env=production −1 level, internet-facing −1 level (only below P2)
```
`exposed`/`internet_facing`/`env` are read from `asset.meta` (to be fed by CMDB/labels).

## Lifecycle

Re-matching an asset marks open findings that are no longer produced as `fixed` (`fixed_at`);
a finding that reappears is re-opened (regression). `suppressed` is sticky (future VEX).

## Distro triage (Debian)

Distro security teams triage CVEs beyond "affected range": *unimportant*, *no-dsa*, *postponed*,
*ignored*, *end-of-life*, *not-affected*. The matcher uses two inputs for OS-package findings:

| Input | Where it comes from | Stored in |
|---|---|---|
| OSV urgency | `affected[].ecosystem_specific.urgency` of OSV Debian records | `affected.extra.urgency` |
| Tracker triage | Debian Security Tracker JSON / security-tracker repo (`sync debian-tracker`) | `distro_triage` table |

Rules (`engine/match.py:_triage`, tracker wins over OSV):
1. Tracker says `not-affected` (or fixed version `0`) → finding dropped (`stats.not_affected`).
2. Tracker `resolved` with fixed version ≤ installed version → dropped (tracker newer than OSV snapshot).
3. Label = tracker `nodsa` (no-dsa / postponed / ignored) → tracker urgency → OSV urgency
   (`not yet assigned` is ignored). Stored as `finding.triage` + `finding.triage_source`.
4. Priority (`engine/scoring.py`): `unimportant` / `ignored` / `end-of-life` → **P4**;
   `no-dsa` / `postponed` / `low` → at most **P3**; **KEV overrides** all caps.

CLI: `secmonk findings --hide-minor` (hides unimportant/ignored/end-of-life),
`--hide-deferred` (also no-dsa/postponed), `--fixable`.

Measured 2026-11-07 on real `python:3.12-slim` (Debian 13) with OSV urgency only: 193 findings →
46 labelled *unimportant* (now P4, hidden by `--hide-minor`), e.g. glibc CVE-2019-1010022
(CVSS 9.8, previously P3). 53.5k of 61k Debian 13 OSV ranges are *not yet assigned*, so tracker
data (no-dsa/postponed/not-affected) is expected to reduce noise further.

## Known gaps

- **Unfixed distro CVEs:** OSV Debian carries open ranges (no `fixed` event) for CVEs the Debian
  tracker marks *unimportant* / *no-dsa* (e.g. CVE-2019-1010022 on glibc). A real
  `python:3.12-slim` (Debian 13) scan on 2026-11-07 gave 193 findings, most of them without a fix.
  Mitigations: `secmonk findings --fixable`; later, ingest the Debian tracker `urgency`/status to
  downgrade or suppress them (see references/vuln-sources/distros.md).

- No VEX ingestion yet; Mozilla-style "unaffected-only" CNA records are stored but not used.
- Name-based matching is precision-limited by the alias table size.
- `GIT` ranges and unparseable CNA versions are stored, not matched.
