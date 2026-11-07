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
| `cve-product` / `cpe-product` | everything else (apps, brew, runtimes, OS) | `affected.product IN (meta.product, normalized name)` with range types CVE / CPE; vendor must match when both known | generic tolerant comparator (see *Generic versions*); a version without any digit never matches | base by `meta.product_source`: `brew-seed` 0.85, `alias-table` 0.8, `brew-name-vendor` 0.7, `normalized-name` 0.5 (0.4 for brew formulae); −0.2 without vendor confirmation, −0.2 unparseable version (generic: does not start with a digit, e.g. `build 120`); with `meta.vendor_hint` (no `vendor`): a row vendor consistent with the hint keeps the base, a different one is −0.4 |

Distro backports are handled by construction: OS packages only ever match distro ecosystems,
never upstream CVE ranges (vision §7).

RPM versions are compared as `epoch:version-release` (collectors always emit an epoch, `0:` by
default) because OSV RPM fixed versions carry an epoch.

Name-based lookups normalize the component's product candidates, `vendor` and `meta.vendor_alts` like
`affected.vendor/product` (lowercase, `_` → space): `kerberos_5` and `kerberos 5` are the same product.

**Per-release-line CNA entries** (Apple lists one `macOS` entry per train, each `unspecified < X`): when one
CVE has several upper-bound-only rows (`introduced 0` + one `fixed`/`last_affected`) for the same
vendor/product whose bounds are on different majors, every row except the lowest-major one is lower-bounded at
its own major (`< 14.4` → `[14.0, 14.4)`). A patched Ventura `13.6.6` no longer matches Sonoma's `< 14.4`; a
version older than every listed train (`12.7`) still matches the lowest train's row. Only applied to
CVE/CPE product rows, never to package (OSV) ranges.

### Generic versions

`engine/versions.py:_generic_key` (vendor/product versions, and the fallback for unparseable ecosystem
versions) orders tokens as **number > post-release word > padding/final > pre-release word**:
`1.0-rc1 < 1.0 == 1.0.0 == 1.0.Final < 1.0p1 < 1.0a < 1.0.1`; `1.1.1t < 1.1.1w`; `9.8 < 9.8p1`.
Post-release words: `p`/`pl`/`patch`/`post`, letters glued to a number (OpenSSL `1.1.1w`) and unknown words.
Pre-release words: `dev`, `alpha`, `beta`, `m`, `pre`, `preview`, `rc`, and `a`/`b` only after `-`, `.` or `~`.
Zero components and `final`/`ga`/`release` at the end of a numeric group are ignored (`1.0.0-rc1 == 1.0-rc1`).
Real ecosystems keep using `univers`.

### OSV range evaluation

`in_osv_range` follows the OSV evaluation algorithm: events are sorted by version (`introduced: "0"` first;
equal versions: introduced < last_affected < fixed), then walked — `introduced <= v` sets affected (a second
`introduced` while affected is a no-op), `fixed <= v` clears it, `last_affected < v` clears it; `limit` caps
the range. The order of events in the record is irrelevant.

Vendor handling: a known `vendor` drops rows of another vendor (any of `meta.vendor_alts` is accepted; `meta.product_alts`
extend the product lookup). A guessed `meta.vendor_hint` (brew formulae, bundle ids) never drops rows; it raises/lowers
confidence. "Consistent" = equal after removing punctuation, or one contains the other (>= 4 chars).

**Formula-patched CVEs**: `meta.patched_cves` (Homebrew `patch ... resolves "CVE-x"`, see
[homebrew collector](../collectors/homebrew.md)) removes the finding for those CVE ids (any alias); counted as `patched` in the
match stats. A Homebrew `3.6.4_1` can be fixed although upstream `3.6.4` is in the CVE range.

## Canonicalization & dedupe

`engine.match.canonical_ids(conn, id) -> (canonical id, alias set)` walks the `alias` table over
**alias edges only** (`alias.kind = 'alias'`, old rows without the column count as aliases; OSV `upstream`
and `related` edges are never followed). The walk is breadth-first with a sorted frontier (deterministic),
capped at 500 nodes (a warning is logged when hit). A CVE id is its own canonical id; another id maps to the
lowest CVE of its set (numeric order), else the lowest id of the set. Within one `match_asset` run every
visited node is cached, so a component of N aliases costs N queries once.

Finding keys of a matched advisory (`_finding_keys`):
- a CVE record → that CVE;
- another advisory → one key per CVE in its alias set (a GHSA listing two CVEs = two findings), else its
  canonical id;
- plus one key per OSV `upstream` id (`alias.kind = 'upstream'`; an RHSA / DSA fixing three CVEs = three
  findings), each with the advisory's fixed version. Upstream lists never merge distinct CVEs, neither on
  the same nor on other assets.

Findings are unique per `(asset, component, key)`; `advisory_ids` holds the key's aliases plus the matched
advisories. Merging several matches of one key: the higher confidence wins the strategy, distro
`urgency`/package/source version are carried over from whichever match has them (order-independent), and the
**fixed version is the highest** fix above the installed version (every matched advisory satisfied).

**Withdrawn**: a finding is dropped only when *every advisory that actually matched* is withdrawn/REJECTED,
or its canonical CVE is REJECTED (state compared case-insensitively). A withdrawn duplicate GHSA no longer
hides the valid advisory. Withdrawn/rejected records never feed CVSS/severity.

**Canonical drift**: when no finding exists yet under the key, an existing finding of the same component
keyed by one of the match's non-CVE advisory ids (e.g. the GHSA before its CVE alias appeared) is re-keyed
(`UPDATE vuln_id`), keeping `status` (suppressed stays suppressed) and `first_seen`.

## Enrichment

Facts come from all aliases: CVSS/severity by source preference `nvd > cvelist > osv > euvd`,
`kev` from the KEV table, `epss` = max score across the finding's CVE (or its CVE aliases when the key
is not a CVE). The key's own records win over its aliases' records.

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
Without a numeric CVSS score (e.g. OSV records carrying only a CVSS v4 vector) the severity label stands in:
CRITICAL 9.0, HIGH 7.0, MEDIUM 5.0, LOW 3.0.
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
  Mitigations (implemented): OSV urgency and the Debian tracker feed `finding.triage` (see above), plus
  `secmonk findings --fixable`. The tracker importer itself is validated on **synthetic** fixtures only
  (host blocked in the sandbox, see [debian-tracker](../../references/vuln-sources/debian-tracker.md)); Ubuntu/Alpine/Red Hat triage is not ingested.

- No VEX ingestion yet; Mozilla-style "unaffected-only" CNA records are stored but not used.
- Name-based matching is precision-limited by the alias table size.
- `GIT` ranges and unparseable CNA versions are stored, not matched.
