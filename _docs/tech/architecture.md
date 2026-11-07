---
title: Prototype architecture
type: tech
context: tech
status: implemented
tags: [architecture, cli, engine, collector, vuln-source]
updated: 2026-11-07
code: src/secmonk/
related: [product/vision.md, tech/data-model.md, decisions/0003-prototype-scope.md, tech/collectors/README.md, tech/engine/matching.md, tech/engine/classification.md, features/README.md]
---

# Prototype architecture

The prototype implements the vision's *"different collectors, one shared engine"* as a single
Python package with a CLI and a SQLite file as the only state.

```
 secmonk sync <source>                                   secmonk collect|scan <collector> <target>
        |                                                                  |
 +------v---------------------------------+      +-------------------------v------------------------------+
 | sources/  (8, one module per feed)     |      | collectors/  (9 registered)                            |
 |  osv cvelist kev epss nvd euvd         |      |  macos  homebrew  rootfs  docker-image  docker-engine  |
 |  msrc debian-tracker                   |      |  fs  ssh  windows  process (running processes)        |
 |  download | --path import -> normalize |      |  each -> Inventory(Asset, [Component], warnings)       |
 +------+---------------------------------+      |                                                        |
        |                                        |  shared helpers                                        |
        |                                        |   collectors/lang/  parser REGISTRY (7 ecosystems)     |
        |                                        |     walk_dir() for directories (fs, rootfs, homebrew,  |
        |                                        |       ssh harvest dir) ; LangAccumulator.feed() for    |
        |                                        |       streamed layers (docker-image, docker-engine)    |
        |                                        |   rootfs.py  dpkg/apk/rpm + OS (DirView/LayeredTarView)|
        |                                        |   harvest.py fixed read-only remote script + safe tar  |
        |                                        |     extract (ssh) ; windows.py PowerShell JSON/osquery |
        |                                        +-------------------------+------------------------------+
        |                                                                  | classify() on every component
        |                                                                  | identity: PURL->OSV ecosystem | alias table
        |                                                                  |   | brew seed | Windows product hints
        v                                                                  v
 +--------------------------------------- SQLite (secmonk.db, schema v2) ---------------------------------------+
 | source_sync raw_record vulnerability alias affected kev epss distro_triage | asset scan component asset_component |
 +----------------------------------------------------------+-----------------------------------------------------+
                                                            v
              engine/match.py  strategies: osv-package | cve-product | cpe-product
                               canonicalize (alias graph) -> enrich (CVSS/EPSS/KEV) -> distro triage (_triage)
                               -> engine/scoring.py priority P1-P4 (triage caps, KEV overrides)
                                                            v
                      finding  (lifecycle open -> fixed, regression re-opens, suppressed sticky)
                                                            v
              secmonk findings [--fixable --hide-minor --hide-deferred] | vuln show/search | inventory ...
```

## Modules

| Module | Responsibility |
|---|---|
| `db.py` | Schema v2 (the integration contract), connection, additive migration, sync-state helpers. See [data-model](data-model.md). |
| `models.py` | `Component`, `Asset`, `Inventory` dataclasses + category constants. |
| `sources/base.py` | `Source` interface + registry, `SyncOptions/SyncResult`, write helpers (`store_raw`, `upsert_vulnerability`, `add_alias`, `add_affected`, `replace_children`), proxy-aware `http_client()`. |
| `sources/osv.py` | OSV bulk per ecosystem (zip, then per-ecosystem `modified_id.csv` delta). |
| `sources/cvelist.py` | CVE List v5 + CISA ADP: sparse git clone (default), per-id raw fetch (`--id`, `@referenced`), local dir. CNA `affected` and `cpeApplicability` to `CVE`/`CPE` rows. |
| `sources/kev.py`, `epss.py` | KEV snapshot (cisa.gov, GitHub mirror fallback); EPSS bulk CSV or API by id. |
| `sources/nvd.py`, `euvd.py` | NVD API 2.0 (CVSS, CWE, CPE ranges, 119-day windows); ENISA EUVD (aliases, exploited flag). |
| `sources/msrc.py` | Microsoft CVRF v3: fixed builds + KBs per product (second source for Windows; the CNA records in cvelist carry the same ranges). |
| `sources/debian_tracker.py` | Debian Security Tracker JSON or repo checkout into `distro_triage`. |
| `collectors/base.py` | `Collector` interface + registry. Collectors never touch the DB. |
| `collectors/macos.py` | `.app` bundles, pkgutil receipts, OS version, Electron/Sparkle runtimes; Homebrew via `homebrew.py`. |
| `collectors/homebrew.py` | Active kegs from Cellar/`opt`, INSTALL_RECEIPT, casks, vendored PyPI/npm packages (via `walk_dir`), formula `patch ... resolves` CVEs. |
| `collectors/rootfs.py` | OS + dpkg/apk/rpm parsers, `DirView` (directory) and `LayeredTarView` (layers + whiteouts), language packages via `collectors/lang`. |
| `collectors/docker_image.py` | Registry v2 client (anonymous token, retries, digest-verified blob cache), `docker save` tarball, OCI layout. Feeds layers to `LayeredTarView`. |
| `collectors/docker_engine.py` | Engine socket (Docker/Podman) read-only GETs: container `export` tar or image `save`. |
| `collectors/fs.py` | Folder/repo: `walk_dir` over lockfiles, manifests, installed packages, binaries; git info in asset meta. |
| `collectors/harvest.py`, `ssh.py` | Agentless SSH: fixed `find | tar` script, safe extraction into a temp dir, then rootfs/macOS/windows code on it. OpenSSH or paramiko transport. |
| `collectors/windows.py` | Windows inventory JSON (script), osquery rows or live `winreg`; OS build identity, display-name cleanup. Script in `src/secmonk/data/windows/`. |
| `collectors/process/` | Process monitor: platform-neutral `Snapshot` + JSON format, shared launch classification and risk flags, per-OS backends (`macos.py`: ps, launchctl, launchd plists, bundle/keg/pkgutil/binary identity, codesign, quarantine). See [process](collectors/process.md). |
| `procmon.py` | `secmonk procs` views: process tree rows joined with findings, `Watcher` for `--watch`. |
| `collectors/lang/*.py` | `base.py` registry (`LangParser`, evidence ranks, `dedupe`), parsers: javascript, python, php, golang, rust, java, dotnet; `walk.py` (`walk_dir`, `LangAccumulator`, `WalkLimits`). |
| `engine/purl.py` | PURL helpers, PURL to OSV ecosystem mapping, ecosystem and name normalization. |
| `engine/versions.py` | Version comparison per ecosystem (`univers`), OSV range evaluation, tolerant generic comparator. |
| `engine/classify.py` | Category / ecosystem / vendor / product / CPE assignment (see identity sources below). |
| `engine/inventory.py` | Persist inventories; "current components" of an asset. |
| `engine/match.py` | Matching strategies, alias canonicalization, enrichment, distro triage, finding lifecycle. |
| `engine/scoring.py` | Priority rules (vision section 8) + triage caps. |
| `cli.py` | Typer CLI: see [features/README.md](../features/README.md#cli-at-a-glance). |

## Classification identity sources

| Source | Applies to | `meta.product_source` | Base confidence |
|---|---|---|---|
| PURL / OSV ecosystem | language + distro packages | n/a (exact package match) | 1.0 |
| `brew_cpe_seed.csv` | Homebrew formulae | `brew-seed` | 0.85 |
| `product_aliases.yaml` (bundle id, brew name, name, `meta.product_hint` incl. Windows hints) | apps, brew, Windows programs/Appx/Chocolatey/Scoop, OS | `alias-table` | 0.8 |
| upstream repo / homepage vendor guess | Homebrew formulae | `brew-name-vendor` | 0.7 |
| normalized name | anything left (`secmonk inventory unmatched`) | `normalized-name` | 0.5 (0.4 brew formulae) |

Details: [classification](engine/classification.md). The Windows OS component is classified by the collector's build table (`alias-table`).

## Matching strategies

| `matched_by` | Components | Data | Notes |
|---|---|---|---|
| `osv-package` | library, os-package with an ecosystem | `affected` ECOSYSTEM / SEMVER / VERSIONS rows | Distro packages by source package; confidence 1.0 (lower for weak jar-by-filename) |
| `cve-product` | apps, brew formulae, runtimes, OS | CNA `affected` (`CVE`), MSRC rows | Vendor must agree when known |
| `cpe-product` | same | NVD / cvelist CPE rows | `introduced_exclusive` approximated as inclusive start, equal version excluded |

After matching: **distro triage** (`_triage`: tracker `not-affected` / fixed-in-tracker drops the finding; label from
tracker `nodsa`, tracker urgency, then OSV urgency, stored as `finding.triage` + `triage_source`) and **scoring**
(KEV P1; minor triage P4; no-dsa/postponed/low at most P3; KEV overrides). `GIT` and `CVE-UNPARSED` rows are stored, never matched.
Formula-patched CVEs (`meta.patched_cves`) are dropped. See [matching](engine/matching.md).

## Findings lifecycle

`open` on first detection; re-matching an asset sets findings no longer produced to `fixed` (`fixed_at`); a finding that
reappears re-opens; `suppressed` is sticky. `secmonk findings` shows open only unless `--all`.

## Data flow per target

| Target (CLI) | Collector | Evidence read | Asset id | Matching strategy |
|---|---|---|---|---|
| `scan macos [/]` | macos (+ homebrew code) | `.app` Info.plist, pkgutil receipts, Homebrew prefix, OS version | `macos:<host>` | cve/cpe-product for apps, OS, brew; osv-package for vendored PyPI/npm |
| `scan homebrew [prefix]` | homebrew | Cellar kegs, `opt/` links, receipts, formula `.rb`, casks, vendored `dist-info` / `node_modules` | `homebrew:<host>` | cve-product (seed/alias/vendor-hint confidence) + osv-package for vendored libs |
| `scan rootfs <dir>` | rootfs (`DirView`) | os-release, dpkg status / apk db / rpmdb.sqlite, lang files via `walk_dir` | `rootfs:<path>` | osv-package (distro ecosystems by source package, language ecosystems) + triage |
| `scan docker-image <ref / tar / dir>` | docker-image (`LayeredTarView`) | whitelisted files of each layer in order with whiteouts; lang files parsed while streaming (`LangAccumulator`) | `image:<repo>@<digest>` | same as rootfs |
| `scan docker-engine <name / image:ref>` | docker-engine (`LayeredTarView`) | container `export` stream (or image save) through the engine socket | `container:<name>` | same as rootfs |
| `scan fs <dir>` | fs | lockfiles, manifests, installed metadata, Go/Rust/jar binaries via `walk_dir` | `repo:<path>` / `dir:<path>` | osv-package (7 ecosystems) |
| `scan ssh user@host` | ssh + harvest | fixed read-only `find` + `tar` stream, extracted to a temp dir, then rootfs / macOS code; Windows hosts: PowerShell inventory script on stdin | `ssh:<host>[:<port>]` (also for Windows hosts) | as rootfs / macOS / windows |
| `scan process [snapshot.json]` / `procs` | process (+ macos/homebrew/lang code) | live `ps` + `launchctl` + launchd plists, or a snapshot file; per executable: bundle, keg, pkgutil, Go/Rust build info, codesign, quarantine | `process:<host>` | as macos (cve/cpe-product, osv-package for Go/Electron) |
| `scan windows [inv.json]` | windows | script JSON, osquery rows, or live registry: OS build + UBR, Uninstall keys, Appx, Chocolatey, Scoop, .NET | `windows:<host>` | cve-product on per-build ranges (CNA/MSRC) + alias-table apps |

## Principles

- **Scans never call external vulnerability APIs** - only the local mirror (vision section 6).
  Collectors may pull images from registries (that's the target, not vuln data).
- **Raw first:** every imported record is kept verbatim in `raw_record` (OSV raw storage can be
  disabled with `SECMONK_OSV_STORE_RAW=0` for big ecosystems).
- **Same CVE, many sources:** rows are keyed `(source, id)`; `alias` links ids; the matcher
  canonicalizes to the CVE id and picks facts by source preference `nvd > cvelist > osv > euvd`.
- **Read-only collection:** nothing is executed on the target except the fixed SSH scripts, the read-only Windows script and the process monitor's fixed read-only commands (`ps`, `launchctl list`, `codesign -dv`, `pkgutil --file-info`); archives are never extracted blindly.
- **Evidence-based docs:** see [`_meta`](../_meta/README.md). What was validated on real data and which hosts are reachable: [probe log](../references/probes.md); open work: [plans](../plans/README.md).
