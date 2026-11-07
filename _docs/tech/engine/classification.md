---
title: Classification — recognizing and categorizing software
type: tech
context: tech
status: implemented
tags: [engine, classification, purl, cpe]
updated: 2026-11-07
code: src/secmonk/engine/classify.py
related: [tech/engine/matching.md, tech/collectors/README.md]
---

# Classification

Collectors report *what they saw*; `engine.classify.classify()` turns it into an identity the
matcher can use. It is idempotent and runs before components are stored.

## Categories

| Category | Meaning | Typical identity | Match strategy |
|---|---|---|---|
| `os` | The operating system itself | vendor/product (`apple:macos`), os-release `ID` | product |
| `os-package` | dpkg / apk / rpm package | `pkg:deb|apk|rpm` + `distro=` → OSV ecosystem `Debian:12` … | package (by **source** package) |
| `library` | Language package | `pkg:pypi|npm|maven|golang|cargo|gem|nuget|composer` | package |
| `application` | End-user app (.app bundle, cask) | bundle id / name → alias table → vendor/product + CPE | product |
| `system-app` | App shipped with the OS (Safari) | as application | product |
| `package` | Package-manager item without an OSV ecosystem (Homebrew formula, pkgutil receipt) | `pkg:brew/...`, receipt id → alias table | product |
| `runtime` | Embedded runtime/framework (Electron, CEF, Sparkle) | `pkg:npm/electron` when it exists in an ecosystem, else product | package or product |

## Rules

1. **PURL → ecosystem.** Language purl types map 1:1 to OSV ecosystems (`engine/purl.py:PURL_TO_OSV`).
   Distro purls use the `distro` qualifier → `osv_distro_ecosystem(id, version_id)`:
   `alpine 3.20.3 → Alpine:v3.20`, `debian 12.7 → Debian:12`, `ubuntu 22.04 → Ubuntu:22.04`,
   `rhel/rocky/almalinux 9.4 → Red Hat:9 / Rocky Linux:9 / AlmaLinux:9`.
   OSV-side ecosystem strings are collapsed by `normalize_ecosystem()` to the same keys
   (`Ubuntu:Pro:18.04:LTS → Ubuntu:18.04`, `Red Hat:enterprise_linux:9::appstream → Red Hat:9`).
2. **Name normalization** (`normalize_ecosystem`-aware): PyPI PEP 503 (`[-_.]+ → -`, lowercase),
   most others lowercase; Go/Maven kept as-is.
3. **Product identity** for everything without an ecosystem: look up `bundle_id`, `brew_name`,
   then the name, then the normalized name (`normalize_product_name`: strip `.app`, `@3`,
   arch/edition noise, years) in the curated **alias table** `src/secmonk/data/product_aliases.yaml`.
   Hit → `vendor`, `meta.product`, `meta.product_source=alias-table`, and a CPE 2.3 string.
   Miss → `meta.product = normalized name`, `product_source=normalized-name` (lower confidence).
4. `secmonk inventory unmatched` lists components that fell back to the normalized name — the
   work queue for growing the alias table (vision §6.1 "name → CPE resolver" R&D).

## Next steps

- Use NVD CPE dictionary for fuzzy name → CPE resolution with a similarity score.
- Use bundle-id vendor hints and Homebrew `homepage` URLs as extra evidence.
