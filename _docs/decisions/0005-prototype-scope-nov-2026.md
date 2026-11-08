---
title: ADR-0005 — Prototype scope (November 2026)
summary: Current prototype scope as of November 2026 - the eight sources, collectors, native engine, Inventory dataclass as exchange format, and what is deferred (SBOM export, VEX, UI). Supersedes ADR-0003.
read_when: you need to know what is in or out of scope for the prototype or question why there is no SBOM export or Grype integration
type: decision
context: decisions
status: accepted
tags: [scope, roadmap]
updated: 2026-11-07
verified: 2026-11-07
supersedes: decisions/0003-prototype-scope.md
related: [product/vision.md, tech/architecture.md, plans/README.md]
---

# ADR-0005 — Prototype scope (November 2026), supersedes ADR-0003

## Context
[ADR-0003](0003-prototype-scope.md) set the first-prototype goals and assumed collectors would emit CycloneDX. The prototype has since
implemented all three goals and more; the exchange format turned out to be a Python dataclass plus SQLite, not an SBOM file.

## Decision
In scope and implemented (see [features/README.md](../features/README.md)):
- **Eight vulnerability sources** into the local mirror: OSV (incl. GHSA, distros), CVE List v5, CISA KEV, EPSS, NVD, EUVD, MSRC and the Debian
  Security Tracker.
- **Collectors**: macOS, Homebrew, Docker image (registry / tarball / OCI), Docker engine, rootfs, language dependencies (`fs`), SSH
  (Linux/macOS/Windows) and Windows (script / osquery / live).
- **Native matching engine** in Python (OSV ranges, CVE/CPE product ranges, canonical ids, distro triage, KEV/EPSS priority); no Grype/Trivy.
- **Exchange format**: the `Inventory` dataclass (`src/secmonk/models.py`: `Asset`, `Component`, warnings, `partial`) produced by every
  collector and consumed by the engine, persisted in SQLite ([ADR-0004](0004-sqlite-schema-v2.md)). Inventory JSON can be written with
  `collect -O`.
- **CLI-first**, results as table / json / csv, exit codes for CI (`scan --fail-on`).

Deferred (planned, not implemented): **CycloneDX/SPDX export**, VEX ingestion/export, Dependency-Track integration, a UI, scheduling,
agents, CMDB-fed asset context (production / internet-facing flags are read from `asset.meta` but nothing fills them). Open work is
tracked in [plans/](../plans/README.md).

## Consequences
- Full control of the data end to end, at the cost of owning parsers and the matching engine.
- Interop with SBOM tooling needs an exporter (a thin mapping from `Inventory`); until then the vision's SBOM output is a plan.
