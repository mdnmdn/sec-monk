---
title: ADR-0003 — Prototype scope and ordering
summary: Superseded first-prototype scope and ordering (sources, recognition, system exploration, native matching). Read ADR-0005 for the current scope.
read_when: you want the history of the first prototype goals, otherwise you read ADR-0005 instead
type: decision
context: decisions
status: superseded
tags: [scope, roadmap]
updated: 2026-11-07
verified: 2026-11-07
---

# ADR-0003 — Prototype scope and ordering

> Superseded by [ADR-0005](0005-prototype-scope-nov-2026.md): current scope; collectors do not emit CycloneDX (deferred).

## Context
The vision roadmap starts with images/repos via Syft→Grype and Dependency-Track. For the first
prototype we want to understand the data end-to-end ourselves before adopting heavy components.

## Decision
CLI-first prototype with three goals, in this order:
1. **Fetch and structure vulnerabilities** from multiple sources into SQLite (CVE List v5,
   OSV bulk, CISA KEV, EPSS, NVD, EUVD, GHSA via OSV).
2. **Recognize and categorize** software: assign PURL / CPE-like identity and a category
   (`os-package`, `library`, `application`, `runtime`…).
3. **Explore a system**: macOS desktop first (apps, Homebrew, pkgutil), then Docker
   (image exploration via registry/tarball, then the live container engine).

Matching is native Python (OSV ranges via univers; CVE `affected` for name-based apps).
Grype/Trivy integration is deferred.

## Consequences
- More code than wiring Grype, but full control and understanding of the data.
- Dependency-Track can still be fed later: collectors emit CycloneDX.
