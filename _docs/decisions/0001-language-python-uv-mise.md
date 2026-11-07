---
title: ADR-0001 — Python 3.13 with mise + uv
type: decision
context: decisions
status: accepted
tags: [language, tooling]
updated: 2026-11-07
---

# ADR-0001 — Python 3.13, managed with mise + uv

## Context
The engine language was an open question (vision §13). Go aligns with Syft/Grype/Trivy; Python is
faster to prototype and has mature libraries for the hard parts: `univers` (version range semantics
for deb, rpm, apk, semver, PEP 440, Maven, gem, nuget…), `packageurl-python` (PURL), `httpx`.

## Decision
- Python 3.13, `src/` layout, package `secmonk`, console script `secmonk`.
- `mise` pins tool versions (`mise.toml`: python, uv); `uv` manages the venv, deps and lockfile.
- Version comparison delegated to **univers** — no home-grown comparators (vision §7).
- External scanners (Syft/Trivy/Grype) are **optional** accelerators, never required.

## Consequences
- Fast iteration, easy fixtures/tests with pytest.
- If throughput becomes an issue, hot paths (matching) can be ported to Go later behind the same
  SQLite schema, which is the integration contract.
