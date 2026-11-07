---
title: Prototype architecture
type: tech
context: tech
status: implemented
tags: [architecture, cli, engine]
updated: 2026-11-07
code: src/secmonk/
related: [product/vision.md, tech/data-model.md, decisions/0003-prototype-scope.md]
---

# Prototype architecture

The prototype implements the vision's *"different collectors, one shared engine"* as a single
Python package with a CLI and a SQLite file as the only state.

```
                 secmonk sync <source>                        secmonk collect|scan <collector> <target>
                        │                                                   │
      ┌─────────────────▼─────────────────┐              ┌──────────────────▼──────────────────┐
      │ sources/   (one module per feed)  │              │ collectors/   (one per target type) │
      │  osv  cvelist  kev  epss  nvd euvd│              │  macos  rootfs  docker-image        │
      │  download/import → normalize      │              │  docker-engine                      │
      └─────────────────┬─────────────────┘              │  → Inventory(Asset, [Component])    │
                        │                                └──────────────────┬──────────────────┘
                        ▼                                                   ▼
  ┌──────────────────────────────── SQLite (secmonk.db) ─────────────────────────────────────────┐
  │ raw_record  vulnerability  alias  affected  kev  epss │ asset  scan  component  asset_comp. │
  └──────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                             ▼
                        engine/: classify → match → enrich → score
                                             ▼
                                   finding  (lifecycle open → fixed)
                                             ▼
                          secmonk findings | vuln show | inventory …
```

## Modules

| Module | Responsibility |
|---|---|
| `db.py` | Schema (the integration contract), connection, sync-state helpers. |
| `models.py` | `Component`, `Asset`, `Inventory` dataclasses + category constants. |
| `sources/base.py` | `Source` interface, `SyncOptions/SyncResult`, write helpers (`upsert_vulnerability`, `add_alias`, `add_affected`), proxy-aware `http_client()`. |
| `sources/*.py` | One feed each. Every source can import from a local path (`--path`) — used by tests and for air-gapped mirrors. |
| `collectors/base.py` | `Collector` interface. Collectors never touch the DB. |
| `collectors/*.py` | macOS, Linux rootfs, Docker image (registry / tarball / OCI layout), Docker engine. |
| `engine/purl.py` | PURL helpers, PURL ↔ OSV ecosystem mapping, ecosystem normalization. |
| `engine/versions.py` | Version comparison per ecosystem (`univers`), OSV range evaluation. |
| `engine/classify.py` | Category / ecosystem / vendor / product / CPE assignment, alias table. |
| `engine/inventory.py` | Persist inventories; "current components" of an asset. |
| `engine/match.py` | Matching strategies, alias canonicalization, enrichment, finding lifecycle. |
| `engine/scoring.py` | Priority rules (vision §8). |
| `cli.py` | Typer CLI. |

## Principles

- **Scans never call external vulnerability APIs** — only the local mirror (vision §6).
  Collectors may pull images from registries (that's the target, not vuln data).
- **Raw first:** every imported record is kept verbatim in `raw_record` (OSV raw storage can be
  disabled with `SECMONK_OSV_STORE_RAW=0` for big ecosystems).
- **Same CVE, many sources:** rows are keyed `(source, id)`; `alias` links ids; the matcher
  canonicalizes to the CVE id and picks facts by source preference `nvd > cvelist > osv > euvd`.
- **Evidence-based docs:** see [`_meta`](../_meta/README.md).
