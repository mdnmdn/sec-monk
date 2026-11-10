---
title: SBOM (CycloneDX) — export builder and import parser
summary: Mapping of assets, components and findings to CycloneDX 1.6 (types, bom-refs, properties, vulnerabilities) and safe parsing of CycloneDX 1.4-1.6 / SPDX 2.x JSON by the sbom collector (caps, validation).
read_when: you change src/secmonk/sbom.py or the sbom collector, map a new category or asset type, or debug an SBOM that does not import or round-trip
type: tech
context: tech
status: implemented
tags: [sbom, cyclonedx, spdx, collectors]
updated: 2026-11-11
verified: 2026-11-11
code: src/secmonk/sbom.py, src/secmonk/collectors/sbom.py
fixtures: tests/fixtures/sbom/
related: [features/sbom.md, tech/data-model.md, tech/engine/classification.md]
---

# SBOM (CycloneDX) — export builder and import parser

## What it is

`src/secmonk/sbom.py` holds both directions. `build_cyclonedx(asset, components, scan_id=, timestamp=, findings=)`
is pure (rows in, dict out); `export_asset(conn, asset_id, with_vulns=)` reads the asset, its current components
(`engine/inventory.current_components`) and, with vulns, its open findings (`reports.findings`). `parse_document(bytes)`
turns a CycloneDX or SPDX JSON document into `ParsedBom` records; the `sbom` collector (`collectors/sbom.py`) reads the
file with `read_within` (64 MiB) and builds the `Inventory`; `classify` runs afterwards like for every collector.

## Rules / model

| secmonk | CycloneDX | Import back |
|---|---|---|
| component key (purl, else `name:<category>/<vendor>/<name>@<version>`) | `bom-ref` | (recomputed from the fields) |
| category `os` / `os-package`, `library` / `application`, `system-app`, `package` / `runtime` / `executable` | `type` `operating-system` / `library` / `application` / `framework` / `file` | `secmonk:category` property first; else from `type`, `library` with a deb/rpm/apk purl -> `os-package`, unknown type -> `library` with a purl, else `application` |
| vendor | `publisher` + `secmonk:vendor` | `secmonk:vendor`, else `publisher`, else `supplier.name` |
| ecosystem, paths | `secmonk:ecosystem`, `secmonk:path` (≤ 20) | kept (first path = source path) |
| asset type `container-image` / `container`, hosts, `repo` / `directory` | `metadata.component.type` `container` / `device` / `application` | `secmonk:asset_type`, else `container` -> container-image, `operating-system` / `device` / `firmware` -> server, else repo |
| finding (open) | `vulnerabilities[]` (one per canonical id; `affects` = bom-refs) | ignored |

- Determinism: components sorted by `bom-ref`, properties by name/value, vulnerabilities by id;
  `serialNumber = urn:uuid:uuid5(<fixed namespace>, "<asset id>#<latest scan id>")`, so a re-export of an unchanged
  asset has the same serial number and a new scan gives a new one. `dependencies` = the asset depends on every component.
- Vulnerability: `source` by id prefix (CVE -> NVD, GHSA -> GitHub, else OSV), one rating (the finding with the highest
  CVSS: severity mapped to CycloneDX's lowercase enum, score), `references` = aliases, `recommendation` = fixed
  versions, `analysis.state = in_triage` with `detail` = `<triage source>: <label>` when a distro triaged it
  (CycloneDX has no state for "minor / deferred"), properties `secmonk:priority`, `secmonk:kev`, `secmonk:epss`,
  `secmonk:matched_by`.
- Import caps: `MAX_COMPONENTS` 100 000 (the rest ignored, warning), `MAX_DEPTH` 32 for nested `components`,
  `MAX_STR` 1 024 per string (a longer name skips the component, a longer purl/version is dropped). A purl must parse
  with `packageurl` (`engine/purl.parse`) and start with `pkg:`; a cpe must start with `cpe:2.3:` or `cpe:/` (≤ 512).
  Non-object entries and unknown fields are ignored. SPDX: `packages[]` with `externalRefs` `purl` / `cpe23Type`,
  `supplier` `Organization: X` -> vendor, the package in `documentDescribes` names the asset, `Tool:` creators -> tools.

## Rationale

The importer does not reuse a secmonk export's `secmonk:asset_id`: an imported file is a claim by whoever wrote it, and
it must not replace the inventory secmonk collected itself. Component meta is not exported or imported (identity hints
such as brew seed data stay with the collector that produced them); since `component.meta` is shared per key and the
last writer wins, importing a component that also exists elsewhere resets that key's meta to what `classify` derives
from the SBOM fields.

## Limitations

- JSON only (no CycloneDX XML / protobuf, no SPDX tag-value / RDF). `dependencies` and services are not imported.
- Export covers current components only (no history) and open findings only.
- Imported versions are taken as written; a component with neither purl nor cpe is matched by normalized name only.

## Related docs

[features/sbom](../features/sbom.md), [data-model](data-model.md) (component keys, current components),
[classification](engine/classification.md).
