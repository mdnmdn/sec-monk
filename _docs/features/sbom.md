---
title: SBOM export and import
summary: CycloneDX 1.6 export of an asset's current components (optionally its open findings) from the CLI and the web API; import of CycloneDX 1.4-1.6 / SPDX 2.x JSON via the `sbom` collector.
read_when: you export a bill of materials, scan an SBOM produced by another tool, or change `inventory export`, the `sbom` collector or `/api/assets/<id>/sbom`
type: feature
context: features
status: implemented
tags: [sbom, cyclonedx, spdx, cli, web-ui, inventory]
updated: 2026-11-11
verified: 2026-11-11
code: src/secmonk/sbom.py, src/secmonk/collectors/sbom.py, src/secmonk/cli.py, src/secmonk/web/server.py, src/secmonk/web/data.py
fixtures: tests/fixtures/sbom/
related: [tech/sbom.md, features/scan-and-findings.md, tech/data-model.md, tech/web-ui.md]
---

# SBOM export and import

## What the user gets

- **Export**: any stored asset becomes a CycloneDX 1.6 JSON bill of materials of its *current* components (what its
  last complete scan saw), optionally with its open findings as CycloneDX `vulnerabilities`, from the CLI or as a
  download from the web API.
- **Import**: a CycloneDX (1.4, 1.5, 1.6) or SPDX 2.x JSON document produced by another tool (or by secmonk) is an
  inventory like any other: `secmonk scan sbom file.json` stores it as an asset and matches it against the local mirror.

## Usage

```bash
secmonk inventory export 'image:@sha256:…' > shop.cdx.json         # CycloneDX 1.6 JSON on stdout
secmonk inventory export macos:mbp --with-vulns -o mbp.cdx.json    # + open findings as `vulnerabilities`
secmonk scan sbom vendor-sbom.cdx.json                              # import + match (asset sbom:<name>@<version>)
secmonk scan sbom app.spdx.json -o asset_id=sbom:billing            # SPDX 2.x JSON, own asset id
```

Web: `GET /api/assets/<url-encoded asset id>/sbom[?vulns=1]` answers the same document as
`application/vnd.cyclonedx+json` with `Content-Disposition: attachment; filename="<asset id>.cdx.json"`. Like every API
call it needs the `X-SecMonk-Request: 1` header, so a plain link cannot download it: the UI fetches it and saves the
response as a blob (`URL.createObjectURL`).

## Behaviour & rules

- **Export** (`inventory export ASSET [--format cyclonedx-json] [--with-vulns] [-o FILE]`): an unknown asset or a
  missing database exits 1; `--format` accepts only `cyclonedx-json` (else exit 2). `-o` writes the file and notes it
  on stderr. The document is deterministic for the same stored state (components sorted by `bom-ref`, properties
  sorted, `serialNumber` derived from the asset id and its latest scan); only `metadata.timestamp` changes.
- **What is exported**: `metadata.component` = the asset (type `container` for images and containers, `device` for
  hosts, `application` for folders and repositories; `secmonk:asset_id`, `secmonk:asset_type`, OS, platform, image id
  and tags as properties); one component per current component (`bom-ref` = the secmonk component key, purl, cpe,
  publisher = vendor, `secmonk:category` / `secmonk:ecosystem` / `secmonk:vendor` / up to 20 `secmonk:path`).
  `--with-vulns`: one vulnerability per open finding id (source NVD / GitHub / OSV, rating with severity and CVSS when
  known, aliases as references, fixed versions as recommendation, distro triage as `analysis` `in_triage` with the
  triage label, the affected components, secmonk priority / KEV / EPSS as properties). Closed findings are not exported.
- **Import** (collector `sbom`, target = file path): CycloneDX JSON (`bomFormat`) 1.4-1.6 (other spec versions are read
  with a warning) or SPDX 2.x JSON (`spdxVersion`); XML, tag-value and other JSON are an error (exit 1, no traceback).
  Nested components are flattened. A component without a usable name is skipped; an invalid purl or cpe is dropped (the
  component stays, by name); counts appear as collector warnings. A `vulnerabilities` section is ignored: secmonk
  matches the components itself.
- **Asset**: id `sbom:<metadata.component name>@<its version, else the serial number, else the file name>` (or
  `-o asset_id=`); type from `secmonk:asset_type` when the file came from secmonk, else from `metadata.component.type`
  (`container` -> container-image, `operating-system` / `device` / `firmware` -> server, otherwise repo); meta: format,
  spec version, serial number, tools, file path. Importing never reuses the original asset id of a secmonk export, so it
  cannot overwrite the scanned asset.
- **Round trip**: exporting an asset and importing the file yields the same component keys (purls; for components
  without a purl the category, vendor, name and version), so findings are the same.
- **Untrusted input**: read through the bounded reader (64 MiB, no symlink escape), at most 100 000 components,
  32 levels of nesting, 1 024 characters per string.

## Acceptance criteria

- `inventory export` output has `bomFormat`, `specVersion` 1.6, a serial number, the asset as `metadata.component`
  and exactly the asset's current components, sorted; two exports of the same state are identical except the timestamp
  (`tests/test_sbom.py`).
- `--with-vulns` lists open findings only, with severity, aliases, fixed version and triage.
- `GET /api/assets/<id>/sbom` returns the document with the CycloneDX media type and an attachment disposition; 404
  for an unknown asset; 403 without `X-SecMonk-Request`.
- `scan sbom` of the synthetic CycloneDX and SPDX fixtures stores the expected components and warnings; malformed or
  oversized files fail cleanly; export -> import keeps the component keys.

## Implemented by

[tech/sbom](../tech/sbom.md), `src/secmonk/sbom.py`, `src/secmonk/collectors/sbom.py`; API row in
[tech/web-ui](../tech/web-ui.md#api).
