"""Import a software bill of materials: CycloneDX 1.4-1.6 JSON or SPDX 2.x JSON -> Inventory.

The document is untrusted input: read through `read_within` with a size cap, parsed by `secmonk.sbom.parse_document`
(caps on component count, nesting depth and string lengths; invalid purls / cpes dropped). Vulnerabilities in the
document are ignored: the engine matches the components against the local mirror like any other inventory.
Asset id: `sbom:<metadata.component name>@<version or serial number>` (or `-o asset_id=`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Asset, Component, Inventory
from .base import Collector, read_within, register

MAX_BYTES = 64 * 1024 * 1024


@register
class SbomCollector(Collector):
    name = "sbom"
    description = "Import a CycloneDX (1.4-1.6) or SPDX 2.x JSON bill of materials"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        from .. import sbom

        if not target:
            raise ValueError("sbom: give the path of a CycloneDX or SPDX JSON file")
        path = Path(target).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"sbom: no file {path}")
        data = read_within(path, path.resolve().parent, MAX_BYTES)
        bom = sbom.parse_document(data)
        label = bom.subject_name or path.name
        asset_id = opts.get("asset_id") or f"sbom:{label}@{bom.subject_version or bom.serial or path.name}"
        asset_type = (bom.asset_type if bom.asset_type in sbom.ASSET_TYPES
                      else sbom.TYPE_ASSET.get(bom.subject_type or "", "repo"))
        os_name, os_version = bom.os_name, bom.os_version
        if not os_name and bom.subject_type == "operating-system":
            os_name, os_version = bom.subject_name, bom.subject_version
        meta = {"source": "sbom", "format": bom.format, "spec_version": bom.spec_version,
                "serial_number": bom.serial, "tools": bom.tools, "file": str(path)}
        inv = Inventory(Asset(id=str(asset_id), type=asset_type, name=label, os_name=os_name, os_version=os_version,
                              platform=bom.platform, meta={k: v for k, v in meta.items() if v}),
                        self.name, warnings=list(bom.warnings))
        for c in bom.components:
            comp = Component(c.name, c.version, c.category, purl=c.purl, cpe=c.cpe, vendor=c.vendor,
                             ecosystem=c.ecosystem, source_path=c.paths[0] if c.paths else None)
            if len(c.paths) > 1:
                comp.meta["paths"] = c.paths[1:]
            inv.components.append(comp)
        if not inv.components:
            inv.warnings.append("the document lists no usable component")
        return inv
