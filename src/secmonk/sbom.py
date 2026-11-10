"""CycloneDX BOMs: export an asset's current inventory (and optionally its open findings), and parse a CycloneDX
(1.4-1.6) or SPDX 2.3 JSON document into components for the `sbom` collector.

Export: `build_cyclonedx` is pure (rows -> dict, deterministic: sorted components, sorted properties, serial number
derived from the asset and its latest scan); `export_asset` reads the rows. Import: `parse_document` turns an
untrusted document into plain component records with caps on counts, depth and string lengths; it never raises for
a bad component (it is skipped with a warning), only for a document that is not a BOM at all.
See _docs/features/sbom.md and _docs/tech/sbom.md.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .db import loads, now

SPEC_VERSION = "1.6"
MEDIA_TYPE = "application/vnd.cyclonedx+json"
MAX_PATHS = 20                       # secmonk:path properties per component
MAX_COMPONENTS = 100_000             # import: components kept
MAX_DEPTH = 32                       # import: nesting of `components`
MAX_STR = 1024                       # import: names, versions, purls…
SERIAL_NS = uuid.UUID("6f0f3b39-8f1c-4c9a-9a51-6a8f1d0b2c11")   # uuid5 namespace for serial numbers

# component category <-> CycloneDX component type
CATEGORY_TYPE = {"os": "operating-system", "os-package": "library", "library": "library",
                 "application": "application", "system-app": "application", "package": "application",
                 "runtime": "framework", "executable": "file"}
TYPE_CATEGORY = {"operating-system": "os", "library": "library", "application": "application",
                 "framework": "runtime", "file": "executable", "platform": "runtime", "firmware": "os"}
# asset type <-> metadata.component.type
ASSET_TYPE = {"container-image": "container", "container": "container", "desktop": "device", "server": "device",
              "host-processes": "device", "repo": "application", "directory": "application"}
TYPE_ASSET = {"container": "container-image", "operating-system": "server", "device": "server",
              "firmware": "server", "application": "repo", "library": "repo", "framework": "repo", "file": "directory"}
ASSET_TYPES = frozenset(ASSET_TYPE)
SEVERITIES = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "MODERATE": "medium", "LOW": "low",
              "NONE": "none", "INFO": "info"}


# --------------------------------------------------------------------------- export

def _props(pairs: list[tuple[str, Any]]) -> list[dict]:
    out = [{"name": k, "value": str(v)} for k, v in pairs if v not in (None, "", [])]
    return sorted(out, key=lambda p: (p["name"], p["value"]))


def _vuln_source(vid: str) -> dict:
    if vid.startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vid}"}
    if vid.startswith("GHSA-"):
        return {"name": "GitHub", "url": f"https://github.com/advisories/{vid}"}
    return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"}


def component_entry(c: dict) -> dict:
    """One current component (engine/inventory.current_components row as a dict) -> CycloneDX component."""
    paths = loads(c.get("paths"), []) or ([c["source_path"]] if c.get("source_path") else [])
    d: dict[str, Any] = {"bom-ref": c["key"], "type": CATEGORY_TYPE.get(c["category"], "library"),
                         "name": c["name"]}
    if c.get("version"):
        d["version"] = c["version"]
    if c.get("vendor"):
        d["publisher"] = c["vendor"]
    if c.get("purl"):
        d["purl"] = c["purl"]
    if c.get("cpe"):
        d["cpe"] = c["cpe"]
    d["properties"] = _props([("secmonk:category", c["category"]), ("secmonk:ecosystem", c.get("ecosystem")),
                              ("secmonk:vendor", c.get("vendor"))]
                             + [("secmonk:path", p) for p in sorted(set(paths))[:MAX_PATHS]])
    return d


def vulnerability_entries(findings: list[dict], refs: dict[int, str]) -> list[dict]:
    """Open findings (reports.finding_dict rows) -> CycloneDX vulnerabilities, one per canonical id."""
    by_id: dict[str, list[dict]] = {}
    for f in findings:
        if f["component_id"] in refs:
            by_id.setdefault(f["vuln_id"], []).append(f)
    out = []
    for vid in sorted(by_id):
        fs = sorted(by_id[vid], key=lambda f: refs[f["component_id"]])
        best = max(fs, key=lambda f: (f["cvss_score"] is not None, f["cvss_score"] or 0))
        v: dict[str, Any] = {"bom-ref": f"vuln:{vid}", "id": vid, "source": _vuln_source(vid)}
        rating: dict[str, Any] = {}
        if best["severity"]:
            rating["severity"] = SEVERITIES.get(str(best["severity"]).upper(), "unknown")
        if best["cvss_score"] is not None:
            rating["score"] = best["cvss_score"]
        if rating:
            v["ratings"] = [{"source": v["source"], **rating}]
        aliases = sorted({a for f in fs for a in f["advisory_ids"] if a != vid})
        if aliases:
            v["references"] = [{"id": a, "source": _vuln_source(a)} for a in aliases]
        fixed = sorted({f["fixed_version"] for f in fs if f["fixed_version"]})
        if fixed:
            v["recommendation"] = "Upgrade to " + " / ".join(fixed)
        triage = sorted({(f["triage"], f["triage_source"] or "distro") for f in fs if f["triage"]})
        if triage:
            v["analysis"] = {"state": "in_triage",
                             "detail": "; ".join(f"{src}: {t}" for t, src in triage)}
        v["affects"] = [{"ref": r} for r in sorted({refs[f["component_id"]] for f in fs})]
        kev = str(any(f["kev"] for f in fs)).lower()
        v["properties"] = _props([("secmonk:priority", best["priority"]), ("secmonk:kev", kev),
                                  ("secmonk:epss", best["epss"]), ("secmonk:matched_by", best["matched_by"])])
        out.append(v)
    return out


def build_cyclonedx(asset: dict, components: list[dict], *, scan_id: int | None, timestamp: str,
                    findings: list[dict] | None = None) -> dict:
    """Pure: asset row + current component rows (+ open finding rows) -> CycloneDX 1.6 JSON document."""
    meta = loads(asset.get("meta"), {}) or {}
    tags = [t for t in meta.get("tags") or [] if isinstance(t, str)]
    subject: dict[str, Any] = {"bom-ref": f"asset:{asset['id']}",
                               "type": ASSET_TYPE.get(asset["type"], "application"),
                               "name": asset.get("name") or asset["id"]}
    if asset.get("os_version"):
        subject["version"] = asset["os_version"]
    subject["properties"] = _props(
        [("secmonk:asset_id", asset["id"]), ("secmonk:asset_type", asset["type"]),
         ("secmonk:os_name", asset.get("os_name")), ("secmonk:os_version", asset.get("os_version")),
         ("secmonk:platform", asset.get("platform")),
         ("secmonk:image_id", meta.get("image_id"))] + [("secmonk:tag", t) for t in sorted(tags)])
    comps = sorted((component_entry(c) for c in components), key=lambda d: d["bom-ref"])
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(SERIAL_NS, f'{asset['id']}#{scan_id}')}", "version": 1,
        "metadata": {"timestamp": timestamp,
                     "tools": {"components": [{"type": "application", "name": "secmonk", "version": __version__}]},
                     "component": subject},
        "components": comps,
        "dependencies": [{"ref": subject["bom-ref"], "dependsOn": [c["bom-ref"] for c in comps]}],
    }
    if findings is not None:
        doc["vulnerabilities"] = vulnerability_entries(findings, {c["id"]: c["key"] for c in components})
    return doc


def export_asset(conn: sqlite3.Connection, asset_id: str, *, with_vulns: bool = False,
                 timestamp: str | None = None) -> dict | None:
    """The CycloneDX document of a stored asset (its current components); None for an unknown asset."""
    from . import reports
    from .engine import queries
    from .engine.inventory import current_components

    a = queries.asset(conn, asset_id)
    if a is None:
        return None
    comps = [dict(r) for r in current_components(conn, asset_id)]
    scans = queries.scans(conn, asset_id, limit=1)
    findings = reports.findings(conn, asset=asset_id, limit=1_000_000) if with_vulns else None
    return build_cyclonedx(dict(a), comps, scan_id=scans[0]["id"] if scans else None,
                           timestamp=timestamp or now(), findings=findings)


def dumps(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


# --------------------------------------------------------------------------- import

@dataclass
class ParsedComponent:
    name: str
    version: str | None
    category: str
    purl: str | None = None
    cpe: str | None = None
    vendor: str | None = None
    ecosystem: str | None = None
    paths: list[str] = field(default_factory=list)


@dataclass
class ParsedBom:
    format: str                                   # cyclonedx | spdx
    spec_version: str | None
    serial: str | None
    subject_name: str | None
    subject_version: str | None
    subject_type: str | None                      # CycloneDX type of metadata.component
    asset_type: str | None                        # secmonk:asset_type of our own exports
    os_name: str | None
    os_version: str | None
    platform: str | None
    tools: list[str]
    components: list[ParsedComponent]
    warnings: list[str]


def _s(v: Any) -> str | None:
    """A string field of the document: str only, stripped, at most MAX_STR (else None)."""
    if not isinstance(v, str):
        return None
    v = v.strip()
    return v if v and len(v) <= MAX_STR else None


def _valid_purl(p: str | None) -> bool:
    from .engine import purl as purls

    return bool(p) and p.startswith("pkg:") and purls.parse(p) is not None


def _valid_cpe(c: str | None) -> bool:
    return bool(c) and c.startswith(("cpe:2.3:", "cpe:/")) and len(c) <= 512


def _prop_map(props: Any) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in props if isinstance(props, list) else []:
        if isinstance(p, dict) and _s(p.get("name")) and _s(p.get("value")):
            out.setdefault(p["name"].strip(), []).append(p["value"].strip())
    return out


class _Counter:
    def __init__(self) -> None:
        self.bad_purl = self.bad_cpe = self.unnamed = self.too_many = self.too_deep = 0


def _cdx_component(c: dict, n: _Counter) -> ParsedComponent | None:
    from .models import CATEGORIES

    name = _s(c.get("name"))
    if not name:
        n.unnamed += 1
        return None
    props = _prop_map(c.get("properties"))
    purl = _s(c.get("purl"))
    if purl and not _valid_purl(purl):
        n.bad_purl += 1
        purl = None
    cpe = _s(c.get("cpe"))
    if cpe and not _valid_cpe(cpe):
        n.bad_cpe += 1
        cpe = None
    category = (props.get("secmonk:category") or [None])[0]
    if category not in CATEGORIES:
        ctype = _s(c.get("type")) or "library"
        category = TYPE_CATEGORY.get(ctype, "library" if purl else "application")
        if category == "library" and purl and purl.split("/", 1)[0] in ("pkg:deb", "pkg:rpm", "pkg:apk"):
            category = "os-package"
    vendor = (props.get("secmonk:vendor") or [None])[0] or _s(c.get("publisher"))
    if not vendor and isinstance(c.get("supplier"), dict):
        vendor = _s(c["supplier"].get("name"))
    return ParsedComponent(name=name, version=_s(c.get("version")), category=category, purl=purl, cpe=cpe,
                           vendor=vendor, ecosystem=(props.get("secmonk:ecosystem") or [None])[0],
                           paths=props.get("secmonk:path", [])[:MAX_PATHS])


def _walk_cdx(items: Any, depth: int, out: list[ParsedComponent], n: _Counter) -> None:
    """Nested `components` flattened (depth-first), capped in depth and count."""
    if not isinstance(items, list):
        return
    if depth > MAX_DEPTH:
        n.too_deep += 1
        return
    for c in items:
        if not isinstance(c, dict):
            continue
        if len(out) >= MAX_COMPONENTS:
            n.too_many += 1
            return
        pc = _cdx_component(c, n)
        if pc is not None:
            out.append(pc)
        _walk_cdx(c.get("components"), depth + 1, out, n)


def _warnings(n: _Counter) -> list[str]:
    w = []
    if n.unnamed:
        w.append(f"{n.unnamed} component(s) without a usable name skipped")
    if n.bad_purl:
        w.append(f"{n.bad_purl} invalid or over-long purl(s) dropped (components kept by name)")
    if n.bad_cpe:
        w.append(f"{n.bad_cpe} invalid cpe(s) dropped")
    if n.too_many:
        w.append(f"more than {MAX_COMPONENTS} components: the rest is ignored")
    if n.too_deep:
        w.append(f"components nested deeper than {MAX_DEPTH} levels ignored")
    return w


def _first(props: dict[str, list[str]], key: str) -> str | None:
    return (props.get(key) or [None])[0]


def _parse_cyclonedx(doc: dict) -> ParsedBom:
    spec = _s(doc.get("specVersion"))
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    subj = meta.get("component") if isinstance(meta.get("component"), dict) else {}
    props = _prop_map(subj.get("properties"))
    tools: list[str] = []
    t = meta.get("tools")
    for tool in (t.get("components") if isinstance(t, dict) else t) or []:   # 1.5+: {components: [...]}; 1.4: [...]
        if isinstance(tool, dict) and _s(tool.get("name")):
            tools.append(" ".join(x for x in (_s(tool.get("name")), _s(tool.get("version"))) if x))
    n = _Counter()
    comps: list[ParsedComponent] = []
    _walk_cdx(doc.get("components"), 0, comps, n)
    warnings = _warnings(n)
    if spec not in ("1.4", "1.5", "1.6"):
        warnings.insert(0, f"CycloneDX specVersion {spec or '?'} (read as 1.6; 1.4-1.6 are supported)")
    return ParsedBom("cyclonedx", spec, _s(doc.get("serialNumber")), _s(subj.get("name")),
                     _s(subj.get("version")), _s(subj.get("type")), _first(props, "secmonk:asset_type"), _first(props, "secmonk:os_name"),
                     _first(props, "secmonk:os_version"), _first(props, "secmonk:platform"), tools[:20], comps, warnings)


def _parse_spdx(doc: dict) -> ParsedBom:
    n = _Counter()
    comps: list[ParsedComponent] = []
    described = {x for x in doc.get("documentDescribes") or [] if isinstance(x, str)}
    subject = None
    for p in doc.get("packages") or []:
        if not isinstance(p, dict):
            continue
        if p.get("SPDXID") in described and subject is None:
            subject = p
        if len(comps) >= MAX_COMPONENTS:
            n.too_many += 1
            break
        name = _s(p.get("name"))
        if not name:
            n.unnamed += 1
            continue
        purl = cpe = None
        for ref in p.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            rtype, loc = ref.get("referenceType"), _s(ref.get("referenceLocator"))
            if rtype == "purl" and loc and purl is None:
                purl = loc if _valid_purl(loc) else None
                n.bad_purl += purl is None
            elif rtype in ("cpe23Type", "cpe22Type") and loc and cpe is None:
                cpe = loc if _valid_cpe(loc) else None
                n.bad_cpe += cpe is None
        category = "library" if purl else "application"
        if purl and purl.split("/", 1)[0] in ("pkg:deb", "pkg:rpm", "pkg:apk"):
            category = "os-package"
        supplier = _s(p.get("supplier"))
        vendor = supplier.split(":", 1)[-1].strip() if supplier and supplier != "NOASSERTION" else None
        comps.append(ParsedComponent(name=name, version=_s(p.get("versionInfo")), category=category, purl=purl,
                                     cpe=cpe, vendor=vendor or None))
    creators = (doc.get("creationInfo") or {}).get("creators") if isinstance(doc.get("creationInfo"), dict) else []
    tools = [c.split(":", 1)[1].strip() for c in creators or [] if isinstance(c, str) and c.startswith("Tool:")]
    sname = _s(subject.get("name")) if subject else _s(doc.get("name"))
    sver = _s(subject.get("versionInfo")) if subject else None
    return ParsedBom("spdx", _s(doc.get("spdxVersion")), _s(doc.get("documentNamespace")), sname, sver, None, None,
                     None, None, None, tools[:20], comps, _warnings(n))


def parse_document(data: bytes) -> ParsedBom:
    """CycloneDX 1.4-1.6 JSON or SPDX 2.x JSON -> ParsedBom. ValueError when it is neither (or not JSON)."""
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"not a JSON document: {e}") from None
    if not isinstance(doc, dict):
        raise ValueError("not a BOM: the JSON document is not an object")  # noqa: TRY004  # a collector error
    if doc.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx(doc)
    if isinstance(doc.get("spdxVersion"), str) and doc["spdxVersion"].startswith("SPDX-2."):
        return _parse_spdx(doc)
    raise ValueError("not a CycloneDX JSON (bomFormat) or SPDX 2.x JSON (spdxVersion) document; "
                     "XML and tag-value formats are not supported")
