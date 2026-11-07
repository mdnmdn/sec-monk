"""JSON payloads shared by the CLI (`--format json`) and the web API (`secmonk ui`).

The presentation layers never re-shape data: `secmonk findings -f json` and `GET /api/findings` return the same rows,
`secmonk vuln show -f json` and `GET /api/vulns/show` the same document. SQL stays in `engine/queries.py`.
See _docs/tech/web-ui.md (API) and _docs/features/scan-and-findings.md.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .db import loads
from .engine import queries

PRIORITY_KEYS = ("P1", "P2", "P3", "P4")


# --------------------------------------------------------------------------- findings

def finding_dict(r: sqlite3.Row) -> dict:
    """One finding row (queries.findings / findings_for_vulns) -> JSON."""
    return {"asset_id": r["asset_id"], "priority": r["priority"], "vuln_id": r["vuln_id"],
            "component": r["name"], "version": r["version"], "category": r["category"],
            "fixed_version": r["fixed_version"], "severity": r["severity"], "cvss_score": r["cvss_score"],
            "epss": r["epss"], "kev": bool(r["kev"]), "triage": r["triage"], "matched_by": r["matched_by"],
            "confidence": r["confidence"], "status": r["status"],
            "component_id": r["component_id"], "advisory_ids": loads(r["advisory_ids"], []) or [],
            "triage_source": r["triage_source"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "fixed_at": r["fixed_at"], "ecosystem": r["ecosystem"], "purl": r["purl"]}


def findings(conn: sqlite3.Connection, **kw: Any) -> list[dict]:
    """queries.findings with the same keyword filters (asset, priority, include_closed, fixable, hide_minor,
    hide_deferred, limit) -> JSON rows."""
    return [finding_dict(r) for r in queries.findings(conn, **kw)]


def priority_counts(rows: list[dict]) -> dict[str, int]:
    c = dict.fromkeys(PRIORITY_KEYS, 0) | {"kev": 0, "total": 0}
    for f in rows:
        if f.get("priority") in c:
            c[f["priority"]] += 1
        c["kev"] += bool(f.get("kev"))
        c["total"] += 1
    return c


# --------------------------------------------------------------------------- inventory

def asset_rows(conn: sqlite3.Connection) -> list[dict]:
    """`secmonk inventory assets` rows, plus open findings per priority (JSON only)."""
    by_asset = queries.open_finding_counts(conn)
    return [{"id": r["id"], "type": r["type"], "os": f"{r['os_name'] or ''} {r['os_version'] or ''}".strip(),
             "platform": r["platform"], "last_seen": r["last_seen"], "components": r["n"] or 0,
             "open_findings": r["f"], "name": r["name"], "first_seen": r["first_seen"],
             "findings_by_priority": by_asset.get(r["id"], dict.fromkeys(PRIORITY_KEYS, 0) | {"kev": 0})}
            for r in queries.assets(conn)]


def component_rows(conn: sqlite3.Connection, asset_id: str, category: str | None = None) -> list[dict]:
    """`secmonk inventory show` rows (components of the latest scan)."""
    from .engine.inventory import current_components

    return [{"category": r["category"], "name": r["name"], "version": r["version"], "ecosystem": r["ecosystem"],
             "vendor": r["vendor"], "purl": r["purl"], "cpe": r["cpe"], "path": r["source_path"], "id": r["id"]}
            for r in current_components(conn, asset_id) if not category or r["category"] == category]


def _small(value: Any, depth: int = 0) -> Any:
    """Asset meta for display: scalars and short lists / dicts of scalars; big structures are summarized
    (the process asset keeps its whole process tree in meta)."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= 300 else value[:300] + "…"
    if isinstance(value, list):
        if depth or len(value) > 20 or any(isinstance(v, (list, dict)) for v in value):
            return f"({len(value)} items)"
        return [_small(v, 1) for v in value]
    if isinstance(value, dict):
        if depth or len(value) > 20:
            return f"({len(value)} keys)"
        return {str(k): _small(v, 1) for k, v in value.items()}
    return str(value)


def asset_detail(conn: sqlite3.Connection, asset_id: str, *, include_closed: bool = True,
                 limit: int = 5000) -> dict | None:
    """Asset, its scans, current components (with open finding counts) and its findings; None if unknown."""
    a = queries.asset(conn, asset_id)
    if a is None:
        return None
    scans = []
    for s in queries.scans(conn, asset_id):
        meta = loads(s["meta"], {}) or {}
        scans.append({"id": s["id"], "collector": s["collector"], "started_at": s["started_at"],
                      "finished_at": s["finished_at"], "components": s["components"],
                      "partial": bool(meta.get("partial")), "partial_reason": meta.get("partial_reason"),
                      "warnings": meta.get("warnings") or []})
    rows = findings(conn, asset=asset_id, include_closed=include_closed, limit=limit)
    per_comp: dict[int, list[dict]] = {}
    for f in rows:
        if f["status"] == "open":
            per_comp.setdefault(f["component_id"], []).append(f)
    comps = []
    for c in component_rows(conn, asset_id):
        fs = per_comp.get(c["id"], [])
        comps.append({**c, "findings": priority_counts(fs)})
    meta = loads(a["meta"], {}) or {}
    latest = scans[0] if scans else None
    return {"asset": {"id": a["id"], "type": a["type"], "name": a["name"], "os_name": a["os_name"],
                      "os_version": a["os_version"], "platform": a["platform"], "first_seen": a["first_seen"],
                      "last_seen": a["last_seen"], "meta": {str(k): _small(v) for k, v in meta.items()}},
            "scans": scans, "components": comps, "findings": rows,
            "summary": {"components": len(comps), "open": priority_counts([f for f in rows if f["status"] == "open"]),
                        "closed": sum(f["status"] != "open" for f in rows), "limit_reached": len(rows) >= limit},
            "partial": bool(latest and latest["partial"]), "warnings": latest["warnings"] if latest else []}


def unmatched_rows(conn: sqlite3.Connection) -> list[dict]:
    """`secmonk inventory unmatched` rows."""
    return [{"category": r["category"], "name": r["name"], "version": r["version"], "product": r["p"],
             "bundle_id": r["b"]} for r in queries.unmatched(conn)]


# --------------------------------------------------------------------------- mirror

def status_payload(conn: sqlite3.Connection, db_path: Path | str) -> dict:
    """`secmonk status -f json`."""
    return {"db": str(db_path), "sources": [dict(r) for r in queries.source_status(conn)],
            "tables": queries.table_counts(conn)}


def registry_rows(reg: dict) -> list[dict]:
    """Sources or collectors registry -> [{name, description, in_all}] (`secmonk sources` / `collectors`)."""
    return [{"name": n, "description": getattr(c, "description", ""), "in_all": getattr(c, "in_all", True)}
            for n, c in sorted(reg.items())]


def _refs(extra: dict) -> list[str]:
    out = []
    for r in extra.get("references") or []:
        url = r.get("url") if isinstance(r, dict) else r
        if isinstance(url, str) and url:
            out.append(url)
    return out[:30]


def vuln_detail(conn: sqlite3.Connection, vuln_id: str, *, raw: bool = False) -> dict | None:
    """`secmonk vuln show -f json`: every source's facts for an id and its aliases; None if unknown."""
    from .engine.match import canonical_ids

    canon, ids = canonical_ids(conn, vuln_id)
    vulns = queries.vulnerabilities(conn, ids)
    k, ep = queries.kev_entry(conn, ids), queries.epss_entry(conn, ids)
    aff = queries.affected_for(conn, ids, limit=200)
    if not (vulns or k or ep or aff):
        return None
    records = []
    for r in vulns:
        extra = loads(r["extra"], {}) or {}
        records.append({"source": r["source"], "id": r["id"], "summary": r["summary"], "details": r["details"],
                        "published": r["published"], "modified": r["modified"], "withdrawn": r["withdrawn"],
                        "state": r["state"], "severity": r["severity"], "cvss_score": r["cvss_score"],
                        "cvss_vector": r["cvss_vector"], "cvss_version": r["cvss_version"],
                        "cwes": loads(r["cwes"], []) or [], "references": _refs(extra)})
    affected = [{"source": r["source"], "vuln_id": r["vuln_id"], "ecosystem": r["ecosystem"], "package": r["package"],
                 "purl": r["purl"], "vendor": r["vendor"], "product": r["product"], "cpe": r["cpe"],
                 "range_type": r["range_type"], "version_type": r["version_type"],
                 "events": loads(r["events"], []) or [], "versions": loads(r["versions"], []) or [],
                 "status": r["status"]} for r in aff]
    best = max(records, key=lambda r: (r["cvss_score"] is not None, r["cvss_score"] or 0), default=None)
    return {"id": canon, "query": vuln_id, "aliases": sorted(ids - {canon}),
            "summary": next((r["summary"] for r in records if r["summary"]), None),
            "severity": best and best["severity"], "cvss_score": best and best["cvss_score"],
            "records": records,
            "kev": dict(k) if k else None,
            "epss": {"score": ep["score"], "percentile": ep["percentile"], "date": ep["date"]} if ep else None,
            "affected": affected, "affected_limit_reached": len(aff) >= 200,
            "findings": [finding_dict(r) for r in queries.findings_for_vulns(conn, ids)],
            **({"raw": [{"source": r["source"], "data": loads(r["data"])} for r in queries.raw_records(conn, ids)]}
               if raw else {})}


def vuln_search(conn: sqlite3.Connection, *, package: str | None = None, ecosystem: str | None = None,
                product: str | None = None, version: str | None = None, limit: int = 50) -> list[dict]:
    """`secmonk vuln search -f json`. Raises ValueError without package / ecosystem / product."""
    from .engine.purl import normalize_name
    from .engine.versions import in_osv_range, scheme_for_ecosystem

    if not (package or ecosystem or product):
        raise ValueError("give a package, an ecosystem and/or a product")
    rows = queries.affected_search(conn, package=normalize_name(ecosystem, package) if package else None,
                                   ecosystem=ecosystem, product=product)
    out: list[dict] = []
    facts: dict[str, sqlite3.Row | None] = {}
    for r in rows:
        events, versions = loads(r["events"], []) or [], loads(r["versions"], []) or []
        if version:
            scheme = scheme_for_ecosystem(r["ecosystem"])
            if not (version in versions or (events and in_osv_range(version, events, scheme))):
                continue
        vid = r["vuln_id"]
        if vid not in facts:
            facts[vid] = queries.best_vulnerability(conn, vid)
        v = facts[vid]
        out.append({"vuln_id": vid, "source": r["source"], "ecosystem": r["ecosystem"], "vendor": r["vendor"],
                    "package": r["package"], "product": r["product"], "range_type": r["range_type"],
                    "events": events, "versions": versions, "summary": v["summary"] if v else None,
                    "severity": v["severity"] if v else None, "cvss_score": v["cvss_score"] if v else None})
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- overview

def overview(conn: sqlite3.Connection, db_path: Path | str, *, top: int = 10) -> dict:
    """Dashboard: open findings across assets, the most urgent ones, assets, and mirror freshness."""
    assets = asset_rows(conn)
    totals = dict.fromkeys(PRIORITY_KEYS, 0) | {"kev": 0}
    for a in assets:
        for k in totals:
            totals[k] += a["findings_by_priority"].get(k, 0)
    return {"db": str(db_path),
            "totals": {"assets": len(assets), "components": sum(a["components"] for a in assets),
                       "open_findings": sum(a["open_findings"] or 0 for a in assets),
                       "fixable": queries.count_open_fixable(conn), **totals},
            "assets": assets, "top_findings": findings(conn, limit=top),
            "sources": [dict(r) for r in queries.source_status(conn)], "tables": queries.table_counts(conn)}
