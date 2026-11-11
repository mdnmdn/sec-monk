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


# component facts a UI shows next to a version (from component.meta / asset_component.meta, also under "process")
COMPONENT_META_KEYS = ("pre_release", "vendor_build", "version_is_installed_not_running")


def component_meta(*metas: dict | None) -> dict:
    """The COMPONENT_META_KEYS present in the given meta dicts (first one wins), scalars only."""
    out: dict = {}
    for m in metas:
        if not isinstance(m, dict):
            continue
        for src in (m, m.get("process") if isinstance(m.get("process"), dict) else {}):
            for k in COMPONENT_META_KEYS:
                v = src.get(k)
                if k not in out and isinstance(v, (bool, int, float, str)) and v not in ("", None):
                    out[k] = v
    return out


def component_rows(conn: sqlite3.Connection, asset_id: str, category: str | None = None) -> list[dict]:
    """`secmonk inventory show` rows (components of the latest scan); `meta` = component_meta (may be {})."""
    from .engine.inventory import current_components

    return [{"category": r["category"], "name": r["name"], "version": r["version"], "ecosystem": r["ecosystem"],
             "vendor": r["vendor"], "purl": r["purl"], "cpe": r["cpe"], "path": r["source_path"], "id": r["id"],
             "meta": component_meta(loads(r["asset_meta"], {}), loads(r["meta"], {}))}
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


# asset meta keys passed whole (not summarized) by asset type: key -> max list items
STRUCTURED_META = {"cluster": {"images": 2000, "access": 0}}


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
    shown = {str(k): _small(v) for k, v in meta.items()}
    for k, cap in STRUCTURED_META.get(a["type"], {}).items():     # kept whole: the page renders them as tables
        v = meta.get(k)
        if isinstance(v, list):
            shown[k] = v[:cap]
        elif isinstance(v, dict):
            shown[k] = v
    latest = scans[0] if scans else None
    return {"asset": {"id": a["id"], "type": a["type"], "name": a["name"], "os_name": a["os_name"],
                      "os_version": a["os_version"], "platform": a["platform"], "first_seen": a["first_seen"],
                      "last_seen": a["last_seen"], "meta": shown},
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


# --------------------------------------------------------------------------- run history (scan / sync jobs)

def job_summary(kind: str, result: dict | None) -> dict:
    """One-line facts about a run for lists: scan {targets, errors, components, P1..P4, kev, total};
    sync {sources, errors, records}. Empty while running or when the run failed before a result."""
    if not isinstance(result, dict):
        return {}
    if kind == "scan":
        targets = result.get("targets") or []
        counts = result.get("counts") or {}
        return {"targets": len(targets), "errors": sum(bool(t.get("error")) for t in targets),
                "components": (result.get("stats") or {}).get("components", 0),
                **{k: counts.get(k, 0) for k in (*PRIORITY_KEYS, "kev", "total")}}
    if kind == "sync":
        sources = result.get("sources") or []
        return {"sources": len(sources), "errors": sum(s.get("status") == "error" for s in sources),
                "records": sum(s.get("records") or 0 for s in sources)}
    return {}


def job_payload(*, id: int, kind: str, origin: str, title: str | None, params: dict | None, started: str | None,
                finished: str | None, status: str, error: str | None, result: dict | None,
                log: list[str] | None, include_log: bool = True, summary: dict | None = None,
                log_lines: int | None = None) -> dict:
    """A scan / sync run (web job or stored history row): `GET /api/jobs[/<id>]`, `secmonk history [show] -f json`."""
    d = {"id": id, "kind": kind, "origin": origin, "title": title, "params": params or {}, "started": started,
         "finished": finished, "status": status, "error": error, "result": result,
         "summary": summary if summary is not None else job_summary(kind, result),
         "log_lines": log_lines if log_lines is not None else len(log or [])}
    if include_log:
        d["log"] = list(log or [])
    return d


def job_dict(row: sqlite3.Row, *, include_log: bool = True) -> dict:
    """Stored `job` row (db.job_row, or db.job_rows without the log) -> job_payload. A 'running' row whose process
    is gone (db.owner_alive) reads as status 'error', error 'interrupted' (nothing is written)."""
    from .db import owner_alive

    keys = set(row.keys())
    status, error, finished = row["status"], row["error"], row["finished_at"]
    if status == "running" and not owner_alive(loads(row["owner"]) if "owner" in keys else None):
        status, error = "error", "interrupted"
    log = loads(row["log"], []) if "log" in keys else None
    return job_payload(id=row["id"], kind=row["kind"], origin=row["origin"], title=row["title"],
                       params=loads(row["params"], {}), started=row["started_at"], finished=finished,
                       status=status, error=error, result=loads(row["result"]), log=log,
                       include_log=include_log and log is not None,
                       summary=loads(row["summary"]) if "summary" in keys and row["summary"] else None,
                       log_lines=row["log_lines"] if "log_lines" in keys else None)


# --------------------------------------------------------------------------- docker engine

def container_rows(raw: list[dict], matched: set[str] | None = None) -> list[dict]:
    """Engine `/containers/json` entries -> `secmonk containers` / `GET /api/docker/containers` rows. `matched`: names
    or ids selected by a `--match` selector (None = no selector: every row matches)."""
    out = []
    for c in raw:
        names = [str(n).lstrip("/") for n in c.get("Names") or []]
        cid = str(c.get("Id", ""))
        hit = matched is None or bool(matched & {*names, cid, cid[:12]})
        out.append({"id": cid[:12], "name": ", ".join(names), "image": c.get("Image"), "state": c.get("State"),
                    "status": c.get("Status"), "matched": hit})
    return out


# --------------------------------------------------------------------------- host discovery

# host facts beyond {kind, target, name, os, os_version, arch}, by host kind (see _docs/tech/discover.md)
DISCOVER_HOST_EXTRA = {"k8s": ("context", "server", "kubernetes_version", "distro", "access", "other_contexts"),
                       "ssh": ("remote_hostname",)}


def discover_payload(raw: dict) -> dict:
    """discover.discover_host output -> `secmonk discover -f json` / `GET /api/discover`: every key present, host
    target without a password, warnings and reasons scrubbed of URL credentials."""
    from .collectors.base import scrub_text, strip_url_secrets

    h = raw.get("host") or {}
    host = {"kind": h.get("kind") or "local", "target": strip_url_secrets(h.get("target"), keep_user=True),
            "name": h.get("name"), "os": h.get("os"), "os_version": h.get("os_version"), "arch": h.get("arch")}
    for k in DISCOVER_HOST_EXTRA.get(host["kind"], ()):       # documented extra facts of that kind, when present
        if h.get(k) is not None:
            host[k] = strip_url_secrets(h[k]) if k == "server" and isinstance(h[k], str) else h[k]
    cands = []
    for c in raw.get("candidates") or []:
        cands.append({"id": c.get("id"), "collector": c.get("collector"), "target": c.get("target"),
                      "options": [str(o) for o in c.get("options") or []], "label": c.get("label") or c.get("id"),
                      "description": c.get("description") or "", "available": bool(c.get("available")),
                      "reason": scrub_text(c.get("reason")), "selected": bool(c.get("selected")),
                      "details": c.get("details") if isinstance(c.get("details"), (dict, list)) else {}})
    return {"host": host, "candidates": cands, "warnings": [scrub_text(str(w)) for w in raw.get("warnings") or []]}


# --------------------------------------------------------------------------- kubernetes

def kubeconfig_rows(raw: list[dict]) -> list[dict]:
    """k8s.list_kubeconfigs -> `GET /api/k8s/kubeconfigs`: [{path, contexts[{name, cluster, server, namespace,
    current}], error}]; server URLs without credentials. Kubeconfigs hold tokens and keys: nothing else is returned."""
    from .collectors.base import scrub_text, strip_url_secrets

    out = []
    for f in raw or []:
        ctxs = [{"name": c.get("name"), "cluster": c.get("cluster"), "server": strip_url_secrets(c.get("server")),
                 "namespace": c.get("namespace"), "current": bool(c.get("current"))}
                for c in f.get("contexts") or [] if isinstance(c, dict)]
        out.append({"path": str(f.get("path")), "contexts": ctxs, "error": scrub_text(f.get("error"))})
    return out
