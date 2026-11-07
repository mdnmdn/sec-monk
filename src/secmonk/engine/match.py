"""Match an asset's components against the local vulnerability mirror.

Strategies (see _docs/tech/engine/matching.md):
  1. `osv-package`  — component has an OSV ecosystem (language or distro package): exact
     (ecosystem, package) lookup in `affected`, OSV range evaluation. Distro packages are also
     looked up by their *source* package name (Debian/Ubuntu OSV records use source names).
     confidence 1.0
  2. `cve-product`  — applications / brew formulae / runtimes / the OS: product-name lookup in
     CNA `affected` (range_type CVE) and NVD/CNA CPE rows (range_type CPE), generic-ish version
     comparison. base confidence by `meta.product_source`: brew-seed 0.85, alias-table 0.8,
     brew-name-vendor 0.7, normalized-name 0.5 (0.4 for brew formulae); vendor mismatch drops the
     candidate (vendor known) or lowers it (vendor only guessed: meta.vendor_hint).
     Findings whose CVE is in `meta.patched_cves` (Homebrew formula backports) are dropped ("patched").

Findings are de-duplicated on a canonical id (the CVE alias when one exists) and enriched with
CVSS/EPSS/KEV, then prioritized (engine/scoring.py).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field

from ..db import dumps, loads, now
from ..models import CAT_LIBRARY, CAT_OS_PACKAGE, CAT_RUNTIME
from . import purl as purls
from .scoring import priority
from .versions import compare, first_fixed_after, in_osv_range, is_parseable, scheme_for_ecosystem

SOURCE_PREFERENCE = ("nvd", "cvelist", "osv", "euvd")


@dataclass
class Match:
    component_id: int
    advisory_id: str
    matched_by: str
    confidence: float
    fixed_version: str | None = None
    advisories: set[str] = field(default_factory=set)


# --------------------------------------------------------------------------- strategies

def _match_package(conn: sqlite3.Connection, comp: sqlite3.Row) -> list[Match]:
    eco, version = comp["ecosystem"], comp["version"]
    if not eco or not version:
        return []
    meta = loads(comp["meta"], {})
    names = {purls.normalize_name(eco, comp["name"])}
    if meta.get("source_package"):
        names.add(purls.normalize_name(eco, meta["source_package"]))
    scheme = scheme_for_ecosystem(eco)
    # distro-package versions in OSV are the *source* version; binary usually equals it,
    # but when the collector knows the source version prefer it.
    check_version = meta.get("source_version") or version
    rows = conn.execute(
        f"""SELECT vuln_id, range_type, events, versions FROM affected
            WHERE ecosystem = ? AND package IN ({','.join('?' * len(names))})
              AND status = 'affected' AND range_type IN ('ECOSYSTEM','SEMVER','VERSIONS')""",
        (eco, *names),
    ).fetchall()
    out: list[Match] = []
    for r in rows:
        events = loads(r["events"], [])
        versions = loads(r["versions"], [])
        # explicit version lists may spell versions with a 'v' prefix (Packagist, Go) or without
        cands = {check_version, version, f"v{version}", version.removeprefix("v")}
        hit = bool(cands & set(versions))
        if not hit and events:
            hit = in_osv_range(check_version, events, scheme)
        if hit:
            # parsers may lower confidence for weak identification (e.g. jar matched by filename)
            out.append(Match(comp["id"], r["vuln_id"], "osv-package", float(meta.get("confidence", 1.0)),
                             first_fixed_after(check_version, events, scheme) if events else None))
    return out


# base confidence of a name-based match by how the component's product identity was derived
# (engine/classify.py sets meta.product_source); see _docs/tech/engine/matching.md
PRODUCT_SOURCE_CONFIDENCE = {"brew-seed": 0.85, "alias-table": 0.8, "brew-name-vendor": 0.7,
                             "normalized-name": 0.5}
BREW_NORMALIZED_NAME_CONFIDENCE = 0.4      # generic formula names collide (portal, cobalt, dex, gh, hub...)


def _base_confidence(meta: dict) -> float:
    src = meta.get("product_source")
    if src == "normalized-name" and meta.get("brew_kind") == "formula":
        return BREW_NORMALIZED_NAME_CONFIDENCE
    return PRODUCT_SOURCE_CONFIDENCE.get(src, 0.5)


def _vendor_consistent(row_vendor: str, hint: str) -> bool:
    """Loose vendor agreement ('tukaani-project' ~ 'tukaani', 'curl' ~ 'haxx' is NOT): equal after
    removing punctuation, or one contains the other (>= 4 chars)."""
    a, b = (re.sub(r"[^a-z0-9]", "", x.lower()) for x in (row_vendor, hint))
    return bool(a and b and (a == b or (min(len(a), len(b)) >= 4 and (a in b or b in a))))


def _product_candidates(meta: dict, name: str) -> set[str]:
    cands = {meta.get("product")} if meta.get("product") else set()
    cands.update(meta.get("product_alts") or [])
    if meta.get("brew_name"):       # normalize_product_name turns 'docker-compose' into 'docker compose'
        cands.add(re.sub(r"@[\d.]+$", "", str(meta["brew_name"]).lower()))
    from .classify import normalize_product_name

    cands.add(normalize_product_name(name))
    return {c for c in cands if c}


def _match_product(conn: sqlite3.Connection, comp: sqlite3.Row) -> list[Match]:
    version = comp["version"]
    if not version:
        return []
    meta = loads(comp["meta"], {})
    products = _product_candidates(meta, comp["name"])
    vendor = (comp["vendor"] or "").lower() or None
    vendors = ({vendor} | {v.lower() for v in meta.get("vendor_alts") or []}) if vendor else set()
    hint = None if vendor else meta.get("vendor_hint")      # guessed from upstream repo/homepage
    base_conf = _base_confidence(meta)
    scheme = "generic"
    rows = conn.execute(
        f"""SELECT vuln_id, vendor, product, range_type, events, versions, status FROM affected
            WHERE product IN ({','.join('?' * len(products))}) AND range_type IN ('CVE','CPE')""",
        tuple(products),
    ).fetchall()
    out: list[Match] = []
    for r in rows:
        if vendor and r["vendor"] and r["vendor"] not in vendors:
            continue
        if r["status"] != "affected":
            continue
        events = loads(r["events"], [])
        versions = loads(r["versions"], [])
        conf = base_conf if (vendor and r["vendor"]) else base_conf - 0.2
        if hint and r["vendor"]:
            # vendor guess: agreeing vendor = full confidence, a different vendor lowers it by 0.2 more
            conf = base_conf if _vendor_consistent(r["vendor"], hint) else base_conf - 0.4
        if not is_parseable(version, scheme):
            conf -= 0.2
        hit = version in versions
        if not hit and events:
            # 'introduced_exclusive' (NVD versionStartExcluding) is approximated as inclusive start
            norm = [{"introduced": e["introduced_exclusive"]} if "introduced_exclusive" in e else e
                    for e in events]
            hit = in_osv_range(version, norm, scheme)
            if hit and any("introduced_exclusive" in e and compare(version, e["introduced_exclusive"],
                                                                   scheme) == 0 for e in events):
                hit = False
        if hit:
            out.append(Match(comp["id"], r["vuln_id"], f"{r['range_type'].lower()}-product", round(conf, 2),
                             first_fixed_after(version, events, scheme) if events else None))
    return out


# --------------------------------------------------------------------------- canonicalization

def _canonical(conn: sqlite3.Connection, vuln_id: str) -> tuple[str, set[str]]:
    """Return (canonical id, all known aliases). CVE ids win."""
    seen = {vuln_id}
    frontier = [vuln_id]
    while frontier and len(seen) < 50:
        cur = frontier.pop()
        for row in conn.execute(
            "SELECT alias AS x FROM alias WHERE vuln_id=? UNION SELECT vuln_id FROM alias WHERE alias=?",
            (cur, cur),
        ):
            if row["x"] not in seen:
                seen.add(row["x"])
                frontier.append(row["x"])
    cves = sorted(a for a in seen if a.startswith("CVE-"))
    return (cves[0] if cves else vuln_id), seen


def _vuln_facts(conn: sqlite3.Connection, ids: set[str]) -> dict:
    ph = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT source, id, severity, cvss_score, withdrawn, state FROM vulnerability WHERE id IN ({ph})",
        tuple(ids),
    ).fetchall()
    rows = sorted(rows, key=lambda r: SOURCE_PREFERENCE.index(r["source"])
                  if r["source"] in SOURCE_PREFERENCE else 99)
    facts = {"severity": None, "cvss_score": None, "withdrawn": False}
    for r in rows:
        if r["withdrawn"] or r["state"] == "REJECTED":
            facts["withdrawn"] = True
        if facts["cvss_score"] is None and r["cvss_score"] is not None:
            facts["cvss_score"] = r["cvss_score"]
            facts["severity"] = r["severity"]
        if facts["severity"] is None and r["severity"]:
            facts["severity"] = r["severity"]
    cves = [i for i in ids if i.startswith("CVE-")]
    facts["kev"] = bool(cves) and conn.execute(
        f"SELECT 1 FROM kev WHERE cve_id IN ({','.join('?' * len(cves))})", cves).fetchone() is not None
    facts["epss"] = None
    if cves:
        r = conn.execute(f"SELECT MAX(score) s FROM epss WHERE cve_id IN ({','.join('?' * len(cves))})",
                         cves).fetchone()
        facts["epss"] = r["s"]
    return facts


# --------------------------------------------------------------------------- entry point

def match_asset(conn: sqlite3.Connection, asset_id: str, min_confidence: float = 0.0) -> dict:
    from .inventory import current_components

    asset = conn.execute("SELECT * FROM asset WHERE id=?", (asset_id,)).fetchone()
    if asset is None:
        raise KeyError(asset_id)
    asset_meta = loads(asset["meta"], {})
    comps = current_components(conn, asset_id)
    matches: list[Match] = []
    for comp in comps:
        # anything with an OSV ecosystem is matched exactly — libraries, distro packages and
        # runtimes such as the Go stdlib (pkg:golang/stdlib) or Electron (pkg:npm/electron)
        if comp["ecosystem"] and (comp["category"] in (CAT_LIBRARY, CAT_OS_PACKAGE, CAT_RUNTIME)):
            matches += _match_package(conn, comp)
        else:
            matches += _match_product(conn, comp)

    # dedupe on (component, canonical id); keep best confidence, merge advisories
    merged: dict[tuple[int, str], Match] = {}
    canon_cache: dict[str, tuple[str, set[str]]] = {}
    for m in matches:
        if m.confidence < min_confidence:
            continue
        canon, aliases = canon_cache.setdefault(m.advisory_id, _canonical(conn, m.advisory_id))
        key = (m.component_id, canon)
        prev = merged.get(key)
        if prev is None or m.confidence > prev.confidence:
            m.advisories = set(aliases) | (prev.advisories if prev else set())
            m.fixed_version = m.fixed_version or (prev.fixed_version if prev else None)
            merged[key] = m
        else:
            prev.advisories |= aliases
            prev.fixed_version = prev.fixed_version or m.fixed_version

    ts = now()
    seen_keys = set()
    stats = {"components": len(comps), "matches": len(matches), "findings": 0, "withdrawn": 0, "patched": 0}
    patched = {c["id"]: {x.upper() for x in loads(c["meta"], {}).get("patched_cves") or []} for c in comps}
    for (comp_id, canon), m in merged.items():
        if patched.get(comp_id) and patched[comp_id] & (m.advisories | {canon}):
            stats["patched"] += 1          # fixed by a Homebrew formula patch (`patch ... resolves CVE-x`)
            continue
        facts = _vuln_facts(conn, m.advisories | {canon})
        if facts["withdrawn"]:
            stats["withdrawn"] += 1
            continue
        prio = priority(cvss=facts["cvss_score"], epss=facts["epss"], kev=facts["kev"], asset_meta=asset_meta)
        seen_keys.add((comp_id, canon))
        conn.execute(
            """INSERT INTO finding(asset_id, component_id, vuln_id, advisory_ids, matched_by, confidence,
                                   fixed_version, severity, cvss_score, epss, kev, priority, status,
                                   first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'open', ?, ?)
               ON CONFLICT(asset_id, component_id, vuln_id) DO UPDATE SET
                 advisory_ids=excluded.advisory_ids, matched_by=excluded.matched_by,
                 confidence=excluded.confidence, fixed_version=excluded.fixed_version,
                 severity=excluded.severity, cvss_score=excluded.cvss_score, epss=excluded.epss,
                 kev=excluded.kev, priority=excluded.priority, last_seen=excluded.last_seen,
                 status=CASE WHEN finding.status='suppressed' THEN 'suppressed' ELSE 'open' END,
                 fixed_at=NULL""",
            (asset_id, comp_id, canon, dumps(sorted(m.advisories)), m.matched_by, m.confidence,
             m.fixed_version, facts["severity"], facts["cvss_score"], facts["epss"], int(facts["kev"]),
             prio, ts, ts),
        )
        stats["findings"] += 1
    # lifecycle: open findings not re-detected are now fixed
    for row in conn.execute("SELECT component_id, vuln_id FROM finding WHERE asset_id=? AND status='open'",
                            (asset_id,)).fetchall():
        if (row["component_id"], row["vuln_id"]) not in seen_keys:
            conn.execute("UPDATE finding SET status='fixed', fixed_at=? WHERE asset_id=? AND component_id=? "
                         "AND vuln_id=?", (ts, asset_id, row["component_id"], row["vuln_id"]))
    conn.commit()
    return stats
