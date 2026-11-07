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

Findings are keyed on a canonical id — the CVE: a CVE advisory is its own key, any other advisory
maps to the CVEs of its alias set (one finding per CVE), plus one finding per `upstream` CVE (OSV
`upstream`, alias.kind='upstream') — and enriched with CVSS/EPSS/KEV, then prioritized
(engine/scoring.py).
"""

from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass, field, replace

from ..db import dumps, loads, now
from ..models import CAT_LIBRARY, CAT_OS_PACKAGE, CAT_RUNTIME
from ..sources.base import norm_vendor_product
from . import purl as purls
from .scoring import priority
from .versions import compare, first_fixed_after, in_osv_range, is_parseable, scheme_for_ecosystem

log = logging.getLogger(__name__)

SOURCE_PREFERENCE = ("nvd", "cvelist", "osv", "euvd")
CANON_MAX_NODES = 500          # alias-graph BFS cap (logged when hit)


@dataclass
class Match:
    component_id: int
    advisory_id: str
    matched_by: str
    confidence: float
    fixed_version: str | None = None
    advisories: set[str] = field(default_factory=set)
    urgency: str | None = None                       # distro urgency from the OSV record (Debian)
    distro: tuple[str, tuple[str, ...]] | None = None  # (ecosystem, package names) for triage lookup
    version: str | None = None                       # installed version compared (source version)
    scheme: str = "generic"                          # version scheme of `version` / `fixed_version`
    matched: set[str] = field(default_factory=set)   # advisory ids whose affected rows matched


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
        f"""SELECT vuln_id, range_type, events, versions, extra FROM affected
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
                             first_fixed_after(check_version, events, scheme) if events else None,
                             urgency=loads(r["extra"], {}).get("urgency"),
                             distro=(eco, tuple(sorted(names))) if comp["category"] == CAT_OS_PACKAGE else None,
                             version=check_version, scheme=scheme))
    return out


# --------------------------------------------------------------------------- distro triage

def _triage(conn: sqlite3.Connection, m: Match, ids: set[str]) -> tuple[str | None, str | None, bool]:
    """(label, source, not_affected) for a distro-package match.

    Distro tracker rows (distro_triage) win over the urgency carried by the OSV record.
    `not_affected` is True when the distro states the release was never affected, or the tracker's
    fixed version is <= the installed one (tracker newer than the OSV snapshot)."""
    if not m.distro:
        return m.urgency if m.urgency not in (None, "", "not yet assigned") else None, "osv", False
    eco, names = m.distro
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    rows = []
    if cves:
        rows = conn.execute(
            f"""SELECT status, urgency, fixed_version, nodsa FROM distro_triage
                WHERE ecosystem = ? AND package IN ({','.join('?' * len(names))})
                  AND cve_id IN ({','.join('?' * len(cves))})""",
            (eco, *names, *cves)).fetchall()
    for r in rows:
        if r["status"] == "not-affected" or r["fixed_version"] == "0":
            return "not-affected", "debian-tracker", True
        if (r["status"] == "resolved" and r["fixed_version"] and m.version
                and compare(m.version, r["fixed_version"], scheme_for_ecosystem(eco)) >= 0):
            return "fixed-in-tracker", "debian-tracker", True
    for r in rows:
        if r["nodsa"]:
            return r["nodsa"], "debian-tracker", False
    for r in rows:
        u = (r["urgency"] or "").strip().lower()
        if u and u != "not yet assigned":
            return u, "debian-tracker", False
    if m.urgency and m.urgency != "not yet assigned":
        return m.urgency, "osv", False
    return None, None, False


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
    """Product keys to look up, normalized like affected.product (lowercase, '_' -> ' ')."""
    cands = {meta.get("product")} if meta.get("product") else set()
    cands.update(meta.get("product_alts") or [])
    if meta.get("brew_name"):       # normalize_product_name turns 'docker-compose' into 'docker compose'
        cands.add(re.sub(r"@[\d.]+$", "", str(meta["brew_name"]).lower()))
    from .classify import normalize_product_name

    cands.add(normalize_product_name(name))
    return {n for n in (norm_vendor_product(str(c)) for c in cands if c) if n}


_MAJOR = re.compile(r"^\s*[vV]?(\d+)")


def _major(v: str | None) -> int | None:
    m = _MAJOR.match(v or "")
    return int(m.group(1)) if m else None


def _upper_bound_only(events: list[dict]) -> str | None:
    """The bound of a range that is only an upper bound ([introduced 0,] fixed|last_affected X)."""
    bounds = [e for e in events if "fixed" in e or "last_affected" in e]
    starts = [e for e in events if "introduced" in e or "introduced_exclusive" in e]
    if len(bounds) != 1 or len(events) != len(bounds) + len(starts):
        return None
    if any(e.get("introduced") not in ("0", "") for e in starts):
        return None
    b = bounds[0]
    return b.get("fixed", b.get("last_affected"))


def _release_line_bounds(rows: list[sqlite3.Row]) -> dict[int, str]:
    """Per-release-line CNA entries (Apple: one 'macOS' entry per train, each 'unspecified < X').

    When one CVE has several upper-bound-only rows for the same vendor/product whose bounds are on
    different majors, each row except the lowest train is lower-bounded at its own major:
    '< 14.4' becomes [14.0, 14.4). Returns {row index: lower bound}."""
    groups: dict[tuple, list[tuple[int, int]]] = {}
    for i, r in enumerate(rows):
        bound = _upper_bound_only(loads(r["events"], []))
        major = _major(bound)
        if major is not None:
            groups.setdefault((r["vuln_id"], r["vendor"], r["product"]), []).append((i, major))
    out: dict[int, str] = {}
    for members in groups.values():
        majors = {m for _, m in members}
        if len(majors) < 2:
            continue
        lowest = min(majors)
        for i, major in members:
            if major != lowest:
                out[i] = f"{major}.0"
    return out


def _match_product(conn: sqlite3.Connection, comp: sqlite3.Row) -> list[Match]:
    version = comp["version"]
    if not version or not re.search(r"\d", version):
        return []                   # 'Version ??? (beta)': nothing to compare against a range
    meta = loads(comp["meta"], {})
    products = _product_candidates(meta, comp["name"])
    if not products:
        return []
    vendor = norm_vendor_product(comp["vendor"])
    vendors = ({vendor} | {n for n in (norm_vendor_product(v) for v in meta.get("vendor_alts") or []) if n}
               if vendor else set())
    hint = None if vendor else meta.get("vendor_hint")      # guessed from upstream repo/homepage
    base_conf = _base_confidence(meta)
    scheme = "generic"
    rows = conn.execute(
        f"""SELECT vuln_id, vendor, product, range_type, events, versions, status FROM affected
            WHERE product IN ({','.join('?' * len(products))}) AND range_type IN ('CVE','CPE')
            ORDER BY vuln_id, rowid""",
        tuple(sorted(products)),
    ).fetchall()
    rows = [r for r in rows if r["status"] == "affected"
            and not (vendor and r["vendor"] and norm_vendor_product(r["vendor"]) not in vendors)]
    line_floor = _release_line_bounds(rows)
    parseable = is_parseable(version, scheme)
    out: list[Match] = []
    for i, r in enumerate(rows):
        events = loads(r["events"], [])
        versions = loads(r["versions"], [])
        conf = base_conf if (vendor and r["vendor"]) else base_conf - 0.2
        if hint and r["vendor"]:
            # vendor guess: agreeing vendor = full confidence, a different vendor lowers it by 0.2 more
            conf = base_conf if _vendor_consistent(r["vendor"], hint) else base_conf - 0.4
        if not parseable:
            conf -= 0.2
        hit = version in versions
        if not hit and events:
            # 'introduced_exclusive' (NVD versionStartExcluding) is approximated as inclusive start
            norm = [{"introduced": e["introduced_exclusive"]} if "introduced_exclusive" in e else e
                    for e in events]
            if i in line_floor:
                norm = [e for e in norm if "introduced" not in e] + [{"introduced": line_floor[i]}]
            hit = in_osv_range(version, norm, scheme)
            if hit and any("introduced_exclusive" in e and compare(version, e["introduced_exclusive"],
                                                                   scheme) == 0 for e in events):
                hit = False
        if hit:
            out.append(Match(comp["id"], r["vuln_id"], f"{r['range_type'].lower()}-product", round(conf, 2),
                             first_fixed_after(version, events, scheme) if events else None,
                             version=version, scheme=scheme))
    return out


# --------------------------------------------------------------------------- canonicalization

def _alias_has_kind(conn: sqlite3.Connection) -> bool:
    """Whether the alias table has the `kind` column (alias | upstream | related)."""
    return any(r[1] == "kind" for r in conn.execute("PRAGMA table_info(alias)"))


def _is_cve(i: str) -> bool:
    return i.upper().startswith("CVE-")


def _cve_key(i: str) -> tuple:
    """Numeric order of CVE ids (CVE-2024-9999 < CVE-2024-10000)."""
    parts = i.split("-")
    return tuple(int(p) if p.isdigit() else 0 for p in parts[1:3]) + (i,)


def canonical_ids(conn: sqlite3.Connection, vuln_id: str, *,
                  cache: dict[str, tuple[str, set[str]]] | None = None,
                  has_kind: bool | None = None) -> tuple[str, set[str]]:
    """Return (canonical id, alias set) for `vuln_id`.

    The alias set is the connected component of `vuln_id` over *alias* edges only (alias.kind =
    'alias'; OSV `upstream`/`related` edges are not followed), walked breadth-first with a sorted
    frontier so the result is deterministic; the walk stops at CANON_MAX_NODES nodes (logged).
    Canonical id: a CVE id is its own canonical id; otherwise the lowest CVE of the set, else the
    lowest id of the set. With `cache`, every visited node is cached (it has the same component)."""
    if cache is not None and vuln_id in cache:
        return cache[vuln_id]
    if has_kind is None:
        has_kind = _alias_has_kind(conn)
    q = ("SELECT alias AS x FROM alias WHERE vuln_id=?{k} UNION SELECT vuln_id FROM alias WHERE alias=?{k}"
         .format(k=" AND COALESCE(kind, 'alias') = 'alias'" if has_kind else ""))
    seen = {vuln_id}
    frontier = [vuln_id]
    truncated = False
    while frontier and not truncated:
        nxt: set[str] = set()
        for cur in sorted(frontier):
            for row in conn.execute(q, (cur, cur)):
                x = row["x"]
                if x in seen:
                    continue
                if len(seen) >= CANON_MAX_NODES:
                    truncated = True
                    break
                seen.add(x)
                nxt.add(x)
            if truncated:
                break
        frontier = sorted(nxt)
    if truncated:
        log.warning("alias graph of %s exceeds %d nodes; canonicalization truncated", vuln_id, CANON_MAX_NODES)
    cves = [a for a in seen if _is_cve(a)]
    group = min(cves, key=_cve_key) if cves else min(seen)
    if cache is not None:
        for node in (seen if not truncated else (vuln_id,)):
            cache.setdefault(node, (node if _is_cve(node) else group, seen))
    return (vuln_id if _is_cve(vuln_id) else group), seen


_canonical = canonical_ids          # backward-compatible name (cli)


def _upstream_ids(conn: sqlite3.Connection, advisory_id: str) -> list[str]:
    """OSV `upstream` ids of an advisory (alias rows with kind='upstream'; needs the kind column)."""
    return sorted({r[0] for r in conn.execute(
        "SELECT alias FROM alias WHERE vuln_id=? AND kind='upstream'", (advisory_id,))})


def _finding_keys(conn: sqlite3.Connection, advisory_id: str, cache: dict, has_kind: bool,
                  ) -> list[tuple[str, set[str]]]:
    """Finding keys (canonical id, its alias set) for one matched advisory.

    A CVE is its own key. Another advisory yields one key per CVE in its alias set (a GHSA listing
    two CVEs = two findings), else its canonical id; plus one key per `upstream` id (an RHSA / DSA
    fixing several CVEs = one finding per CVE)."""
    def keys_of(vid: str) -> dict[str, set[str]]:
        canon, ids = canonical_ids(conn, vid, cache=cache, has_kind=has_kind)
        if _is_cve(vid):
            return {vid: ids}
        cves = sorted(i for i in ids if _is_cve(i))
        if len(cves) <= 1:
            return {canon: ids}
        return {c: canonical_ids(conn, c, cache=cache, has_kind=has_kind)[1] for c in cves}

    out = keys_of(advisory_id)
    if has_kind and not _is_cve(advisory_id):
        for up in _upstream_ids(conn, advisory_id):
            for k, ids in keys_of(up).items():
                out[k] = out.get(k, set()) | ids
    if len(out) > 1:
        # an advisory with CVE keys never yields its own (non-CVE) id as an extra finding
        cve_keys = {k for k in out if _is_cve(k)}
        if cve_keys:
            out = {k: v for k, v in out.items() if k in cve_keys}
    return sorted(out.items())


def _withdrawn_ids(conn: sqlite3.Connection, ids: set[str]) -> set[str]:
    """Ids with a withdrawn / REJECTED record in any source."""
    if not ids:
        return set()
    return {r[0] for r in conn.execute(
        f"""SELECT DISTINCT id FROM vulnerability WHERE id IN ({','.join('?' * len(ids))})
            AND (withdrawn IS NOT NULL AND withdrawn != '' OR UPPER(COALESCE(state, '')) = 'REJECTED')""",
        tuple(ids))}


def _vuln_facts(conn: sqlite3.Connection, ids: set[str], canon: str) -> dict:
    ph = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT source, id, severity, cvss_score, withdrawn, state FROM vulnerability WHERE id IN ({ph})",
        tuple(ids),
    ).fetchall()
    # withdrawn / rejected records never feed the facts; the canonical id's own records win
    rows = [r for r in rows if not r["withdrawn"] and (r["state"] or "").upper() != "REJECTED"]
    rows = sorted(rows, key=lambda r: (r["id"] != canon, SOURCE_PREFERENCE.index(r["source"])
                                       if r["source"] in SOURCE_PREFERENCE else 99, r["id"]))
    facts = {"severity": None, "cvss_score": None}
    for r in rows:
        if facts["cvss_score"] is None and r["cvss_score"] is not None:
            facts["cvss_score"] = r["cvss_score"]
            facts["severity"] = r["severity"]
        if facts["severity"] is None and r["severity"]:
            facts["severity"] = r["severity"]
    cves = sorted({canon} if _is_cve(canon) else {i for i in ids if _is_cve(i)})
    facts["kev"] = bool(cves) and conn.execute(
        f"SELECT 1 FROM kev WHERE cve_id IN ({','.join('?' * len(cves))})", cves).fetchone() is not None
    facts["epss"] = None
    if cves:
        r = conn.execute(f"SELECT MAX(score) s FROM epss WHERE cve_id IN ({','.join('?' * len(cves))})",
                         cves).fetchone()
        facts["epss"] = r["s"]
    return facts


# --------------------------------------------------------------------------- merging

def _merge(prev: Match, m: Match) -> Match:
    """Merge two matches of the same (component, canonical id). The higher confidence wins the
    strategy; advisories are unioned; urgency/distro/version are carried from whichever has them;
    the fixed version is the HIGHEST fix above the installed version (all advisories satisfied)."""
    best, other = (m, prev) if m.confidence > prev.confidence else (prev, m)
    best.advisories |= other.advisories
    best.matched |= other.matched
    best.urgency = best.urgency or other.urgency
    best.distro = best.distro or other.distro
    best.version = best.version or other.version
    fixes = [f for f in (prev.fixed_version, m.fixed_version) if f]
    if best.version:
        fixes = [f for f in fixes if compare(f, best.version, best.scheme) > 0] or fixes
    fixed = None
    for f in fixes:
        if fixed is None or compare(f, fixed, best.scheme) > 0:
            fixed = f
    best.fixed_version = fixed
    return best


def _rekey(conn: sqlite3.Connection, asset_id: str, comp_id: int, canon: str, m: Match,
           current_keys: set[str]) -> None:
    """Canonical ids drift (a GHSA gains its CVE alias on the next sync). Before writing a finding
    under `canon`, move an existing finding of the same component keyed by one of this match's
    advisory ids to `canon`, keeping status (suppressed!) and first_seen."""
    if conn.execute("SELECT 1 FROM finding WHERE asset_id=? AND component_id=? AND vuln_id=?",
                    (asset_id, comp_id, canon)).fetchone():
        return
    # CVE ids are their own keys: only non-CVE keys (GHSA, PYSEC, RHSA...) are ever re-keyed
    olds = sorted(i for i in (m.advisories | m.matched) - current_keys - {canon} if not _is_cve(i))
    if not olds:
        return
    row = conn.execute(
        f"""SELECT vuln_id FROM finding WHERE asset_id=? AND component_id=?
              AND vuln_id IN ({','.join('?' * len(olds))})
            ORDER BY status='suppressed' DESC, first_seen, vuln_id LIMIT 1""",
        (asset_id, comp_id, *olds)).fetchone()
    if row:
        conn.execute("UPDATE finding SET vuln_id=? WHERE asset_id=? AND component_id=? AND vuln_id=?",
                     (canon, asset_id, comp_id, row["vuln_id"]))


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

    # one finding per (component, canonical id); see _finding_keys / _merge
    has_kind = _alias_has_kind(conn)
    canon_cache: dict[str, tuple[str, set[str]]] = {}
    keys_cache: dict[str, list[tuple[str, set[str]]]] = {}
    merged: dict[tuple[int, str], Match] = {}
    for m in matches:
        if m.confidence < min_confidence:
            continue
        keys = keys_cache.get(m.advisory_id)
        if keys is None:
            keys = keys_cache[m.advisory_id] = _finding_keys(conn, m.advisory_id, canon_cache, has_kind)
        for canon, aliases in keys:
            mm = replace(m, advisories=set(aliases) | {m.advisory_id}, matched={m.advisory_id})
            key = (m.component_id, canon)
            prev = merged.get(key)
            merged[key] = mm if prev is None else _merge(prev, mm)

    ts = now()
    seen_keys = set()
    keys_by_comp: dict[int, set[str]] = {}
    for comp_id, canon in merged:
        keys_by_comp.setdefault(comp_id, set()).add(canon)
    stats = {"components": len(comps), "matches": len(matches), "findings": 0, "withdrawn": 0, "patched": 0}
    patched = {c["id"]: {x.upper() for x in loads(c["meta"], {}).get("patched_cves") or []} for c in comps}
    for (comp_id, canon), m in sorted(merged.items()):
        ids = m.advisories | {canon}
        own = {canon} if _is_cve(canon) else ids
        if patched.get(comp_id) and patched[comp_id] & {i.upper() for i in own}:
            stats["patched"] += 1          # fixed by a Homebrew formula patch (`patch ... resolves CVE-x`)
            continue
        # drop only when every advisory that matched is withdrawn, or the CVE itself is rejected
        withdrawn = _withdrawn_ids(conn, m.matched | ({canon} if _is_cve(canon) else set()))
        if m.matched <= withdrawn or (_is_cve(canon) and canon in withdrawn):
            stats["withdrawn"] += 1
            continue
        triage, triage_src, not_affected = _triage(conn, m, own)
        if not_affected:
            stats["not_affected"] = stats.get("not_affected", 0) + 1   # distro tracker says not affected
            continue
        facts = _vuln_facts(conn, ids, canon)
        prio = priority(cvss=facts["cvss_score"], epss=facts["epss"], kev=facts["kev"], asset_meta=asset_meta,
                        triage=triage, severity=facts["severity"])
        seen_keys.add((comp_id, canon))
        _rekey(conn, asset_id, comp_id, canon, m, keys_by_comp[comp_id])
        conn.execute(
            """INSERT INTO finding(asset_id, component_id, vuln_id, advisory_ids, matched_by, confidence,
                                   fixed_version, severity, cvss_score, epss, kev, priority, status,
                                   first_seen, last_seen, triage, triage_source)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'open', ?, ?, ?, ?)
               ON CONFLICT(asset_id, component_id, vuln_id) DO UPDATE SET
                 advisory_ids=excluded.advisory_ids, matched_by=excluded.matched_by,
                 confidence=excluded.confidence, fixed_version=excluded.fixed_version,
                 severity=excluded.severity, cvss_score=excluded.cvss_score, epss=excluded.epss,
                 kev=excluded.kev, priority=excluded.priority, last_seen=excluded.last_seen,
                 triage=excluded.triage, triage_source=excluded.triage_source,
                 status=CASE WHEN finding.status='suppressed' THEN 'suppressed' ELSE 'open' END,
                 fixed_at=NULL""",
            (asset_id, comp_id, canon, dumps(sorted(m.advisories)), m.matched_by, m.confidence,
             m.fixed_version, facts["severity"], facts["cvss_score"], facts["epss"], int(facts["kev"]),
             prio, ts, ts, triage, triage_src),
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
