"""CVE List v5 (CVEProject/cvelistV5 + CISA Vulnrichment ADP) source.

Spec: _docs/references/vuln-sources/cvelist-v5.md. Sync modes: local file/dir, per-id raw fetch,
sparse partial git clone (default). All CNA/ADP `affected` data is stored with range_type "CVE"
(or "CPE" / "GIT" / "CVE-UNPARSED") so the matcher knows it is name-based CNA data.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import sqlite3
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .. import paths
from ..db import get_sync_cursor, loads, set_sync_state
from ..engine import purl as purl_mod
from ..engine.versions import compare as compare_versions
from .base import (
    Source,
    SyncOptions,
    SyncResult,
    add_affected,
    cpe_fields,
    http_client,
    norm_vendor_product,
    normalize_severity,
    register,
    replace_children,
    severity_from_score,
    store_raw,
    upsert_vulnerability,
)

SOURCE = "cvelist"
REPO_URL = "https://github.com/CVEProject/cvelistV5"
RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
CACHE_REPO: Path | None = None   # override (tests); default paths.cache_subdir("cvelistV5")
REFERENCED = "@referenced"

_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)


# --------------------------------------------------------------------------- paths


def cve_path(cve_id: str) -> str:
    """Repo-relative path: CVE-2021-44228 -> cves/2021/44xxx/CVE-2021-44228.json.

    The file name keeps the id's digits verbatim (CVE-2014-0160 -> cves/2014/0xxx/CVE-2014-0160.json);
    only the folder is derived from the numeric value (thousands + "xxx")."""
    m = _ID_RE.match(cve_id.strip())
    if not m:
        raise ValueError(f"not a CVE id: {cve_id!r}")
    year, digits = m.group(1), m.group(2)
    return f"cves/{year}/{int(digits) // 1000}xxx/CVE-{year}-{digits}.json"


def raw_url(cve_id: str) -> str:
    return RAW_BASE + cve_path(cve_id)


# --------------------------------------------------------------------------- version parsing

_VERSION_LIKE = re.compile(r"^[vV]?\d[0-9A-Za-z.+~_:\-]*$")
_HEX_HASH = re.compile(r"^[0-9a-fA-F]{7,64}$")
_NO_VERSION = {"", "n/a", "na", "unspecified", "unknown", "none", "-"}
_OPEN = {"0", "*", ""}


def is_version_like(s: Any) -> bool:
    """True for plain version strings ('2.0-beta9', '1.2.3', 'v4'); False for '128.*', 'log4j-core*',
    URLs, free text, comparison expressions."""
    return isinstance(s, str) and bool(_VERSION_LIKE.match(s.strip()))


def looks_like_commit(s: Any) -> bool:
    if not isinstance(s, str) or not _HEX_HASH.match(s.strip()):
        return False
    s = s.strip()
    return any(c in "abcdefABCDEF" for c in s) and len(s) >= 7 and (len(s) >= 12 or any(c.isdigit() for c in s))


_CMP = r"(?P<op><=|>=|<|>|=)\s*(?P<v>[^\s,;]+)"
_CMP_RE = re.compile(_CMP)
_SEP_RE = re.compile(r"[\s,;]+|\band\b|&&|&", re.IGNORECASE)
_RANGE_RE = re.compile(r"^(?P<a>[^\s]+)\s+(?:-|to|through|thru)\s+(?P<b>[^\s]+)$", re.IGNORECASE)
_OLDER_RE = re.compile(
    r"^(?:up to and including|up to|through|thru)\s+(?P<v>[^\s]+)$"
    r"|^(?P<v2>[^\s]+)\s+(?:and|or)\s+(?:earlier|older|prior|below|before|lower)(?:\s+versions?)?$",
    re.IGNORECASE,
)
_BEFORE_RE = re.compile(r"^(?:prior to|before|earlier than|below|older than)\s+(?P<v>[^\s]+)$", re.IGNORECASE)
_LATER_RE = re.compile(
    r"^(?P<v>[^\s]+)\s+(?:and|or)\s+(?:later|newer|above|higher)(?:\s+versions?)?$", re.IGNORECASE
)


def parse_version_expression(s: str) -> list[dict] | None:
    """Parse a free-text version expression into OSV-style events, or None if not understood.

    Handled: '< 2.5.4', '<= 1.2', '>= 1.0, <= 1.2', '>=1.0 <1.2', '3.0.0 - 3.0.3', '2.3 and earlier',
    '7.3.3-7015 and older versions', 'prior to 4.5', 'before 4.5', 'up to 2.0', '= 1.2', '1.0 or later'.
    A plain version ('1.2.3') is NOT an expression and returns None (callers treat it as exact).
    """
    if not isinstance(s, str):
        return None
    s = s.strip().rstrip(".,;")
    if not s or len(s) > 120:
        return None
    if is_version_like(s):
        return None

    m = _OLDER_RE.match(s)
    if m:
        v = m.group("v") or m.group("v2")
        return [{"introduced": "0"}, {"last_affected": v}] if is_version_like(v) else None
    m = _BEFORE_RE.match(s)
    if m:
        v = m.group("v")
        return [{"introduced": "0"}, {"fixed": v}] if is_version_like(v) else None
    m = _LATER_RE.match(s)
    if m:
        v = m.group("v")
        return [{"introduced": v}] if is_version_like(v) else None
    m = _RANGE_RE.match(s)
    if m and is_version_like(m.group("a")) and is_version_like(m.group("b")):
        return [{"introduced": m.group("a")}, {"last_affected": m.group("b")}]

    # comparison operators; everything must be consumed
    pos, parts = 0, []
    while pos < len(s):
        sep = _SEP_RE.match(s, pos)
        if sep and sep.end() > pos:
            pos = sep.end()
            continue
        cm = _CMP_RE.match(s, pos)
        if not cm:
            return None
        parts.append((cm.group("op"), cm.group("v")))
        pos = cm.end()
    if not parts or len(parts) > 2:
        return None
    if not all(is_version_like(v) for _, v in parts):
        return None
    intro: str | None = None
    fixed = last = None
    for op, v in parts:
        if op in (">=", ">"):
            intro = v
        elif op == "<":
            fixed = v
        elif op == "<=":
            last = v
        elif op == "=":
            intro, last = v, v
    if intro is None and fixed is None and last is None:
        return None
    ev: list[dict] = [{"introduced": intro or "0"}]
    if fixed is not None:
        ev.append({"fixed": fixed})
    elif last is not None:
        ev.append({"last_affected": last})
    return ev


def _events_from_changes(start: str | None, changes: list[dict]) -> list[dict] | None:
    """Build events from `changes[]` ([{at, status}]); None if any `at` is not version-like."""
    events: list[dict] = []
    open_ = False
    if start is not None:
        events.append({"introduced": start})
        open_ = True
    for ch in changes:
        at, st = ch.get("at"), str(ch.get("status", "")).lower()
        if not is_version_like(at):
            return None
        if st == "unaffected":
            if open_:
                events.append({"fixed": at})
                open_ = False
        elif st == "affected" and not open_:
            events.append({"introduced": at})
            open_ = True
    return events or None


def convert_version_entry(entry: dict) -> tuple[str, Any]:
    """Convert one `versions[]` entry (status affected) into a storable shape.

    Returns (kind, payload):
      ("events", [...])    range_type CVE
      ("versions", [v])    exact version, range_type CVE
      ("git", [...events]) commit-based, range_type GIT
      ("unparsed", None)   range_type CVE-UNPARSED, raw entry kept in extra
      ("skip", None)       nothing usable (version n/a with no bounds)
    """
    raw_v = entry.get("version")
    version = str(raw_v).strip() if raw_v is not None else ""
    lt = entry.get("lessThan")
    lte = entry.get("lessThanOrEqual")
    lt = str(lt).strip() if lt is not None else None
    lte = str(lte).strip() if lte is not None else None
    vtype = str(entry.get("versionType") or "").strip().lower()
    changes = [c for c in (entry.get("changes") or []) if isinstance(c, dict)]

    # commit-based data is not an installed-software version
    if vtype in ("git", "original_commit_for_fix") or looks_like_commit(version) or looks_like_commit(lt) \
            or looks_like_commit(lte):
        ev: list[dict] = []
        if version and version.lower() not in _NO_VERSION and version != "0":
            ev.append({"introduced": version})
        if lt:
            ev.append({"fixed": lt})
        elif lte:
            ev.append({"last_affected": lte})
        return "git", ev

    has_bound = lt is not None or lte is not None
    if not has_bound:
        if version.lower() in _NO_VERSION and version != "":
            return "skip", None
        if version in _OPEN:
            return "events", [{"introduced": "0"}]
        if is_version_like(version):
            if changes:
                ev2 = _events_from_changes(version, changes)
                return ("events", ev2) if ev2 else ("unparsed", None)
            return "versions", [version]
        expr = parse_version_expression(version)
        if expr:
            return "events", expr
        return "unparsed", None

    # bounded entry
    if version.lower() in _NO_VERSION and version != "":
        version = "0"
    start: str | None
    if version in _OPEN:
        start = "0"
    elif is_version_like(version):
        start = version
    else:
        start = None  # free text lower bound

    bound_kind = "fixed" if lt is not None else "last_affected"
    bound = lt if lt is not None else lte
    open_ended = bound == "*"
    bound_ok = open_ended or is_version_like(bound)

    if start is not None and bound_ok:
        if bound_kind == "fixed" and not open_ended and bound == start:
            start = "0"  # Chrome style: version == lessThan means "below this version"
        events: list[dict] = [{"introduced": start}]
        is_open = True
        valid = [c for c in changes if is_version_like(c.get("at"))]
        valid.sort(key=functools.cmp_to_key(lambda a, b: compare_versions(str(a["at"]), str(b["at"]))))
        for ch in valid:
            at, st = str(ch["at"]), str(ch.get("status", "")).lower()
            if not open_ended and compare_versions(at, bound) >= 0:
                continue                                  # changes at/after the bound are moot
            if st == "unaffected" and is_open:
                events.append({"fixed": at})
                is_open = False
            elif st == "affected" and not is_open:
                events.append({"introduced": at})
                is_open = True
        if is_open and not open_ended:
            events.append({bound_kind: bound})
        return "events", events

    # invalid bound or lower bound: try changes[], then free-text expression
    if changes:
        ev3 = _events_from_changes(start if start is not None else None, changes)
        if ev3:
            return "events", ev3
    return "unparsed", None


# --------------------------------------------------------------------------- ecosystems

_REGISTRY_HOSTS = {
    "registry.npmjs.org": "npm", "npmjs.com": "npm", "www.npmjs.com": "npm", "npmjs.org": "npm",
    "pypi.org": "PyPI", "pypi.python.org": "PyPI", "files.pythonhosted.org": "PyPI",
    "repo.maven.apache.org": "Maven", "repo1.maven.org": "Maven", "search.maven.org": "Maven",
    "mvnrepository.com": "Maven",
    "rubygems.org": "RubyGems",
    "crates.io": "crates.io",
    "packagist.org": "Packagist", "repo.packagist.org": "Packagist",
    "nuget.org": "NuGet", "www.nuget.org": "NuGet", "api.nuget.org": "NuGet",
    "pkg.go.dev": "Go", "proxy.golang.org": "Go",
}


def ecosystem_from_url(url: str | None) -> str | None:
    if not url or not isinstance(url, str):
        return None
    u = url.strip()
    if "://" not in u:
        u = "https://" + u
    try:
        host = (urlparse(u).hostname or "").lower()
    except ValueError:
        return None
    return _REGISTRY_HOSTS.get(host)


# --------------------------------------------------------------------------- record helpers


def _english(descs: list[dict] | None) -> str | None:
    for d in descs or []:
        if str(d.get("lang", "")).lower().startswith("en") and d.get("value"):
            return d["value"]
    return None


def _metric_candidates(container: dict) -> list[tuple[str, dict]]:
    out = []
    for m in container.get("metrics") or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if isinstance(m.get(key), dict) and m[key].get("baseScore") is not None:
                out.append((key, m[key]))
    return out


_CVSS_ORDER = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


def _best_cvss(cna: dict, adps: list[dict]) -> tuple[dict | None, str | None]:
    """(metric, provenance): CNA first (V4 > 3.1 > 3.0 > 2.0), else first ADP with any."""
    containers = [("cna", cna)] + [(f"adp:{a.get('providerMetadata', {}).get('shortName', '?')}", a)
                                   for a in adps]
    for prov, c in containers:
        cands = _metric_candidates(c)
        if cands:
            cands.sort(key=lambda kv: _CVSS_ORDER.index(kv[0]))
            return cands[0][1], prov
    return None, None


def _cwes(container: dict) -> list[str]:
    out: list[str] = []
    for pt in container.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId")
            if cwe and cwe not in out:
                out.append(cwe)
    return out


def _adp_other(adps: list[dict], typ: str) -> dict | None:
    for a in adps:
        for m in a.get("metrics") or []:
            o = m.get("other")
            if isinstance(o, dict) and o.get("type") == typ and isinstance(o.get("content"), dict):
                return o["content"]
    return None


def _ssvc(adps: list[dict]) -> dict | None:
    c = _adp_other(adps, "ssvc")
    if not c:
        return None
    out: dict[str, Any] = {}
    for opt in c.get("options") or []:
        if isinstance(opt, dict):
            out.update(opt)
    for k in ("version", "timestamp", "role"):
        if c.get(k):
            out[k] = c[k]
    return out or None


# --------------------------------------------------------------------------- affected import


def _import_affected_entry(conn: sqlite3.Connection, cve_id: str, aff: dict, container: str) -> int:
    vendor, product = aff.get("vendor"), aff.get("product")
    pkg = aff.get("packageName")
    pkg_raw = pkg.strip() if isinstance(pkg, str) and pkg.strip() else None
    if pkg_raw is None and norm_vendor_product(vendor) is None and norm_vendor_product(product) is None:
        return 0
    coll = aff.get("collectionURL")
    ecosystem = ecosystem_from_url(coll) if pkg_raw else None
    package = purl_mod.normalize_name(ecosystem, pkg_raw) if pkg_raw else None

    base_extra: dict[str, Any] = {"container": container}
    for k, v in (("package_name", pkg), ("collection_url", coll), ("platforms", aff.get("platforms")),
                 ("default_status", aff.get("defaultStatus")), ("cpes", aff.get("cpes"))):
        if v:
            base_extra[k] = v

    def row(range_type: str, vtype: str | None, status: str = "affected", events=None, versions=None,
            extra: dict | None = None) -> None:
        add_affected(conn, SOURCE, cve_id, ecosystem=ecosystem, package=package, vendor=vendor,
                     product=product, range_type=range_type, version_type=vtype, events=events,
                     versions=versions, status=status, extra={**base_extra, **(extra or {})})

    n = 0
    unaffected: list[dict] = []
    for v in aff.get("versions") or []:
        if not isinstance(v, dict):
            continue
        status = str(v.get("status") or aff.get("defaultStatus") or "").lower()
        vtype = str(v.get("versionType") or "").strip().lower() or None
        if status == "unaffected":
            unaffected.append(v)
            continue
        if status not in ("affected", ""):
            continue  # 'unknown'
        kind, payload = convert_version_entry(v)
        if kind == "events":
            row("CVE", vtype, events=payload)
        elif kind == "versions":
            row("CVE", vtype, versions=payload)
        elif kind == "git":
            row("GIT", vtype, events=payload)
        elif kind == "unparsed":
            row("CVE-UNPARSED", vtype, extra={"raw": v})
        else:
            continue
        n += 1
    # Unaffected-only entries (Mozilla style) are kept as ONE status="unaffected" row; they are
    # not converted to events (the implied affected set is ambiguous, see doc quirk 2).
    if n == 0 and unaffected:
        row("CVE", None, status="unaffected", extra={"unaffected_versions": unaffected})
        n += 1
    # defaultStatus "affected" with no usable versions: keep the statement (not matchable, but not lost)
    if n == 0 and str(aff.get("defaultStatus") or "").lower() == "affected":
        row("CVE-UNPARSED", None, status="affected", extra={"default_status": "affected"})
        n += 1
    return n


def _import_cpe_applicability(conn: sqlite3.Connection, cve_id: str, apps: list[dict]) -> int:
    n = 0
    stack = []
    for app in apps or []:
        stack.extend(app.get("nodes") or [])
    seen: set[str] = set()
    while stack:
        node = stack.pop(0)
        stack.extend(node.get("children") or [])
        for m in node.get("cpeMatch") or []:
            if m.get("vulnerable") is False or not m.get("criteria"):
                continue
            crit = m["criteria"]
            key = m.get("matchCriteriaId") or json.dumps(m, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            fields = cpe_fields(crit)
            if len(fields) < 6 or fields[0] != "cpe":
                continue
            vendor, product, raw_ver = fields[3], fields[4], fields[5]
            update = fields[6] if len(fields) > 6 else "*"
            exact = None if raw_ver in ("*", "-", "") else raw_ver
            events: list[dict] = []
            dropped: dict[str, Any] = {}
            start_key = start = None
            for field, ev in (("versionStartIncluding", "introduced"),
                              ("versionStartExcluding", "introduced_exclusive")):
                val = m.get(field)
                if val:
                    if is_version_like(val):
                        if start is None:
                            start_key, start = ev, val
                    else:
                        dropped[field] = val
            end_key = end = None
            for field, ev in (("versionEndExcluding", "fixed"), ("versionEndIncluding", "last_affected")):
                val = m.get(field)
                if val:
                    if is_version_like(val):
                        end_key, end = ev, val
                    else:
                        dropped[field] = val
            if start is not None or end is not None:
                events.append({start_key: start} if start is not None else {"introduced": "0"})
                if end is not None:
                    events.append({end_key: end})
            elif exact is None and raw_ver == "*" and not dropped:
                events = [{"introduced": "0"}]          # wildcard, no bounds: all versions (as nvd.py)
            versions = [exact] if exact and not events and is_version_like(exact) else None
            extra: dict[str, Any] = {"container": "cna"}
            # A bound we could not parse (e.g. a URL in versionEndExcluding), or a CPE `update`
            # such as beta/rc/p1, must never widen the range to "all versions"/the final release:
            # keep the row but make it unmatchable.
            if update not in ("*", "-", ""):
                dropped_update = True
                extra["cpe_update"] = update
            else:
                dropped_update = False
            if dropped:
                extra["dropped_bounds"] = dropped
            range_type = "CVE-UNPARSED" if (dropped or dropped_update) else "CPE"
            add_affected(conn, SOURCE, cve_id, vendor=vendor, product=product, cpe=crit,
                         range_type=range_type, events=events or None, versions=versions, extra=extra)
            n += 1
    return n


# --------------------------------------------------------------------------- record import


def import_record(conn: sqlite3.Connection, rec: dict) -> str | None:
    """Import one CVE record (parsed JSON). Returns the CVE id, or None if not a CVE record."""
    meta = rec.get("cveMetadata") if isinstance(rec, dict) else None
    if not isinstance(meta, dict) or not meta.get("cveId"):
        return None
    cve_id = meta["cveId"]
    state = meta.get("state")
    modified = meta.get("dateUpdated")
    containers = rec.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = [a for a in containers.get("adp") or [] if isinstance(a, dict)]
    rejected = state == "REJECTED"

    store_raw(conn, SOURCE, cve_id, rec, modified)
    replace_children(conn, SOURCE, cve_id)

    summary = _english(cna.get("rejectedReasons")) if rejected else None
    if summary is None:
        summary = _english(cna.get("descriptions")) or cna.get("title")
    if summary is None and rejected:
        summary = _english(cna.get("rejectedReasons"))

    extra: dict[str, Any] = {}
    metric, prov = _best_cvss(cna, adps)
    score = vector = version = severity = None
    if metric:
        score = float(metric["baseScore"])
        vector = metric.get("vectorString")
        version = str(metric["version"]) if metric.get("version") is not None else None
        sev = metric.get("baseSeverity")
        severity = normalize_severity(str(sev)) if sev else severity_from_score(score)
        extra["cvss_source"] = "cna" if prov == "cna" else prov
    cwes = _cwes(cna)
    if not cwes:
        for a in adps:
            cwes = _cwes(a)
            if cwes:
                break
    ssvc = _ssvc(adps)
    if ssvc:
        extra["ssvc"] = ssvc
    kev = _adp_other(adps, "kev")
    if kev:
        extra["adp_kev"] = kev
    if meta.get("assignerShortName"):
        extra["assigner"] = meta["assignerShortName"]
    if cna.get("title"):
        extra["title"] = cna["title"]
    refs: list[str] = []
    for c in [cna, *adps]:
        for r in c.get("references") or []:
            u = r.get("url")
            if u and u not in refs:
                refs.append(u)
    if refs:
        extra["references"] = refs[:20]

    upsert_vulnerability(
        conn, SOURCE, cve_id, summary=summary, published=meta.get("datePublished"), modified=modified,
        withdrawn=meta.get("dateRejected") if rejected else None, state=state, severity=severity,
        cvss_score=score, cvss_vector=vector, cvss_version=version, cwes=cwes, extra=extra or None)

    if not rejected:
        for aff in cna.get("affected") or []:
            if isinstance(aff, dict):
                _import_affected_entry(conn, cve_id, aff, "cna")
        for a in adps:
            short = a.get("providerMetadata", {}).get("shortName", "adp")
            for aff in a.get("affected") or []:
                if isinstance(aff, dict):
                    _import_affected_entry(conn, cve_id, aff, f"adp:{short}")
        _import_cpe_applicability(conn, cve_id, cna.get("cpeApplicability") or [])
    return cve_id


def _is_newer(conn: sqlite3.Connection, rec: dict) -> bool:
    meta = rec.get("cveMetadata") or {}
    row = conn.execute("SELECT modified FROM vulnerability WHERE source=? AND id=?",
                       (SOURCE, meta.get("cveId"))).fetchone()
    return not (row and row["modified"] and meta.get("dateUpdated")
                and row["modified"] >= meta["dateUpdated"])


def _import_guarded(conn: sqlite3.Connection, rec: dict) -> str | None:
    """import_record inside a SAVEPOINT: any exception rolls back that record only (the previous
    version of the record, children included, stays intact) and is re-raised to the caller."""
    if not conn.in_transaction:
        conn.execute("BEGIN")
    conn.execute("SAVEPOINT cve_rec")
    try:
        cid = import_record(conn, rec)
    except Exception:
        conn.execute("ROLLBACK TO cve_rec")
        conn.execute("RELEASE cve_rec")
        raise
    conn.execute("RELEASE cve_rec")
    return cid


def _import_files(conn: sqlite3.Connection, files: Iterator[Path] | list[Path], opts: SyncOptions
                  ) -> tuple[int, int, bool]:
    """Import files; returns (imported, errors, hit_limit)."""
    count = errors = 0
    for i, f in enumerate(files):
        if opts.limit is not None and count >= opts.limit:
            conn.commit()
            return count, errors, True
        try:
            rec = json.loads(Path(f).read_text(encoding="utf-8"))
            if not isinstance(rec, dict) or "cveMetadata" not in rec:
                continue
            if not opts.full and not _is_newer(conn, rec):
                continue
            if _import_guarded(conn, rec):
                count += 1
        except Exception as e:  # noqa: BLE001 - one bad record must not abort the sync
            errors += 1
            opts.log(f"cvelist: skipping {f}: {type(e).__name__}: {e}")
        if i % 500 == 499:
            conn.commit()
            opts.log(f"cvelist: {count} records")
    conn.commit()
    return count, errors, False


def _walk(path: Path) -> Iterator[Path]:
    if path.is_file():
        yield path
    else:
        yield from sorted(path.rglob("CVE-*.json"))


def renormalize(conn: sqlite3.Connection) -> tuple[int, int]:
    """Rebuild every cvelist vulnerability/affected row from `raw_record` (no download), so
    importer fixes reach an existing DB. Returns (rebuilt, errors)."""
    ok = errors = 0
    rows = conn.execute("SELECT record_id, data FROM raw_record WHERE source=?", (SOURCE,)).fetchall()
    for r in rows:
        try:
            if _import_guarded(conn, loads(r["data"])):
                ok += 1
        except Exception:  # noqa: BLE001
            errors += 1
    conn.commit()
    return ok, errors


# --------------------------------------------------------------------------- referenced ids


def referenced_ids(conn: sqlite3.Connection, limit: int | None = None) -> list[str]:
    """CVE ids seen in alias/kev with no cvelist row."""
    rows = conn.execute(
        """SELECT id FROM (
               SELECT DISTINCT alias AS id FROM alias WHERE alias LIKE 'CVE-%'
               UNION SELECT cve_id AS id FROM kev
           ) WHERE id NOT IN (SELECT id FROM vulnerability WHERE source=?) ORDER BY id""",
        (SOURCE,)).fetchall()
    ids = [r["id"] for r in rows if _ID_RE.match(r["id"] or "")]
    return ids[:limit] if limit is not None else ids


def _fetch_ids(conn: sqlite3.Connection, ids: list[str], opts: SyncOptions) -> tuple[int, int]:
    """Fetch via raw.githubusercontent.com. Returns (imported, errors); 404s are not errors."""
    count = errors = 0
    with http_client(timeout=30.0) as client:
        for cid in ids:
            if opts.limit is not None and count >= opts.limit:
                break
            try:
                url = raw_url(cid)
                resp = client.get(url)
                if resp.status_code == 404:
                    opts.log(f"cvelist: {cid} not found")
                    continue
                resp.raise_for_status()
                if _import_guarded(conn, resp.json()):
                    count += 1
            except Exception as e:  # noqa: BLE001 - network/JSON/record errors: keep going, report partial
                errors += 1
                opts.log(f"cvelist: {cid}: {type(e).__name__}: {e}")
            if count and count % 500 == 0:
                conn.commit()
    conn.commit()
    return count, errors


def fetch_missing(conn: sqlite3.Connection, cve_ids: list[str] | None, opts: SyncOptions) -> SyncResult:
    """Fetch (raw mode) CVE ids that have no cvelist row. With opts.ids == ['@referenced'] (or
    cve_ids None) the ids come from alias/kev tables, capped by opts.limit."""
    if cve_ids is None or opts.ids == [REFERENCED]:
        ids = referenced_ids(conn, opts.limit)
    else:
        have = {r["id"] for r in conn.execute("SELECT id FROM vulnerability WHERE source=?", (SOURCE,))}
        ids = [i.upper() for i in cve_ids if i.upper() not in have]
        if opts.limit is not None:
            ids = ids[:opts.limit]
    count, errors = _fetch_ids(conn, ids, opts)
    return SyncResult(SOURCE, records=count, status="partial" if errors else "ok",
                      message=f"fetched {count}/{len(ids)} ids" + (f", {errors} errors" if errors else ""))


# --------------------------------------------------------------------------- git mode

GIT_KEY = "cvelist:git"        # internal cursor row: last fully imported commit
YEARS_KEY = "cvelist:years"    # internal row: cursor = oldest year ever synced (backfill persistence)
_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GIT_HARDEN = ["-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
               "-c", "core.sshCommand=ssh", "-c", "protocol.ext.allow=never"]
_GIT_DROP_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_EXEC_PATH",
                 "GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_ASKPASS", "GIT_PAGER",
                 "GIT_CONFIG_COUNT")


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if k not in _GIT_DROP_ENV and not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    return env


def _git(args: list[str], cwd: Path | None = None) -> str:
    r = subprocess.run(["git", *_GIT_HARDEN, *args], cwd=cwd, check=True, capture_output=True,
                       text=True, env=_git_env(), timeout=3600)
    return r.stdout.strip()


def _years(since: str | None, oldest: int | None = None) -> list[str]:
    """Years to keep checked out: default previous+current year, widened by --since and by the
    oldest year synced earlier (so a plain sync never shrinks a --since backfill)."""
    cur = datetime.now(UTC).year
    start = cur - 1
    if since:
        m = re.match(r"\d{4}", since)
        if m:
            start = min(start, int(m.group()), cur)
    if oldest is not None:
        start = min(start, oldest)
    return [str(y) for y in range(start, cur + 1)]


def _cache_repo() -> Path:
    return CACHE_REPO if CACHE_REPO is not None else paths.cache_subdir("cvelistV5")


def _origin_matches(repo: Path, url: str) -> bool:
    if not (repo / ".git").is_dir():
        return False
    try:
        return _git(["config", "--local", "--get", "remote.origin.url"], repo) == url
    except subprocess.CalledProcessError:
        return False


def _sync_git(conn: sqlite3.Connection, opts: SyncOptions, repo: Path | None = None) -> SyncResult:
    repo = repo or _cache_repo()
    url = REPO_URL
    stored_years = get_sync_cursor(conn, YEARS_KEY)
    oldest = int(stored_years) if stored_years and stored_years.isdigit() else None
    years = _years(opts.since, oldest)
    sparse = [f"cves/{y}" for y in years]
    stored = get_sync_cursor(conn, GIT_KEY)
    old = stored if stored and _SHA_RE.match(stored) and not opts.full else None
    changed: list[Path] | None = None

    if (repo / ".git").exists() and not _origin_matches(repo, url):
        opts.log("cvelist: cache has a foreign/unknown origin; re-cloning")
        shutil.rmtree(repo)
    fresh = not (repo / ".git").exists()
    if fresh:
        repo.parent.mkdir(parents=True, exist_ok=True)
        opts.log("cvelist: cloning (partial, sparse)")
        _git(["clone", "--depth", "1", "--filter=blob:none", "--sparse", "--", url, str(repo)])
        old = None
    new_years = [y for y in years if not (repo / "cves" / y).exists()]
    _git(["sparse-checkout", "add", *sparse], repo)

    if not fresh:
        # always bring the cache to upstream HEAD; the cursor only picks diff vs full walk
        _git(["fetch", "--depth", "1", "origin", "main"], repo)
        new_sha = _git(["rev-parse", "FETCH_HEAD"], repo)
        walk_years = years
        if old is not None:
            walk_years = new_years
            if new_sha != old:
                try:
                    names = _git(["diff", "--name-only", "--end-of-options", old, new_sha, "--", "cves"],
                                 repo).splitlines()
                    changed = [repo / n for n in names if n.endswith(".json")]
                except subprocess.CalledProcessError:
                    # shallow history: old commit not available -> rely on dateUpdated comparison
                    opts.log("cvelist: diff unavailable, falling back to dateUpdated comparison")
                    walk_years = years
            else:
                changed = []
        _git(["reset", "--hard", "FETCH_HEAD"], repo)   # only inside the dedicated cache dir
        _git(["sparse-checkout", "reapply"], repo)
        walk_dirs = [repo / "cves" / y for y in walk_years]
    else:
        walk_dirs = [repo / "cves" / y for y in years]

    head = _git(["rev-parse", "HEAD"], repo)

    def files() -> Iterator[Path]:
        seen: set[Path] = set()
        for f in changed or []:
            if f.exists() and f not in seen:
                seen.add(f)
                yield f
        for d in walk_dirs:
            for f in _walk(d) if d.exists() else []:
                if f not in seen:
                    seen.add(f)
                    yield f

    count, errors, hit_limit = _import_files(conn, files(), opts)
    complete = not hit_limit and errors == 0
    if complete:
        # only a fully imported run may advance the internal cursor / widen the synced year range
        set_sync_state(conn, GIT_KEY, status="ok", cursor=head, message=f"git {head[:10]}")
        set_sync_state(conn, YEARS_KEY, status="ok", cursor=years[0], message="oldest synced year")
    return SyncResult(SOURCE, records=count, status="ok" if complete else "partial",
                      cursor=head if complete else None,
                      message=f"git {head[:10]}, years {years[0]}..{years[-1]}"
                      + (", limit reached" if hit_limit else "")
                      + (f", {errors} record errors" if errors else ""))


# --------------------------------------------------------------------------- source


@register
class CveListSource(Source):
    name = "cvelist"
    description = "CVE List v5 (CVEProject/cvelistV5) with CISA Vulnrichment ADP data"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        """Never writes the main `source_sync` row (the CLI does, from the SyncResult); the git
        cursor and year range live in the internal rows `cvelist:git` / `cvelist:years`.
        `SyncResult.records` = imported this run, `.total` = cvelist records in the DB."""
        try:
            if opts.path:
                path = Path(opts.path)
                if not path.exists():
                    return SyncResult(SOURCE, status="error", message=f"path not found: {path}")
                count, errors, _hit = _import_files(conn, _walk(path), opts)
                res = SyncResult(SOURCE, records=count, status="partial" if errors else "ok",
                                 message=f"imported {count} from {path}")
            elif opts.ids == [REFERENCED]:
                res = fetch_missing(conn, None, opts)
            elif opts.ids:
                count, errors = _fetch_ids(conn, [i.strip().upper() for i in opts.ids], opts)
                res = SyncResult(SOURCE, records=count, status="partial" if errors else "ok",
                                 message=f"fetched {count} ids")
            else:
                res = _sync_git(conn, opts)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            conn.rollback()
            detail = getattr(e, "stderr", "") or str(e)
            return SyncResult(SOURCE, status="error", message=f"git failed: {detail.strip()[:300]}")
        total = conn.execute("SELECT COUNT(*) FROM vulnerability WHERE source=?", (SOURCE,)).fetchone()[0]
        res.total = total
        return res
