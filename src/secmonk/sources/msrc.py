"""Microsoft Security Response Center (MSRC) CVRF v3 source: per-product *fixed build numbers*.

Spec: _docs/references/vuln-sources/msrc.md. `api.msrc.microsoft.com` is blocked in the dev sandbox and
the CVRF JSON shape below is written from knowledge: the fixture is SYNTHETIC. Import from a local
file/dir with `--path`, or download (`/cvrf/v3.0/updates`, then `/cvrf/v3.0/cvrf/{YYYY-Mon}`).

Each Vulnerability x Remediation(FixedBuild) x ProductID becomes an `affected` row
(vendor microsoft, product = normalized product name, events [introduced 0, fixed FixedBuild]).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx

from ..db import dumps, get_sync_cursor, loads, transaction
from .base import (
    Source,
    SyncOptions,
    SyncResult,
    add_affected,
    http_client,
    register,
    severity_from_score,
    store_raw,
    upsert_vulnerability,
)

SOURCE = "msrc"
API = "https://api.msrc.microsoft.com/cvrf/v3.0"
_JSON = {"Accept": "application/json"}
_ARCH_SUFFIX = re.compile(r"\s+for\s+(?:(?:x64|x86|arm64|itanium|ia-64)-based|32-bit|64-bit)\s+systems\s*$", re.IGNORECASE)
_CORE_SUFFIX = re.compile(r"\s*\(server core installation\)\s*$", re.IGNORECASE)
_SERVER_VERSION = re.compile(r"^windows server, version (\w+)", re.IGNORECASE)


def normalize_product_name(full_name: str) -> str:
    """MSRC FullProductName -> the product spelling Microsoft CNA records use (lowercase).

    'Windows 11 Version 23H2 for x64-based Systems' -> 'windows 11 version 23h2'
    'Windows Server 2022 (Server Core installation)' -> 'windows server 2022'
    The arch suffix and the Server Core suffix are dropped: CNA lists the base product (and, for 2019/2016,
    additionally a Core product with the same range), and arch variants share one FixedBuild.
    Exception: 'Windows Server, version 23H2 (Server Core installation)' is CNA's
    'Windows Server 2022, 23H2 Edition (Server Core installation)'."""
    s = " ".join(full_name.split())
    m = _SERVER_VERSION.match(s)
    if m:
        return f"windows server 2022, {m.group(1).lower()} edition (server core installation)"
    s = _ARCH_SUFFIX.sub("", _CORE_SUFFIX.sub("", _ARCH_SUFFIX.sub("", s)))
    return s.strip().lower()


def _walk_products(node: Any, out: dict[str, str]) -> None:
    if isinstance(node, dict):
        if "ProductID" in node and "Value" in node and isinstance(node["ProductID"], str):
            out[node["ProductID"]] = node["Value"]
        for v in node.values():
            _walk_products(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_products(v, out)


def product_tree(doc: dict) -> dict[str, str]:
    """ProductID -> FullProductName (flat list or nested Branch, both handled)."""
    out: dict[str, str] = {}
    _walk_products(doc.get("ProductTree") or {}, out)
    return out


def _value(x: Any) -> str | None:
    if isinstance(x, dict):
        x = x.get("Value")
    return str(x) if x not in (None, "") else None


def import_cvrf(conn: sqlite3.Connection, doc: dict) -> int:
    """Import one CVRF document (one month). Returns the number of vulnerabilities."""
    tree = product_tree(doc)
    tracking = doc.get("DocumentTracking") or {}
    doc_id = _value((tracking.get("Identification") or {}).get("ID"))
    released = tracking.get("CurrentReleaseDate")
    n = 0
    for vuln in doc.get("Vulnerability") or []:
        cve = vuln.get("CVE")
        if not cve:
            continue
        scores = [s for s in vuln.get("CVSSScoreSets") or [] if isinstance(s.get("BaseScore"), (int, float))]
        best = max(scores, key=lambda s: s["BaseScore"], default=None)
        desc = next((_value(nt) for nt in vuln.get("Notes") or [] if nt.get("Title") == "Description"), None)
        kbs: set[str] = set()
        rows: dict[tuple[str, str], dict] = {}
        for rem in vuln.get("Remediations") or []:
            kb = _value(rem.get("Description"))
            if kb and re.fullmatch(r"\d{6,8}", kb):
                kbs.add("KB" + kb)
            if str(rem.get("Type")) not in ("2", "Vendor Fix") or not rem.get("FixedBuild"):
                continue
            for pid in rem.get("ProductID") or []:
                name = tree.get(str(pid))
                if not name:
                    continue
                prod = normalize_product_name(name)
                key = (prod, rem["FixedBuild"])
                row = rows.setdefault(key, {"kbs": set(), "product_ids": [], "full_names": [],
                                            "supersedes": set()})
                if kb:
                    row["kbs"].add("KB" + kb)
                row["product_ids"].append(str(pid))
                row["full_names"].append(name)
                if rem.get("Supercedence"):
                    row["supersedes"].add(str(rem["Supercedence"]))
        with transaction(conn):
            # Only this document's rows are replaced: the same CVE ships fixes for different
            # products in different monthly documents, and each document owns its own rows.
            conn.execute("DELETE FROM affected WHERE source=? AND vuln_id=? "
                         "AND json_extract(extra,'$.document') IS ?", (SOURCE, cve, doc_id))
            prev = conn.execute("SELECT modified, extra FROM vulnerability WHERE source=? AND id=?",
                                (SOURCE, cve)).fetchone()
            prev_extra = loads(prev["extra"], {}) if prev else {}
            if not (prev and prev["modified"] and released and prev["modified"] > released):
                # newest document wins the vulnerability row (an older one never overwrites it)
                all_kbs = sorted(kbs | set(prev_extra.get("kbs") or []))
                upsert_vulnerability(
                    conn, SOURCE, cve, summary=_value(vuln.get("Title")), details=desc,
                    modified=released, published=tracking.get("InitialReleaseDate"),
                    severity=severity_from_score(best["BaseScore"]) if best else None,
                    cvss_score=best["BaseScore"] if best else None,
                    cvss_vector=best.get("Vector") if best else None,
                    cvss_version=(best.get("Vector") or "").split("/")[0].replace("CVSS:", "") or None
                    if best else None,
                    extra={"document": doc_id, "kbs": all_kbs})
                store_raw(conn, SOURCE, cve, vuln, modified=released)
            elif kbs - set(prev_extra.get("kbs") or []):
                prev_extra["kbs"] = sorted(kbs | set(prev_extra.get("kbs") or []))
                conn.execute("UPDATE vulnerability SET extra=? WHERE source=? AND id=?",
                             (dumps(prev_extra), SOURCE, cve))
            for (prod, fixed), row in sorted(rows.items()):
                add_affected(conn, SOURCE, cve, vendor="microsoft", product=prod, range_type="CVE",
                             version_type="custom", events=[{"introduced": "0"}, {"fixed": fixed}],
                             extra={"kb": sorted(row["kbs"]), "product_ids": row["product_ids"],
                                    "full_names": sorted(set(row["full_names"])),
                                    "supersedes": sorted(row["supersedes"]), "document": doc_id})
        n += 1
    return n


def _walk_files(path: Path) -> Iterator[Path]:
    if path.is_file():
        yield path
    else:
        yield from sorted(path.rglob("*.json"))


def _release_date(doc: dict) -> str:
    return str((doc.get("DocumentTracking") or {}).get("CurrentReleaseDate") or "")


def _local_docs(path: Path) -> Iterator[tuple[str, dict]]:
    """Local CVRF files in chronological order of their CurrentReleaseDate (file names do not sort
    chronologically). Only the date is kept while sorting; documents are re-read one at a time."""
    dated: list[tuple[str, str]] = []
    for p in _walk_files(path):
        try:
            dated.append((_release_date(json.loads(p.read_text(encoding="utf-8-sig"))), str(p)))
        except (ValueError, OSError, AttributeError):
            dated.append(("", str(p)))        # imported (and reported) in the main loop
    for _date, name in sorted(dated):
        p = Path(name)
        yield p.name, json.loads(p.read_text(encoding="utf-8-sig"))


def _download_months(opts: SyncOptions, cursor: str | None) -> Iterator[tuple[str, dict]]:
    with http_client(timeout=120.0) as client:
        resp = client.get(f"{API}/updates", headers=_JSON)
        resp.raise_for_status()
        updates = sorted(resp.json().get("value") or [], key=lambda u: u.get("CurrentReleaseDate") or "")
        if opts.since:
            updates = [u for u in updates if (u.get("CurrentReleaseDate") or "") >= opts.since]
        if cursor and not opts.full:         # months already imported (a revised month has a newer date)
            updates = [u for u in updates if (u.get("CurrentReleaseDate") or "") > cursor]
        if opts.limit:
            updates = updates[-opts.limit:]
        for u in updates:
            doc_id = u.get("ID") or u.get("Alias")
            opts.log(f"msrc: {doc_id}")
            r = client.get(u.get("CvrfUrl") or f"{API}/cvrf/{doc_id}", headers=_JSON)
            r.raise_for_status()
            yield doc_id, r.json()


@register
class MsrcSource(Source):
    name = SOURCE
    description = "Microsoft MSRC CVRF v3: per-product fixed builds + KBs for Windows/Office/.NET (API blocked in sandbox)"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        """Does not write `source_sync` (the CLI does, from the SyncResult). The cursor only
        advances over documents imported before the first failure."""
        total, errors, cursor = 0, 0, None
        try:
            if opts.path:
                path = Path(opts.path)
                if not path.exists():
                    return SyncResult(SOURCE, status="error", message=f"path not found: {path}")
                docs = _local_docs(path)
            else:
                docs = _download_months(opts, get_sync_cursor(conn, SOURCE))
            for name, doc in docs:
                try:
                    total += import_cvrf(conn, doc)
                    if not errors:
                        cursor = max(filter(None, [cursor, _release_date(doc)]), default=cursor)
                except (ValueError, KeyError, TypeError, AttributeError) as e:
                    errors += 1
                    opts.log(f"msrc: {name}: {e}")
        except (httpx.HTTPError, OSError, ValueError) as e:
            return SyncResult(SOURCE, records=total, status="partial" if total else "error",
                              cursor=cursor, message=str(e))
        n_all = conn.execute("SELECT COUNT(*) FROM vulnerability WHERE source=?", (SOURCE,)).fetchone()[0]
        return SyncResult(SOURCE, records=total, total=n_all, status="partial" if errors else "ok",
                          cursor=cursor, message=f"{total} vulnerabilities")
