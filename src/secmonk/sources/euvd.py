"""ENISA EUVD source.

Spec: _docs/references/vuln-sources/euvd.md. Default sync reads the exploited view
(`/exploitedvulnerabilities`) and the recent view (`/lastvulnerabilities`). With `opts.limit` it also
pages `/vulnerabilities`. `opts.path` imports a local JSON file, either a bare list or an object with
`items` or `content`. The endpoint shapes and product fields come from the docs and a synthetic
fixture, not from a live response, so they are handled defensively.

EUVD never overwrites EPSS: it inserts with INSERT OR IGNORE, so FIRST data stays first.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import httpx

from ..db import transaction
from .base import (
    Source,
    SyncOptions,
    SyncResult,
    add_affected,
    add_alias,
    http_client,
    register,
    replace_children,
    severity_from_score,
    store_raw,
    upsert_vulnerability,
)

SOURCE = "euvd"
BASE_URL = "https://euvdservices.enisa.europa.eu/api"
PAGE_SIZE = 100
_SPLIT = re.compile(r"[\s,]+")  # aliases: newline, space or comma separated


def _items(doc: Any) -> list[dict[str, Any]]:
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for key in ("items", "content"):
            if isinstance(doc.get(key), list):
                return doc[key]
    raise ValueError("unexpected EUVD response shape (no list of records)")


def _get(client: httpx.Client, path: str, params: dict[str, Any]) -> Any:
    resp = client.get(f"{BASE_URL}/{path}", params=params)
    resp.raise_for_status()
    return resp.json()


def _paged(client: httpx.Client, limit: int) -> list[dict[str, Any]]:
    got: list[dict[str, Any]] = []
    page = 0
    while len(got) < limit:
        items = _items(_get(client, "vulnerabilities", {"page": page, "size": PAGE_SIZE}))
        if not items:
            break
        got.extend(items)
        page += 1
    return got[:limit]


def _load_remote(opts: SyncOptions) -> list[tuple[str, list[dict[str, Any]]]]:
    """Return [(view, records)]; view is 'exploited' for the exploited feed, else 'other'."""
    batches: list[tuple[str, list[dict[str, Any]]]] = []
    with http_client(timeout=60.0) as client:
        exploited = _get(client, "exploitedvulnerabilities", {"size": PAGE_SIZE})
        batches.append(("exploited", _items(exploited)))
        batches.append(("other", _items(_get(client, "lastvulnerabilities", {}))))
        if opts.limit:
            batches.append(("other", _paged(client, opts.limit)))
    return batches


def _store(conn: sqlite3.Connection, rec: dict[str, Any], exploited_view: bool) -> bool:
    euvd_id = rec.get("id")
    if not euvd_id:
        return False
    exploited = bool(rec.get("exploited")) or exploited_view
    epss = rec.get("epss")
    products = [p for p in rec.get("products") or [] if isinstance(p, dict)]
    cves = [a.upper() for a in _SPLIT.split(rec.get("aliases") or "") if a.upper().startswith("CVE-")]
    score = rec.get("baseScore")
    modified = rec.get("dateUpdated")

    store_raw(conn, SOURCE, euvd_id, rec, modified=modified)
    upsert_vulnerability(
        conn, SOURCE, euvd_id,
        summary=rec.get("description"),
        published=rec.get("datePublished"),
        modified=modified,
        severity=severity_from_score(score),
        cvss_score=score,
        cvss_vector=rec.get("baseScoreVector"),
        cvss_version=rec.get("baseScoreVersion"),
        extra={
            "exploited": exploited,
            "epss": epss,
            "assigner": rec.get("assigner"),
            "vendors": sorted({p["vendor"] for p in products if p.get("vendor")}),
            "products": sorted({p["product"] for p in products if p.get("product")}),
        },
    )
    replace_children(conn, SOURCE, euvd_id)
    for cve in cves:
        add_alias(conn, SOURCE, euvd_id, cve)
    for p in products:
        add_affected(
            conn, SOURCE, euvd_id,
            vendor=p.get("vendor"), product=p.get("product"), range_type="CVE", version_type="euvd",
            versions=[p["version"]] if p.get("version") else None, extra=p,
        )
    if epss is not None:
        day = (modified or "")[:10] or None
        for cve in cves:  # keep first data: never overwrite an existing (FIRST) score
            conn.execute(
                "INSERT OR IGNORE INTO epss(cve_id, score, percentile, date, source) VALUES (?,?,NULL,?,'euvd')",
                (cve, float(epss), day),
            )
    return True


@register
class EuvdSource(Source):
    name = "euvd"
    description = "ENISA EUVD: exploited and recent EU vulnerability records, with CVE aliases"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        try:
            if opts.path:
                doc = json.loads(Path(opts.path).read_text(encoding="utf-8"))
                batches = [("other", _items(doc))]
                origin = f"from file {opts.path}"
            else:
                batches = _load_remote(opts)
                origin = f"from {BASE_URL}"
            seen: set[str] = set()
            with transaction(conn):
                for view, records in batches:
                    for rec in records:
                        if _store(conn, rec, exploited_view=view == "exploited"):
                            seen.add(rec["id"])
        except (httpx.HTTPError, OSError, ValueError, KeyError) as e:
            return SyncResult(self.name, status="error", message=str(e))

        return SyncResult(self.name, records=len(seen), status="ok", message=f"{len(seen)} records {origin}")

