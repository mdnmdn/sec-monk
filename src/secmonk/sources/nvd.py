"""NVD CVE API 2.0 source.

Spec: _docs/references/vuln-sources/nvd.md. Modes, by precedence:
  * `opts.path`: a local API-shaped JSON file, or a directory of them (tests, air-gapped import).
  * `opts.ids`: one `cveId` request per id.
  * otherwise the CVE endpoint: a delta from the stored cursor (lastModStartDate/lastModEndDate,
    split into windows under NVD's 120-day cap), or a full paginated pull when `opts.full` or no
    cursor is stored. The new cursor is the window end, captured before any request is sent.

Each page is committed in its own transaction, so a network failure keeps the progress made so far.
The cursor is only returned when the whole run succeeds.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self

import httpx

from ..db import get_sync_cursor, transaction
from .base import (
    Source,
    SyncOptions,
    SyncResult,
    add_affected,
    http_client,
    register,
    replace_children,
    severity_from_score,
    store_raw,
    upsert_vulnerability,
)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
WINDOW = timedelta(days=119)  # NVD caps lastMod windows at 120 days
_METRIC_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_CPE_SPLIT = re.compile(r"(?<!\\):")
_CPE_UNESCAPE = re.compile(r"\\(.)")
# (NVD cpeMatch field, events key). Order matters only for readability.
_BOUNDS = (
    ("versionStartIncluding", "introduced"),
    ("versionStartExcluding", "introduced_exclusive"),
    ("versionEndExcluding", "fixed"),
    ("versionEndIncluding", "last_affected"),
)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_ts(s: str) -> datetime:
    dt = datetime.fromisoformat(s)  # Python 3.12+ accepts a trailing Z
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    cur = start
    while cur < end:
        nxt = min(cur + WINDOW, end)
        yield cur, nxt
        cur = nxt


class _NvdClient:
    """HTTP client that applies the apiKey header and spaces requests to respect NVD rate limits."""

    def __init__(self, api_key: str | None) -> None:
        self._headers = {"apiKey": api_key} if api_key else {}
        self._pause = 0.6 if api_key else 6.0
        self._http = http_client(timeout=60.0)
        self._last: float | None = None

    def get(self, params: dict[str, Any]) -> dict[str, Any]:
        if self._last is not None:
            wait = self._pause - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        resp = self._http.get(API_URL, params=params, headers=self._headers)
        self._last = time.monotonic()
        resp.raise_for_status()
        return resp.json()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self._http.close()


def _local_pages(path: Path) -> Iterator[dict[str, Any]]:
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    for f in files:
        yield json.loads(f.read_text(encoding="utf-8"))


def _cve_pages(client: _NvdClient, params: dict[str, str]) -> Iterator[dict[str, Any]]:
    start = 0
    while True:
        doc = client.get({**params, "resultsPerPage": PAGE_SIZE, "startIndex": start})
        items = doc.get("vulnerabilities", [])
        yield doc
        start += len(items)
        if not items or start >= doc.get("totalResults", 0):
            return


def _id_pages(client: _NvdClient, ids: Iterable[str]) -> Iterator[dict[str, Any]]:
    for cve_id in ids:
        yield client.get({"cveId": cve_id.strip().upper()})


def _english(descriptions: list[dict[str, Any]] | None) -> str | None:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _best_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None, str | None]:
    """(score, vector, version, severity) from the newest CVSS metric available; Primary preferred."""
    for key in _METRIC_ORDER:
        entries = metrics.get(key) or []
        if not entries:
            continue
        m = min(entries, key=lambda e: e.get("type") != "Primary")
        data = m.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or m.get("baseSeverity") or severity_from_score(score)
        return score, data.get("vectorString"), data.get("version"), severity
    return None, None, None, None


def _cwes(weaknesses: list[dict[str, Any]] | None) -> list[str]:
    out: list[str] = []
    for w in sorted(weaknesses or [], key=lambda w: w.get("type") != "Primary"):
        for d in w.get("description", []):
            value = d.get("value", "")
            if value.startswith("CWE-") and value not in out:  # skips NVD-CWE-Other / NVD-CWE-noinfo
                out.append(value)
    return out


def _add_cpe(conn: sqlite3.Connection, cve_id: str, match: dict[str, Any]) -> None:
    criteria = match.get("criteria", "")
    fields = [_CPE_UNESCAPE.sub(r"\1", f) for f in _CPE_SPLIT.split(criteria)]
    if len(fields) < 6 or fields[0] != "cpe":
        return
    vendor, product, version = fields[3], fields[4], fields[5]

    events = [{ev: match[key]} for key, ev in _BOUNDS if match.get(key)]
    versions: list[str] | None = None
    if not events:
        if version == "*":
            events = [{"introduced": "0"}]  # all versions
        elif version not in ("-", ""):
            versions = [version]
        else:
            return  # '-' with no bounds: no version applies, nothing to match on

    add_affected(
        conn, "nvd", cve_id,
        vendor=vendor, product=product, cpe=criteria, range_type="CPE",
        events=events or None, versions=versions,
        extra={"matchCriteriaId": match.get("matchCriteriaId")},
    )


def _store_cve(conn: sqlite3.Connection, cve: dict[str, Any]) -> bool:
    cve_id = cve["id"]
    if cve.get("vulnStatus") == "Rejected":
        return False
    store_raw(conn, "nvd", cve_id, cve, modified=cve.get("lastModified"))
    score, vector, version, severity = _best_cvss(cve.get("metrics", {}))
    upsert_vulnerability(
        conn, "nvd", cve_id,
        summary=_english(cve.get("descriptions")),
        published=cve.get("published"),
        modified=cve.get("lastModified"),
        state=cve.get("vulnStatus"),
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=version,
        cwes=_cwes(cve.get("weaknesses")),
        extra={"sourceIdentifier": cve.get("sourceIdentifier"), "cveTags": cve.get("cveTags", [])},
    )
    replace_children(conn, "nvd", cve_id)
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    _add_cpe(conn, cve_id, match)
    return True


def _store_pages(conn: sqlite3.Connection, pages: Iterable[dict[str, Any]], opts: SyncOptions) -> int:
    count = 0
    for doc in pages:
        with transaction(conn):
            for item in doc.get("vulnerabilities", []):
                count += _store_cve(conn, item["cve"])
        opts.log(f"nvd: {count} records")
    return count


@register
class NvdSource(Source):
    name = "nvd"
    description = "NVD CVE API 2.0: CVSS, CWE and CPE applicability"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        api_key = opts.api_key or os.environ.get("NVD_API_KEY") or None
        try:
            if opts.path:
                count = _store_pages(conn, _local_pages(Path(opts.path)), opts)
                return SyncResult(self.name, records=count, message=f"from file {opts.path}")

            with _NvdClient(api_key) as client:
                if opts.ids:
                    count = _store_pages(conn, _id_pages(client, opts.ids), opts)
                    return SyncResult(self.name, records=count, message=f"{len(opts.ids)} ids")

                end = datetime.now(UTC)
                start = self._delta_start(conn, opts)
                if start is None:
                    count = _store_pages(conn, _cve_pages(client, {}), opts)
                    mode = "full"
                else:
                    count = 0
                    for lo, hi in _windows(start, end):
                        params = {"lastModStartDate": _iso(lo), "lastModEndDate": _iso(hi)}
                        count += _store_pages(conn, _cve_pages(client, params), opts)
                    mode = f"delta since {_iso(start)}"
            return SyncResult(self.name, records=count, cursor=_iso(end),
                              message=f"{mode}, NVD API {'with' if api_key else 'without'} key")
        except (httpx.HTTPError, OSError, ValueError, KeyError) as e:
            return SyncResult(self.name, status="error", message=str(e))

    @staticmethod
    def _delta_start(conn: sqlite3.Connection, opts: SyncOptions) -> datetime | None:
        if opts.full:
            return None
        if opts.since:
            return _parse_ts(opts.since)
        cursor = get_sync_cursor(conn, "nvd")
        return _parse_ts(cursor) if cursor else None
