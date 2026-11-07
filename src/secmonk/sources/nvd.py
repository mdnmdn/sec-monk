"""NVD CVE API 2.0 source.

Spec: _docs/references/vuln-sources/nvd.md. Modes, by precedence:
  * `opts.path`: a local API-shaped JSON file, or a directory of them (tests, air-gapped import).
  * `opts.ids`: one `cveId` request per id.
  * otherwise the CVE endpoint: a delta from the stored cursor (lastModStartDate/lastModEndDate,
    split into windows under NVD's 120-day cap), or a full paginated pull when `opts.full` or no
    cursor is stored. The new cursor is the window end, captured before any request is sent.

Each page is committed in its own transaction, so a network failure keeps the progress made so far.
Delta windows are processed oldest first; the end of every completed window is persisted in the
internal row `nvd:progress` (the main `nvd` row is written by the CLI from the SyncResult), so a
failure in window N never re-downloads windows 1..N-1. Failures return status "partial" with the
records and cursor of the completed work. Requests are retried (403/429/5xx, transport errors) with
exponential backoff honoring Retry-After. Redirects are never followed (the apiKey header must not
leave services.nvd.nist.gov).
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Self

import httpx

from ..db import get_sync_cursor, loads, set_sync_state, transaction
from .base import (
    Source,
    SyncOptions,
    SyncResult,
    add_affected,
    cpe_fields,
    http_client,
    normalize_severity,
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
PROGRESS_KEY = "nvd:progress"
MAX_RETRIES = 5
BACKOFF_BASE = 2.0
BACKOFF_MAX = 120.0
_RETRY_STATUS = {403, 429, 500, 502, 503, 504}
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


def _retry_after(resp: httpx.Response) -> float | None:
    raw = resp.headers.get("retry-after")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        try:
            return max(0.0, (parsedate_to_datetime(raw) - datetime.now(UTC)).total_seconds())
        except (TypeError, ValueError):
            return None


class _NvdClient:
    """HTTP client that applies the apiKey header, spaces requests to respect NVD rate limits and
    retries throttling/transient errors with exponential backoff."""

    def __init__(self, api_key: str | None) -> None:
        self._headers = {"apiKey": api_key} if api_key else {}
        self._pause = 0.6 if api_key else 6.0
        self._http = http_client(timeout=60.0, follow_redirects=False)
        self._last: float | None = None

    def get(self, params: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(MAX_RETRIES + 1):
            if self._last is not None:
                wait = self._pause - (time.monotonic() - self._last)
                if wait > 0:
                    time.sleep(wait)
            try:
                resp = self._http.get(API_URL, params=params, headers=self._headers)
            except httpx.TransportError:
                self._last = time.monotonic()
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(min(BACKOFF_MAX, BACKOFF_BASE * 2 ** attempt))
                continue
            self._last = time.monotonic()
            if resp.status_code in _RETRY_STATUS and attempt < MAX_RETRIES:
                delay = _retry_after(resp)
                time.sleep(min(BACKOFF_MAX, delay if delay is not None else BACKOFF_BASE * 2 ** attempt))
                continue
            resp.raise_for_status()
            return resp.json()
        raise RuntimeError("unreachable")  # pragma: no cover

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
    """(score, vector, version, severity): a Primary (NVD) assessment beats a Secondary (CNA) one
    whatever the version; within the same type the newest version wins (4.0 > 3.1 > 3.0 > 2.0)."""
    best: tuple[tuple[bool, int], dict[str, Any]] | None = None
    for rank, key in enumerate(_METRIC_ORDER):
        for m in metrics.get(key) or []:
            k = (m.get("type") != "Primary", rank)
            if best is None or k < best[0]:
                best = (k, m)
    if best is None:
        return None, None, None, None
    m = best[1]
    data = m.get("cvssData", {})
    score = data.get("baseScore")
    severity = normalize_severity(data.get("baseSeverity") or m.get("baseSeverity")) or severity_from_score(score)
    return score, data.get("vectorString"), data.get("version"), severity


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
    fields = cpe_fields(criteria)
    if len(fields) < 6 or fields[0] != "cpe":
        return
    vendor, product, version = fields[3], fields[4], fields[5]
    update = fields[6] if len(fields) > 6 else "*"

    events = [{ev: match[key]} for key, ev in _BOUNDS if match.get(key)]
    versions: list[str] | None = None
    if events and not any(k in ev for ev in events for k in ("introduced", "introduced_exclusive")):
        events.insert(0, {"introduced": "0"})   # end-only bound (e.g. < 120.0.6099.109): from the beginning
    if not events:
        if version == "*":
            events = [{"introduced": "0"}]  # all versions
        elif version not in ("-", ""):
            versions = [version]
        else:
            return  # '-' with no bounds: no version applies, nothing to match on

    extra: dict[str, Any] = {"matchCriteriaId": match.get("matchCriteriaId")}
    range_type = "CPE"
    if update not in ("*", "-", ""):
        # beta/rc/pN: matching the bare version would flag the final release -> unmatchable row
        range_type = "CVE-UNPARSED"
        extra["cpe_update"] = update
    add_affected(
        conn, "nvd", cve_id,
        vendor=vendor, product=product, cpe=criteria, range_type=range_type,
        events=events or None, versions=versions, extra=extra,
    )


def _store_cve(conn: sqlite3.Connection, cve: dict[str, Any]) -> bool:
    """Store one CVE. Returns False for a Rejected CVE (state/withdrawn recorded, children dropped)."""
    cve_id = cve["id"]
    rejected = cve.get("vulnStatus") == "Rejected"
    store_raw(conn, "nvd", cve_id, cve, modified=cve.get("lastModified"))
    score, vector, version, severity = _best_cvss(cve.get("metrics", {}))
    upsert_vulnerability(
        conn, "nvd", cve_id,
        summary=_english(cve.get("descriptions")),
        published=cve.get("published"),
        modified=cve.get("lastModified"),
        withdrawn=cve.get("lastModified") if rejected else None,
        state="REJECTED" if rejected else cve.get("vulnStatus"),
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=version,
        cwes=_cwes(cve.get("weaknesses")),
        extra={"sourceIdentifier": cve.get("sourceIdentifier"), "cveTags": cve.get("cveTags", [])},
    )
    replace_children(conn, "nvd", cve_id)
    if rejected:
        return False
    seen: set[str] = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                key = match.get("matchCriteriaId") or json.dumps(match, sort_keys=True)
                if key in seen:
                    continue
                seen.add(key)
                _add_cpe(conn, cve_id, match)
    return True


def renormalize(conn: sqlite3.Connection) -> int:
    """Rebuild all nvd vulnerability/affected rows from `raw_record` (no download), so importer
    fixes reach an existing DB. Returns the number of records rebuilt."""
    n = 0
    rows = conn.execute("SELECT data FROM raw_record WHERE source='nvd'").fetchall()
    with transaction(conn):
        for r in rows:
            cve = loads(r["data"])
            if isinstance(cve, dict) and cve.get("id"):
                _store_cve(conn, cve)
                n += 1
    return n


class _Budget:
    """Counts stored records; `exhausted` once opts.limit is reached."""

    def __init__(self, limit: int | None) -> None:
        self.limit, self.count = limit, 0

    @property
    def exhausted(self) -> bool:
        return self.limit is not None and self.count >= self.limit


def _store_pages(conn: sqlite3.Connection, pages: Iterable[dict[str, Any]], opts: SyncOptions,
                 budget: _Budget | None = None) -> int:
    budget = budget or _Budget(opts.limit)
    start = budget.count
    for doc in pages:
        with transaction(conn):
            for item in doc.get("vulnerabilities", []):
                if budget.exhausted:
                    break
                _store_cve(conn, item["cve"])
                budget.count += 1
        opts.log(f"nvd: {budget.count} records")
        if budget.exhausted:
            break
    return budget.count - start


def parse_since(s: str) -> datetime:
    """--since: '2020', '2020-05', '2020-05-17' or a full ISO timestamp (naive = UTC)."""
    s = s.strip()
    if re.fullmatch(r"\d{4}", s):
        s += "-01-01"
    elif re.fullmatch(r"\d{4}-\d{2}", s):
        s += "-01"
    return _parse_ts(s)


@register
class NvdSource(Source):
    name = "nvd"
    description = "NVD CVE API 2.0: CVSS, CWE and CPE applicability"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        api_key = opts.api_key or os.environ.get("NVD_API_KEY") or None
        budget = _Budget(opts.limit)
        cursor: str | None = None      # end of the last fully completed window / run
        try:
            if opts.path:
                count = _store_pages(conn, _local_pages(Path(opts.path)), opts, budget)
                return SyncResult(self.name, records=count, message=f"from file {opts.path}")

            with _NvdClient(api_key) as client:
                if opts.ids:
                    count = _store_pages(conn, _id_pages(client, opts.ids), opts, budget)
                    return SyncResult(self.name, records=count, message=f"{len(opts.ids)} ids")

                end = datetime.now(UTC)
                stored = self._stored_cursor(conn)
                start = self._delta_start(conn, opts, stored)
                trust_cursor = True
                if opts.since and not opts.full:
                    # a --since run may only move the cursor when it re-covers [since, stored]
                    trust_cursor = stored is not None and start is not None and start <= stored
                if start is None:
                    _store_pages(conn, _cve_pages(client, {}), opts, budget)
                    mode = "full"
                    if not budget.exhausted:
                        cursor = _iso(end)
                else:
                    for lo, hi in _windows(start, end):
                        params = {"lastModStartDate": _iso(lo), "lastModEndDate": _iso(hi)}
                        _store_pages(conn, _cve_pages(client, params), opts, budget)
                        if budget.exhausted:
                            break
                        cursor = _iso(hi)
                        if trust_cursor:
                            set_sync_state(conn, PROGRESS_KEY, status="ok", cursor=cursor,
                                           message="last completed window end")
                    mode = f"delta since {_iso(start)}"
        except (httpx.HTTPError, OSError, ValueError, KeyError) as e:
            conn.rollback()
            return SyncResult(self.name, records=budget.count, status="partial" if budget.count else "error",
                              cursor=cursor if cursor and self._cursor_ok(opts, conn) else None,
                              message=f"{type(e).__name__}: {e}")
        status = "partial" if budget.exhausted else "ok"
        note = ", limit reached" if budget.exhausted else ""
        return SyncResult(self.name, records=budget.count, status=status,
                          cursor=cursor if self._cursor_ok(opts, conn, start) else None,
                          message=f"{mode}, NVD API {'with' if api_key else 'without'} key{note}")

    @staticmethod
    def _stored_cursor(conn: sqlite3.Connection) -> datetime | None:
        best: datetime | None = None
        for key in ("nvd", PROGRESS_KEY):
            c = get_sync_cursor(conn, key)
            if c:
                try:
                    t = _parse_ts(c)
                except ValueError:
                    continue
                best = t if best is None or t > best else best
        return best

    @staticmethod
    def _cursor_ok(opts: SyncOptions, conn: sqlite3.Connection, start: datetime | None = None) -> bool:
        """--since may only advance the cursor when it does not skip an unsynced gap."""
        if not opts.since or opts.full:
            return True
        stored = NvdSource._stored_cursor(conn)
        s = parse_since(opts.since)
        return stored is not None and s <= stored

    @staticmethod
    def _delta_start(conn: sqlite3.Connection, opts: SyncOptions, stored: datetime | None = None) -> datetime | None:
        if opts.full:
            return None
        if opts.since:
            return parse_since(opts.since)
        return stored if stored is not None else NvdSource._stored_cursor(conn)
