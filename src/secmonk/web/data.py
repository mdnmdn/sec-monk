"""Read handlers of the web API over the local database (overview, assets, findings, vulnerabilities, sources).

Each handler opens its own connection (WAL: reads never block a running sync job), validates query parameters like
the CLI validates options, and returns the payloads of `secmonk.reports` (the CLI's `--format json` documents).
Only `match()` writes: it re-matches a stored asset, like `secmonk match`. See _docs/tech/web-ui.md.
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .. import db as dbm
from .. import ops, reports
from ..engine import queries
from .api import ApiError

Query = dict[str, list[str]]
MAX_LIMIT = 5000


def _one(q: Query, name: str, default: str | None = None) -> str | None:
    v = (q.get(name) or [None])[-1]
    v = v.strip() if isinstance(v, str) else v
    return v or default


def _flag(q: Query, name: str) -> bool:
    return _one(q, name) in ("1", "true", "yes")


def _int(q: Query, name: str, default: int, lo: int = 1, hi: int = MAX_LIMIT) -> int:
    v = _one(q, name)
    if v is None:
        return default
    try:
        n = int(v)
    except ValueError:
        raise ApiError(400, f"{name}: expected an integer, got {v!r}") from None
    if not lo <= n <= hi:
        raise ApiError(400, f"{name}: expected {lo}..{hi}, got {n}")
    return n


def _priority(q: Query) -> str | None:
    p = _one(q, "priority")
    if p is None:
        return None
    if p.upper() not in queries.PRIORITIES:
        raise ApiError(400, f"priority: expected one of {', '.join(queries.PRIORITIES)}")
    return p.upper()


class DataApi:
    def __init__(self, db_path: Path, *, min_confidence: float = 0.5):
        self.db_path = Path(db_path)
        self.min_confidence = min_confidence

    def no_db(self) -> ApiError:
        return ApiError(404, f"no database at {self.db_path}",
                        "Create the local vulnerability mirror first (Sources & sync, or `secmonk sync kev epss osv`), "
                        "then scan assets.", code="no-db")

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """Read-only commands never create the database (like the CLI)."""
        if not self.db_path.exists():
            raise self.no_db()
        conn = dbm.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------ reads
    def overview(self) -> dict[str, Any]:
        with self._conn() as c:
            return reports.overview(c, self.db_path)

    def assets(self) -> list[dict]:
        with self._conn() as c:
            return reports.asset_rows(c)

    def asset(self, q: Query) -> dict[str, Any]:
        aid = _one(q, "id")
        if not aid:
            raise ApiError(400, "id: required")
        with self._conn() as c:
            d = reports.asset_detail(c, aid, limit=_int(q, "limit", MAX_LIMIT))
        if d is None:
            raise ApiError(404, f"unknown asset {aid!r}", code="unknown-asset")
        return d

    def unmatched(self) -> list[dict]:
        with self._conn() as c:
            return reports.unmatched_rows(c)

    def findings(self, q: Query) -> dict[str, Any]:
        """`secmonk findings` with the same filters; `limit_reached` tells the UI to offer a bigger limit."""
        limit = _int(q, "limit", 200)
        asset = _one(q, "asset")
        with self._conn() as c:
            if asset and not queries.asset_exists(c, asset):
                raise ApiError(404, f"unknown asset {asset!r}", code="unknown-asset")
            rows = reports.findings(c, asset=asset, priority=_priority(q), include_closed=_flag(q, "all"),
                                    fixable=_flag(q, "fixable"), hide_minor=_flag(q, "hide_minor"),
                                    hide_deferred=_flag(q, "hide_deferred"), limit=limit)
        return {"findings": rows, "limit": limit, "limit_reached": len(rows) >= limit}

    def vuln(self, q: Query) -> dict[str, Any]:
        vid = _one(q, "id")
        if not vid:
            raise ApiError(400, "id: required")
        with self._conn() as c:
            d = reports.vuln_detail(c, vid, raw=_flag(q, "raw"))
        if d is None:
            raise ApiError(404, f"unknown vulnerability id {vid!r}", "Not in the local mirror: sync the source that "
                           "publishes it (osv, cvelist, nvd, euvd…).", code="unknown-vuln")
        return d

    def vuln_search(self, q: Query) -> dict[str, Any]:
        limit = _int(q, "limit", 50, hi=1000)
        with self._conn() as c:
            try:
                rows = reports.vuln_search(c, package=_one(q, "package"), ecosystem=_one(q, "ecosystem"),
                                           product=_one(q, "product"), version=_one(q, "version"), limit=limit)
            except ValueError as e:
                raise ApiError(400, str(e)) from None
        return {"results": rows, "limit": limit, "limit_reached": len(rows) >= limit}

    def sources(self) -> dict[str, Any]:
        """Registered sources + sync state (works without a database: the page offers the first sync)."""
        status = None
        if self.db_path.exists():
            with self._conn() as c:
                status = reports.status_payload(c, self.db_path)
        return {"db": {"path": str(self.db_path), "exists": status is not None},
                "registry": reports.registry_rows(ops.sources_registry()), "sync_all_order": list(ops.SYNC_ALL_ORDER),
                "status": status}

    def collectors(self) -> list[dict]:
        return reports.registry_rows(ops.collectors_registry())

    # ------------------------------------------------------------------ actions
    def match(self, q: Query) -> dict[str, Any]:
        """Re-match a stored asset against the current mirror (`secmonk match`)."""
        from ..engine.match import match_asset

        aid = _one(q, "id")
        if not aid:
            raise ApiError(400, "id: required")
        with self._conn() as c:
            if not queries.asset_exists(c, aid):
                raise ApiError(404, f"unknown asset {aid!r}", code="unknown-asset")
            stats = match_asset(c, aid, min_confidence=self.min_confidence)
        return {"asset": aid, "stats": stats}
