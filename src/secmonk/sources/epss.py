"""FIRST EPSS source.

Spec: _docs/references/vuln-sources/epss.md. Default is the daily gzip CSV; `opts.path` reads a
local `.csv` or `.csv.gz`; `opts.ids` queries the FIRST API in batches of 100 instead. The file is
streamed line by line (no pandas) and inserted with executemany in chunks.

Schema note: `epss.cve_id` is the primary key, so each CVE keeps only its latest score.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Iterator
from itertools import batched, islice
from pathlib import Path
from typing import Any

import httpx

from ..db import executemany, transaction
from .base import Source, SyncOptions, SyncResult, decompress_stream, http_client, register

BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
API_URL = "https://api.first.org/data/v1/epss"
API_BATCH = 100
CHUNK = 5000
MAX_DECOMPRESSED = 1024**3   # decompression-bomb cap for the bulk file
MAX_LINE = 64 * 1024         # longest CSV line accepted
_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")
_UPSERT = "INSERT OR REPLACE INTO epss(cve_id, score, percentile, date, source) VALUES (?,?,?,?,'epss')"

Row = tuple[str, float, float, str | None]


class _Refused(Exception):
    """The imported file failed the sanity guard; the surrounding transaction is rolled back."""


def _file_chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as f:
        yield from iter(lambda: f.read(1 << 16), b"")


def _decompressed(chunks: Iterable[bytes], gz: bool) -> Iterator[bytes]:
    if not gz:
        yield from chunks
        return
    # raises DecompressError (a ValueError) on truncated/corrupt gzip or output above the cap
    yield from decompress_stream(chunks, "gz", MAX_DECOMPRESSED)


def _iter_lines(chunks: Iterable[bytes], gz: bool) -> Iterator[str]:
    """Split a (optionally gzipped) byte stream into text lines without buffering the whole file."""
    tail = b""
    for data in _decompressed(chunks, gz):
        *lines, tail = (tail + data).split(b"\n")
        if len(tail) > MAX_LINE or any(len(x) > MAX_LINE for x in lines):
            raise ValueError(f"EPSS line longer than {MAX_LINE} bytes")
        for line in lines:
            yield line.decode("utf-8")
    if tail:
        yield tail.decode("utf-8")


def _parse_rows(lines: Iterable[str]) -> Iterator[Row]:
    """Yield (cve, epss, percentile, score_date). `#` comment lines carry score_date; header skipped."""
    score_date: str | None = None
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = _SCORE_DATE.search(line)
            if m:
                score_date = m.group(1)
            continue
        if line.lower().startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        try:
            score, pct = float(parts[1]), float(parts[2])
        except ValueError:
            continue
        yield parts[0].strip().upper(), score, pct, score_date


def _insert_bulk(conn: sqlite3.Connection, rows: Iterable[Row]) -> tuple[int, str | None]:
    count, last_date = 0, None
    for chunk in batched(rows, CHUNK):
        executemany(conn, _UPSERT, chunk)
        count += len(chunk)
        last_date = chunk[-1][3]
    return count, last_date


def _api_get(client: httpx.Client, batch: list[str]) -> dict[str, Any]:
    resp = client.get(API_URL, params={"cve": ",".join(batch)})
    resp.raise_for_status()
    return resp.json()


@register
class EpssSource(Source):
    name = "epss"
    description = "FIRST EPSS exploitation probability scores (daily bulk or API lookup)"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        limited = opts.limit is not None
        try:
            with transaction(conn):
                if opts.ids:
                    count, cursor, where = self._sync_api(conn, opts)
                else:
                    if opts.path:
                        path = Path(opts.path)
                        stream: Iterable[bytes] = _file_chunks(path)
                        gz, where = path.name.endswith(".gz"), f"file {path}"
                        client_cm = None
                    else:
                        client_cm = http_client(timeout=120.0)
                        gz, where = True, BULK_URL
                    try:
                        if client_cm is None:
                            count, cursor = self._bulk(conn, stream, gz, opts)
                        else:
                            with client_cm as client, client.stream("GET", BULK_URL) as resp:
                                resp.raise_for_status()
                                count, cursor = self._bulk(conn, resp.iter_raw(), gz, opts)
                    except _Refused as r:
                        raise ValueError(str(r)) from r
        except (httpx.HTTPError, OSError, ValueError) as e:   # DecompressError is a ValueError
            return SyncResult(self.name, status="error", message=f"{type(e).__name__}: {e}")

        return SyncResult(self.name, records=count, status="partial" if limited else "ok",
                          cursor=None if limited else cursor, message=f"{count} scores from {where}")

    def _bulk(self, conn: sqlite3.Connection, chunks: Iterable[bytes], gz: bool,
              opts: SyncOptions) -> tuple[int, str | None]:
        rows: Iterable[Row] = _parse_rows(_iter_lines(chunks, gz))
        if opts.limit is not None:
            rows = islice(rows, opts.limit)
        existing = conn.execute("SELECT COUNT(*) FROM epss WHERE source='epss'").fetchone()[0]
        count, cursor = _insert_bulk(conn, rows)
        if opts.limit is None:
            # a plausible daily file holds ~all CVEs: an empty/tiny one is a broken download
            if count == 0:
                raise _Refused("EPSS file has no rows; refusing")
            if not opts.full and existing and count * 2 < existing:
                raise _Refused(f"EPSS file has only {count} rows (stored: {existing}, < 50%); "
                               "refusing (use --full to force)")
        return count, cursor

    def _sync_api(self, conn: sqlite3.Connection, opts: SyncOptions) -> tuple[int, str | None, str]:
        ids = [i.strip().upper() for i in opts.ids if i.strip()]
        if opts.limit is not None:
            ids = ids[:opts.limit]
        count = 0
        cursor: str | None = None
        with http_client(timeout=60.0) as client:
            for start in range(0, len(ids), API_BATCH):
                doc = _api_get(client, ids[start:start + API_BATCH])
                # The API returns numbers as strings: parse explicitly.
                rows = [(d["cve"], float(d["epss"]), float(d["percentile"]), d.get("date"))
                        for d in doc.get("data", [])]
                executemany(conn, _UPSERT, rows)
                count += len(rows)
                cursor = rows[-1][3] if rows else cursor
                opts.log(f"epss: {count} scores from API")
        return count, cursor, f"FIRST API ({len(ids)} ids)"
