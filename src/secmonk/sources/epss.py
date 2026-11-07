"""FIRST EPSS source.

Spec: _docs/references/vuln-sources/epss.md. Default is the daily gzip CSV; `opts.path` reads a
local `.csv` or `.csv.gz`; `opts.ids` queries the FIRST API in batches of 100 instead. The file is
streamed line by line (no pandas) and inserted with executemany in chunks.

Schema note: `epss.cve_id` is the primary key, so each CVE keeps only its latest score.
"""

from __future__ import annotations

import re
import sqlite3
import zlib
from collections.abc import Iterable, Iterator
from itertools import batched
from pathlib import Path
from typing import Any

import httpx

from ..db import executemany, transaction
from .base import Source, SyncOptions, SyncResult, http_client, register

BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
API_URL = "https://api.first.org/data/v1/epss"
API_BATCH = 100
CHUNK = 5000
_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")
_UPSERT = "INSERT OR REPLACE INTO epss(cve_id, score, percentile, date, source) VALUES (?,?,?,?,'epss')"

Row = tuple[str, float, float, str | None]


def _file_chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as f:
        yield from iter(lambda: f.read(1 << 16), b"")


def _decompressed(chunks: Iterable[bytes], gz: bool) -> Iterator[bytes]:
    if not gz:
        yield from chunks
        return
    dec = zlib.decompressobj(zlib.MAX_WBITS | 16)  # gzip container
    for chunk in chunks:
        yield dec.decompress(chunk)
    yield dec.flush()


def _iter_lines(chunks: Iterable[bytes], gz: bool) -> Iterator[str]:
    """Split a (optionally gzipped) byte stream into text lines without buffering the whole file."""
    tail = b""
    for data in _decompressed(chunks, gz):
        *lines, tail = (tail + data).split(b"\n")
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
        try:
            with transaction(conn):
                if opts.ids:
                    count, cursor, where = self._sync_api(conn, opts)
                elif opts.path:
                    path = Path(opts.path)
                    lines = _iter_lines(_file_chunks(path), gz=path.name.endswith(".gz"))
                    count, cursor = _insert_bulk(conn, _parse_rows(lines))
                    where = f"file {path}"
                else:
                    with http_client(timeout=120.0) as client, client.stream("GET", BULK_URL) as resp:
                        resp.raise_for_status()
                        lines = _iter_lines(resp.iter_raw(), gz=True)
                        count, cursor = _insert_bulk(conn, _parse_rows(lines))
                    where = BULK_URL
        except (httpx.HTTPError, OSError, ValueError) as e:
            return SyncResult(self.name, status="error", message=str(e))

        return SyncResult(self.name, records=count, status="ok", cursor=cursor,
                          message=f"{count} scores from {where}")

    def _sync_api(self, conn: sqlite3.Connection, opts: SyncOptions) -> tuple[int, str | None, str]:
        ids = [i.strip().upper() for i in opts.ids if i.strip()]
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
