"""Common plumbing for vulnerability sources.

A source module exposes a subclass of `Source` registered with `@register`. `sync()` downloads
(or reads a local file/dir passed via `opts.path`, which is how tests and air-gapped imports work)
and writes into the tables defined in secmonk/db.py using the helpers below.
"""

from __future__ import annotations

import bz2
import lzma
import re
import sqlite3
import zlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import httpx

from .. import __version__, paths
from ..db import dumps, now

USER_AGENT = f"secmonk/{__version__} (+vulnerability-scanner-prototype)"
CACHE_DIR = paths.cache_dir()   # per-user cache root (never the CWD); create via paths.cache_subdir()


def http_client(timeout: float = 60.0, follow_redirects: bool = True, **kw: Any) -> httpx.Client:
    """httpx client honoring HTTPS_PROXY / SSL_CERT_FILE from the environment."""
    return httpx.Client(timeout=timeout, follow_redirects=follow_redirects, trust_env=True,
                        headers={"User-Agent": USER_AGENT}, **kw)


class DecompressError(ValueError):
    """Truncated/corrupt compressed data, or output above the configured cap."""


_OUT_CHUNK = 1 << 20


def decompress_stream(chunks: Iterable[bytes], fmt: str, max_total: int) -> Iterator[bytes]:
    """Incrementally decompress gz/bz2/xz data, refusing more than `max_total` output bytes
    (decompression bombs) and truncated streams (the codec never reached its end marker)."""
    zdec = zlib.decompressobj(zlib.MAX_WBITS | 16) if fmt == "gz" else None
    dec = bz2.BZ2Decompressor() if fmt == "bz2" else lzma.LZMADecompressor() if fmt == "xz" else None
    if zdec is None and dec is None:
        raise ValueError(f"unknown compression {fmt!r}")
    total = 0

    def emit(out: bytes) -> bytes:
        nonlocal total
        total += len(out)
        if total > max_total:
            raise DecompressError(f"decompressed data exceeds the {max_total} byte limit")
        return out

    try:
        for chunk in chunks:
            if zdec is not None:
                buf = chunk
                while buf and not zdec.eof:
                    out = zdec.decompress(buf, _OUT_CHUNK)
                    buf = zdec.unconsumed_tail
                    if out:
                        yield emit(out)
                done = zdec.eof
            else:
                assert dec is not None
                data = chunk
                while not dec.eof:
                    out = dec.decompress(data, _OUT_CHUNK)
                    data = b""
                    if out:
                        yield emit(out)
                    if dec.needs_input:
                        break
                done = dec.eof
            if done:
                break
        else:
            done = zdec.eof if zdec is not None else dec.eof  # type: ignore[union-attr]
    except (zlib.error, EOFError, lzma.LZMAError, OSError) as e:
        raise DecompressError(f"corrupt {fmt} data: {e}") from e
    if not done:
        raise DecompressError(f"truncated {fmt} data (no end-of-stream marker)")


@dataclass
class SyncOptions:
    path: Path | None = None            # import from a local file/dir instead of downloading
    ecosystems: list[str] = field(default_factory=list)   # OSV: which ecosystems
    ids: list[str] = field(default_factory=list)          # fetch specific records (cvelist, nvd)
    since: str | None = None            # delta: only records modified since (ISO date)
    full: bool = False                  # ignore stored cursor
    limit: int | None = None            # cap number of records (debug / prototype)
    api_key: str | None = None          # NVD
    progress: Callable[[str], None] | None = None

    def log(self, msg: str) -> None:
        if self.progress:
            self.progress(msg)


@dataclass
class SyncResult:
    source: str
    records: int = 0                    # records imported/changed by this run
    total: int | None = None            # total records of this source in the DB afterwards (for source_sync.records)
    status: str = "ok"                  # ok | partial | error
    cursor: str | None = None
    message: str | None = None


class Source:
    name: ClassVar[str]
    description: ClassVar[str] = ""

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:  # pragma: no cover
        raise NotImplementedError


REGISTRY: dict[str, type[Source]] = {}


def register(cls: type[Source]) -> type[Source]:
    REGISTRY[cls.name] = cls
    return cls


# --------------------------------------------------------------------------- write helpers

def store_raw(conn: sqlite3.Connection, source: str, record_id: str, data: Any,
              modified: str | None = None) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO raw_record(source, record_id, modified, fetched_at, data) VALUES (?,?,?,?,?)",
        (source, record_id, modified, now(), dumps(data)),
    )


def upsert_vulnerability(conn: sqlite3.Connection, source: str, id: str, *, summary: str | None = None,
                         details: str | None = None, published: str | None = None,
                         modified: str | None = None, withdrawn: str | None = None,
                         state: str | None = None, severity: str | None = None,
                         cvss_score: float | None = None, cvss_vector: str | None = None,
                         cvss_version: str | None = None, cwes: list[str] | None = None,
                         extra: dict | None = None) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO vulnerability
           (source,id,summary,details,published,modified,withdrawn,state,severity,
            cvss_score,cvss_vector,cvss_version,cwes,extra)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (source, id, summary, details, published, modified, withdrawn, state, severity,
         cvss_score, cvss_vector, cvss_version, dumps(cwes or []), dumps(extra)),
    )


def replace_children(conn: sqlite3.Connection, source: str, vuln_id: str) -> None:
    """Delete aliases/affected previously stored for (source, vuln_id) before re-inserting."""
    conn.execute("DELETE FROM alias WHERE source=? AND vuln_id=?", (source, vuln_id))
    conn.execute("DELETE FROM affected WHERE source=? AND vuln_id=?", (source, vuln_id))


def add_alias(conn: sqlite3.Connection, source: str, vuln_id: str, alias: str, kind: str = "alias") -> None:
    """Add an id edge. `kind` is alias | upstream | related; if the pair is already stored as a
    plain 'alias' it stays one."""
    if alias and alias != vuln_id:
        conn.execute("INSERT OR IGNORE INTO alias(vuln_id, alias, source, kind) VALUES (?,?,?,?)",
                     (vuln_id, alias, source, kind))
        if kind == "alias":
            conn.execute("UPDATE alias SET kind='alias' WHERE vuln_id=? AND alias=? AND source=?",
                         (vuln_id, alias, source))


def add_affected(conn: sqlite3.Connection, source: str, vuln_id: str, *, ecosystem: str | None = None,
                 package: str | None = None, purl: str | None = None, vendor: str | None = None,
                 product: str | None = None, cpe: str | None = None, range_type: str | None = None,
                 version_type: str | None = None, events: list[dict] | None = None,
                 versions: list[str] | None = None, status: str = "affected",
                 extra: dict | None = None) -> None:
    conn.execute(
        """INSERT INTO affected(source,vuln_id,ecosystem,package,purl,vendor,product,cpe,range_type,
                                version_type,events,versions,status,extra)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (source, vuln_id, ecosystem, package, purl,
         norm_vendor_product(vendor), norm_vendor_product(product), cpe, range_type, version_type,
         dumps(events) if events is not None else None,
         dumps(versions) if versions else None, status, dumps(extra)),
    )


_CPE_SPLIT = re.compile(r"(?<!\\):")
_CPE_UNESCAPE = re.compile(r"\\(.)")


def cpe_fields(criteria: str) -> list[str]:
    """Split a CPE 2.3 formatted string on unescaped ':' and unescape each field."""
    return [_CPE_UNESCAPE.sub(r"\1", f) for f in _CPE_SPLIT.split(criteria or "")]


def norm_vendor_product(s: str | None) -> str | None:
    """Normalize vendor/product names for name-based matching: lowercase, '_'/' ' unified."""
    if s is None:
        return None
    s = s.strip().lower()
    if s in ("", "n/a", "-", "*", "unknown"):
        return None
    return " ".join(s.replace("_", " ").split())


def snapshot_guard(conn: sqlite3.Connection, table: str, new_count: int, opts: SyncOptions,
                   where: str = "1=1", params: tuple = ()) -> str | None:
    """Sanity guard for sources that replace a whole table from a snapshot: returns a refusal
    message when the new snapshot is empty or smaller than half of what is stored, unless
    `opts.full` forces it. Call before deleting anything."""
    if opts.full:
        return None
    old = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0]
    if new_count == 0:
        return "refusing to replace the data with an empty snapshot (use --full to force)"
    if old and new_count * 2 < old:
        return (f"refusing to replace {old} rows with a snapshot of only {new_count} "
                "(< 50%; use --full to force)")
    return None


_SEVERITY_MAP = {"MODERATE": "MEDIUM", "NEGLIGIBLE": "LOW", "UNTRIAGED": None, "UNKNOWN": None}


def normalize_severity(label: str | None) -> str | None:
    """Unify severity vocabularies at import: MODERATE -> MEDIUM, NEGLIGIBLE -> LOW,
    UNTRIAGED/UNKNOWN -> NULL; everything else upper-cased."""
    if not isinstance(label, str) or not label.strip():
        return None
    u = label.strip().upper()
    return _SEVERITY_MAP.get(u, u)


def severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
