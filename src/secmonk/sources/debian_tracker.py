"""Debian Security Tracker source -> `distro_triage`.

Spec: _docs/references/vuln-sources/debian-tracker.md. Two inputs, auto-detected from `opts.path`:

* the tracker JSON (`https://security-tracker.debian.org/tracker/data/json`, also a local
  `.json`/`.gz`/`.bz2`/`.xz` file): source package -> CVE -> releases -> status/urgency/nodsa;
* a checkout of the security-tracker git repo (`data/CVE/list`, `data/DSA/list`, `data/DLA/list`),
  parsed from its text format. DSA/DLA lists attach `advisory` ids.

The tracker is a snapshot, so each sync replaces every row with source='debian-tracker', unless the new
snapshot is empty or under 50% of the stored rows (refused; `opts.full` forces). `--limit` upserts a subset
without replacing. Decompression is capped (MAX_DECOMPRESSED) and truncated archives are errors.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from itertools import batched
from pathlib import Path
from typing import Any

import httpx

from ..db import transaction
from .base import Source, SyncOptions, SyncResult, decompress_stream, http_client, register, snapshot_guard

SOURCE = "debian-tracker"
TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
CHUNK = 5000
MAX_DECOMPRESSED = 2 * 1024**3   # decompression-bomb cap (the real tracker JSON is ~100 MB)
MAX_DOWNLOAD = 512 * 1024**2     # cap on the downloaded (possibly compressed) bytes

# codename -> OSV Debian release. 'sid' (unstable) has no OSV ecosystem and is skipped:
# the matcher can only look up 'Debian:<n>', and sid is a rolling target, not a deployed release.
CODENAME_TO_RELEASE = {
    "wheezy": "7", "jessie": "8", "stretch": "9", "buster": "10", "bullseye": "11",
    "bookworm": "12", "trixie": "13", "forky": "14", "duke": "15",
}
SID_NAMES = {"sid", "unstable"}
# releases that an unbracketed (sid) text line without a fixed version is propagated to
IMPLICIT_RELEASES = ("bullseye", "bookworm", "trixie", "forky")

URGENCIES = {"unimportant", "low", "medium", "high", "not yet assigned", "end-of-life"}
DEFAULT_URGENCY = "not yet assigned"
NODSA_REASONS = {"postponed", "ignored"}
STAR_NOTE = "urgency marked '*' by tracker"

_UPSERT = """INSERT OR REPLACE INTO distro_triage
    (ecosystem, package, cve_id, status, urgency, fixed_version, nodsa, note, advisory, source)
    VALUES (?,?,?,?,?,?,?,?,?,'debian-tracker')"""

# (ecosystem, package, cve_id, status, urgency, fixed_version, nodsa, note, advisory)
Row = tuple[str, str, str, str | None, str | None, str | None, str | None, str | None, str | None]


class Stats:
    def __init__(self) -> None:
        self.temp = 0
        self.sid = 0
        self.unknown_release = 0
        self.orphan_advisories = 0


# --------------------------------------------------------------------------- shared helpers

def _release_of(codename: str, stats: Stats) -> str | None:
    c = codename.strip().lower()
    if c in SID_NAMES:
        stats.sid += 1
        return None
    rel = CODENAME_TO_RELEASE.get(c)
    if rel is None:
        stats.unknown_release += 1
    return rel


def _urgency(raw: str | None) -> tuple[str | None, bool]:
    """('low*' -> ('low', True)); lowercased, None for empty."""
    if not raw:
        return None, False
    u = raw.strip().lower()
    star = u.endswith("*")
    u = u.rstrip("*").strip()
    return (u or None), star


def _join(*parts: str | None) -> str | None:
    s = "; ".join(p for p in parts if p)
    return s or None


# --------------------------------------------------------------------------- JSON input

def rows_from_json(doc: dict[str, Any], stats: Stats, limit: int | None = None) -> Iterator[Row]:
    for n, pkg in enumerate(sorted(doc)):
        if limit is not None and n >= limit:
            break
        cves = doc[pkg]
        if not isinstance(cves, dict):
            continue
        pkg_l = pkg.lower()
        for cve, entry in cves.items():
            if not isinstance(entry, dict):
                continue
            if not cve.startswith("CVE-"):
                stats.temp += 1          # TEMP-* (no stable id, cannot match advisories)
                continue
            for codename, rel in (entry.get("releases") or {}).items():
                if not isinstance(rel, dict):
                    continue
                release = _release_of(codename, stats)
                if release is None:
                    continue
                yield _json_row(f"Debian:{release}", pkg_l, cve, rel)


def _json_row(eco: str, pkg: str, cve: str, rel: dict[str, Any]) -> Row:
    status = (rel.get("status") or "").lower() or None
    fixed = rel.get("fixed_version")
    fixed = str(fixed) if fixed not in (None, "") else None
    if status == "resolved" and fixed == "0":
        status = "not-affected"
    urgency, star = _urgency(rel.get("urgency"))
    nodsa_text = rel.get("nodsa")
    reason = (rel.get("nodsa_reason") or "").strip().lower()
    nodsa = None
    if nodsa_text is not None or reason in NODSA_REASONS:
        nodsa = reason if reason in NODSA_REASONS else "no-dsa"
    note = _join(nodsa_text.strip() if isinstance(nodsa_text, str) else None,
                 STAR_NOTE if star else None)
    return (eco, pkg, cve, status, urgency, fixed, nodsa, note, None)


# --------------------------------------------------------------------------- text input

_CVE_HEAD = re.compile(r"^(CVE-\d{4}-\d{4,}|TEMP-\S+)(?:\s|$)")
_PKG_LINE = re.compile(
    r"^\t(?:\[(?P<rel>[A-Za-z0-9._-]+)\]\s+)?-\s+(?P<pkg>[^\s<>]+)"
    r"(?:\s+(?P<arg>\S+))?(?:\s+\((?P<paren>.*)\))?\s*$"
)
_ADV_HEAD = re.compile(r"^(?:\[[^\]]*\]\s+)?((?:DSA|DLA|DTSA)-\d+(?:-\d+)?)\s")
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
_NODSA_ARGS = {"<no-dsa>": "no-dsa", "<postponed>": "postponed", "<ignored>": "ignored",
               "<end-of-life>": "ignored"}


def _split_paren(paren: str | None, whole_is_note: bool) -> tuple[str | None, str | None]:
    """(urgency, note) from the parenthesized suffix of a package line."""
    if not paren:
        return None, None
    p = paren.strip()
    u, _ = _urgency(p)
    if u in URGENCIES:
        return u, None
    if whole_is_note:
        return None, p
    urgency, notes = None, []
    for tok in (t.strip() for t in p.split(";")):
        tu, _ = _urgency(tok)
        if tu in URGENCIES:
            urgency = tu
        elif tok and not tok.lower().startswith("bug #"):
            notes.append(tok)
    return urgency, _join(*notes)


def _text_row(eco: str, pkg: str, cve: str, arg: str | None, paren: str | None,
              inherited_urgency: str | None) -> Row | None:
    """Row for one package line; None for forms that carry no triage (<itp>, <removed>, bare)."""
    if arg is None:
        return None
    note_only = arg in _NODSA_ARGS or arg == "<not-affected>"
    urgency, note = _split_paren(paren, whole_is_note=note_only)
    status, fixed, nodsa = None, None, None
    if arg == "<unfixed>":
        status = "open"
    elif arg == "<undetermined>":
        status = "undetermined"
    elif arg == "<not-affected>":
        status, fixed = "not-affected", "0"
    elif arg in _NODSA_ARGS:
        status, nodsa = "open", _NODSA_ARGS[arg]
        if arg == "<end-of-life>":
            urgency = urgency or "end-of-life"
    elif arg.startswith("<"):
        return None                     # <itp>, <removed>, <not-yet-built>, ...
    else:
        status, fixed = "resolved", arg
    return (eco, pkg, cve, status, urgency or inherited_urgency or DEFAULT_URGENCY, fixed,
            nodsa, note, None)


def rows_from_cve_list(lines: Iterable[str], stats: Stats) -> dict[tuple[str, str, str], Row]:
    out: dict[tuple[str, str, str], Row] = {}
    cve: str | None = None
    block: list[tuple[str | None, str, str | None, str | None]] = []

    def flush() -> None:
        if cve is None:
            return
        sid_urg: dict[str, str | None] = {}
        for rel, pkg, arg, paren in block:        # first pass: urgency from the sid lines
            if rel is None:
                sid_urg[pkg] = _split_paren(paren, arg in _NODSA_ARGS or arg == "<not-affected>")[0]
        explicit: set[tuple[str, str]] = set()
        for rel, pkg, arg, paren in block:
            if rel is None:
                continue
            release = _release_of(rel, stats)
            if release is None:
                continue
            explicit.add((release, pkg))
            row = _text_row(f"Debian:{release}", pkg, cve, arg, paren, sid_urg.get(pkg))
            if row:
                out[(row[0], pkg, cve)] = row
        for rel, pkg, arg, paren in block:        # sid lines: skipped, but open/not-affected
            if rel is not None:                    # states propagate to unlisted releases
                continue
            stats.sid += 1
            if arg not in ("<unfixed>", "<undetermined>", "<not-affected>"):
                continue
            for codename in IMPLICIT_RELEASES:
                release = CODENAME_TO_RELEASE[codename]
                if (release, pkg) in explicit:
                    continue
                row = _text_row(f"Debian:{release}", pkg, cve, arg, paren, None)
                if row:
                    out[(row[0], pkg, cve)] = row

    for line in lines:
        line = line.rstrip("\n")
        if not line or line[0] == "\t" and line.startswith("\t\t"):
            continue
        if line[0] != "\t":
            flush()
            block = []
            m = _CVE_HEAD.match(line)
            if m and m.group(1).startswith("CVE-"):
                cve = m.group(1)
            else:
                cve = None
                if m:
                    stats.temp += 1
            continue
        if cve is None:
            continue
        m = _PKG_LINE.match(line)
        if m:
            block.append((m["rel"], m["pkg"].lower(), m["arg"], m["paren"]))
    flush()
    return out


def parse_advisory_list(lines: Iterable[str]) -> list[tuple[str, list[str], str, str, str]]:
    """DSA/DLA list -> [(advisory id, [CVEs], codename, package, fixed version)]."""
    out: list[tuple[str, list[str], str, str, str]] = []
    adv: str | None = None
    cves: list[str] = []
    rels: list[tuple[str, str, str]] = []

    def flush() -> None:
        if adv:
            out.extend((adv, cves, r, p, v) for r, p, v in rels)

    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line[0] != "\t":
            flush()
            m = _ADV_HEAD.match(line)
            adv, cves, rels = (m.group(1), [], []) if m else (None, [], [])
            continue
        s = line.strip()
        if s.startswith("{"):
            cves.extend(_CVE_ID.findall(s))
            continue
        m = _PKG_LINE.match(line)
        if m and m["rel"] and m["arg"] and not m["arg"].startswith("<"):
            rels.append((m["rel"].lower(), m["pkg"].lower(), m["arg"]))
    flush()
    return out


def attach_advisories(rows: dict[tuple[str, str, str], Row],
                      advisories: list[tuple[str, list[str], str, str, str]],
                      stats: Stats) -> None:
    """Set `advisory` on (release, package, CVE) rows. When several advisories cover a row, prefer
    the one whose fixed version equals the row's, else the first listed (lists are newest first)."""
    chosen: dict[tuple[str, str, str], tuple[str, bool]] = {}
    for adv, cves, codename, pkg, ver in advisories:
        release = CODENAME_TO_RELEASE.get(codename)
        if release is None:
            continue
        for cve in cves:
            key = (f"Debian:{release}", pkg, cve)
            row = rows.get(key)
            if row is None:
                stats.orphan_advisories += 1
                continue
            exact = row[5] == ver
            if key not in chosen or (exact and not chosen[key][1]):
                chosen[key] = (adv, exact)
    for key, (adv, _) in chosen.items():
        r = rows[key]
        rows[key] = (*r[:8], adv)  # type: ignore[assignment]


def _read_text(path: Path) -> Iterator[str]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8", errors="replace") as f:
        yield from f


def load_repo(root: Path, stats: Stats, limit: int | None = None) -> list[Row]:
    data = root / "data" if (root / "data").is_dir() else root
    rows = rows_from_cve_list(_read_text(data / "CVE" / "list"), stats)
    advisories: list[tuple[str, list[str], str, str, str]] = []
    for name in ("DSA", "DLA"):
        advisories += parse_advisory_list(_read_text(data / name / "list"))
    attach_advisories(rows, advisories, stats)
    out = list(rows.values())
    if limit is not None:
        keep = set(sorted({r[1] for r in out})[:limit])
        out = [r for r in out if r[1] in keep]
    return out


# --------------------------------------------------------------------------- loading

def _decompress(raw: bytes) -> bytes:
    """Sniff gzip/bzip2/xz and decompress with an output cap; raises DecompressError (a
    ValueError) on truncated/corrupt data or a decompression bomb."""
    if raw[:2] == b"\x1f\x8b":
        fmt = "gz"
    elif raw[:3] == b"BZh":
        fmt = "bz2"
    elif raw[:6] == b"\xfd7zXZ\x00":
        fmt = "xz"
    else:
        return raw
    return b"".join(decompress_stream([raw], fmt, MAX_DECOMPRESSED))


def load_json_bytes(raw: bytes) -> tuple[dict[str, Any], str]:
    """(document, sha256 of the decompressed content)."""
    data = _decompress(raw)
    doc = json.loads(data)
    if not isinstance(doc, dict):
        raise TypeError("tracker JSON: top level is not an object")
    return doc, hashlib.sha256(data).hexdigest()


def _download() -> tuple[bytes, str | None]:
    with http_client(timeout=300.0) as client, client.stream("GET", TRACKER_URL) as resp:
        resp.raise_for_status()
        buf = bytearray()
        for chunk in resp.iter_bytes(1 << 20):
            buf += chunk
            if len(buf) > MAX_DOWNLOAD:
                raise ValueError(f"tracker download exceeds {MAX_DOWNLOAD} bytes")
        return bytes(buf), resp.headers.get("etag") or resp.headers.get("last-modified")


def _insert(conn: sqlite3.Connection, rows: Iterable[Row], replace: bool = True) -> int:
    if replace:
        conn.execute("DELETE FROM distro_triage WHERE source=?", (SOURCE,))
    n = 0
    for chunk in batched(rows, CHUNK):
        conn.executemany(_UPSERT, chunk)
        n += len(chunk)
    return n


@register
class DebianTrackerSource(Source):
    name = SOURCE
    description = "Debian Security Tracker: per-release status, urgency, no-dsa and DSA/DLA ids"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        stats = Stats()
        try:
            if opts.path and Path(opts.path).is_dir():
                rows: Iterable[Row] = load_repo(Path(opts.path), stats, opts.limit)
                cursor = None
                origin = f"repo checkout {opts.path}"
            else:
                if opts.path:
                    raw, validator = Path(opts.path).read_bytes(), None
                    origin = f"file {opts.path}"
                else:
                    raw, validator = _download()
                    origin = TRACKER_URL
                doc, digest = load_json_bytes(raw)
                rows = rows_from_json(doc, stats, opts.limit)
                cursor = validator or digest
            with transaction(conn):
                if not isinstance(rows, list):
                    rows = list(rows)       # stats must be complete before the message is built
                limited = opts.limit is not None
                if not limited:
                    refusal = snapshot_guard(conn, "distro_triage", len(rows), opts,
                                             "source=?", (SOURCE,))
                    if refusal:
                        return SyncResult(self.name, status="error", message=f"debian-tracker: {refusal}")
                # --limit is a debug subset: upsert it without wiping the other rows
                n = _insert(conn, rows, replace=not limited)
        except (httpx.HTTPError, OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            return SyncResult(self.name, status="error", message=f"{type(e).__name__}: {e}")
        if cursor is None:
            cursor = hashlib.sha256(repr(sorted(rows)).encode()).hexdigest()
        msg = (f"{n} triage rows from {origin}; skipped {stats.temp} TEMP ids, "
               f"{stats.sid} sid entries, {stats.unknown_release} unknown-release entries")
        if stats.orphan_advisories:
            msg += f"; {stats.orphan_advisories} advisory refs without a matching row"
        return SyncResult(self.name, records=n, status="partial" if limited else "ok",
                          cursor=None if limited else cursor, message=msg)
