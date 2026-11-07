"""OSV.dev bulk source (https://osv.dev), read from the public GCS bucket.

Spec: _docs/references/vuln-sources/osv.md. Full import from `<Eco>/all.zip`, delta via
`<Eco>/modified_id.csv` + `<Eco>/<ID>.json`. Cursor per ecosystem is stored as source_sync row `osv:<Eco>`.
"""

from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import zipfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..db import get_sync_cursor, set_sync_state
from ..engine import purl as purl_mod
from .base import (
    CACHE_DIR,
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

BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_ECOSYSTEMS = [
    "PyPI", "npm", "Maven", "Go", "crates.io", "RubyGems", "NuGet", "Packagist",
    "Debian", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux",
]
MAX_MEMBER_SIZE = 50 * 1024 * 1024
DELTA_MAX_IDS = 5000
COMMIT_EVERY = 2000
LOG_EVERY = 5000

STORE_RAW = True  # override with env SECMONK_OSV_STORE_RAW=0


def _store_raw_enabled() -> bool:
    return STORE_RAW and os.environ.get("SECMONK_OSV_STORE_RAW", "1").strip().lower() not in ("0", "false", "no")


# --------------------------------------------------------------------------- CVSS 3.x

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """CVSS 3.0/3.1 base score from a vector string, or None if not a valid v3 vector."""
    try:
        parts = vector.split("/")
        if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
            return None
        m = dict(p.split(":", 1) for p in parts[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        total = 1.08 * (impact + expl) if scope_changed else impact + expl
        return _roundup(min(total, 10.0))
    except (KeyError, ValueError, IndexError):
        return None


# --------------------------------------------------------------------------- helpers

def parse_ts(s: str) -> datetime:
    """Parse an RFC3339 timestamp with 0-9 fractional digits to an aware UTC datetime."""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def ids_modified_since(lines: Iterable[str], cursor: str | None) -> list[tuple[str, str]]:
    """Parse `<ts>,<ID>` lines; return [(ts, id)] with ts strictly newer than cursor (all if no cursor)."""
    cur = parse_ts(cursor) if cursor else None
    out: list[tuple[str, str]] = []
    for line in lines:
        line = line.strip()
        if not line or "," not in line:
            continue
        ts, _, rid = line.partition(",")
        try:
            if cur is None or parse_ts(ts) > cur:
                out.append((ts, rid.strip()))
        except ValueError:
            continue
    return out


def validate_ecosystems(names: list[str]) -> list[str]:
    for n in names:
        if ":" in n:
            raise ValueError(
                f"OSV ecosystem {n!r} is release-qualified; use the base name ({n.split(':')[0]!r}). "
                "Per-release zips are stale legacy dumps; the base-name zip contains all releases.")
    return names


def _strip_purl(p: str | None) -> str | None:
    if not p:
        return None
    parsed = purl_mod.parse(p)
    if parsed:
        return purl_mod.build(parsed.type, parsed.name, namespace=parsed.namespace)
    return p.split("?", 1)[0].split("#", 1)[0]


def _cvss(severity: list[dict] | None) -> tuple[float | None, str | None, str | None, str | None]:
    """-> (score, vector, version, label_from_word)"""
    v3 = v4 = word = None
    for s in severity or []:
        t, sc = s.get("type"), s.get("score")
        if not isinstance(sc, str):
            continue
        if t == "CVSS_V3" and v3 is None:
            v3 = sc
        elif t == "CVSS_V4" and v4 is None:
            v4 = sc
        elif t == "Ubuntu" and word is None:
            word = sc
    if v3:
        return cvss3_score(v3), v3, v3.split("/")[0].split(":")[-1], word
    if v4:
        return None, v4, "4.0", word
    return None, None, None, word


def import_record(conn: sqlite3.Connection, rec: dict) -> bool:
    """Import one OSV record. Does not commit. Returns False if skipped."""
    if not isinstance(rec, dict) or not rec.get("id"):
        return False
    rid = str(rec["id"])
    modified = rec.get("modified")
    if _store_raw_enabled():
        store_raw(conn, "osv", rid, rec, modified)
    replace_children(conn, "osv", rid)

    dbs = rec.get("database_specific") or {}
    if not isinstance(dbs, dict):
        dbs = {}
    details = rec.get("details")
    summary = rec.get("summary")
    if not summary and details:
        summary = details.strip().split("\n", 1)[0][:300] or None
    score, vector, cvss_ver, word = _cvss(rec.get("severity"))
    label = dbs.get("severity") if isinstance(dbs.get("severity"), str) else None
    label = (label or word or severity_from_score(score))
    if label:
        label = label.upper()
    cwes = [c for c in (dbs.get("cwe_ids") or []) if isinstance(c, str)]
    if isinstance(dbs.get("cwe_ids"), str):
        cwes = [dbs["cwe_ids"]]
    refs = [r["url"] for r in (rec.get("references") or []) if isinstance(r, dict) and r.get("url")][:10]
    src_db = dbs.get("source") if isinstance(dbs.get("source"), str) else None
    upsert_vulnerability(
        conn, "osv", rid, summary=summary, details=details, published=rec.get("published"),
        modified=modified, withdrawn=rec.get("withdrawn"), severity=label,
        cvss_score=score, cvss_vector=vector, cvss_version=cvss_ver, cwes=cwes,
        extra={"source_db": src_db or rid.split("-", 1)[0], "references": refs},
    )
    for key in ("aliases", "upstream"):
        for a in rec.get(key) or []:
            if isinstance(a, str):
                add_alias(conn, "osv", rid, a)
    if rec.get("withdrawn"):
        return True

    for aff in rec.get("affected") or []:
        pkg = aff.get("package") if isinstance(aff, dict) else None
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        eco = purl_mod.normalize_ecosystem(pkg.get("ecosystem"))
        name = purl_mod.normalize_name(eco, pkg["name"])
        purl = _strip_purl(pkg.get("purl"))
        ranges = [r for r in (aff.get("ranges") or []) if isinstance(r, dict)]
        espec = aff.get("ecosystem_specific") if isinstance(aff.get("ecosystem_specific"), dict) else {}
        binaries = [b.get("binary_name") for b in (espec.get("binaries") or [])
                    if isinstance(b, dict) and b.get("binary_name")]
        has_eco_range = False
        for r in ranges:
            rt = r.get("type")
            if rt not in ("ECOSYSTEM", "SEMVER", "GIT"):
                continue
            extra: dict[str, Any] = {}
            if rt != "GIT":
                has_eco_range = True
                extra["raw_ecosystem"] = pkg.get("ecosystem")
            if r.get("database_specific"):
                extra["database_specific"] = r["database_specific"]
            if binaries:
                extra["binaries"] = binaries
            if isinstance(espec.get("urgency"), str):      # Debian triage label (unimportant, low, …)
                extra["urgency"] = espec["urgency"].strip().lower()
            if rt == "GIT" and r.get("repo"):
                extra["repo"] = r["repo"]
            add_affected(conn, "osv", rid, ecosystem=eco, package=name, purl=purl, range_type=rt,
                         events=r.get("events") or [], extra=extra or None)
        versions = [v for v in (aff.get("versions") or []) if isinstance(v, str)]
        if versions and not has_eco_range:
            extra = {"raw_ecosystem": pkg.get("ecosystem")}
            if binaries:
                extra["binaries"] = binaries
            add_affected(conn, "osv", rid, ecosystem=eco, package=name, purl=purl,
                         range_type="VERSIONS", versions=versions, extra=extra)
    return True


class _Importer:
    """Imports records with batched commits and progress logging."""

    def __init__(self, conn: sqlite3.Connection, opts: SyncOptions, label: str):
        self.conn, self.opts, self.label = conn, opts, label
        self.count = 0
        self.max_modified: datetime | None = None
        self.max_modified_str: str | None = None

    @property
    def full(self) -> bool:
        return self.opts.limit is not None and self.count >= self.opts.limit

    def add(self, rec: dict) -> None:
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN")
        try:
            self.conn.execute("SAVEPOINT osv_rec")
            ok = import_record(self.conn, rec)
            self.conn.execute("RELEASE osv_rec")
        except Exception as e:  # noqa: BLE001 - malformed record: log and continue
            self.conn.execute("ROLLBACK TO osv_rec")
            self.conn.execute("RELEASE osv_rec")
            self.opts.log(f"osv: skipping {rec.get('id') if isinstance(rec, dict) else '?'}: {e}")
            return
        if not ok:
            return
        self.count += 1
        m = rec.get("modified")
        if isinstance(m, str):
            try:
                dt = parse_ts(m)
                if self.max_modified is None or dt > self.max_modified:
                    self.max_modified, self.max_modified_str = dt, m
            except ValueError:
                pass
        if self.count % COMMIT_EVERY == 0:
            self.conn.commit()
        if self.count % LOG_EVERY == 0:
            self.opts.log(f"osv {self.label}: {self.count} records")

    def finish(self) -> None:
        self.conn.commit()


def _iter_zip(path: Path, opts: SyncOptions) -> Iterator[dict]:
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            if info.file_size > MAX_MEMBER_SIZE:
                opts.log(f"osv: skipping oversized zip member {info.filename} ({info.file_size} B)")
                continue
            try:
                with zf.open(info) as f:
                    yield json.loads(f.read())
            except (ValueError, zipfile.BadZipFile) as e:
                opts.log(f"osv: bad member {info.filename}: {e}")


def _iter_json_files(paths: Iterable[Path], opts: SyncOptions) -> Iterator[dict]:
    for p in paths:
        try:
            if p.stat().st_size > MAX_MEMBER_SIZE:
                opts.log(f"osv: skipping oversized file {p}")
                continue
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            opts.log(f"osv: bad file {p}: {e}")
            continue
        yield from (doc if isinstance(doc, list) else [doc])


def _import_iter(imp: _Importer, recs: Iterable[dict]) -> None:
    for rec in recs:
        if imp.full:
            break
        imp.add(rec)


@register
class OsvSource(Source):
    name = "osv"
    description = "OSV.dev bulk (package ecosystems + distro advisories)"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        try:
            if opts.path:
                return self._sync_path(conn, opts)
            ecos = validate_ecosystems(list(opts.ecosystems) or list(DEFAULT_ECOSYSTEMS))
        except ValueError as e:
            return SyncResult(self.name, status="error", message=str(e))
        total, errors = 0, []
        for eco in ecos:
            try:
                total += self._sync_ecosystem(conn, opts, eco)
            except Exception as e:  # noqa: BLE001
                conn.commit()
                errors.append(f"{eco}: {e}")
                opts.log(f"osv {eco}: failed: {e}")
        status = "ok" if not errors else ("partial" if total else "error")
        return SyncResult(self.name, records=total, status=status,
                          message="; ".join(errors) or f"{len(ecos)} ecosystems")

    # ---- local import
    def _sync_path(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        p = Path(opts.path)  # type: ignore[arg-type]
        imp = _Importer(conn, opts, str(p))
        if p.is_dir():
            files = sorted(p.glob("*.json"))
            _import_iter(imp, _iter_json_files(files, opts))
        elif p.suffix.lower() == ".zip":
            _import_iter(imp, _iter_zip(p, opts))
        else:
            _import_iter(imp, _iter_json_files([p], opts))
        imp.finish()
        set_sync_state(conn, "osv", status="ok", records=imp.count, message=f"from {p}")
        return SyncResult(self.name, records=imp.count, cursor=imp.max_modified_str)

    # ---- download
    def _sync_ecosystem(self, conn: sqlite3.Connection, opts: SyncOptions, eco: str) -> int:
        key = f"osv:{eco}"
        cursor = None if opts.full else get_sync_cursor(conn, key)
        enc = quote(eco)
        with http_client(timeout=120.0) as client:
            if cursor:
                resp = client.get(f"{BUCKET}/{enc}/modified_id.csv")
                resp.raise_for_status()
                changed = ids_modified_since(resp.text.splitlines(), cursor)
                if len(changed) <= DELTA_MAX_IDS:
                    return self._delta(conn, opts, client, eco, key, cursor, changed)
                opts.log(f"osv {eco}: {len(changed)} changes since cursor, falling back to full zip")
            return self._full(conn, opts, client, eco, key)

    def _full(self, conn, opts, client, eco: str, key: str) -> int:
        dest = CACHE_DIR / "osv" / f"{eco.replace(' ', '_')}.zip"
        dest.parent.mkdir(parents=True, exist_ok=True)
        opts.log(f"osv {eco}: downloading {eco}/all.zip")
        with client.stream("GET", f"{BUCKET}/{quote(eco)}/all.zip") as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                f.writelines(r.iter_bytes(1 << 20))
        imp = _Importer(conn, opts, eco)
        _import_iter(imp, _iter_zip(dest, opts))
        imp.finish()
        partial = opts.limit is not None and imp.full
        set_sync_state(conn, key, status="partial" if partial else "ok", records=imp.count,
                       cursor=imp.max_modified_str, message="full")
        opts.log(f"osv {eco}: imported {imp.count} records (full)")
        return imp.count

    def _delta(self, conn, opts, client, eco: str, key: str, cursor: str,
               changed: list[tuple[str, str]]) -> int:
        imp = _Importer(conn, opts, eco)
        changed.sort(key=lambda t: parse_ts(t[0]))  # oldest first so a limit leaves a valid cursor
        for ts, rid in changed:
            if imp.full:
                break
            r = client.get(f"{BUCKET}/{quote(eco)}/{quote(rid)}.json")
            if r.status_code == 404:
                continue
            r.raise_for_status()
            imp.add(r.json())
        imp.finish()
        newest = imp.max_modified_str if (imp.max_modified and imp.max_modified > parse_ts(cursor)) else None
        set_sync_state(conn, key, status="ok", records=imp.count, cursor=newest or cursor, message="delta")
        opts.log(f"osv {eco}: imported {imp.count} records (delta)")
        return imp.count
