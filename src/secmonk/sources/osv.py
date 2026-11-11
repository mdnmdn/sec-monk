"""OSV.dev bulk source (https://osv.dev), read from the public GCS bucket.

Spec: _docs/references/vuln-sources/osv.md. Full import from `<Eco>/all.zip`, delta via
`<Eco>/modified_id.csv` + `<Eco>/<ID>.json`. Cursor per ecosystem is stored as source_sync row `osv:<Eco>`.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import sqlite3
import zipfile
import zlib
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import paths
from ..db import set_sync_state
from ..engine import purl as purl_mod
from .base import (
    Source,
    SyncOptions,
    SyncResult,
    add_affected,
    add_alias,
    http_client,
    normalize_severity,
    register,
    replace_children,
    severity_from_score,
    store_raw,
    upsert_vulnerability,
)

BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_ECOSYSTEMS = [
    "PyPI", "npm", "Maven", "Go", "crates.io", "RubyGems", "NuGet", "Packagist", "Pub", "SwiftURL",
    "Debian", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux",
]
MAX_MEMBER_SIZE = 50 * 1024 * 1024
DELTA_MAX_IDS = 5000
COMMIT_EVERY = 2000
LOG_EVERY = 5000

MAX_ZIP_BYTES = 4 * 1024**3   # download cap per all.zip (env SECMONK_OSV_MAX_ZIP_MB overrides)

# Raw JSON dominates the DB size (details are stored twice) and is only needed to re-normalize
# without re-downloading: off by default, enable with env SECMONK_OSV_STORE_RAW=1.
STORE_RAW = False

# conservative score for a CVSS v4-only record, derived from its severity label (no v4 calculator)
DERIVED_SCORE = {"LOW": 3.0, "MEDIUM": 5.5, "HIGH": 8.0, "CRITICAL": 9.5}


def _store_raw_enabled() -> bool:
    return STORE_RAW or os.environ.get("SECMONK_OSV_STORE_RAW", "0").strip().lower() in ("1", "true", "yes")


def _max_zip_bytes() -> int:
    try:
        return int(os.environ["SECMONK_OSV_MAX_ZIP_MB"]) * 1024 * 1024
    except (KeyError, ValueError):
        return MAX_ZIP_BYTES


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


def _cvss(severity: list[dict] | None) -> tuple[float | None, str | None, str | None, str | None, str | None]:
    """-> (score, vector, version, label_from_word, v4_vector_when_v3_chosen)

    A v3 vector wins (we can compute its score; the v4 vector is then returned separately for
    `extra`). A v4-only record keeps the v4 vector with score None: the caller derives a score
    from the severity label."""
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
        return cvss3_score(v3), v3, v3.split("/")[0].split(":")[-1], word, v4
    if v4:
        return None, v4, "4.0", word, None
    return None, None, None, word, None


def _ubuntu_variant(raw: Any) -> str | None:
    """'Ubuntu:Pro:FIPS-updates:22.04:LTS' -> 'Pro:FIPS-updates' (None for plain releases)."""
    if not isinstance(raw, str) or not raw.startswith("Ubuntu:"):
        return None
    parts = [p for p in raw.split(":")[1:] if p and not p[0].isdigit() and p != "LTS"]
    return ":".join(parts) or None


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
    score, vector, cvss_ver, word, v4_vector = _cvss(rec.get("severity"))
    label = dbs.get("severity") if isinstance(dbs.get("severity"), str) else None
    label = normalize_severity(label) or normalize_severity(word) or severity_from_score(score)
    vuln_extra: dict[str, Any] = {}
    if score is None and vector and label in DERIVED_SCORE:
        score = DERIVED_SCORE[label]           # no CVSS v4 calculator: conservative label-based score
        vuln_extra["score_derived"] = True
    if v4_vector:
        vuln_extra["cvss_v4_vector"] = v4_vector
    cwes = [c for c in (dbs.get("cwe_ids") or []) if isinstance(c, str)]
    if isinstance(dbs.get("cwe_ids"), str):
        cwes = [dbs["cwe_ids"]]
    refs = [r["url"] for r in (rec.get("references") or []) if isinstance(r, dict) and r.get("url")][:10]
    src_db = dbs.get("source") if isinstance(dbs.get("source"), str) else None
    upsert_vulnerability(
        conn, "osv", rid, summary=summary, details=details, published=rec.get("published"),
        modified=modified, withdrawn=rec.get("withdrawn"), severity=label,
        cvss_score=score, cvss_vector=vector, cvss_version=cvss_ver, cwes=cwes,
        extra={"source_db": src_db or rid.split("-", 1)[0], "references": refs, **vuln_extra},
    )
    # `upstream` ids are the CVEs a downstream advisory (Ubuntu/Debian/...) derives from, NOT
    # aliases: stored with kind='upstream' so the matcher does not merge them. `related` is ignored.
    for key, kind in (("aliases", "alias"), ("upstream", "upstream")):
        for a in rec.get(key) or []:
            if isinstance(a, str):
                add_alias(conn, "osv", rid, a, kind)
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
        custom = [r for r in (espec.get("custom_ranges") or []) if isinstance(r, dict) and r.get("events")]
        if custom:
            # Go: the SEMVER range is an open-ended `introduced: 0` placeholder and the real
            # bounds live in custom_ranges. Ingest each custom range as its own row and drop the
            # placeholder (it would flag every version as vulnerable).
            ranges = [r for r in ranges if not (r.get("type") in ("ECOSYSTEM", "SEMVER")
                                                and r.get("events") == [{"introduced": "0"}])]
            ranges += [{**r, "type": r.get("type") if r.get("type") in ("ECOSYSTEM", "SEMVER", "GIT")
                        else "ECOSYSTEM", "_custom": True} for r in custom]
        variant = _ubuntu_variant(pkg.get("ecosystem"))
        has_eco_range = False
        for r in ranges:
            rt = r.get("type")
            if rt not in ("ECOSYSTEM", "SEMVER", "GIT"):
                continue
            extra: dict[str, Any] = {}
            if r.get("_custom"):
                extra["custom_range"] = True
            if variant:
                extra["ecosystem_variant"] = variant
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
            if variant:
                extra["ecosystem_variant"] = variant
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
                    data = f.read(MAX_MEMBER_SIZE + 1)   # declared sizes can lie: cap the real read
                if len(data) > MAX_MEMBER_SIZE:
                    opts.log(f"osv: skipping oversized zip member {info.filename}")
                    continue
                yield json.loads(data)
            except (ValueError, zipfile.BadZipFile, zlib.error) as e:
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


def _state(conn: sqlite3.Connection, key: str) -> tuple[str | None, str | None]:
    row = conn.execute("SELECT status, cursor FROM source_sync WHERE source=?", (key,)).fetchone()
    return (row["status"], row["cursor"]) if row else (None, None)


def _safe_name(eco: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", eco)


def _download_zip(client, eco: str, opts: SyncOptions) -> Path:
    """Stream <Eco>/all.zip to a private temp file (O_EXCL|O_NOFOLLOW) in the user cache, then
    atomically move it into place. Refuses downloads above the size cap."""
    cache = paths.cache_subdir("osv")
    dest = cache / f"{_safe_name(eco)}.zip"
    tmp = cache / f".{_safe_name(eco)}.{secrets.token_hex(8)}.part"
    cap = _max_zip_bytes()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f, client.stream("GET", f"{BUCKET}/{quote(eco)}/all.zip") as r:
            r.raise_for_status()
            declared = r.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > cap:
                raise ValueError(f"{eco}/all.zip is {declared} bytes, above the {cap} byte limit")
            total = 0
            for chunk in r.iter_bytes(1 << 20):
                total += len(chunk)
                if total > cap:
                    raise ValueError(f"{eco}/all.zip exceeds the {cap} byte download limit")
                f.write(chunk)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return dest


@register
class OsvSource(Source):
    name = "osv"
    description = "OSV.dev bulk (package ecosystems + distro advisories)"

    def sync(self, conn: sqlite3.Connection, opts: SyncOptions) -> SyncResult:
        """Never writes the main `osv` source_sync row (the CLI does, from the SyncResult);
        per-ecosystem cursors live in `osv:<Eco>`. `records` = imported this run, `.total` = OSV records in the DB."""
        try:
            if opts.path:
                res = self._sync_path(conn, opts)
            else:
                ecos = validate_ecosystems(list(opts.ecosystems) or list(DEFAULT_ECOSYSTEMS))
                res = self._sync_all(conn, opts, ecos)
        except ValueError as e:
            return SyncResult(self.name, status="error", message=str(e))
        if res.status != "error":
            total = conn.execute("SELECT COUNT(*) FROM vulnerability WHERE source='osv'").fetchone()[0]
            res.total = total
        return res

    def _sync_all(self, conn: sqlite3.Connection, opts: SyncOptions, ecos: list[str]) -> SyncResult:
        total, errors, ok, partial = 0, [], 0, False
        for eco in ecos:
            try:
                n, eco_partial = self._sync_ecosystem(conn, opts, eco)
                total += n
                ok += 1
                partial = partial or eco_partial
            except Exception as e:  # noqa: BLE001
                conn.commit()
                errors.append(f"{eco}: {e}")
                opts.log(f"osv {eco}: failed: {e}")
        if errors and not ok:
            status = "error"
        else:
            status = "partial" if (errors or partial) else "ok"
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
        return SyncResult(self.name, records=imp.count, cursor=imp.max_modified_str,
                          message=f"from {p}")

    # ---- download
    def _sync_ecosystem(self, conn: sqlite3.Connection, opts: SyncOptions, eco: str) -> tuple[int, bool]:
        key = f"osv:{eco}"
        status, cursor = _state(conn, key)
        # the delta path needs a trustworthy cursor: only after a complete (status ok) sync
        cursor = None if (opts.full or status != "ok") else cursor
        enc = quote(eco)
        with http_client(timeout=120.0) as client:
            if cursor:
                resp = client.get(f"{BUCKET}/{enc}/modified_id.csv")
                resp.raise_for_status()
                changed = ids_modified_since(resp.text.splitlines(), cursor)
                if len(changed) <= DELTA_MAX_IDS:
                    return self._delta(conn, opts, client, eco, key, cursor, changed)
                opts.log(f"osv {eco}: {len(changed)} changes since cursor, falling back to full zip")
            return self._full(conn, opts, client, eco, key), bool(opts.limit)

    def _full(self, conn, opts, client, eco: str, key: str) -> int:
        opts.log(f"osv {eco}: downloading {eco}/all.zip")
        dest = _download_zip(client, eco, opts)
        imp = _Importer(conn, opts, eco)
        _import_iter(imp, _iter_zip(dest, opts))
        imp.finish()
        truncated = opts.limit is not None and imp.full
        if truncated:
            # a --limit run imported an arbitrary subset: no cursor, and the next run must be full
            conn.execute("UPDATE source_sync SET cursor=NULL WHERE source=?", (key,))
        set_sync_state(conn, key, status="partial" if truncated else "ok", records=imp.count,
                       cursor=None if truncated else imp.max_modified_str, message="full")
        opts.log(f"osv {eco}: imported {imp.count} records (full)")
        return imp.count

    def _delta(self, conn, opts, client, eco: str, key: str, cursor: str,
               changed: list[tuple[str, str]]) -> tuple[int, bool]:
        imp = _Importer(conn, opts, eco)
        changed.sort(key=lambda t: parse_ts(t[0]))  # oldest first so the cursor can advance contiguously
        good_ts: list[str] = []                    # successes before the first failure
        first_fail: str | None = None
        failures = 0
        for ts, rid in changed:
            if imp.full:
                break
            try:
                r = client.get(f"{BUCKET}/{quote(eco)}/{quote(rid)}.json")
                if r.status_code != 404:
                    r.raise_for_status()
                    doc = r.json()
                    if not isinstance(doc, dict):
                        raise ValueError("record is not a JSON object")
                    imp.add(doc)
            except Exception as e:  # noqa: BLE001 - skip this id, keep going
                failures += 1
                opts.log(f"osv {eco}: {rid}: {type(e).__name__}: {e}")
                if first_fail is None:
                    first_fail = ts
                continue
            if first_fail is None:
                good_ts.append(ts)
        imp.finish()
        newest = None
        for ts in good_ts:
            if first_fail is None or parse_ts(ts) < parse_ts(first_fail):
                newest = ts
        if newest is not None and parse_ts(newest) <= parse_ts(cursor):
            newest = None
        # the per-ecosystem row stays "ok" (cursor valid, failed ids are retried by the next delta);
        # the failure is surfaced through the returned flag -> overall status "partial"
        set_sync_state(conn, key, status="ok", records=imp.count, cursor=newest or cursor,
                       message=f"delta, {failures} failed" if failures else "delta")
        opts.log(f"osv {eco}: imported {imp.count} records (delta)")
        return imp.count, bool(failures)
