"""SQLite storage: schema + small helpers.

The schema is the integration contract between sources, collectors and the engine.
Documented in _docs/tech/data-model.md (history: _docs/decisions/0004-sqlite-schema-v2.md) — keep
them in sync. The file lives in the per-user data directory, mode 0600 (secmonk/paths.py).
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import paths

SCHEMA_VERSION = 2

SCHEMA = """
-- ------------------------------------------------------------------ vuln data
CREATE TABLE IF NOT EXISTS source_sync (
    source        TEXT PRIMARY KEY,          -- 'cvelist' 'kev' 'epss' 'nvd' 'euvd' 'msrc' 'debian-tracker', 'osv:<Ecosystem>'
                                             -- (one row per OSV ecosystem); internal: 'cvelist:git', 'cvelist:years', 'nvd:progress'
    last_sync     TEXT,                      -- ISO timestamp of last successful sync
    cursor        TEXT,                      -- source-specific delta cursor (e.g. modified date)
    records       INTEGER DEFAULT 0,
    status        TEXT,                      -- ok | error | partial (partial: some records skipped, last_sync still moves)
    message       TEXT
);

-- Raw record as published by the source (re-normalize without re-downloading).
CREATE TABLE IF NOT EXISTS raw_record (
    source        TEXT NOT NULL,
    record_id     TEXT NOT NULL,
    modified      TEXT,
    fetched_at    TEXT NOT NULL,
    data          TEXT NOT NULL,             -- JSON
    PRIMARY KEY (source, record_id)
);

-- One row per (source, id). The same CVE may appear from cvelist, nvd, euvd...
CREATE TABLE IF NOT EXISTS vulnerability (
    source        TEXT NOT NULL,
    id            TEXT NOT NULL,             -- CVE-…, GHSA-…, PYSEC-…, DEBIAN-CVE-…, EUVD-…
    summary       TEXT,
    details       TEXT,
    published     TEXT,
    modified      TEXT,
    withdrawn     TEXT,
    state         TEXT,                      -- PUBLISHED | REJECTED | … (cvelist), vulnStatus (nvd)
    severity      TEXT,                      -- CRITICAL/HIGH/MEDIUM/LOW/NONE (derived or declared)
    cvss_score    REAL,
    cvss_vector   TEXT,
    cvss_version  TEXT,
    cwes          TEXT,                      -- JSON list
    extra         TEXT,                      -- JSON: ssvc, adp_kev, references, cvss_source ...
    PRIMARY KEY (source, id)
);
CREATE INDEX IF NOT EXISTS ix_vuln_id ON vulnerability(id);

-- Undirected alias edges, e.g. GHSA-jfh8-c2jp-5v3q <-> CVE-2021-44228.
CREATE TABLE IF NOT EXISTS alias (
    vuln_id       TEXT NOT NULL,
    alias         TEXT NOT NULL,
    source        TEXT NOT NULL,
    kind          TEXT DEFAULT 'alias',      -- alias | upstream | related (OSV); only 'alias' edges mean "same vulnerability"
    PRIMARY KEY (vuln_id, alias, source)
);
CREATE INDEX IF NOT EXISTS ix_alias_alias ON alias(alias);

-- What is affected. Two flavours share the table:
--  * package-based (OSV): ecosystem + package, range_type ECOSYSTEM/SEMVER/GIT, events JSON
--  * product-based (CVE List `affected`, NVD CPE): vendor + product, version bounds
CREATE TABLE IF NOT EXISTS affected (
    rowid_        INTEGER PRIMARY KEY AUTOINCREMENT,
    source        TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    ecosystem     TEXT,                      -- OSV ecosystem incl. release: 'PyPI', 'Debian:12', 'Alpine:v3.20'
    package       TEXT,                      -- normalized (lowercase) package name
    purl          TEXT,                      -- purl without version, if known
    vendor        TEXT,                      -- normalized vendor (product-based)
    product       TEXT,                      -- normalized product (product-based)
    cpe           TEXT,                      -- cpe criteria, if any
    range_type    TEXT,                      -- ECOSYSTEM | SEMVER | VERSIONS (osv, matched as osv-package) | CVE (CNA, matched as
                                             -- cve-product) | CPE (matched as cpe-product) | GIT and CVE-UNPARSED (stored, never matched)
    version_type  TEXT,                      -- cvelist versionType (semver, custom, git, ...)
    events        TEXT,                      -- JSON list of {introduced|introduced_exclusive|fixed|last_affected|limit: v}
    versions      TEXT,                      -- JSON list of explicitly affected versions
    status        TEXT DEFAULT 'affected',   -- affected | unaffected | unknown
    extra         TEXT
);
CREATE INDEX IF NOT EXISTS ix_aff_pkg ON affected(ecosystem, package);
CREATE INDEX IF NOT EXISTS ix_aff_prod ON affected(product, vendor);
CREATE INDEX IF NOT EXISTS ix_aff_vuln ON affected(vuln_id);

CREATE TABLE IF NOT EXISTS kev (
    cve_id        TEXT PRIMARY KEY,
    vendor        TEXT,
    product       TEXT,
    name          TEXT,
    date_added    TEXT,
    due_date      TEXT,
    ransomware    TEXT,
    source        TEXT DEFAULT 'kev',
    extra         TEXT
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id        TEXT PRIMARY KEY,
    score         REAL,
    percentile    REAL,
    date          TEXT,
    source        TEXT DEFAULT 'epss'
);

-- Distribution triage per (release ecosystem, source package, CVE): what the distro security
-- team decided, beyond affected ranges. Filled by distro trackers (sources/debian_tracker.py);
-- read by engine/match.py to drop not-affected findings and to downgrade minor ones.
CREATE TABLE IF NOT EXISTS distro_triage (
    ecosystem     TEXT NOT NULL,             -- normalized OSV ecosystem: 'Debian:12'
    package       TEXT NOT NULL,             -- source package (lowercase)
    cve_id        TEXT NOT NULL,
    status        TEXT,                      -- open | resolved | not-affected | undetermined
    urgency       TEXT,                      -- unimportant | low | medium | high | not yet assigned | end-of-life …
    fixed_version TEXT,                      -- distro fixed version ('0' = never affected)
    nodsa         TEXT,                      -- no-dsa | postponed | ignored (Debian 'nodsa' + reason)
    note          TEXT,                      -- free-text reason (nodsa_reason, description)
    advisory      TEXT,                      -- DSA-/DLA- id when known
    source        TEXT NOT NULL,             -- 'debian-tracker'
    PRIMARY KEY (ecosystem, package, cve_id, source)
);
CREATE INDEX IF NOT EXISTS ix_triage_cve ON distro_triage(cve_id);

-- ------------------------------------------------------------------ inventory
CREATE TABLE IF NOT EXISTS asset (
    id            TEXT PRIMARY KEY,          -- stable id: 'macos:<host>', 'homebrew:<host>', 'windows:<host>', 'ssh:<host>[:<port>]',
                                             -- 'image:<repo>@<digest>', 'image:@<Id>' (engine image, by image Id),
                                             -- 'container:<name>' ('container:<label>/<name>' on a remote engine),
                                             -- 'rootfs:<path>', 'repo:<path>', 'dir:<path>',
                                             -- 'process:<host>' (running processes only)
    type          TEXT NOT NULL,             -- desktop | server | container-image | container | repo | directory | host-processes
    name          TEXT,
    os_name       TEXT,
    os_version    TEXT,
    platform      TEXT,                      -- linux/amd64, darwin/arm64
    meta          TEXT,                      -- JSON (labels, owner, env, exposure, ...)
    first_seen    TEXT,
    last_seen     TEXT
);

CREATE TABLE IF NOT EXISTS scan (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id      TEXT NOT NULL REFERENCES asset(id),
    collector     TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    components    INTEGER DEFAULT 0,
    meta          TEXT
);

CREATE TABLE IF NOT EXISTS component (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key           TEXT NOT NULL UNIQUE,      -- purl if any, else 'name:<category>/<vendor>/<name>@<version>'
                                             -- (meta below = identity facts shared by every asset with this key)
    name          TEXT NOT NULL,
    version       TEXT,
    category      TEXT NOT NULL,             -- os | os-package | library | application | runtime | ...
    ecosystem     TEXT,                      -- OSV ecosystem used for matching, if any
    purl          TEXT,
    cpe           TEXT,
    vendor        TEXT,
    meta          TEXT
);

CREATE TABLE IF NOT EXISTS asset_component (
    asset_id      TEXT NOT NULL REFERENCES asset(id),
    component_id  INTEGER NOT NULL REFERENCES component(id),
    source_path   TEXT,
    first_seen    TEXT,
    last_seen     TEXT,
    last_scan_id  INTEGER,
    paths         TEXT,                      -- JSON list: every location of this component on the asset
    meta          TEXT,                      -- JSON: per-asset facts (users, install_location, scope…)
    PRIMARY KEY (asset_id, component_id)
);

-- ------------------------------------------------------------------ findings
CREATE TABLE IF NOT EXISTS finding (
    asset_id      TEXT NOT NULL,
    component_id  INTEGER NOT NULL,
    vuln_id       TEXT NOT NULL,             -- canonical id (CVE when available)
    advisory_ids  TEXT,                      -- JSON list of all matched advisory ids/aliases
    matched_by    TEXT,                      -- osv-package | cve-product | cpe-product (see engine/match.py)
    confidence    REAL,                      -- 1.0 exact package match, lower for name-based
    fixed_version TEXT,
    severity      TEXT,
    cvss_score    REAL,
    epss          REAL,
    kev           INTEGER DEFAULT 0,
    priority      TEXT,                      -- P1..P4
    status        TEXT DEFAULT 'open',       -- open | fixed | suppressed
    first_seen    TEXT,
    last_seen     TEXT,
    fixed_at      TEXT,
    triage        TEXT,                      -- distro triage label: unimportant | no-dsa | postponed | ignored | end-of-life | low …
    triage_source TEXT,                      -- debian-tracker | osv
    PRIMARY KEY (asset_id, component_id, vuln_id)
);

-- ------------------------------------------------------------------ run history
-- One row per `scan` / `sync` run, from the CLI or the web UI (never shadowed by ephemeral_overlay: a --no-save scan
-- is listed too). Parameters are stored redacted (ops.scan_params / sync_params). The last JOB_KEEP rows are kept.
CREATE TABLE IF NOT EXISTS job (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,             -- scan | sync
    origin        TEXT NOT NULL,             -- cli | ui
    title         TEXT,
    params        TEXT,                      -- JSON (secrets redacted)
    status        TEXT,                      -- running | ok | partial | error
    started_at    TEXT,
    finished_at   TEXT,
    error         TEXT,
    result        TEXT,                      -- JSON: scan {saved, targets[], stats, counts} | sync {sources[]}
    log           TEXT,                      -- JSON list of lines (last JOB_LOG_LINES)
    summary       TEXT,                      -- JSON: reports.job_summary of the result (lists read it, not result/log)
    owner         TEXT                       -- JSON {pid, host} of the process running it (stale 'running' detection)
);
CREATE INDEX IF NOT EXISTS ix_job_kind ON job(kind, id);
"""


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def default_db_path() -> Path:
    """Per-user database location (see secmonk/paths.py); never relative to the CWD."""
    return paths.default_db_path()


def _create_private_file(path: Path) -> None:
    """Create an empty DB file with mode 0600 before SQLite would create it with the umask."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    os.close(fd)


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    if str(path) == ":memory:":
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        init_schema(conn)
        return conn
    path = Path(path) if path else default_db_path()
    if path == default_db_path():
        paths.ensure_private_dir(path.parent)
    elif not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        _create_private_file(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    init_schema(conn)
    return conn


# columns added after a table was first created: (table, column, type)
_ADDED_COLUMNS = (("finding", "triage", "TEXT"), ("finding", "triage_source", "TEXT"),
                  ("alias", "kind", "TEXT DEFAULT 'alias'"),
                  ("asset_component", "paths", "TEXT"), ("asset_component", "meta", "TEXT"),
                  ("job", "summary", "TEXT"), ("job", "owner", "TEXT"))


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    for table, col, typ in _ADDED_COLUMNS:          # lightweight migration for existing DBs
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if col not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    # Only ever raise the version: a DB written by a newer secmonk must not be stamped back down.
    if conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    conn.commit()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def dumps(obj: Any) -> str | None:
    if obj is None:
        return None
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str)


def loads(s: str | None, default: Any = None) -> Any:
    if not s:
        return default
    return json.loads(s)


def set_sync_state(
    conn: sqlite3.Connection,
    source: str,
    *,
    status: str,
    records: int = 0,
    cursor: str | None = None,
    message: str | None = None,
) -> None:
    """Record the outcome of a sync run.

    `last_sync` only moves for status ok/partial. An `error` run keeps the previous records and
    cursor (and last_sync) and only updates status + message, so a failure never zeroes the
    totals of the last good sync.
    """
    if status in ("ok", "partial"):
        conn.execute(
            """INSERT INTO source_sync(source, last_sync, cursor, records, status, message)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(source) DO UPDATE SET last_sync=excluded.last_sync,
                 cursor=COALESCE(excluded.cursor, source_sync.cursor),
                 records=excluded.records, status=excluded.status, message=excluded.message""",
            (source, now(), cursor, records, status, message),
        )
    else:
        conn.execute(
            """INSERT INTO source_sync(source, last_sync, cursor, records, status, message)
               VALUES (?,NULL,NULL,0,?,?)
               ON CONFLICT(source) DO UPDATE SET status=excluded.status, message=excluded.message""",
            (source, status, message),
        )
    conn.commit()


def get_sync_cursor(conn: sqlite3.Connection, source: str) -> str | None:
    row = conn.execute("SELECT cursor FROM source_sync WHERE source=?", (source,)).fetchone()
    return row["cursor"] if row else None


# --------------------------------------------------------------------------- run history (table `job`)

JOB_KEEP = 200          # runs kept; older ones are pruned when a new one starts
JOB_LOG_LINES = 300     # log lines kept per stored run


def this_owner() -> dict:
    """The process recording a run: {pid, host}."""
    return {"pid": os.getpid(), "host": socket.gethostname()}


def owner_alive(owner: dict | None) -> bool:
    """Whether the process that owns a 'running' row still runs. Unknown owner (old row), another host name (the
    database is per-user and local: most likely this host renamed) or a pid that is gone -> False. Windows cannot
    probe a pid with signal 0, so there only this process's own rows count as alive."""
    if not isinstance(owner, dict) or owner.get("host") != socket.gethostname():
        return False
    pid = owner.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name != "posix":
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:          # exists, belongs to someone else
        return True
    except OSError:
        return False
    return True


def job_insert(conn: sqlite3.Connection, *, kind: str, origin: str, title: str | None, params: dict | None,
               started_at: str | None = None) -> int:
    """Record a run that starts now (status 'running', owned by this process); prunes runs beyond JOB_KEEP."""
    cur = conn.execute("INSERT INTO job(kind, origin, title, params, status, started_at, owner) VALUES (?,?,?,?,?,?,?)",
                       (kind, origin, title, dumps(params), "running", started_at or now(), dumps(this_owner())))
    job_id = int(cur.lastrowid)
    conn.execute("DELETE FROM job WHERE id <= ?", (job_id - JOB_KEEP,))
    conn.commit()
    return job_id


def job_finish(conn: sqlite3.Connection, job_id: int, *, status: str, result: Any = None, error: str | None = None,
               log: list[str] | None = None, summary: dict | None = None) -> None:
    conn.execute("UPDATE job SET status=?, finished_at=?, error=?, result=?, log=?, summary=? WHERE id=?",
                 (status, now(), error, dumps(result), dumps(list(log or [])[-JOB_LOG_LINES:]), dumps(summary),
                  job_id))
    conn.commit()


def job_mark_interrupted(conn: sqlite3.Connection) -> int:
    """Runs left 'running' by a process that is gone (owner_alive) -> status 'error', error 'interrupted'.
    A run that does finish later still overwrites this."""
    dead = [r["id"] for r in conn.execute("SELECT id, owner FROM job WHERE status='running'")
            if not owner_alive(loads(r["owner"]))]
    if dead:
        conn.executemany("UPDATE job SET status='error', error='interrupted', finished_at=COALESCE(finished_at, ?) "
                         "WHERE id=? AND status='running'", [(now(), i) for i in dead])
        conn.commit()
    return len(dead)


# list columns: no `log` (its length is computed in SQL)
_JOB_LIST_COLS = ("id, kind, origin, title, params, status, started_at, finished_at, error, result, summary, owner, "
                  "json_array_length(COALESCE(log, '[]')) AS log_lines")


def job_rows(conn: sqlite3.Connection, *, kind: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
    """Stored runs, newest first, without their log (column `log_lines` instead)."""
    sql = f"SELECT {_JOB_LIST_COLS} FROM job"
    if kind:
        return conn.execute(sql + " WHERE kind=? ORDER BY id DESC LIMIT ?", (kind, limit)).fetchall()
    return conn.execute(sql + " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def job_row(conn: sqlite3.Connection, job_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM job WHERE id=?", (job_id,)).fetchone()


def executemany(conn: sqlite3.Connection, sql: str, rows: Iterable[tuple]) -> None:
    conn.executemany(sql, rows)


def ephemeral_overlay(conn: sqlite3.Connection) -> None:
    """Shadow the inventory tables with TEMP copies so a scan can match without persisting anything
    (`scan --no-save`, `procs`, the web UI). Lives as long as the connection."""
    import re

    conn.execute("PRAGMA foreign_keys=OFF")
    for t in ("asset", "scan", "component", "asset_component", "finding"):
        sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()[0]
        conn.execute(re.sub(r"^\s*CREATE TABLE", "CREATE TEMP TABLE", sql, count=1))
