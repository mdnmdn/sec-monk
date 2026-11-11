"""Read-only access to the host's databases for engine modules (rust ADR-0006).

The host's `hello` grants `db_read {state, mirror}`. A request opens `file:<state>?mode=ro`, attaches the mirror
read-only, runs inside one read transaction and rolls it back at the end. `secmonk.db.connect` is never used (it runs
`init_schema`, a write). TEMP tables (the shadows `engine.match` needs) are the only thing a request may write:

* `mode=ro` is the hard guard: no write to any database file is possible;
* `PRAGMA query_only=ON` for plain reports (it also forbids TEMP writes, measured 2026-11-11: sqlite 3.51);
* an authorizer for matches: INSERT / UPDATE / DELETE / CREATE / DROP only on the `temp` database, no ATTACH / DETACH.

Table names stay unqualified: state and mirror have no table in common except `store_meta`, which Python never reads.
"""

from __future__ import annotations

import contextlib
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path, PurePath

from .errors import WireError
from .wire import Session

_TEMP_OK = {sqlite3.SQLITE_CREATE_TEMP_INDEX, sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
            sqlite3.SQLITE_CREATE_TEMP_VIEW, sqlite3.SQLITE_DROP_TEMP_INDEX, sqlite3.SQLITE_DROP_TEMP_TABLE,
            sqlite3.SQLITE_DROP_TEMP_TRIGGER, sqlite3.SQLITE_DROP_TEMP_VIEW}
_DENIED = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TABLE,
           sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_DROP_INDEX,
           sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_DROP_VIEW,
           sqlite3.SQLITE_ALTER_TABLE, sqlite3.SQLITE_REINDEX, sqlite3.SQLITE_ANALYZE,
           sqlite3.SQLITE_CREATE_VTABLE, sqlite3.SQLITE_DROP_VTABLE}
_WRITES = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}


class RoConnection(sqlite3.Connection):
    """`commit` / `rollback` are no-ops: code written for a writable connection (`match_asset` ends with a commit)
    must not end the request's read transaction. The session ends it itself."""

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None


def _authorizer(action: int, arg1, arg2, dbname, source) -> int:
    if action in _WRITES:
        return sqlite3.SQLITE_OK if dbname == "temp" else sqlite3.SQLITE_DENY
    if action in _TEMP_OK:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_CREATE_TABLE and dbname == "temp":      # sqlite_sequence of an AUTOINCREMENT shadow
        return sqlite3.SQLITE_OK
    if action in _DENIED:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def plain_path(path: str) -> str:
    """A Windows extended-length path (`\\\\?\\C:\\...`, `\\\\?\\UNC\\server\\share\\...`, what Rust's
    `canonicalize` returns) as a plain one: the verbatim prefix breaks `file:` URIs. Other paths are unchanged."""
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def file_uri(path: PurePath) -> str:
    """`file:` URI of an absolute path, read-only (`as_uri` percent-encodes `?`, `#` and `%`)."""
    return path.as_uri() + "?mode=ro"


def _uri(path: str) -> str:
    return file_uri(Path(plain_path(path)).resolve())


def open_readonly(state: str, mirror: str, *, temp_writes: bool = False) -> sqlite3.Connection:
    """A read-only connection on `state` with `mirror` attached (skipped when both are the same file, a v2 layout).
    `WireError no-db` when a file is missing."""
    state, mirror = plain_path(state), plain_path(mirror)
    for p in {state, mirror}:
        if not Path(p).is_file():
            raise WireError("no-db", f"no database at {p}",
                            "Create the local vulnerability mirror first (Sources & sync), then scan assets.")
    conn = sqlite3.connect(_uri(state), uri=True, timeout=5.0, isolation_level=None, factory=RoConnection)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        if Path(mirror).resolve() != Path(state).resolve():
            conn.execute("ATTACH DATABASE ? AS mirror", (_uri(mirror),))
        if not temp_writes:
            conn.execute("PRAGMA query_only=ON")
        conn.set_authorizer(_authorizer)
        conn.execute("BEGIN")                                   # one snapshot per request, on both files
        conn.execute("SELECT 1 FROM main.sqlite_master LIMIT 1").fetchall()
        if Path(mirror).resolve() != Path(state).resolve():
            conn.execute("SELECT 1 FROM mirror.sqlite_master LIMIT 1").fetchall()
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def read_session(session: Session, *, temp_writes: bool = False) -> Iterator[tuple[sqlite3.Connection, str]]:
    """`(connection, state path)` for one request, from the host's `db_read` grant (`no-db` without one)."""
    grant = session.db_read
    if grant is None:
        raise WireError("no-db", "this module has no database grant",
                        "The host grants db_read to modules that declare db-read.")
    conn = open_readonly(grant["state"], grant["mirror"], temp_writes=temp_writes)
    try:
        yield conn, grant["state"]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e) or "no such column" in str(e):
            raise WireError("no-db", "the database is not initialized yet",
                            "Create the local vulnerability mirror first, then scan assets.") from None
        raise
    finally:
        with contextlib.suppress(sqlite3.Error):
            sqlite3.Connection.execute(conn, "ROLLBACK")
        conn.close()


_CREATE = re.compile(r"^\s*CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?", re.IGNORECASE)


def shadow_table(conn: sqlite3.Connection, table: str, where: str = "", args: tuple = ()) -> None:
    """A TEMP copy of `table` (same DDL, constraints included) holding the rows matching `where`; from then on the
    unqualified name resolves to the copy, the real table stays untouched (read-only)."""
    row = conn.execute("SELECT sql FROM main.sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    if row is None:
        raise WireError("no-db", f"the database has no table {table}")
    conn.execute(_CREATE.sub("CREATE TEMP TABLE ", row[0], count=1))
    if where:
        conn.execute(f"INSERT INTO temp.{table} SELECT * FROM main.{table} WHERE {where}", args)
