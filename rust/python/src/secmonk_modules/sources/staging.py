"""The staging database of the source adapter (rust ADR-0010).

A schema-v2 SQLite file owned by this module (`secmonk.db.connect`, so the unchanged sources read and write their own
previous state: cursors, `raw_record`, `vulnerability.modified`, MSRC merges). AFTER INSERT / UPDATE / DELETE triggers on
the mirror tables append JSON row images to `_sm_log`; the adapter streams the log as row operations and drops what the
host acknowledged. Changes are numbered into batches **once** (`_sm_log.batch`), so an un-acknowledged batch is replayed
unchanged (same seq) at the next sync.

The file has a random **generation** (`_sm_meta.generation`, created with the file): batch seqs only compare within one
generation, so a recreated staging file (seqs from 1 again) is never mistaken for a replay by the host. The highest seq
acknowledged per source (`_sm_meta."acked:<source>"`) tells the host when its mirror lost rows this log already dropped.
Both travel in every batch; the host repairs the source from `source.export` when they disagree with its mirror.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

MIRROR_TABLES = ("source_sync", "raw_record", "vulnerability", "alias", "affected", "kev", "epss", "distro_triage")
JSON_COLUMNS = {"raw_record": {"data"}, "vulnerability": {"cwes", "extra"}, "affected": {"events", "versions", "extra"},
                "kev": {"extra"}}
SKIP_COLUMNS = {"affected": {"rowid_"}}            # surrogate key: the host has its own
NO_NATURAL_KEY = {"affected"}                      # delete carries the whole row, deletes one match
LOCK = threading.Lock()                            # one writer of the staging file at a time

DDL = """
CREATE TABLE IF NOT EXISTS _sm_ctx (id INTEGER PRIMARY KEY CHECK (id = 1), src TEXT);
INSERT OR IGNORE INTO _sm_ctx(id, src) VALUES (1, NULL);
CREATE TABLE IF NOT EXISTS _sm_log (
    seq   INTEGER PRIMARY KEY AUTOINCREMENT,
    src   TEXT,
    tbl   TEXT NOT NULL,
    op    TEXT NOT NULL,
    row   TEXT NOT NULL,
    batch INTEGER
);
CREATE INDEX IF NOT EXISTS _sm_log_src ON _sm_log(src, batch, seq);
CREATE TABLE IF NOT EXISTS _sm_meta (key TEXT PRIMARY KEY, value TEXT);
"""


def staging_path(settings: dict[str, Any]) -> Path:
    """`session.settings.module_dir` (the host: `{data_dir}/modules/py-sources`), else `$SECMONK_MODULE_DIR`, else under
    `$SECMONK_HOME` (never the working directory, rust ADR-0006)."""
    d = settings.get("module_dir") or os.environ.get("SECMONK_MODULE_DIR")
    if not d:
        from secmonk import paths

        d = paths.data_dir() / "modules" / "py-sources"
    return Path(d) / "staging.sqlite3"


def _columns(conn: sqlite3.Connection, table: str) -> tuple[list[str], list[str]]:
    """(columns without the skipped ones, primary key columns in key order)."""
    info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    cols = [r[1] for r in info if r[1] not in SKIP_COLUMNS.get(table, ())]
    pk = [r[1] for r in sorted((r for r in info if r[5]), key=lambda r: r[5])]
    return cols, ([] if table in NO_NATURAL_KEY else pk)


def _image(prefix: str, cols: list[str]) -> str:
    return "json_object(" + ", ".join(f"'{c}', {prefix}.{c}" for c in cols) + ")"


def install(conn: sqlite3.Connection) -> None:
    """Create the log and the triggers (recreated when a mirror table's columns changed)."""
    conn.executescript(DDL)
    conn.execute("INSERT OR IGNORE INTO _sm_meta(key, value) VALUES ('generation', ?)", (secrets.token_hex(16),))
    conn.commit()
    sig, plans = [], {}
    for t in MIRROR_TABLES:
        cols, pk = _columns(conn, t)
        plans[t] = (cols, pk)
        sig.append(f"{t}:{','.join(cols)}")
    signature = ";".join(sig)
    row = conn.execute("SELECT value FROM _sm_meta WHERE key='trigger_signature'").fetchone()
    if row and row[0] == signature:
        return
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE '_sm_%'").fetchall():
        conn.execute(f"DROP TRIGGER {name}")
    src = "(SELECT src FROM _sm_ctx WHERE id = 1)"
    for t, (cols, pk) in plans.items():
        key = _image('OLD', pk or cols)                # no natural key: the whole row identifies it
        conn.execute(f"CREATE TRIGGER _sm_{t}_ai AFTER INSERT ON {t} BEGIN INSERT INTO _sm_log(src, tbl, op, row) "
                     f"VALUES ({src}, '{t}', 'upsert', {_image('NEW', cols)}); END")
        if pk:
            changed = " OR ".join(f"OLD.{c} IS NOT NEW.{c}" for c in pk)
            conn.execute(f"CREATE TRIGGER _sm_{t}_au1 AFTER UPDATE ON {t} WHEN {changed} BEGIN "
                         f"INSERT INTO _sm_log(src, tbl, op, row) VALUES ({src}, '{t}', 'delete', {key}); END")
        else:
            conn.execute(f"CREATE TRIGGER _sm_{t}_au1 AFTER UPDATE ON {t} BEGIN INSERT INTO _sm_log(src, tbl, op, row) "
                         f"VALUES ({src}, '{t}', 'delete', {key}); END")
        conn.execute(f"CREATE TRIGGER _sm_{t}_au2 AFTER UPDATE ON {t} BEGIN INSERT INTO _sm_log(src, tbl, op, row) "
                     f"VALUES ({src}, '{t}', 'upsert', {_image('NEW', cols)}); END")
        conn.execute(f"CREATE TRIGGER _sm_{t}_ad AFTER DELETE ON {t} BEGIN INSERT INTO _sm_log(src, tbl, op, row) "
                     f"VALUES ({src}, '{t}', 'delete', {key}); END")
    conn.execute("INSERT OR REPLACE INTO _sm_meta(key, value) VALUES ('trigger_signature', ?)", (signature,))
    conn.commit()


def open_staging(path: Path) -> sqlite3.Connection:
    """The staging database (created, mode 0600, schema v2 + log + triggers)."""
    from secmonk import db as dbm

    conn = dbm.connect(path)
    install(conn)
    return conn


# --------------------------------------------------------------------------- ops

def to_op(tbl: str, op: str, row_json: str) -> dict[str, Any]:
    row = json.loads(row_json)
    for c in JSON_COLUMNS.get(tbl, ()):
        v = row.get(c)
        if isinstance(v, str):
            row[c] = json.loads(v)
    if op == "upsert":
        return {"op": "upsert", "table": tbl, "row": row}
    return {"op": "delete", "table": tbl, "key": row}


def set_source(conn: sqlite3.Connection, name: str | None) -> None:
    conn.execute("UPDATE _sm_ctx SET src=? WHERE id=1", (name,))
    conn.commit()


def _next_batch(conn: sqlite3.Connection) -> int:
    r = conn.execute("SELECT value FROM _sm_meta WHERE key='next_batch'").fetchone()
    n = int(r[0]) if r else 1
    conn.execute("INSERT OR REPLACE INTO _sm_meta(key, value) VALUES ('next_batch', ?)", (str(n + 1),))
    return n


def generation(conn: sqlite3.Connection) -> str:
    """This staging file's generation (created by `install`)."""
    return conn.execute("SELECT value FROM _sm_meta WHERE key='generation'").fetchone()[0]


def acked_through(conn: sqlite3.Connection, src: str) -> int:
    """The highest seq the host acknowledged for `src` in this generation (0: never)."""
    r = conn.execute("SELECT value FROM _sm_meta WHERE key=?", (f"acked:{src}",)).fetchone()
    return int(r[0]) if r else 0


def high_water(conn: sqlite3.Connection) -> int:
    """The highest seq ever assigned in this generation (0: none): every numbered batch is at or below it."""
    r = conn.execute("SELECT value FROM _sm_meta WHERE key='next_batch'").fetchone()
    return int(r[0]) - 1 if r else 0


def pending_batches(conn: sqlite3.Connection, src: str, *, max_ops: int, max_bytes: int,
                    ) -> Iterator[tuple[int, list[dict[str, Any]]]]:
    """Every un-acknowledged batch of `src`, oldest first: first the batches already numbered (replay, same seq), then
    new ones cut from the unnumbered log (≤ `max_ops` operations and about `max_bytes` of JSON each), numbered and
    committed *before* they are yielded so a crash replays exactly what was sent."""
    for (b,) in conn.execute("SELECT DISTINCT batch FROM _sm_log WHERE src=? AND batch IS NOT NULL ORDER BY batch",
                             (src,)).fetchall():
        rows = conn.execute("SELECT tbl, op, row FROM _sm_log WHERE src=? AND batch=? ORDER BY seq", (src, b)).fetchall()
        yield b, [to_op(*r) for r in rows]
    for b, rows in _number_new(conn, src, max_ops=max_ops, max_bytes=max_bytes):
        yield b, [to_op(r[1], r[2], r[3]) for r in rows]


def number_pending(conn: sqlite3.Connection, src: str, *, max_ops: int, max_bytes: int) -> None:
    """Number (cut into batches) every change of `src` not numbered yet, without streaming it: before an export, so
    `high_water` covers every change the exported state already contains."""
    for _ in _number_new(conn, src, max_ops=max_ops, max_bytes=max_bytes):
        pass


def _number_new(conn: sqlite3.Connection, src: str, *, max_ops: int, max_bytes: int,
                ) -> Iterator[tuple[int, list[tuple[int, str, str, str]]]]:
    while True:
        rows, size = [], 0
        for r in conn.execute("SELECT seq, tbl, op, row FROM _sm_log WHERE src=? AND batch IS NULL ORDER BY seq LIMIT ?",
                              (src, max_ops)):
            rows.append(r)
            size += len(r[3]) + 40
            if size >= max_bytes:
                break
        if not rows:
            return
        b = _next_batch(conn)
        conn.execute("UPDATE _sm_log SET batch=? WHERE src=? AND batch IS NULL AND seq BETWEEN ? AND ?",
                     (b, src, rows[0][0], rows[-1][0]))
        conn.commit()
        yield b, rows


def ack(conn: sqlite3.Connection, src: str, through_seq: int) -> int:
    """Drop the batches of `src` up to `through_seq` and remember the highest seq acknowledged (never lowered)."""
    cur = conn.execute("DELETE FROM _sm_log WHERE src=? AND batch IS NOT NULL AND batch<=?", (src, through_seq))
    if through_seq > acked_through(conn, src):
        conn.execute("INSERT OR REPLACE INTO _sm_meta(key, value) VALUES (?, ?)", (f"acked:{src}", str(through_seq)))
    conn.commit()
    return cur.rowcount


def source_rows(conn: sqlite3.Connection, src: str, *, max_ops: int, max_bytes: int,
                ) -> Iterator[tuple[int, list[dict[str, Any]]]]:
    """Every staging row of `src` as upserts (a rebuild of the mirror), in table order; batch seq from 1."""
    ops: list[dict[str, Any]] = []
    size, seq = 0, 0
    prefix = src + ":"
    for t in MIRROR_TABLES:
        cols, _ = _columns(conn, t)
        sel = ", ".join(cols)
        cur = conn.execute(f"SELECT {sel} FROM {t} WHERE source = ? OR substr(source, 1, ?) = ? ORDER BY rowid",
                           (src, len(prefix), prefix))
        for r in cur:
            row = dict(zip(cols, r, strict=True))
            for c in JSON_COLUMNS.get(t, ()):
                if isinstance(row.get(c), str):
                    row[c] = json.loads(row[c])
            ops.append({"op": "upsert", "table": t, "row": row})
            size += len(json.dumps(row, default=str))
            if len(ops) >= max_ops or size >= max_bytes:
                seq += 1
                yield seq, ops
                ops, size = [], 0
    if ops:
        seq += 1
        yield seq, ops
