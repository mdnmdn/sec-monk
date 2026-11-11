"""py-sources: the staging adapter (rust ADR-0010). The decisive test applies the streamed row operations, as the host
would, to an empty mirror and compares it with the staging database the unchanged sources wrote."""

from __future__ import annotations

import json
import sqlite3
import time

from scripts import golden

from . import contracts, dbfactory

SYNCS = {c.id: c for c in golden.CASES if c.method == "source.sync" and c.id != "kev-missing-file"}
ROOTS = {"fixtures": str(dbfactory.FIX), "repo": str(dbfactory.REPO)}
JSON_COLS = {"data", "cwes", "extra", "events", "versions"}


def params(case_id: str, **opts):
    p = golden.expand(SYNCS[case_id].params, ROOTS)
    p["options"] = {**p["options"], **opts}
    return p


def new_mirror(path) -> sqlite3.Connection:
    """A mirror with the v2 mirror DDL (the v3 migrations when present)."""
    from secmonk import db as dbm

    tmp = sqlite3.connect(":memory:")
    tmp.executescript(dbm.SCHEMA)
    conn = sqlite3.connect(path)
    if dbfactory.uses_real_migrations():
        dbfactory._migrate(conn, "mirror")
    else:
        for stmt in dbfactory._v2_ddl(tmp, dbfactory.MIRROR_TABLES):
            conn.execute(stmt)
    conn.row_factory = sqlite3.Row
    return conn


def apply_ops(conn: sqlite3.Connection, ops: list[dict]) -> None:
    """The host's side of secmonk-mirror-rows/1: upsert by primary key, delete by key (one row for `affected`)."""
    for op in ops:
        t = op["table"]
        info = conn.execute(f"PRAGMA table_info({t})").fetchall()
        pk = [r[1] for r in sorted((r for r in info if r[5]), key=lambda r: r[5])]
        if op["op"] == "upsert":
            row = {k: (json.dumps(v, separators=(",", ":")) if k in JSON_COLS and v is not None else v)
                   for k, v in op["row"].items()}
            cols = ", ".join(row)
            marks = ", ".join("?" * len(row))
            if t == "affected":
                conn.execute(f"INSERT INTO {t}({cols}) VALUES ({marks})", list(row.values()))
            else:
                upd = ", ".join(f"{c}=excluded.{c}" for c in row if c not in pk)
                conflict = f"ON CONFLICT({', '.join(pk)}) DO UPDATE SET {upd}" if upd else "ON CONFLICT DO NOTHING"
                conn.execute(f"INSERT INTO {t}({cols}) VALUES ({marks}) {conflict}", list(row.values()))
        else:
            key = {k: (json.dumps(v, separators=(",", ":")) if k in JSON_COLS and v is not None else v)
                   for k, v in op["key"].items()}
            where = " AND ".join(f"{k} IS ?" for k in key)
            if t == "affected":
                conn.execute(f"DELETE FROM {t} WHERE rowid_ = (SELECT MIN(rowid_) FROM {t} WHERE {where})",
                             list(key.values()))
            else:
                conn.execute(f"DELETE FROM {t} WHERE {where}", list(key.values()))
    conn.commit()


def table_rows(conn: sqlite3.Connection, t: str) -> list[tuple]:
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({t})") if r[1] != "rowid_"]
    rows = [tuple(json.dumps(json.loads(v), sort_keys=True) if c in JSON_COLS and isinstance(v, str) else v
                  for c, v in zip(cols, r, strict=True))
            for r in conn.execute(f"SELECT {', '.join(cols)} FROM {t}")]
    return sorted(rows, key=lambda r: json.dumps(r, default=str))


def assert_same(mirror: sqlite3.Connection, staging_path) -> None:
    st = sqlite3.connect(staging_path)
    for t in dbfactory.MIRROR_TABLES:
        assert table_rows(mirror, t) == table_rows(st, t), f"table {t} differs"
    st.close()


def run_sync(cli, case_id: str, **opts):
    r = cli.request("source.sync", params(case_id, **opts), timeout=120).ok()
    for f in r.items:
        contracts.check("source/rows.schema.json", f)
    return r


def test_all_sources_replayed_on_an_empty_mirror_equal_the_staging_database(sources, tmp_path):
    mirror = new_mirror(tmp_path / "mirror.sqlite3")
    for case_id in SYNCS:
        r = run_sync(sources, case_id)
        assert r.result["entry"]["status"] in ("ok", "partial"), (case_id, r.result["entry"])
        for f in r.items:
            apply_ops(mirror, f["ops"])
        assert sources.request("source.ack", {"source": SYNCS[case_id].params["source"],
                                              "through_seq": r.result["last_seq"]}).ok()
    n = sum(mirror.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in dbfactory.MIRROR_TABLES)
    assert n > 100
    assert_same(mirror, sources.module_dir / "staging.sqlite3")


def test_second_sync_streams_deletes_and_updates(sources, tmp_path):
    """A replace-all source (kev) and merged `affected` rows (msrc): deletes and updates travel as operations."""
    mirror = new_mirror(tmp_path / "mirror.sqlite3")
    for case_id in ("kev", "msrc", "nvd", "kev", "msrc", "nvd"):
        r = run_sync(sources, case_id, full=True)
        for f in r.items:
            apply_ops(mirror, f["ops"])
        sources.request("source.ack", {"source": SYNCS[case_id].params["source"], "through_seq": r.result["last_seq"]})
    deletes = [o for o in r.items[0]["ops"] if o["op"] == "delete"] if r.items else []
    assert deletes, "re-importing a snapshot replaces rows: expected delete operations"
    assert_same(mirror, sources.module_dir / "staging.sqlite3")


def test_unacknowledged_batches_are_replayed_with_the_same_seq(sources):
    first = run_sync(sources, "kev")
    again = run_sync(sources, "kev", full=True)                  # not acknowledged: the first batches come first
    assert again.items[0]["seq"] == first.items[0]["seq"]
    assert again.items[0]["ops"] == first.items[0]["ops"]
    assert again.result["last_seq"] > first.result["last_seq"]
    sources.request("source.ack", {"source": "kev", "through_seq": again.result["last_seq"]}).ok()
    third = run_sync(sources, "kev", full=True)
    assert third.items[0]["seq"] > again.result["last_seq"]       # numbering never goes back
    con = sqlite3.connect(sources.module_dir / "staging.sqlite3")
    left = con.execute("SELECT COUNT(DISTINCT batch) FROM _sm_log WHERE batch <= ?", (again.result["last_seq"],))
    assert left.fetchone()[0] == 0


def test_ack_only_touches_its_source(sources):
    a, b = run_sync(sources, "kev"), run_sync(sources, "epss")
    sources.request("source.ack", {"source": "kev", "through_seq": a.result["last_seq"]}).ok()
    again = run_sync(sources, "epss", full=True)
    assert again.items[0]["seq"] == b.items[0]["seq"]


def test_a_failing_source_is_an_end_not_an_err(sources):
    case = golden.expand(golden.CASES[[c.id for c in golden.CASES].index("kev-missing-file")].params, ROOTS)
    r = sources.request("source.sync", case).ok()
    assert r.result["entry"]["status"] == "error" and r.result["entry"]["records"] == 0
    contracts.check("source/sync-end.schema.json", r.result)


def test_unknown_source_and_bad_options(sources):
    assert sources.request("source.sync", {"source": "nope", "options": {}}).error["code"] == "unknown-source"
    bad = sources.request("source.sync", {"source": "kev", "options": {"mystery": 1}})
    assert bad.error["code"] == "invalid-params"
    bad = sources.request("source.sync", {"source": "kev", "options": {"limit": 0}})
    assert bad.error["code"] == "invalid-params"
    bad = sources.request("source.sync", {"source": "kev", "options": {}, "secrets": {"token": "x"}})
    assert bad.error["code"] == "invalid-params"


def test_export_rebuilds_the_mirror(sources, tmp_path):
    for case_id in ("kev", "osv-zip", "euvd"):
        r = run_sync(sources, case_id)
        sources.request("source.ack", {"source": SYNCS[case_id].params["source"], "through_seq": r.result["last_seq"]})
    mirror = new_mirror(tmp_path / "rebuilt.sqlite3")
    for source in ("kev", "osv", "euvd"):
        e = sources.request("source.export", {"source": source, "through_seq": 0}).ok()
        for f in e.items:
            contracts.check("source/rows.schema.json", f)
            apply_ops(mirror, f["ops"])
    st = sqlite3.connect(sources.module_dir / "staging.sqlite3")
    for t in ("kev", "raw_record", "vulnerability", "alias", "affected", "source_sync"):
        assert table_rows(mirror, t) == table_rows(st, t), t


def test_cancel_stops_a_sync_and_keeps_staging_consistent(sources):
    """The progress hook is the cancel point: a cancelled run raises Cancelled inside the unchanged source."""
    rid = sources.start_request("source.sync", params("cvelist-record"))
    sources.send({"type": "cancel", "id": rid})
    r = sources.collect(rid, 60)
    assert r.error is None or r.error["code"] == "cancelled"     # tiny fixture: it may finish before the cancel lands
    again = run_sync(sources, "kev")
    assert again.result["entry"]["status"] == "ok"


def test_batches_respect_the_row_and_size_caps(sources, monkeypatch):
    from secmonk_modules.sources import staging

    con = staging.open_staging(sources.module_dir / "x" / "s.sqlite3")
    con.execute("UPDATE _sm_ctx SET src='t'")
    for i in range(12):
        con.execute("INSERT INTO kev(cve_id, vendor) VALUES (?, ?)", (f"CVE-2000-{i:04d}", "v" * 1000))
    con.commit()
    batches = list(staging.pending_batches(con, "t", max_ops=5, max_bytes=10**9))
    assert [len(b[1]) for b in batches] == [5, 5, 2]
    con2 = staging.open_staging(sources.module_dir / "x" / "s2.sqlite3")
    con2.execute("UPDATE _sm_ctx SET src='t'")
    for i in range(12):
        con2.execute("INSERT INTO kev(cve_id, vendor) VALUES (?, ?)", (f"CVE-2000-{i:04d}", "v" * 1000))
    con2.commit()
    assert all(len(b[1]) <= 4 for b in staging.pending_batches(con2, "t", max_ops=5000, max_bytes=3000))


def test_staging_file_is_private_and_inside_the_module_dir(sources):
    run_sync(sources, "kev")
    f = sources.module_dir / "staging.sqlite3"
    assert f.exists()
    import os
    import sys

    if sys.platform != "win32":
        assert os.stat(f).st_mode & 0o077 == 0
    assert not any(p.name == "forbidden.db" and p.exists() for p in f.parents[2].rglob("forbidden.db"))
    time.sleep(0)


# ---------------------------------------------------------------------------------------------- W4.4: generations

def test_batches_carry_the_staging_generation_and_what_was_acknowledged(sources):
    """Review M1: seqs are bound to the staging file; a recreated file is a new generation (seqs restart)."""
    first = run_sync(sources, "kev")
    gen = first.items[0]["generation"]
    assert len(gen) == 32 and all(b["generation"] == gen for b in first.items)
    assert all(b["acked_through"] == 0 for b in first.items)
    sources.request("source.ack", {"source": "kev", "through_seq": first.result["last_seq"]}).ok()
    again = run_sync(sources, "kev", full=True)
    assert again.items and all(b["generation"] == gen for b in again.items), "stable across opens"
    assert all(b["acked_through"] == first.result["last_seq"] for b in again.items)
    sources.request("source.ack", {"source": "kev", "through_seq": 1}).ok()       # an older ack never lowers it
    con = sqlite3.connect(sources.module_dir / "staging.sqlite3")
    assert con.execute("SELECT value FROM _sm_meta WHERE key='acked:kev'").fetchone()[0] == str(first.result["last_seq"])
    con.close()
    for f in sources.module_dir.glob("staging.sqlite3*"):                        # the file is recreated
        f.unlink()
    fresh = run_sync(sources, "kev")
    assert fresh.items[0]["generation"] != gen
    assert fresh.items[0]["seq"] == 1 and fresh.items[0]["acked_through"] == 0


def test_export_covers_every_change_up_to_its_high_water(sources, tmp_path):
    """Review M5: the repair applies the export, records `high_water` and acknowledges through it; no batch of the
    log may be newer than the exported state, so a later replay can only be skipped."""
    first = run_sync(sources, "kev")                                             # numbered, not acknowledged
    from secmonk_modules.sources import staging

    con = staging.open_staging(sources.module_dir / "staging.sqlite3")
    staging.set_source(con, "kev")
    con.execute("UPDATE kev SET vendor='changed' WHERE rowid = (SELECT MIN(rowid) FROM kev)")   # not numbered yet
    con.commit()
    staging.set_source(con, None)
    con.close()
    e = sources.request("source.export", {"source": "kev", "through_seq": 0}).ok()
    contracts.check("source/sync-end.schema.json", e.result)
    assert e.result["generation"] == first.items[0]["generation"]
    assert e.result["high_water"] > first.result["last_seq"], "the pending change was numbered first"
    mirror = new_mirror(tmp_path / "repaired.sqlite3")
    for f in e.items:
        contracts.check("source/rows.schema.json", f)
        apply_ops(mirror, f["ops"])
    sources.request("source.ack", {"source": "kev", "through_seq": e.result["high_water"]}).ok()
    con = sqlite3.connect(sources.module_dir / "staging.sqlite3")
    assert con.execute("SELECT COUNT(*) FROM _sm_log WHERE src='kev'").fetchone()[0] == 0
    con.close()
    st = sqlite3.connect(sources.module_dir / "staging.sqlite3")
    for t in ("kev", "raw_record", "source_sync"):
        assert table_rows(mirror, t) == table_rows(st, t), t
    nothing = run_sync(sources, "kev")                                           # same file: no change left
    assert nothing.items == [] or all(b["seq"] > e.result["high_water"] for b in nothing.items)
