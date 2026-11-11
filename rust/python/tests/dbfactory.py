"""Databases for tests: the schema of the host's store (v3: state + mirror files), built offline from fixtures.

The v3 migrations of `rust/crates/secmonk-store/migrations/` are used when present (the host's real DDL); otherwise the
schema-v2 DDL of `secmonk.db` is split into a state and a mirror file (v3 is a v2 superset, data-model.md rule R2).
Data is produced by the unchanged Python code (sources on fixtures, `save_inventory`, `match_asset`).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FIX = REPO / "tests" / "fixtures"
MIGRATIONS = REPO / "rust" / "crates" / "secmonk-store" / "migrations"
MIRROR_TABLES = ("source_sync", "raw_record", "vulnerability", "alias", "affected", "kev", "epss", "distro_triage")
STATE_TABLES = ("asset", "scan", "component", "asset_component", "finding", "job")

LOG4J = {"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "category": "library",
         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "ecosystem": "Maven"}


def uses_real_migrations() -> bool:
    return (MIGRATIONS / "state" / "sqlite").is_dir() and (MIGRATIONS / "mirror" / "sqlite").is_dir()


def build_v2(path: Path) -> sqlite3.Connection:
    """A v2 database (one file) holding mirror data from fixtures, one inventory and its findings."""
    from secmonk import db as dbm
    from secmonk.engine.inventory import save_inventory
    from secmonk.engine.match import match_asset
    from secmonk.models import Asset, Component, Inventory
    from secmonk.sources.base import SyncOptions
    from secmonk.sources.euvd import EuvdSource
    from secmonk.sources.kev import KevSource
    from secmonk.sources.osv import OsvSource

    conn = dbm.connect(path)
    src = FIX / "sources"
    KevSource().sync(conn, SyncOptions(path=src / "kev" / "known_exploited_vulnerabilities.json"))
    EuvdSource().sync(conn, SyncOptions(path=src / "euvd" / "exploited-sample.json"))
    OsvSource().sync(conn, SyncOptions(path=src / "osv" / "maven-GHSA-jfh8-c2jp-5v3q.json"))
    dbm.set_sync_state(conn, "kev", status="ok", records=9, cursor="2026.11.06", message="fixture")
    inv = Inventory(
        asset=Asset(id="dir:/srv/payments-api", type="directory", name="payments-api", meta={"env": "prod"}),
        collector="fs",
        components=[Component(**LOG4J), Component(name="left-pad", version="1.3.0", category="library",
                                                   purl="pkg:npm/left-pad@1.3.0", ecosystem="npm")],
        warnings=["synthetic fixture"])
    save_inventory(conn, inv)
    match_asset(conn, inv.asset.id, min_confidence=0.5)
    conn.commit()
    return conn


def _v2_ddl(v2: sqlite3.Connection, tables: tuple[str, ...]) -> list[str]:
    """CREATE statements (tables, then their indexes) of the v2 database for `tables`."""
    marks = ",".join("?" * len(tables))
    rows = v2.execute(f"SELECT sql FROM sqlite_master WHERE tbl_name IN ({marks}) AND sql IS NOT NULL "
                      "ORDER BY type = 'index', rowid", tables).fetchall()
    return [r[0] for r in rows]


def _migrate(conn: sqlite3.Connection, kind: str) -> None:
    for f in sorted((MIGRATIONS / kind / "sqlite").glob("*.sql")):
        conn.executescript(f.read_text())


def split_v3(v2: sqlite3.Connection, state: Path, mirror: Path) -> None:
    """Copy a v2 database into a state file and a mirror file."""
    for path, tables, kind in ((state, STATE_TABLES, "state"), (mirror, MIRROR_TABLES, "mirror")):
        dst = sqlite3.connect(path)
        if uses_real_migrations():
            _migrate(dst, kind)
        else:
            for stmt in _v2_ddl(v2, tables):
                dst.execute(stmt)
        for t in tables:
            cols = [r[1] for r in v2.execute(f"PRAGMA table_info({t})")]
            have = {r[1] for r in dst.execute(f"PRAGMA table_info({t})")}
            cols = [c for c in cols if c in have]
            rows = v2.execute(f"SELECT {','.join(cols)} FROM {t}").fetchall()
            dst.executemany(f"INSERT INTO {t}({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                            [tuple(r) for r in rows])
        if kind == "state" and "product" in {r[1] for r in dst.execute("PRAGMA table_info(component)")}:
            dst.execute("UPDATE component SET product=json_extract(meta,'$.product'), "
                        "product_source=json_extract(meta,'$.product_source'), bundle_id=json_extract(meta,'$.bundle_id')")
        dst.commit()
        dst.close()


def make_store(root: Path) -> dict[str, str]:
    """Build the standard test store under `root`; returns the `db_read` grant."""
    root.mkdir(parents=True, exist_ok=True)
    v2 = build_v2(root / "v2.sqlite3")
    split_v3(v2, root / "state.sqlite3", root / "mirror.sqlite3")
    v2.close()
    return {"state": str(root / "state.sqlite3"), "mirror": str(root / "mirror.sqlite3"), "uri_flags": "mode=ro"}
