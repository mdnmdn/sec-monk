"""Persist a collector `Inventory` into the asset/scan/component tables."""

from __future__ import annotations

import sqlite3

from ..db import dumps, now
from ..models import Inventory
from .classify import classify


def save_inventory(conn: sqlite3.Connection, inv: Inventory) -> int:
    """Upsert asset + components, record a scan. Returns the scan id.

    Components not seen in this scan keep their old `last_seen`, which is how removal is
    detected (asset_component.last_scan_id != latest scan).
    """
    ts = now()
    a = inv.asset
    conn.execute(
        """INSERT INTO asset(id,type,name,os_name,os_version,platform,meta,first_seen,last_seen)
           VALUES (?,?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET type=excluded.type, name=excluded.name,
             os_name=excluded.os_name, os_version=excluded.os_version, platform=excluded.platform,
             meta=excluded.meta, last_seen=excluded.last_seen""",
        (a.id, a.type, a.name, a.os_name, a.os_version, a.platform, dumps(a.meta), ts, ts),
    )
    cur = conn.execute(
        "INSERT INTO scan(asset_id, collector, started_at, finished_at, components, meta) VALUES (?,?,?,?,?,?)",
        (a.id, inv.collector, ts, ts, len(inv.components), dumps({"warnings": inv.warnings})),
    )
    scan_id = cur.lastrowid
    for c in inv.components:
        classify(c)
        conn.execute(
            """INSERT INTO component(key,name,version,category,ecosystem,purl,cpe,vendor,meta)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET category=excluded.category, ecosystem=excluded.ecosystem,
                 cpe=COALESCE(excluded.cpe, component.cpe), vendor=COALESCE(excluded.vendor, component.vendor),
                 meta=excluded.meta""",
            (c.key, c.name, c.version, c.category, c.ecosystem, c.purl, c.cpe, c.vendor, dumps(c.meta)),
        )
        comp_id = conn.execute("SELECT id FROM component WHERE key=?", (c.key,)).fetchone()[0]
        conn.execute(
            """INSERT INTO asset_component(asset_id, component_id, source_path, first_seen, last_seen, last_scan_id)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(asset_id, component_id) DO UPDATE SET source_path=excluded.source_path,
                 last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id""",
            (a.id, comp_id, c.source_path, ts, ts, scan_id),
        )
    conn.commit()
    return scan_id


def current_components(conn: sqlite3.Connection, asset_id: str) -> list[sqlite3.Row]:
    """Components present in the asset's latest scan."""
    return conn.execute(
        """SELECT c.*, ac.source_path FROM asset_component ac JOIN component c ON c.id = ac.component_id
           WHERE ac.asset_id = ? AND ac.last_scan_id = (SELECT MAX(id) FROM scan WHERE asset_id = ?)
           ORDER BY c.category, c.name""",
        (asset_id, asset_id),
    ).fetchall()
