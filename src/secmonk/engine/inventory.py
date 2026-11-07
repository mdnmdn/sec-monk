"""Persist a collector `Inventory` into the asset/scan/component tables."""

from __future__ import annotations

import sqlite3

from ..db import dumps, now
from ..models import Inventory
from .classify import classify


def save_inventory(conn: sqlite3.Connection, inv: Inventory) -> int:
    """Upsert asset + components, record a scan. Returns the scan id.

    Components not seen in this scan keep their old `last_seen`, which is how removal is
    detected: a component is current when `last_scan_id >=` the latest *complete* scan.

    A partial inventory (`inv.partial`, e.g. an aborted SSH stream or skipped layers) is recorded
    with `scan.meta.partial = true` and its components are upserted, but it does not become the
    reference for removal: whatever the last complete scan saw stays current. See
    _docs/tech/data-model.md ("Partial scans").
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
        (a.id, inv.collector, ts, ts, len(inv.components), dumps(_scan_meta(inv))),
    )
    scan_id = cur.lastrowid
    # Several copies of the same component on one asset (two Foo.app bundles, a library in two
    # venvs) share a key: keep one row per asset+component with *all* their paths.
    grouped: dict[str, tuple] = {}
    for c in inv.components:
        classify(c)
        paths = [p for p in ([c.source_path] + list(c.meta.get("paths") or [])) if p]
        if c.key in grouped:
            _, all_paths = grouped[c.key]
            all_paths.extend(p for p in paths if p not in all_paths)
        else:
            grouped[c.key] = (c, list(dict.fromkeys(paths)))
    for c, paths in grouped.values():
        conn.execute(
            """INSERT INTO component(key,name,version,category,ecosystem,purl,cpe,vendor,meta)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET category=excluded.category, ecosystem=excluded.ecosystem,
                 cpe=COALESCE(excluded.cpe, component.cpe), vendor=COALESCE(excluded.vendor, component.vendor),
                 meta=excluded.meta""",
            (c.key, c.name, c.version, c.category, c.ecosystem, c.purl, c.cpe, c.vendor, dumps(c.meta)),
        )
        comp_id = conn.execute("SELECT id FROM component WHERE key=?", (c.key,)).fetchone()[0]
        # component.meta is shared by every asset with this key (identity facts used for matching);
        # asset_component.meta keeps this asset's own view (users, install location, scope…).
        conn.execute(
            """INSERT INTO asset_component(asset_id, component_id, source_path, first_seen, last_seen,
                                           last_scan_id, paths, meta)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(asset_id, component_id) DO UPDATE SET source_path=excluded.source_path,
                 last_seen=excluded.last_seen, last_scan_id=excluded.last_scan_id,
                 paths=excluded.paths, meta=excluded.meta""",
            (a.id, comp_id, paths[0] if paths else c.source_path, ts, ts, scan_id, dumps(paths), dumps(c.meta)),
        )
    conn.commit()
    return scan_id


def _scan_meta(inv: Inventory) -> dict:
    meta: dict = {"warnings": inv.warnings}
    if inv.partial:
        meta["partial"] = True
        meta["partial_reason"] = inv.partial_reason
    return meta


def current_components(conn: sqlite3.Connection, asset_id: str) -> list[sqlite3.Row]:
    """Components currently present on the asset.

    Reference point is the latest non-partial scan: everything seen in it or in any later (partial)
    scan is current; components only seen in older scans were removed. With no complete scan at all,
    everything ever seen is returned.
    """
    return conn.execute(
        """SELECT c.*, ac.source_path, ac.paths, ac.meta AS asset_meta FROM asset_component ac JOIN component c ON c.id = ac.component_id
           WHERE ac.asset_id = ? AND ac.last_scan_id >= COALESCE(
               (SELECT MAX(id) FROM scan WHERE asset_id = ?
                  AND COALESCE(json_extract(meta, '$.partial'), 0) = 0), 0)
           ORDER BY c.category, c.name""",
        (asset_id, asset_id),
    ).fetchall()
