"""engine.match: `engine/match.match_asset` on a read-only connection (rust ADR-0006).

persisted  the asset's `finding` rows are copied into a TEMP `finding` (the name resolves to TEMP first), the
           unchanged `match_asset` runs, and the asset's complete finding set comes back for the host to write.
           `based_on.latest_scan_id` lets the host detect a scan that landed in between (`stale`).
ephemeral  the inventory tables are shadowed by empty TEMP copies (`db.ephemeral_overlay`), the given inventory is
           saved into them and matched; nothing is returned for writing.
"""

from __future__ import annotations

from typing import Any

from ..common import inventory_from_dict
from ..db import read_session, shadow_table
from ..errors import WireError
from ..wire import Request
from . import TABLE

DEFAULT_VIEW = 500          # `ops.STORED_FINDINGS`: findings shown per target


def finding_set(conn, asset_id: str) -> list[dict[str, Any]]:
    """The (TEMP) finding rows of an asset as the contract's `finding` objects, in a stable order."""
    from secmonk.db import loads

    rows = conn.execute("SELECT * FROM temp.finding WHERE asset_id=? ORDER BY component_id, vuln_id",
                        (asset_id,)).fetchall()
    return [{"component_id": r["component_id"], "vuln_id": r["vuln_id"],
             "advisory_ids": loads(r["advisory_ids"], []) or [], "matched_by": r["matched_by"],
             "confidence": r["confidence"], "fixed_version": r["fixed_version"], "severity": r["severity"],
             "cvss_score": r["cvss_score"], "epss": r["epss"], "kev": bool(r["kev"]), "priority": r["priority"],
             "status": r["status"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
             "fixed_at": r["fixed_at"], "triage": r["triage"], "triage_source": r["triage_source"]}
            for r in rows]


@TABLE.unary("engine.match", {"mode": str, "asset_id?": str, "inventory?": dict, "min_confidence": float,
                              "view_limit?": int})
def match(ctx: Request, p: dict) -> dict:
    from secmonk import reports
    from secmonk.engine.match import match_asset

    mode, conf = p["mode"], float(p["min_confidence"])
    limit = p.get("view_limit", DEFAULT_VIEW)
    if not 0 <= conf <= 1:
        raise WireError("invalid-params", "min_confidence: expected 0..1")
    if not 0 <= limit <= 5000:
        raise WireError("invalid-params", "view_limit: expected 0..5000")
    if mode == "persisted":
        if "asset_id" not in p or "inventory" in p:
            raise WireError("invalid-params", "persisted match takes asset_id (and no inventory)")
        aid = p["asset_id"]
        with read_session(ctx.session, temp_writes=True) as (conn, _):
            from secmonk.engine import queries

            if not queries.asset_exists(conn, aid):
                raise WireError("unknown-asset", f"unknown asset {aid!r}")
            latest = conn.execute("SELECT MAX(id) FROM scan WHERE asset_id=?", (aid,)).fetchone()[0]
            synced = conn.execute("SELECT MAX(last_sync) FROM source_sync").fetchone()[0]
            shadow_table(conn, "finding", "asset_id=?", (aid,))
            ctx.check()
            stats = match_asset(conn, aid, min_confidence=conf)
            return {"asset_id": aid, "mode": mode, "stats": stats,
                    "based_on": {"latest_scan_id": latest, "mirror_synced_at": synced},
                    "finding_set": finding_set(conn, aid),
                    "view": reports.findings(conn, asset=aid, limit=limit) if limit else []}
    if mode == "ephemeral":
        if "inventory" not in p or "asset_id" in p:
            raise WireError("invalid-params", "ephemeral match takes inventory (and no asset_id)")
        from secmonk import db as dbm
        from secmonk.engine.inventory import save_inventory

        inv = inventory_from_dict(p["inventory"])
        with read_session(ctx.session, temp_writes=True) as (conn, _):
            dbm.ephemeral_overlay(conn)
            save_inventory(conn, inv)
            ctx.check()
            stats = match_asset(conn, inv.asset.id, min_confidence=conf)
            return {"asset_id": inv.asset.id, "mode": mode, "stats": stats,
                    "view": reports.findings(conn, asset=inv.asset.id, limit=limit) if limit else []}
    raise WireError("invalid-params", "mode: expected persisted or ephemeral")
