"""Read-only SQL used by the CLI (kept out of cli.py so the presentation layer has no SQL)."""

from __future__ import annotations

import sqlite3

from .scoring import DEFERRED_TRIAGE, MINOR_TRIAGE

PRIORITIES = ("P1", "P2", "P3", "P4")

STATUS_TABLES = ("vulnerability", "alias", "affected", "kev", "epss", "asset", "component", "finding")


def asset_exists(conn: sqlite3.Connection, asset_id: str) -> bool:
    return conn.execute("SELECT 1 FROM asset WHERE id=?", (asset_id,)).fetchone() is not None


def source_status(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM source_sync ORDER BY source").fetchall()


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {n: conn.execute(f"SELECT COUNT(*) FROM {n}").fetchone()[0] for n in STATUS_TABLES}


# --------------------------------------------------------------------------- findings

def findings(conn: sqlite3.Connection, *, asset: str | None = None, priority: str | None = None,
             include_closed: bool = False, fixable: bool = False, hide_minor: bool = False,
             hide_deferred: bool = False, limit: int = 200) -> list[sqlite3.Row]:
    where: list[str] = []
    args: list[object] = []
    if asset:
        where.append("f.asset_id = ?")
        args.append(asset)
    if priority:
        where.append("f.priority = ?")
        args.append(priority.upper())
    if not include_closed:
        where.append("f.status = 'open'")
    if fixable:
        where.append("f.fixed_version IS NOT NULL")
    hidden: list[str] = []
    if hide_minor or hide_deferred:
        hidden += sorted(MINOR_TRIAGE)
    if hide_deferred:
        hidden += sorted(DEFERRED_TRIAGE)
    if hidden:
        where.append(f"(f.triage IS NULL OR f.triage NOT IN ({','.join('?' * len(hidden))}))")
        args.extend(hidden)
    sql = f"""SELECT f.*, c.name, c.version, c.category, c.ecosystem, c.purl FROM finding f JOIN component c ON c.id = f.component_id
              {'WHERE ' + ' AND '.join(where) if where else ''}
              ORDER BY f.priority, f.kev DESC, f.epss DESC, f.cvss_score DESC, f.vuln_id, c.name LIMIT ?"""
    return conn.execute(sql, (*args, limit)).fetchall()


def count_open_at_or_above(conn: sqlite3.Connection, asset: str, level: str) -> int:
    """Open findings of `asset` with priority <= level (P1 is the highest)."""
    levels = PRIORITIES[: PRIORITIES.index(level.upper()) + 1]
    return conn.execute(
        f"SELECT COUNT(*) FROM finding WHERE asset_id=? AND status='open' "
        f"AND priority IN ({','.join('?' * len(levels))})", (asset, *levels)).fetchone()[0]


def findings_for_vulns(conn: sqlite3.Connection, ids, limit: int = 500) -> list[sqlite3.Row]:
    """Findings (any status, any asset) whose canonical id is one of `ids`."""
    ph, a = _ph(ids)
    return conn.execute(f"""SELECT f.*, c.name, c.version, c.category, c.ecosystem, c.purl FROM finding f
                            JOIN component c ON c.id = f.component_id WHERE f.vuln_id IN ({ph})
                            ORDER BY f.status = 'open' DESC, f.priority, f.asset_id, c.name LIMIT ?""",
                        (*a, limit)).fetchall()


def open_finding_counts(conn: sqlite3.Connection) -> dict[str, dict[str, int]]:
    """{asset_id: {P1..P4: n, kev: n}} over open findings."""
    out: dict[str, dict[str, int]] = {}
    for r in conn.execute("""SELECT asset_id, priority, COUNT(*) n, SUM(kev) k FROM finding WHERE status='open'
                             GROUP BY asset_id, priority"""):
        d = out.setdefault(r["asset_id"], {**dict.fromkeys(PRIORITIES, 0), "kev": 0})
        if r["priority"] in d:
            d[r["priority"]] += r["n"]
        d["kev"] += r["k"] or 0
    return out


def count_open_fixable(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM finding WHERE status='open' AND fixed_version IS NOT NULL").fetchone()[0]


# --------------------------------------------------------------------------- inventory

def assets(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("""SELECT a.*,
              (SELECT components FROM scan WHERE asset_id=a.id ORDER BY id DESC LIMIT 1) n,
              (SELECT COUNT(*) FROM finding WHERE asset_id=a.id AND status='open') f
              FROM asset a ORDER BY a.id""").fetchall()


def asset(conn: sqlite3.Connection, asset_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM asset WHERE id=?", (asset_id,)).fetchone()


def scans(conn: sqlite3.Connection, asset_id: str, limit: int = 20) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM scan WHERE asset_id=? ORDER BY id DESC LIMIT ?", (asset_id, limit)).fetchall()


def unmatched(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("""SELECT name, version, category, json_extract(meta,'$.product') p,
                                  json_extract(meta,'$.bundle_id') b FROM component
                           WHERE json_extract(meta,'$.product_source') = 'normalized-name'
                           ORDER BY category, name""").fetchall()


# --------------------------------------------------------------------------- vulnerabilities

def _ph(ids) -> tuple[str, tuple]:
    ids = tuple(ids)
    return ",".join("?" * len(ids)), ids


def vulnerabilities(conn: sqlite3.Connection, ids) -> list[sqlite3.Row]:
    ph, a = _ph(ids)
    return conn.execute(f"SELECT * FROM vulnerability WHERE id IN ({ph}) ORDER BY source", a).fetchall()


def best_vulnerability(conn: sqlite3.Connection, vuln_id: str) -> sqlite3.Row | None:
    """The record of `vuln_id` with the highest CVSS score (any source), for one-line summaries."""
    return conn.execute("""SELECT summary, severity, cvss_score FROM vulnerability WHERE id=?
                           ORDER BY cvss_score IS NULL, cvss_score DESC, summary IS NULL LIMIT 1""",
                        (vuln_id,)).fetchone()


def kev_entry(conn: sqlite3.Connection, ids) -> sqlite3.Row | None:
    ph, a = _ph(ids)
    return conn.execute(f"SELECT * FROM kev WHERE cve_id IN ({ph})", a).fetchone()


def epss_entry(conn: sqlite3.Connection, ids) -> sqlite3.Row | None:
    ph, a = _ph(ids)
    return conn.execute(f"SELECT * FROM epss WHERE cve_id IN ({ph})", a).fetchone()


def affected_for(conn: sqlite3.Connection, ids, limit: int = 60) -> list[sqlite3.Row]:
    ph, a = _ph(ids)
    return conn.execute(f"SELECT * FROM affected WHERE vuln_id IN ({ph}) LIMIT {int(limit)}", a).fetchall()


def raw_records(conn: sqlite3.Connection, ids) -> list[sqlite3.Row]:
    ph, a = _ph(ids)
    return conn.execute(f"SELECT source, data FROM raw_record WHERE record_id IN ({ph})", a).fetchall()


def affected_search(conn: sqlite3.Connection, *, package: str | None, ecosystem: str | None,
                    product: str | None, cap: int = 5000) -> list[sqlite3.Row]:
    """`package` must already be normalized for `ecosystem`."""
    where, args = [], []
    if package:
        where.append("package = ?")
        args.append(package)
    if ecosystem:
        where.append("ecosystem = ?")
        args.append(ecosystem)
    if product:
        where.append("product = ?")
        args.append(product.lower())
    sql = f"SELECT * FROM affected WHERE {' AND '.join(where)} LIMIT {int(cap)}"
    return conn.execute(sql, args).fetchall()
