"""secmonk command line. See _docs/features/cli.md."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import db as dbm

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="sec-monk — holistic vulnerability scanner prototype")
vuln_app = typer.Typer(no_args_is_help=True, help="Query the local vulnerability mirror")
inv_app = typer.Typer(no_args_is_help=True, help="Inspect collected inventories")
app.add_typer(vuln_app, name="vuln")
app.add_typer(inv_app, name="inventory")

console = Console()
DbOpt = Annotated[Path | None, typer.Option("--db", envvar="SECMONK_DB", help="SQLite file")]


def _conn(db: Path | None):
    return dbm.connect(db or dbm.default_db_path())


def _sources():
    from . import sources  # noqa: F401  (registers)
    from .sources.base import REGISTRY
    return REGISTRY


def _collectors():
    from . import collectors  # noqa: F401  (registers)
    from .collectors.base import REGISTRY
    return REGISTRY


# --------------------------------------------------------------------------- db / status

@app.command()
def status(db: DbOpt = None):
    """Show mirror freshness and table sizes."""
    conn = _conn(db)
    t = Table(title="Sources")
    for col in ("source", "last_sync", "records", "status", "cursor", "message"):
        t.add_column(col)
    for r in conn.execute("SELECT * FROM source_sync ORDER BY source"):
        t.add_row(r["source"], r["last_sync"] or "", str(r["records"]), r["status"] or "",
                  (r["cursor"] or "")[:28], (r["message"] or "")[:60])
    console.print(t)
    t = Table(title="Tables")
    t.add_column("table")
    t.add_column("rows", justify="right")
    for name in ("vulnerability", "alias", "affected", "kev", "epss", "asset", "component", "finding"):
        t.add_row(name, f"{conn.execute(f'SELECT COUNT(*) FROM {name}').fetchone()[0]:,}")
    console.print(t)


# --------------------------------------------------------------------------- sync

@app.command("sources")
def list_sources():
    """List available vulnerability sources."""
    for name, cls in sorted(_sources().items()):
        console.print(f"[bold]{name:10}[/] {cls.description}")


@app.command()
def sync(
    names: Annotated[list[str], typer.Argument(help="Sources to sync, or 'all'")],
    path: Annotated[Path | None, typer.Option(help="Import from local file/dir instead of downloading")] = None,
    ecosystem: Annotated[list[str] | None, typer.Option("--ecosystem", "-e", help="OSV ecosystems")] = None,
    ids: Annotated[list[str] | None, typer.Option("--id", help="Specific record ids ('@referenced' "
                                                                  "for cvelist)")] = None,
    since: Annotated[str | None, typer.Option(help="Only records modified since (ISO date / year)")] = None,
    full: Annotated[bool, typer.Option(help="Ignore stored delta cursor")] = False,
    limit: Annotated[int | None, typer.Option(help="Max records (debug)")] = None,
    api_key: Annotated[str | None, typer.Option(envvar="NVD_API_KEY", help="NVD API key")] = None,
    db: DbOpt = None,
):
    """Fetch vulnerability data into the local mirror."""
    from .sources.base import SyncOptions

    reg = _sources()
    if names == ["all"]:
        names = [n for n in ("kev", "epss", "osv", "cvelist", "nvd", "euvd") if n in reg]
    conn = _conn(db)
    for name in names:
        if name not in reg:
            console.print(f"[red]unknown source {name}[/] (known: {', '.join(sorted(reg))})")
            raise typer.Exit(2)
        opts = SyncOptions(path=path, ecosystems=ecosystem or [], ids=ids or [], since=since, full=full,
                           limit=limit, api_key=api_key, progress=lambda m: console.log(m))
        t0 = time.monotonic()
        with console.status(f"syncing {name}…"):
            try:
                res = reg[name]().sync(conn, opts)
            except Exception as e:  # noqa: BLE001  # keep the CLI alive for the remaining sources
                from .sources.base import SyncResult
                res = SyncResult(name, status="error", message=f"{type(e).__name__}: {e}")
        dbm.set_sync_state(conn, name, status=res.status, records=res.records, cursor=res.cursor,
                           message=res.message)
        colour = {"ok": "green", "partial": "yellow"}.get(res.status, "red")
        console.print(f"[{colour}]{name}: {res.status}[/] {res.records:,} records "
                      f"in {time.monotonic() - t0:.1f}s {res.message or ''}")


# --------------------------------------------------------------------------- vuln queries

@vuln_app.command("show")
def vuln_show(vuln_id: str, db: DbOpt = None, raw: bool = typer.Option(False, help="Print raw records")):
    """Everything known about a vulnerability id (CVE, GHSA, OSV, EUVD…) across sources."""
    from .engine.match import _canonical

    conn = _conn(db)
    canon, ids = _canonical(conn, vuln_id)
    console.print(f"[bold]{canon}[/] aliases: {', '.join(sorted(ids - {canon})) or '-'}")
    ph = ",".join("?" * len(ids))
    for r in conn.execute(f"SELECT * FROM vulnerability WHERE id IN ({ph}) ORDER BY source", tuple(ids)):
        console.print(f"  [cyan]{r['source']:8}[/] {r['id']:24} {r['severity'] or '':9} "
                      f"{r['cvss_score'] if r['cvss_score'] is not None else '':5} "
                      f"{(r['summary'] or '')[:90]}")
    k = conn.execute(f"SELECT * FROM kev WHERE cve_id IN ({ph})", tuple(ids)).fetchone()
    if k:
        console.print(f"  [red]KEV[/] added {k['date_added']} due {k['due_date']} ransomware={k['ransomware']}")
    e = conn.execute(f"SELECT * FROM epss WHERE cve_id IN ({ph})", tuple(ids)).fetchone()
    if e:
        console.print(f"  EPSS {e['score']:.4f} (pct {e['percentile'] or 0:.3f}) {e['date'] or ''}")
    t = Table(title="Affected")
    for col in ("source", "ecosystem/vendor", "package/product", "type", "ranges / versions"):
        t.add_column(col)
    for r in conn.execute(f"SELECT * FROM affected WHERE vuln_id IN ({ph}) LIMIT 60", tuple(ids)):
        rng = r["events"] or r["versions"] or ""
        t.add_row(r["source"], r["ecosystem"] or r["vendor"] or "", r["package"] or r["product"] or "",
                  r["range_type"] or "", rng[:80])
    console.print(t)
    if raw:
        for r in conn.execute(f"SELECT source, data FROM raw_record WHERE record_id IN ({ph})", tuple(ids)):
            console.rule(r["source"])
            console.print_json(r["data"])


@vuln_app.command("search")
def vuln_search(
    package: Annotated[str | None, typer.Option(help="Package name (OSV)")] = None,
    ecosystem: Annotated[str | None, typer.Option(help="OSV ecosystem, e.g. PyPI, Debian:12")] = None,
    product: Annotated[str | None, typer.Option(help="Product name (CVE/NVD)")] = None,
    version: Annotated[str | None, typer.Option(help="Only advisories affecting this version")] = None,
    limit: int = 50,
    db: DbOpt = None,
):
    """Find advisories for a package or product (optionally a specific version)."""
    from .db import loads
    from .engine.purl import normalize_name
    from .engine.versions import in_osv_range, scheme_for_ecosystem

    conn = _conn(db)
    where, args = [], []
    if package:
        where.append("package = ?")
        args.append(normalize_name(ecosystem, package))
    if ecosystem:
        where.append("ecosystem = ?")
        args.append(ecosystem)
    if product:
        where.append("product = ?")
        args.append(product.lower())
    if not where:
        raise typer.BadParameter("give --package and/or --product")
    rows = conn.execute(f"SELECT * FROM affected WHERE {' AND '.join(where)} LIMIT 5000", args).fetchall()
    n = 0
    for r in rows:
        events, versions = loads(r["events"], []), loads(r["versions"], [])
        if version:
            scheme = scheme_for_ecosystem(r["ecosystem"])
            if not (version in versions or (events and in_osv_range(version, events, scheme))):
                continue
        console.print(f"{r['vuln_id']:28} {r['source']:8} {r['ecosystem'] or r['vendor'] or '':14} "
                      f"{r['package'] or r['product']:24} {(r['events'] or r['versions'] or '')[:70]}")
        n += 1
        if n >= limit:
            break
    console.print(f"[dim]{n} result(s)[/]")


# --------------------------------------------------------------------------- collect / scan

OptsOpt = Annotated[list[str] | None, typer.Option(
    "--opt", "-o", help="Collector option key=value (repeatable), e.g. -o use_brew_cli=true -o platform=linux/arm64")]


def _parse_opts(items: list[str] | None) -> dict:
    out: dict = {}
    for item in items or []:
        key, sep, val = item.partition("=")
        if not sep:
            raise typer.BadParameter(f"expected key=value, got {item!r}")
        low = val.lower()
        if low in ("true", "yes", "1", "false", "no", "0"):
            out[key] = low in ("true", "yes", "1")
        elif "," in val:
            out[key] = [v for v in val.split(",") if v]
        else:
            out[key] = val
    return out


def _collect(collector: str, target: str | None, opts: dict):
    reg = _collectors()
    if collector not in reg:
        console.print(f"[red]unknown collector {collector}[/] (known: {', '.join(sorted(reg))})")
        raise typer.Exit(2)
    return reg[collector]().collect(target, **opts)


@app.command("collectors")
def list_collectors():
    """List available inventory collectors."""
    for name, cls in sorted(_collectors().items()):
        console.print(f"[bold]{name:14}[/] {cls.description}")


def _print_inventory(inv) -> None:
    t = Table(title=f"{inv.asset.id} — {len(inv.components)} components")
    for col in ("category", "name", "version", "ecosystem / vendor", "purl / cpe"):
        t.add_column(col, overflow="fold")
    for c in sorted(inv.components, key=lambda c: (c.category, c.name.lower())):
        t.add_row(c.category, c.name, c.version or "", c.ecosystem or c.vendor or "", c.purl or c.cpe or "")
    console.print(t)
    for w in inv.warnings:
        console.print(f"[yellow]warning:[/] {w}")


@app.command()
def collect(
    collector: Annotated[str, typer.Argument(help="macos | docker-image | docker-engine | rootfs …")],
    target: Annotated[str | None, typer.Argument(help="Collector target (root dir, image ref, tar…)")] = None,
    save: Annotated[bool, typer.Option(help="Store the inventory in the DB")] = True,
    output: Annotated[Path | None, typer.Option("--json", help="Write inventory JSON here")] = None,
    quiet: bool = False,
    opt: OptsOpt = None,
    db: DbOpt = None,
):
    """Discover installed software (no matching)."""
    from dataclasses import asdict

    from .engine.classify import classify
    from .engine.inventory import save_inventory

    inv = _collect(collector, target, _parse_opts(opt))
    for c in inv.components:
        classify(c)
    if not quiet:
        _print_inventory(inv)
    if output:
        output.write_text(json.dumps(asdict(inv), indent=2, default=str))
        console.print(f"wrote {output}")
    if save:
        scan_id = save_inventory(_conn(db), inv)
        console.print(f"saved asset [bold]{inv.asset.id}[/] (scan {scan_id})")


@app.command()
def scan(
    collector: str,
    target: Annotated[str | None, typer.Argument()] = None,
    min_confidence: float = typer.Option(0.5, help="Drop name-based matches below this"),
    opt: OptsOpt = None,
    db: DbOpt = None,
):
    """collect + save + match, then print findings."""
    from .engine.classify import classify
    from .engine.inventory import save_inventory
    from .engine.match import match_asset

    conn = _conn(db)
    inv = _collect(collector, target, _parse_opts(opt))
    for c in inv.components:
        classify(c)
    save_inventory(conn, inv)
    stats = match_asset(conn, inv.asset.id, min_confidence=min_confidence)
    console.print(f"{inv.asset.id}: {stats}")
    findings(asset=inv.asset.id, db=db)


@app.command()
def match(asset: str, min_confidence: float = 0.5, db: DbOpt = None):
    """(Re)match a stored asset against the current mirror."""
    from .engine.match import match_asset

    console.print(match_asset(_conn(db), asset, min_confidence=min_confidence))


@app.command()
def findings(
    asset: Annotated[str | None, typer.Argument()] = None,
    priority: Annotated[str | None, typer.Option(help="P1..P4")] = None,
    all_: Annotated[bool, typer.Option("--all", help="Include fixed/suppressed")] = False,
    limit: int = 200,
    db: DbOpt = None,
):
    """List findings ordered by priority."""
    conn = _conn(db)
    where, args = [], []
    if asset:
        where.append("f.asset_id = ?")
        args.append(asset)
    if priority:
        where.append("f.priority = ?")
        args.append(priority.upper())
    if not all_:
        where.append("f.status = 'open'")
    sql = f"""SELECT f.*, c.name, c.version, c.category FROM finding f JOIN component c ON c.id = f.component_id
              {'WHERE ' + ' AND '.join(where) if where else ''}
              ORDER BY f.priority, f.kev DESC, f.epss DESC, f.cvss_score DESC LIMIT ?"""
    t = Table(title="Findings")
    for col in ("prio", "vuln", "component", "version", "fix", "sev", "cvss", "epss", "kev", "match", "conf"):
        t.add_column(col, overflow="fold")
    rows = conn.execute(sql, (*args, limit)).fetchall()
    for r in rows:
        t.add_row(r["priority"], r["vuln_id"], r["name"], r["version"] or "", r["fixed_version"] or "",
                  r["severity"] or "", f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "",
                  f"{r['epss']:.3f}" if r["epss"] is not None else "", "✔" if r["kev"] else "",
                  r["matched_by"], f"{r['confidence']:.1f}")
    console.print(t)


# --------------------------------------------------------------------------- inventory queries

@inv_app.command("assets")
def inv_assets(db: DbOpt = None):
    """List assets."""
    conn = _conn(db)
    t = Table()
    for col in ("id", "type", "os", "platform", "last_seen", "components", "open findings"):
        t.add_column(col)
    for r in conn.execute("""SELECT a.*,
              (SELECT components FROM scan WHERE asset_id=a.id ORDER BY id DESC LIMIT 1) n,
              (SELECT COUNT(*) FROM finding WHERE asset_id=a.id AND status='open') f FROM asset a"""):
        t.add_row(r["id"], r["type"], f"{r['os_name'] or ''} {r['os_version'] or ''}", r["platform"] or "",
                  r["last_seen"], str(r["n"] or 0), str(r["f"]))
    console.print(t)


@inv_app.command("show")
def inv_show(asset: str, category: str | None = None, db: DbOpt = None):
    """Components of an asset (latest scan)."""
    from .engine.inventory import current_components

    t = Table(title=asset)
    for col in ("category", "name", "version", "ecosystem / vendor", "purl / cpe", "path"):
        t.add_column(col, overflow="fold")
    for r in current_components(_conn(db), asset):
        if category and r["category"] != category:
            continue
        t.add_row(r["category"], r["name"], r["version"] or "", r["ecosystem"] or r["vendor"] or "",
                  r["purl"] or r["cpe"] or "", r["source_path"] or "")
    console.print(t)


@inv_app.command("unmatched")
def inv_unmatched(db: DbOpt = None):
    """Applications whose product identity is only a normalized name (alias-table candidates)."""
    conn = _conn(db)
    for r in conn.execute("""SELECT name, version, category, json_extract(meta,'$.product') p,
                                    json_extract(meta,'$.bundle_id') b FROM component
                             WHERE json_extract(meta,'$.product_source') = 'normalized-name'
                             ORDER BY category, name"""):
        console.print(f"{r['category']:12} {r['name']:40} {r['version'] or '':16} product={r['p']} {r['b'] or ''}")


if __name__ == "__main__":
    app()
