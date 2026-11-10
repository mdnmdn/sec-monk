"""secmonk command line. Command reference: _docs/features/README.md (CLI at a glance);
scan/match/findings contract: _docs/features/scan-and-findings.md.

Exit codes: 0 ok; 1 runtime error (unknown asset, missing database, collector failure, a sync source
that failed); 2 usage error (unknown source/collector, bad option); 3 `scan --fail-on` threshold hit.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import logging
import os
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from . import db as dbm
from . import ops, paths, reports
from .engine import queries
from .errors import COLLECT_ERRORS

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="sec-monk — holistic vulnerability scanner prototype")
vuln_app = typer.Typer(no_args_is_help=True, help="Query the local vulnerability mirror")
inv_app = typer.Typer(no_args_is_help=True, help="Inspect collected inventories")
history_app = typer.Typer(help="Past scan and sync runs (CLI and web UI) with their results")
app.add_typer(vuln_app, name="vuln")
app.add_typer(inv_app, name="inventory")
app.add_typer(history_app, name="history")

console = Console(emoji=False, highlight=False)
err_console = Console(stderr=True, emoji=False, highlight=False)
_state = SimpleNamespace(verbose=False, quiet=False)


class Fmt(str, Enum):
    table = "table"
    json = "json"
    csv = "csv"


DbOpt = Annotated[Path | None, typer.Option(
    "--db", help="SQLite file (default: $SECMONK_DB or the per-user data dir; see README)")]
FmtOpt = Annotated[Fmt, typer.Option("--format", "-f", help="Output format: table, json or csv")]
LimitOpt = Annotated[int, typer.Option("--limit", "-n", min=1, help="Maximum rows")]

# shared with the web UI's jobs (ops.py)
SYNC_ALL_ORDER, BOOL_OPTS, LIST_OPTS = ops.SYNC_ALL_ORDER, ops.BOOL_OPTS, ops.LIST_OPTS



@app.callback()
def _root(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging and tracebacks")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only results and errors")] = False,
) -> None:
    _state.verbose, _state.quiet = verbose, quiet
    if verbose:
        logging.basicConfig(level=logging.DEBUG, force=True)


# --------------------------------------------------------------------------- helpers

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(v: object) -> str:
    return "" if v is None else _CTRL.sub("", str(v))


def _e(v: object) -> str:
    """Untrusted value -> safe inside a rich markup string."""
    return escape(_clean(v))


def _t(v: object, **kw: Any) -> Text:
    """Untrusted value -> markup-free Text cell."""
    return Text(_clean(v), **kw)


def _info(msg: str, fmt: Fmt = Fmt.table) -> None:
    """Informational line: hidden by --quiet, on stderr when stdout carries json/csv."""
    if not _state.quiet:
        (console if fmt is Fmt.table else err_console).print(msg)


def _fail(msg: str, code: int = 1) -> typer.Exit:
    err_console.print(f"[red]{msg}[/]")
    return typer.Exit(code)


def _traceback() -> None:
    if _state.verbose:
        err_console.print_exception()


def _print(renderable: Any) -> None:
    # piped output must not be truncated to 80 columns
    (console if console.is_terminal else Console(width=250, emoji=False, highlight=False)).print(renderable)


def _emit(rows: list[dict], columns: list[str], fmt: Fmt, *, title: str | None = None,
          cell: dict[str, Callable[[Any], str]] | None = None, right: tuple[str, ...] = ()) -> None:
    """Render rows (dicts of raw values) as a table, JSON or CSV on stdout."""
    if fmt is Fmt.json:
        typer.echo(json.dumps(rows, indent=2, default=str))
    elif fmt is Fmt.csv:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in columns})
        typer.echo(buf.getvalue(), nl=False)
    else:
        t = Table(title=_t(title) if title else None)
        for col in columns:
            t.add_column(col, overflow="fold", justify="right" if col in right else "left")
        for r in rows:
            t.add_row(*[_t((cell or {}).get(c, _plain)(r.get(c))) for c in columns])
        _print(t)


def _plain(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "✔" if v else ""
    return str(v)


def _db_path(db: Path | None) -> Path:
    return db or paths.default_db_path()


@contextlib.contextmanager
def _open(db: Path | None, *, create: bool = False) -> Iterator[sqlite3.Connection]:
    """Open the DB and always close it. Read-only commands refuse to create an empty database."""
    p = _db_path(db)
    if not create and not p.exists():
        raise _fail(f"no database at {p} — run `secmonk sync …` first")
    try:
        if create:
            if db is None:
                paths.ensure_private_dir(p.parent)
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
        conn = dbm.connect(p)
    except PermissionError as e:
        raise _fail(_denied_db_hint(e)) from None
    try:
        yield conn
    finally:
        conn.close()


def _denied_db_hint(e: PermissionError) -> str:
    msg = f"cannot use the database: {e}"
    if hasattr(os, "geteuid") and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        msg += (" — under sudo HOME still points to the invoking user's state; use `sudo -H` (root's own state), "
                "`--db <path>`, or take a snapshot as root (`--no-match --snapshot-out snap.json`) and analyse it as "
                "yourself (`secmonk procs snap.json`)")
    return msg


def _db_denied(db: Path | None) -> PermissionError | None:
    """The default database folder exists but belongs to someone else (typically root running under `sudo`)."""
    p = _db_path(db)
    if db is not None or p != paths.default_db_path():
        return None
    try:
        paths.ensure_private_dir(p.parent)
    except PermissionError as e:
        return e
    return None


def _require_asset(conn: sqlite3.Connection, asset: str) -> None:
    if not queries.asset_exists(conn, asset):
        raise _fail(f"unknown asset {asset!r} — see `secmonk inventory assets`")


def _check_priority(v: str | None) -> str | None:
    if v is None:
        return None
    if v.upper() not in queries.PRIORITIES:
        raise typer.BadParameter(f"expected one of {', '.join(queries.PRIORITIES)}")
    return v.upper()


PrioOpt = Annotated[str | None, typer.Option("--priority", callback=_check_priority, help="Only P1..P4")]


def _sources():
    return ops.sources_registry()


def _collectors():
    return ops.collectors_registry()


# --------------------------------------------------------------------------- db / status

@app.command()
def status(db: DbOpt = None, fmt: FmtOpt = Fmt.table):
    """Show mirror freshness and table sizes."""
    with _open(db) as conn:
        payload = reports.status_payload(conn, _db_path(db))
    if fmt is Fmt.json:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    srcs, counts = payload["sources"], payload["tables"]
    cols = ["source", "last_sync", "records", "status", "cursor", "message"]
    if fmt is Fmt.csv:
        _emit(srcs, cols, fmt)
        return
    _emit([{**r, "cursor": (r["cursor"] or "")[:28], "message": (r["message"] or "")[:60]} for r in srcs],
          cols, fmt, title=f"Sources ({_db_path(db)})")
    _emit([{"table": k, "rows": f"{v:,}"} for k, v in counts.items()], ["table", "rows"], fmt,
          title="Tables", right=("rows",))


# --------------------------------------------------------------------------- sync

@app.command("sources")
def list_sources():
    """List available vulnerability sources."""
    for name, cls in sorted(_sources().items()):
        extra = "" if getattr(cls, "in_all", True) else " (not in `sync all`)"
        console.print(f"[bold]{name:15}[/] {_e(cls.description)}{extra}")


def _expand_sources(names: list[str], reg: dict) -> list[str]:
    return ops.expand_sources(names, reg)


@app.command()
def sync(
    names: Annotated[list[str], typer.Argument(help="Sources to sync (see `secmonk sources`), or 'all'")],
    path: Annotated[Path | None, typer.Option(help="Import from local file/dir instead of downloading")] = None,
    ecosystem: Annotated[list[str] | None, typer.Option("--ecosystem", "-e", help="OSV ecosystems")] = None,
    ids: Annotated[list[str] | None, typer.Option("--id", help="Specific record ids ('@referenced' "
                                                                  "for cvelist)")] = None,
    since: Annotated[str | None, typer.Option(help="Only records modified since (ISO date / year)")] = None,
    full: Annotated[bool, typer.Option(help="Ignore stored delta cursor")] = False,
    limit: Annotated[int | None, typer.Option("--limit", "-n", help="Max records (debug)")] = None,
    api_key: Annotated[str | None, typer.Option(envvar="NVD_API_KEY", help="NVD API key")] = None,
    db: DbOpt = None,
):
    """Fetch vulnerability data into the local mirror.

    Exit code 1 if any source failed (status error); a partial sync exits 0 with a yellow note.
    """
    from .sources.base import SyncOptions

    reg = _sources()
    todo = _expand_sources(names, reg)
    unknown = [n for n in todo if n not in reg]
    if unknown:
        raise _fail(f"unknown source {', '.join(unknown)} (known: {', '.join(sorted(reg))})", 2)
    failed, partial, results = [], [], []
    params = {"sources": todo, "ecosystems": ecosystem or [], "ids": ids or [], "since": since, "full": full,
              "limit": limit, "path": str(path) if path else None}
    with _open(db, create=True) as conn, \
            ops.record_run(_db_path(db), "sync", "cli", ops.sync_title(todo), params) as run:
        for name in todo:
            opts = SyncOptions(path=path, ecosystems=ecosystem or [], ids=ids or [], since=since, full=full,
                               limit=limit, api_key=api_key,
                               progress=None if _state.quiet else (lambda m: err_console.log(_t(m))))
            with err_console.status(f"syncing {name}…"):
                # an exception becomes status 'error' (the CLI keeps going with the remaining sources)
                res, secs = ops.sync_source(conn, name, reg[name], opts, on_exception=lambda e: _traceback())
            colour = {"ok": "green", "partial": "yellow"}.get(res.status, "red")
            console.print(f"[{colour}]{_e(name)}: {_e(res.status)}[/] {res.records:,} records "
                          f"in {secs:.1f}s {_e(res.message)}")
            run.say(f"{name}: {res.status} — {res.records:,} records in {secs:.1f}s {res.message or ''}".rstrip())
            results.append(ops.sync_entry(name, res, secs))
            if res.status == "error":
                failed.append(name)
            elif res.status == "partial":
                partial.append(name)
        run.finish(ops.sync_status(results), {"sources": results})
    if partial:
        err_console.print(f"[yellow]partial: {', '.join(partial)} (data kept; rerun to complete)[/]")
    if failed:
        raise _fail(f"failed: {', '.join(failed)}")


# --------------------------------------------------------------------------- vuln queries

@vuln_app.command("show")
def vuln_show(
    vuln_id: Annotated[str, typer.Argument(help="CVE / GHSA / OSV / EUVD … id")],
    db: DbOpt = None,
    raw: Annotated[bool, typer.Option(help="Print raw records")] = False,
    fmt: Annotated[Fmt, typer.Option("--format", "-f", help="Output format: table or json")] = Fmt.table,
):
    """Everything known about a vulnerability id (CVE, GHSA, OSV, EUVD…) across sources."""
    if fmt is Fmt.csv:
        raise typer.BadParameter("vuln show supports --format table or json")
    with _open(db) as conn:
        d = reports.vuln_detail(conn, vuln_id, raw=raw)
    if d is None:
        raise _fail(f"unknown vulnerability id {vuln_id!r}")
    if fmt is Fmt.json:
        typer.echo(json.dumps(d, indent=2, default=str))
        return
    console.print(f"[bold]{_e(d['id'])}[/] aliases: {_e(', '.join(d['aliases']) or '-')}")
    for r in d["records"]:
        cvss = "" if r["cvss_score"] is None else r["cvss_score"]
        console.print(f"  [cyan]{_e(r['source']):8}[/] {_e(r['id']):24} {_e(r['severity']):9} "
                      f"{_e(cvss):5} {_e((r['summary'] or '')[:90])}")
    if k := d["kev"]:
        console.print(f"  [red]KEV[/] added {_e(k['date_added'])} due {_e(k['due_date'])} "
                      f"ransomware={_e(k['ransomware'])}")
    if ep := d["epss"]:
        console.print(f"  EPSS {ep['score']:.4f} (pct {ep['percentile'] or 0:.3f}) {_e(ep['date'])}")
    t = Table(title="Affected")
    for col in ("source", "ecosystem/vendor", "package/product", "type", "ranges / versions"):
        t.add_column(col, overflow="fold")
    for r in d["affected"][:60]:
        t.add_row(_t(r["source"]), _t(r["ecosystem"] or r["vendor"]), _t(r["package"] or r["product"]),
                  _t(r["range_type"]), _t(_ranges(r)[:80]))
    _print(t)
    for r in d.get("raw", []):
        console.rule(_e(r["source"]))
        console.print_json(json.dumps(r["data"], default=str))


def _ranges(r: dict) -> str:
    return json.dumps(r["events"] or r["versions"]) if (r["events"] or r["versions"]) else ""


@vuln_app.command("search")
def vuln_search(
    package: Annotated[str | None, typer.Option(help="Package name (OSV)")] = None,
    ecosystem: Annotated[str | None, typer.Option(help="OSV ecosystem, e.g. PyPI, Debian:12")] = None,
    product: Annotated[str | None, typer.Option(help="Product name (CVE/NVD)")] = None,
    version: Annotated[str | None, typer.Option(help="Only advisories affecting this version")] = None,
    limit: LimitOpt = 50,
    fmt: FmtOpt = Fmt.table,
    db: DbOpt = None,
):
    """Find advisories for a package or product (optionally a specific version)."""
    if not (package or ecosystem or product):
        raise typer.BadParameter("give --package, --ecosystem and/or --product")
    with _open(db) as conn:
        rows = reports.vuln_search(conn, package=package, ecosystem=ecosystem, product=product, version=version,
                                   limit=limit)
    if fmt is not Fmt.table:
        _emit([{**r, "ranges": _ranges(r)} for r in rows] if fmt is Fmt.csv else rows,
              ["vuln_id", "source", "ecosystem", "vendor", "package", "product", "range_type", "ranges",
               "severity", "cvss_score"], fmt)
        return
    for r in rows:
        console.print(f"{_e(r['vuln_id']):28} {_e(r['source']):8} {_e(r['ecosystem'] or r['vendor']):14} "
                      f"{_e(r['package'] or r['product']):24} {_e(_ranges(r)[:70])}")
    _info(f"[dim]{len(rows)} result(s)[/]")


# --------------------------------------------------------------------------- collect / scan

OptsOpt = Annotated[list[str] | None, typer.Option(
    "--opt", "-o", help="Collector option key=value (repeatable; repeated keys become a list), "
                        "e.g. -o use_brew_cli=true -o platform=linux/arm64")]


def _parse_opts(items: list[str] | None) -> dict:
    """`-o key=value` -> kwargs (rules in ops.parse_opts)."""
    try:
        return ops.parse_opts(items)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None


def _collect(collector: str, target: str | None, opts: dict):
    reg = _collectors()
    if collector not in reg:
        raise _fail(f"unknown collector {collector} (known: {', '.join(sorted(reg))})", 2)
    try:
        return ops.collect(collector, target, opts)   # components classified
    except COLLECT_ERRORS as e:  # connection/permission/target/format errors: no traceback
        _traceback()
        raise _fail(f"{collector}: {type(e).__name__}: {e}") from None


def _report_inventory_notes(inv, *, to_stderr_json: bool = False) -> None:
    """Collector warnings are never hidden (not even by --quiet)."""
    for w in inv.warnings:
        err_console.print(f"[yellow]warning:[/] {_e(w)}")
    if getattr(inv, "partial", False):
        err_console.print("[yellow]partial inventory — previous components kept[/]")


@app.command("collectors")
def list_collectors():
    """List available inventory collectors."""
    for name, cls in sorted(_collectors().items()):
        console.print(f"[bold]{name:14}[/] {_e(cls.description)}")


def _prepare(inv) -> None:
    from .engine.classify import classify

    for c in inv.components:
        classify(c)


def _print_inventory(inv) -> None:
    t = Table(title=_t(f"{inv.asset.id} — {len(inv.components)} components"))
    for col in ("category", "name", "version", "ecosystem / vendor", "purl / cpe"):
        t.add_column(col, overflow="fold")
    for c in sorted(inv.components, key=lambda c: (c.category, c.name.lower())):
        t.add_row(_t(c.category), _t(c.name), _t(c.version), _t(c.ecosystem or c.vendor), _t(c.purl or c.cpe))
    _print(t)


@app.command()
def collect(
    collector: Annotated[str, typer.Argument(help="macos | docker-image | docker-engine | rootfs …")],
    target: Annotated[str | None, typer.Argument(help="Collector target (root dir, image ref, tar…)")] = None,
    save: Annotated[bool, typer.Option(help="Store the inventory in the DB")] = True,
    output: Annotated[Path | None, typer.Option("--output", "-O", help="Write inventory JSON here")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", hidden=True,
                                                   help="Deprecated alias of --output")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Don't print the component table")] = False,
    opt: OptsOpt = None,
    db: DbOpt = None,
):
    """Discover installed software (no matching)."""
    from dataclasses import asdict

    from .engine.inventory import save_inventory

    if json_path is not None:
        err_console.print("[yellow]--json is deprecated; use --output / -O[/]")
        output = output or json_path
    quiet = quiet or _state.quiet
    inv = _collect(collector, target, _parse_opts(opt))
    if not quiet:
        _print_inventory(inv)
    _report_inventory_notes(inv)
    if output:
        output.write_text(json.dumps(asdict(inv), indent=2, default=str))
        _info(f"wrote {_e(output)}")
    if save:
        with _open(db, create=True) as conn:
            scan_id = save_inventory(conn, inv)
        _info(f"saved asset [bold]{_e(inv.asset.id)}[/] (scan {scan_id})")


@app.command("ui")
def ui(
    host: Annotated[str, typer.Option(help="Address to listen on (default loopback only; the UI has no authentication)")]
    = "127.0.0.1",
    port: Annotated[int, typer.Option(min=0, max=65535, help="Port (0 = any free port)")] = 8765,
    snapshot: Annotated[Path | None, typer.Option(
        "--snapshot", help="Serve a process snapshot file instead of this machine (any OS)")] = None,
    open_browser: Annotated[bool, typer.Option("--open/--no-open", help="Open the browser")] = False,
    allow_host: Annotated[list[str] | None, typer.Option(
        "--allow-host", help="Extra name accepted in the Host header (e.g. the machine's DNS name); repeatable")] = None,
    allow_actions: Annotated[bool | None, typer.Option(
        "--allow-actions/--no-actions",
        help="Allow scans and syncs from the browser (default: only when listening on loopback)")] = None,
    min_confidence: Annotated[float, typer.Option(help="Drop name-based matches below this")] = 0.5,
    opt: OptsOpt = None,
    db: DbOpt = None,
):
    """Local web interface: dashboard, assets, findings, vulnerabilities, sources, scans and the process monitor.
    Ctrl-C stops it."""
    from .web.api import ProcessMonitor
    from .web.server import make_server

    if host not in ("127.0.0.1", "localhost", "::1"):
        err_console.print(f"[yellow]warning: listening on {_e(host)} — the UI has no authentication; anyone who can "
                          "reach this address can read the database, the process list and findings"
                          + (", and run scans and syncs" if allow_actions else
                             " (scans and syncs stay disabled unless --allow-actions)") + "[/]")
    if snapshot is not None and not snapshot.is_file():
        raise _fail(f"no snapshot file {snapshot}", 2)
    monitor = ProcessMonitor(db_path=_db_path(db), target=str(snapshot) if snapshot else None,
                             opts=_parse_opts(opt), min_confidence=min_confidence)
    try:
        srv = make_server(monitor, host, port, mode="snapshot" if snapshot else "live", verbose=_state.verbose,
                          allow_hosts=allow_host, actions=allow_actions)
    except OSError as e:
        raise _fail(f"cannot listen on {host}:{port}: {e}") from None
    shown = "localhost" if host in ("127.0.0.1", "::1", "localhost") else (f"[{host}]" if ":" in host else host)
    url = f"http://{shown}:{srv.port}/"
    console.print(f"sec-monk UI on [bold]{_e(url)}[/] — Ctrl-C to stop")
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


@app.command("windows-script")
def windows_script(compact: Annotated[bool, typer.Option(
        help="Strip comments/blank lines (for `powershell -Command -`)")] = False):
    """Print the read-only PowerShell inventory script.

    Usage: `secmonk windows-script > secmonk-inventory.ps1`, run that on Windows, then
    `secmonk scan windows inventory.json`.
    """
    from .collectors.windows import inventory_script

    typer.echo(inventory_script(compact=compact), nl=False)


@app.command()
def containers(
    socket: Annotated[str | None, typer.Option(help="Docker/Podman socket path")] = None,
    host: Annotated[str | None, typer.Option(
        help="Engine address: unix:///path, tcp://host:2376, ssh://user@host[:port] (default: local socket)")] = None,
    context: Annotated[str | None, typer.Option(help="Docker context name (see `docker context ls`)")] = None,
    match: Annotated[str | None, typer.Option(
        "--match", "-m", help="Only containers selected by this docker-engine target: names, globs, re:<regex>, "
                              "comma separated")] = None,
    all_: Annotated[bool, typer.Option("--all", help="Include stopped containers")] = False,
    fmt: FmtOpt = Fmt.table,
    opt: Annotated[list[str] | None, typer.Option(
        "--opt", "-o", help="docker-engine option key=value (repeatable): tls_ca, tls_cert, tls_key, tls_verify, "
                            "identity, ssh_bin, timeout…")] = None,
):
    """List containers of a Docker/Podman engine (targets for `scan docker-engine <name|glob|re:regex,…>`)."""
    opts = _parse_opts(opt)
    try:
        payload = ops.docker_containers(host=host, context=context, socket=socket, all=all_, match=match, opts=opts)
    except ValueError as e:
        raise _fail(_e(e), 2) from None
    except Exception as e:  # noqa: BLE001
        _traceback()
        raise _fail(_e(e)) from None
    rows = [r for r in payload["containers"] if r["matched"]]
    _emit(rows, ["id", "name", "image", "state", "status"], fmt, title=f"Containers ({payload['engine']})")


def _ephemeral(conn: sqlite3.Connection) -> None:
    dbm.ephemeral_overlay(conn)


FINDING_COLS = ["priority", "vuln_id", "component", "version", "fixed_version", "severity", "cvss_score",
                "epss", "kev", "triage", "matched_by", "confidence"]
_FINDING_CELLS: dict[str, Callable[[Any], str]] = {
    "cvss_score": lambda v: "" if v is None else f"{v:.1f}",
    "epss": lambda v: "" if v is None else f"{v:.3f}",
    "confidence": lambda v: "" if v is None else f"{v:.1f}",
}


def _render_findings(conn: sqlite3.Connection, fmt: Fmt, *, asset: str | None = None,
                     priority: str | None = None, all_: bool = False, fixable: bool = False,
                     hide_minor: bool = False, hide_deferred: bool = False, limit: int = 200) -> list[dict]:
    rows = reports.findings(conn, asset=asset, priority=priority, include_closed=all_, fixable=fixable,
                            hide_minor=hide_minor, hide_deferred=hide_deferred, limit=limit)
    _emit_findings(rows, fmt)
    return rows


def _stats_line(asset_id: str, stats: dict) -> str:
    labels = {"components": "components", "matches": "matches", "findings": "findings",
              "withdrawn": "withdrawn", "patched": "patched", "not_affected": "not affected"}
    parts = [f"{stats[k]} {v}" for k, v in labels.items() if k in stats]
    return f"[bold]{_e(asset_id)}[/]: " + " · ".join(parts)


@app.command()
def scan(
    collector: Annotated[str, typer.Argument(help="Collector name (see `secmonk collectors`)")],
    target: Annotated[str | None, typer.Argument(
        help="Collector target (root dir, image ref, tar…); docker-engine: names, globs, re:<regex>, comma "
             "separated")] = None,
    min_confidence: Annotated[float, typer.Option(help="Drop name-based matches below this")] = 0.5,
    fail_on: Annotated[str | None, typer.Option(
        "--fail-on", callback=_check_priority,
        help="Exit 3 if any open finding is at or above this priority (P1 highest)")] = None,
    priority: PrioOpt = None,
    fixable: Annotated[bool, typer.Option(help="Only findings with a known fixed version")] = False,
    hide_minor: Annotated[bool, typer.Option(help="Hide distro-triaged minor issues")] = False,
    hide_deferred: Annotated[bool, typer.Option(help="Also hide no-dsa / postponed")] = False,
    limit: LimitOpt = 200,
    save: Annotated[bool, typer.Option(help="Store the inventory and findings in the DB (--no-save needs an "
                                            "existing mirror and stores no inventory or findings; the run is "
                                            "listed in the history)")] = True,
    fmt: FmtOpt = Fmt.table,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only the findings")] = False,
    opt: OptsOpt = None,
    db: DbOpt = None,
):
    """collect + save + match, then print findings (json/csv: findings on stdout, notes on stderr).

    A target that expands to several (docker-engine selectors) is scanned one by one: a section per target, JSON
    {"targets": [...]}; a failing target does not stop the others (exit 1 at the end).
    """
    if collector not in _collectors():
        raise _fail(f"unknown collector {_e(collector)} (known: {', '.join(sorted(_collectors()))})", 2)
    try:
        item = ops.scan_item(collector, target, opt)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None
    _run_scan(
        [item], title=ops.scan_title(collector, target),
        params=ops.scan_params(collector, target, opt, save=save, min_confidence=min_confidence),
        single_spec=not ops.is_selector(collector, target), save=save, min_confidence=min_confidence,
        fail_on=fail_on, fmt=fmt, quiet=quiet or _state.quiet, db=db,
        fkw={"priority": priority, "fixable": fixable, "hide_minor": hide_minor, "hide_deferred": hide_deferred,
             "limit": limit})


def _run_scan(items: list, *, title: str, params: dict, single_spec: bool, save: bool, min_confidence: float,
              fail_on: str | None, fkw: dict, fmt: Fmt, quiet: bool, db: Path | None) -> None:
    """`scan` and `scan-host`: ops.scan_items (the web job's loop) with the CLI's output, history and exit codes.
    A single-collector scan (single_spec, one item) whose target expands to exactly that one target prints the
    single-target document; otherwise a section per target and JSON = the stored result."""
    if not save and not _db_path(db).exists():        # before the history row would create the database
        raise _fail(f"no database at {_e(_db_path(db))} — run `secmonk sync …` first")
    strict = len(items) == 1 and single_spec
    state = {"single": False, "hit": 0}
    csv_rows: list[dict] = []

    def on_expanded(item, targets) -> None:
        state["single"] = strict and len(targets) == 1

    def on_entry(entry: dict, inv) -> None:
        single = state["single"]
        name = " ".join(x for x in (entry["collector"] if len(items) > 1 else "",
                                    entry["target"] or "") if x) or entry["collector"]
        if not single and fmt is Fmt.table and not quiet:
            console.rule(_e(name))
        if entry["error"]:
            if not single:
                err_console.print(f"[red]{_e(name)}: {_e(entry['error'])}[/]")
            return
        if fmt is not Fmt.json:
            if inv is not None:                        # None: a reused image inventory (nothing collected)
                _report_inventory_notes(inv)
            elif entry.get("reused"):
                _info(f"[dim]{_e(entry['asset'])}: already inventoried (scan {entry['reused_scan_id']}), "
                      "re-matched without collecting (-o rescan=true collects again)[/]", fmt)
            if not quiet:
                (console if fmt is Fmt.table else err_console).print(_stats_line(entry["asset"], entry["stats"]))
            if fmt is Fmt.csv:
                csv_rows.extend(entry["findings"])     # one CSV document for every target
            else:
                _emit_findings(entry["findings"], fmt)
        if fail_on:
            state["hit"] += queries.count_open_at_or_above(conn, entry["asset"], fail_on)

    # the history row lives on its own connection and is finished after the scan connection is closed: recording
    # a run never commits (or waits on) the scan's own transaction
    with ops.record_run(_db_path(db), "scan", "cli", title, params) as run:
        with _open(db, create=save) as conn:
            if not save:
                _ephemeral(conn)
            try:
                entries = ops.scan_items(conn, items, save=save, min_confidence=min_confidence, findings=fkw,
                                         say=run.say, on_exception=lambda e: _traceback(), on_expanded=on_expanded,
                                         on_entry=on_entry, strict_expand=strict)
            except Exception as e:  # noqa: BLE001  # single collector: no match, engine unreachable
                _traceback()
                run.finish("error", None, f"{type(e).__name__}: {e}")
                raise _fail(f"{_e(items[0].collector)}: {_e(type(e).__name__)}: {_e(e)}") from None
        status, result, error = ops.scan_result(entries, saved=save)
        run.finish(status, result, error)
    single, hit = state["single"], state["hit"]
    if single and entries[0]["error"]:
        raise _fail(f"{_e(items[0].collector)}: {_e(entries[0]['error'])}")
    if fmt is Fmt.csv:
        _emit_findings(csv_rows, fmt)
    if fmt is Fmt.json:
        if single:
            e = entries[0]
            doc: Any = {"asset": e["asset"], "stats": e["stats"], "warnings": e["warnings"], "partial": e["partial"],
                        "findings": e["findings"]}
        else:
            doc = result                      # the stored scan result: {saved, targets, stats, counts}
        typer.echo(json.dumps(doc, indent=2, default=str))
    failed = [e for e in entries if e["error"]]
    if hit:
        err_console.print(f"[red]{hit} open finding(s) at or above {fail_on}[/]")
    if failed:                                # a failed target (exit 1) wins over --fail-on (exit 3)
        raise _fail(f"{len(failed)} of {len(entries)} target(s) failed")
    if hit:
        raise typer.Exit(3)


def _emit_findings(rows: list[dict], fmt: Fmt) -> None:
    if fmt is not Fmt.json:
        _emit(rows, FINDING_COLS if fmt is Fmt.table else FINDING_COLS + ["asset_id", "status"], fmt,
              title="Findings", cell=_FINDING_CELLS)


# --------------------------------------------------------------------------- host mode (discover + batch scan)

HostTarget = Annotated[str | None, typer.Argument(
    help="Host to explore: nothing = this machine, or [ssh://]user@host[:port] (Linux/macOS over ssh)")]
DiscoverOpts = Annotated[list[str] | None, typer.Option(
    "--opt", "-o", help="Discovery option key=value (repeatable): identity, known_hosts, connect_timeout, context, "
                        "host (docker engine)…")]


def _discover(target: str | None, opt: list[str] | None) -> dict:
    try:
        return ops.discover_host(target, _parse_opts(opt))
    except ValueError as e:
        raise _fail(f"discover: {_e(e)}", 2) from None
    except Exception as e:  # noqa: BLE001  # ssh / engine failures: a clean message (-v for the traceback)
        _traceback()
        raise _fail(f"discover: {_e(type(e).__name__)}: {_e(e)}") from None


def _host_notes(payload: dict) -> None:
    """Host line and discovery warnings on stderr (never hidden: warnings; the host line: not with --quiet)."""
    h = payload["host"]
    if not _state.quiet:
        os_text = " ".join(str(x) for x in (h["os"], h["os_version"], h["arch"]) if x)
        err_console.print(f"[bold]{_e(h['name'] or h['target'] or 'this machine')}[/] ({_e(h['kind'])}"
                          f"{', ' + _e(os_text) if os_text else ''})")
    for w in payload["warnings"]:
        err_console.print(f"[yellow]warning:[/] {_e(w)}")


def _candidate_table(cands: list[dict], *, numbered: bool = False) -> Table:
    t = Table(title="Scan candidates")
    cols = (["#"] if numbered else []) + ["id", "available", "selected", "collector", "target", "label / reason"]
    for c in cols:
        t.add_column(c, overflow="fold")
    for n, c in enumerate(cands, 1):
        note = c["label"] + (f" — {c['reason']}" if c["reason"] else "")
        t.add_row(*([_t(n)] if numbered else []), _t(c["id"]), _t(_plain(c["available"])), _t(_plain(c["selected"])),
                  _t(c["collector"]), _t(c["target"]), _t(note, style="" if c["available"] else "dim"))
    return t


@app.command()
def discover(
    target: HostTarget = None,
    opt: DiscoverOpts = None,
    fmt: Annotated[Fmt, typer.Option("--format", "-f", help="Output format: table or json")] = Fmt.table,
):
    """Explore a host and list what can be scanned there (candidates for `secmonk scan-host`)."""
    if fmt is Fmt.csv:
        raise typer.BadParameter("discover supports --format table or json")
    payload = _discover(target, opt)
    if fmt is Fmt.json:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    _host_notes(payload)
    _print(_candidate_table(payload["candidates"]))


def _interactive() -> bool:
    import sys

    return sys.stdin.isatty()


def _choose(payload: dict, *, only: str | None, all_: bool, yes: bool) -> list[str]:
    """Candidate ids to scan: --only, --all, --yes, or a prompt on a terminal. Exit 2 when no choice is possible."""
    cands = payload["candidates"]
    if sum(bool(x) for x in (only, all_, yes)) > 1:
        raise _fail("choose one of --only, --all, --yes", 2)
    if only:
        return [x.strip() for x in only.split(",") if x.strip()]
    if all_:
        return [c["id"] for c in cands if c["available"]]
    default = [c["id"] for c in cands if c["available"] and c["selected"]]
    if yes:
        return default
    if not _interactive():
        raise _fail("nothing chosen: pass --only id,id, --all (every available) or --yes (the default selection); "
                    "see `secmonk discover`", 2)
    err_console.print(_candidate_table(cands, numbered=True))      # stdout may carry the JSON result
    nums = [str(n) for n, c in enumerate(cands, 1) if c["id"] in default]
    answer = typer.prompt("Scan which (numbers or ids, comma separated; no ranges)", default=",".join(nums) or "",
                          show_default=True, err=True)
    out = []
    for x in (y.strip() for y in answer.split(",")):
        if not x:
            continue
        if re.fullmatch(r"[0-9]+", x):
            if not 1 <= int(x) <= len(cands):
                raise _fail(f"no candidate number {_e(x)}", 2)
            out.append(cands[int(x) - 1]["id"])
        else:
            out.append(x)
    return out


@app.command("scan-host")
def scan_host(
    target: HostTarget = None,
    only: Annotated[str | None, typer.Option("--only", help="Candidate ids to scan, comma separated")] = None,
    all_: Annotated[bool, typer.Option("--all", help="Every available candidate")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="The default selection, without asking")] = False,
    opt: DiscoverOpts = None,
    min_confidence: Annotated[float, typer.Option(help="Drop name-based matches below this")] = 0.5,
    fail_on: Annotated[str | None, typer.Option(
        "--fail-on", callback=_check_priority,
        help="Exit 3 if any open finding is at or above this priority (P1 highest)")] = None,
    limit: LimitOpt = 200,
    save: Annotated[bool, typer.Option(help="Store inventories and findings (--no-save: needs an existing mirror, "
                                            "stores none; the run is listed in the history)")] = True,
    fmt: FmtOpt = Fmt.table,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only the findings")] = False,
    db: DbOpt = None,
):
    """Host mode: explore a host (`secmonk discover`), choose what to scan, then scan it all in one run.

    Without --only / --all / --yes the candidates are listed and you are asked (on a terminal). Output like a
    multi-target scan: a section per target, JSON = {saved, targets, stats, counts}; a failing item does not stop
    the others (exit 1 at the end).
    """
    if not save and not _db_path(db).exists():
        raise _fail(f"no database at {_e(_db_path(db))} — run `secmonk sync …` first")
    payload = _discover(target, opt)
    _host_notes(payload)
    ids = list(dict.fromkeys(_choose(payload, only=only, all_=all_, yes=yes)))
    if not ids:
        raise _fail("nothing to scan (no candidate chosen)", 2)
    try:
        items = ops.candidate_items(payload, ids)
    except ValueError as e:
        raise _fail(_e(e), 2) from None
    host = payload["host"]
    _run_scan(items, title=ops.batch_title(host["name"] or host["target"] or target, ids),
              params=ops.batch_params(items, save=save, min_confidence=min_confidence, host=target),
              single_spec=False, save=save, min_confidence=min_confidence, fail_on=fail_on, fkw={"limit": limit},
              fmt=fmt, quiet=quiet or _state.quiet, db=db)


@app.command()
def match(
    asset: Annotated[str, typer.Argument(help="Asset id (see `secmonk inventory assets`)")],
    min_confidence: Annotated[float, typer.Option(help="Drop name-based matches below this")] = 0.5,
    db: DbOpt = None,
):
    """(Re)match a stored asset against the current mirror."""
    from .engine.match import match_asset

    with _open(db) as conn:
        try:
            stats = match_asset(conn, asset, min_confidence=min_confidence)
        except (KeyError, ValueError):
            _traceback()
            raise _fail(f"unknown asset {asset!r} — see `secmonk inventory assets`") from None
    console.print(_stats_line(asset, stats))


# --------------------------------------------------------------------------- process monitor

def _procs_match(conn: sqlite3.Connection, inv, min_confidence: float) -> dict:
    from . import procmon

    return procmon.match_inventory(conn, inv, min_confidence)


def _procs_table(rows: list[dict], title: str) -> None:
    t = Table(title=_t(title))
    for col in ("pid", "user", "launch", "process", "identity", "findings", "flags"):
        t.add_column(col, overflow="fold", justify="right" if col == "pid" else "left")
    for r in rows:
        style = "red" if r["findings"].startswith(("P1", "P2")) else ("yellow" if r["flags"] or r["findings"] else "")
        proc = "  " * r["depth"] + r["process"] + (f"  [{r['script']}]" if r.get("script") else "")
        t.add_row(_t(r["pid"]), _t(r["user"]), _t(r["launch_detail"]), _t(proc), _t(r["identity"]),
                  _t(r["findings"], style=style), _t(", ".join(r["flags"]), style="yellow" if r["flags"] else ""))
    _print(t)


def _event_line(ev, fmap: dict) -> tuple[str, dict]:
    from . import procmon

    data = procmon.event_dict(ev, fmap)
    if ev.kind in ("new-executable", "changed-executable"):
        word = "NEW exe" if ev.kind == "new-executable" else "CHANGED exe (replaced on disk)"
        text = (f"{word}  pid {data['pid']} {data['user'] or ''}  {data['launch_detail']}  {data['exe']}"
                + (f"  -> {data['identity']} [{data['identity_method']}]" if data["identity"] else "")
                + (f"  findings: {data['findings']}" if data["findings"] else "")
                + (f"  flags: {', '.join(data['flags'])}" if data["flags"] else ""))
        return text, data
    word = {"new-launch-item": "NEW", "removed-launch-item": "REMOVED"}.get(ev.kind, "CHANGED")
    return (f"{word} launch item  {data['label']} ({data['mechanism']}, {data['scope']})  -> {data['program']}"
            f"  [{data['source']}]"), data


@app.command()
def procs(
    target: Annotated[str | None, typer.Argument(
        help="Process snapshot JSON (secmonk-process-snapshot/1); default: this machine, live")] = None,
    flat: Annotated[bool, typer.Option("--flat", help="List instead of a parent/child tree")] = False,
    suspicious: Annotated[bool, typer.Option(
        "--suspicious", "-s", help="Only processes with findings or risk flags")] = False,
    match_: Annotated[bool, typer.Option(
        "--match/--no-match", help="Match running software against the mirror (if a database exists)")] = True,
    save: Annotated[bool, typer.Option(
        "--save", help="Persist asset process:<host> + findings (default: match in a temporary overlay)")] = False,
    watch: Annotated[float | None, typer.Option(
        "--watch", "-w", min=1.0, help="Keep running: re-snapshot every N seconds, report new executables "
                                       "and new/removed launch items (live only)")] = None,
    max_ticks: Annotated[int | None, typer.Option("--max-ticks", hidden=True)] = None,
    snapshot_out: Annotated[Path | None, typer.Option(
        "--snapshot-out", help="Also write the raw process snapshot JSON here")] = None,
    min_confidence: Annotated[float, typer.Option(help="Drop name-based matches below this")] = 0.5,
    fmt: FmtOpt = Fmt.table,
    opt: OptsOpt = None,
    db: DbOpt = None,
):
    """Process monitor: what runs, how it was started, which software/version it is, findings, provenance."""
    from . import procmon
    from .collectors.process.collector import ProcessCollector

    opts = _parse_opts(opt)
    if snapshot_out:
        opts["snapshot_out"] = str(snapshot_out)
    if watch and target:
        raise _fail("--watch needs a live snapshot (no TARGET)", 2)
    col = ProcessCollector()
    try:
        snap, inspector, views = col.analyse(target, **opts)
    except COLLECT_ERRORS as e:
        _traceback()
        raise _fail(f"process: {type(e).__name__}: {e}") from None
    inv = col.inventory(snap, inspector, views, opts)
    _prepare(inv)
    if fmt is not Fmt.json:
        _report_inventory_notes(inv)
    have_db = _db_path(db).exists()
    if match_ and not have_db and not save:
        _info(f"[dim]no database at {_e(_db_path(db))}: showing processes without findings "
              "(run `secmonk sync …` first)[/]", fmt)
    if match_ and have_db and not save and (denied := _db_denied(db)) is not None:
        _info(f"[yellow]{_e(_denied_db_hint(denied))}: showing processes without findings[/]", fmt)
        have_db = False
    use_db = save or (match_ and have_db)
    with contextlib.ExitStack() as stack:
        conn = stack.enter_context(_open(db, create=save)) if use_db else None
        if conn is not None and not save:
            _ephemeral(conn)
        fmap = _procs_match(conn, inv, min_confidence) if conn is not None else {}
        rows = [procmon.view_row(v, fmap) for v in views] if flat else procmon.tree_rows(views, fmap)
        if suspicious:
            rows = [r for r in rows if procmon.interesting(r)]
        if fmt is Fmt.json and not watch:
            typer.echo(json.dumps({"asset": inv.asset.id, "taken_at": snap.taken_at, "platform": snap.platform,
                                   "os": snap.os, "warnings": inv.warnings,
                                   "launch_items_missing_program": inv.asset.meta.get("launch_items_missing_program", []),
                                   "processes": rows}, indent=2, default=str))
        elif fmt is Fmt.csv and not watch:
            _emit(rows, ["pid", "ppid", "user", "launch", "label", "exe", "identity", "identity_method", "findings",
                         "flags"], fmt, cell={"flags": lambda v: " ".join(v or [])})
        elif fmt is Fmt.table and (not watch or not _state.quiet):
            kinds = inv.asset.meta.get("launch_kinds", {})
            _procs_table(rows, f"{inv.asset.id} — {len(views)} processes, {len(inv.components)} components")
            _info(" · ".join(f"{k} {n}" for k, n in sorted(kinds.items(), key=lambda x: -x[1])))
            for m in inv.asset.meta.get("launch_items_missing_program", []):
                err_console.print(f"[yellow]launch item {_e(m['label'])} points to a missing program "
                                  f"{_e(m['program'])} ({_e(m['source'])})[/]")
        if not watch:
            return
        watcher = procmon.Watcher(inspector)
        watcher.tick(snap)
        _info(f"[dim]watching every {watch:g}s — Ctrl-C to stop[/]", fmt)
        ticks = 0
        try:
            while max_ticks is None or ticks < max_ticks:
                ticks += 1
                time.sleep(watch)
                try:
                    snap = col.snapshot(None, **{k: v for k, v in opts.items() if k != "snapshot_out"})
                except COLLECT_ERRORS as e:
                    err_console.print(f"[yellow]snapshot failed: {_e(e)}[/]")
                    continue
                views, events = watcher.tick(snap)
                if not events:
                    continue
                fresh = [e.data["view"] for e in events if e.kind in ("new-executable", "changed-executable")]
                if conn is not None and fresh:
                    new_inv = col.inventory(snap, inspector, fresh, opts)
                    if save:
                        # an increment of the saved asset: partial, so nothing it did not see counts as removed,
                        # and the baseline asset meta (process tree) is kept
                        new_inv.asset.id, new_inv.asset.meta = inv.asset.id, inv.asset.meta
                        new_inv.mark_partial("procs --watch increment")
                    else:
                        new_inv.asset.id = f"{inv.asset.id}#watch"
                    fmap = _procs_match(conn, new_inv, min_confidence)
                for ev in events:
                    text, data = _event_line(ev, fmap)
                    stamp = time.strftime("%H:%M:%S")
                    if fmt is Fmt.json:
                        typer.echo(json.dumps({"time": stamp, **data}, default=str))
                    else:
                        bad = data.get("findings", "").startswith(("P1", "P2")) or "flags" in data and data["flags"]
                        console.print(_t(f"{stamp} {text}", style="red" if bad else ""))
        except KeyboardInterrupt:
            pass



@app.command()
def findings(
    asset: Annotated[str | None, typer.Argument(help="Only this asset")] = None,
    priority: PrioOpt = None,
    all_: Annotated[bool, typer.Option("--all", help="Include fixed/suppressed")] = False,
    fixable: Annotated[bool, typer.Option(help="Only findings with a known fixed version")] = False,
    hide_minor: Annotated[bool, typer.Option(help="Hide distro-triaged minor issues "
                                                  "(unimportant, ignored, end-of-life)")] = False,
    hide_deferred: Annotated[bool, typer.Option(help="Also hide no-dsa / postponed")] = False,
    limit: LimitOpt = 200,
    fmt: FmtOpt = Fmt.table,
    db: DbOpt = None,
):
    """List findings ordered by priority."""
    with _open(db) as conn:
        if asset:
            _require_asset(conn, asset)
        rows = _render_findings(conn, fmt, asset=asset, priority=priority, all_=all_, fixable=fixable,
                                hide_minor=hide_minor, hide_deferred=hide_deferred, limit=limit)
    if fmt is Fmt.json:
        typer.echo(json.dumps(rows, indent=2, default=str))


# --------------------------------------------------------------------------- inventory queries

@inv_app.command("assets")
def inv_assets(db: DbOpt = None, fmt: FmtOpt = Fmt.table):
    """List assets."""
    with _open(db) as conn:
        rows = reports.asset_rows(conn)
    _emit(rows, ["id", "type", "os", "platform", "last_seen", "components", "open_findings"], fmt,
          right=("components", "open_findings"))


@inv_app.command("show")
def inv_show(
    asset: Annotated[str, typer.Argument(help="Asset id")],
    category: Annotated[str | None, typer.Option(help="Only this component category")] = None,
    db: DbOpt = None,
    fmt: FmtOpt = Fmt.table,
):
    """Components of an asset (latest scan)."""
    with _open(db) as conn:
        _require_asset(conn, asset)
        rows = reports.component_rows(conn, asset, category)
    _emit(rows, ["category", "name", "version", "ecosystem", "vendor", "purl", "cpe", "path"], fmt, title=asset)


@inv_app.command("unmatched")
def inv_unmatched(db: DbOpt = None, fmt: FmtOpt = Fmt.table):
    """Applications whose product identity is only a normalized name (alias-table candidates)."""
    with _open(db) as conn:
        rows = reports.unmatched_rows(conn)
    _emit(rows, ["category", "name", "version", "product", "bundle_id"], fmt)


# --------------------------------------------------------------------------- run history

class Kind(str, Enum):
    scan = "scan"
    sync = "sync"


def _summary_text(kind: str, s: dict) -> str:
    if not s:
        return ""
    if kind == "scan":
        prio = " ".join(f"{k}:{s[k]}" for k in ("P1", "P2", "P3", "P4") if s.get(k))
        return (f"{s['targets']} target(s)" + (f", {s['errors']} failed" if s["errors"] else "")
                + f", {s['components']} components, {s['total']} findings" + (f" ({prio})" if prio else ""))
    return (f"{s['sources']} source(s)" + (f", {s['errors']} failed" if s["errors"] else "")
            + f", {s['records']:,} records")


@history_app.callback(invoke_without_command=True)
def history(
    ctx: typer.Context,
    kind: Annotated[Kind | None, typer.Option("--kind", help="Only scan or sync runs")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, max=dbm.JOB_KEEP, help="Maximum rows")] = 20,
    fmt: FmtOpt = Fmt.table,
    db: DbOpt = None,
):
    """Recent scan and sync runs, newest first (`history show ID` for one run's result)."""
    if ctx.invoked_subcommand is not None:
        return
    with _open(db) as conn:
        rows = [reports.job_dict(r, include_log=False) for r in dbm.job_rows(conn, kind=kind.value if kind else None,
                                                                              limit=limit)]
    if fmt is Fmt.json:
        typer.echo(json.dumps(rows, indent=2, default=str))
        return
    table = [{**r, "summary": _summary_text(r["kind"], r["summary"]), "error": r["error"] or ""} for r in rows]
    _emit(table, ["id", "kind", "origin", "title", "status", "started", "summary"]
          + (["finished", "error"] if fmt is Fmt.csv else []), fmt, title="History", right=("id",))


@history_app.command("show")
def history_show(
    job_id: Annotated[int, typer.Argument(help="Run id (see `secmonk history`)")],
    log: Annotated[bool, typer.Option("--log", help="Also print the run's log")] = False,
    fmt: Annotated[Fmt, typer.Option("--format", "-f", help="Output format: table or json")] = Fmt.table,
    db: DbOpt = None,
):
    """One run: parameters, status and the stored result (findings per target, or sources)."""
    if fmt is Fmt.csv:
        raise typer.BadParameter("history show supports --format table or json")
    with _open(db) as conn:
        row = dbm.job_row(conn, job_id)
    if row is None:
        raise _fail(f"no run {job_id} — see `secmonk history`")
    d = reports.job_dict(row)
    if fmt is Fmt.json:
        typer.echo(json.dumps(d, indent=2, default=str))
        return
    colour = {"ok": "green", "partial": "yellow", "running": "cyan"}.get(d["status"], "red")
    console.print(f"[bold]#{d['id']} {_e(d['title'])}[/] [{colour}]{_e(d['status'])}[/] ({_e(d['origin'])}) "
                  f"{_e(d['started'])} → {_e(d['finished'] or '…')}")
    if d["error"]:
        console.print(f"[red]{_e(d['error'])}[/]")
    console.print(_t(", ".join(f"{k}={v}" for k, v in d["params"].items()), style="dim"))
    res = d["result"] or {}
    if d["kind"] == "sync":
        _emit(res.get("sources") or [], ["source", "status", "records", "seconds", "message"], fmt, title="Sources",
              right=("records", "seconds"))
    for t in res.get("targets") or []:
        console.rule(_e(t["target"] or t["asset"] or ""))
        if t["error"]:
            console.print(f"[red]{_e(t['error'])}[/]")
            continue
        if not res.get("saved"):
            console.print("[dim]not saved (matched in a temporary overlay)[/]")
        console.print(_stats_line(t["asset"], t["stats"]))
        for w in t["warnings"]:
            console.print(f"[yellow]warning:[/] {_e(w)}")
        _emit_findings(t["findings"], fmt)
    if log:
        console.rule("log")
        for line in d["log"]:
            console.print(_t(line))


if __name__ == "__main__":
    app()
