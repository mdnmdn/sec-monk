"""Operations shared by the CLI and the web UI's background jobs: collector options, source and target expansion,
one-source sync (with its `source_sync` bookkeeping), collect -> save -> match per target, the run history (table
`job`: what ran, redacted parameters, result) and the docker-engine listings behind `secmonk containers` / the API.

The CLI wraps these with its own output (rich, exit codes); `web/jobs.py` with a job log. Neither re-implements them.
"""

from __future__ import annotations

import contextlib
import sqlite3
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from . import db as dbm
from . import reports

# `sync all` order: small authoritative feeds first, then bulk; any source not listed runs last, unless it sets
# `in_all = False` (e.g. one that needs credentials or a very large download).
SYNC_ALL_ORDER = ("kev", "epss", "osv", "cvelist", "nvd", "euvd", "msrc", "debian-tracker")
# Collector options that really are booleans / comma-separated lists (see parse_opts).
BOOL_OPTS = frozenset({"binaries", "sudo", "all_kegs", "use_brew_cli", "include_system",
                       "insecure_host_key", "xdev", "no_cache", "lang", "verbose",
                       "allow_agent", "look_for_keys", "all", "tls_verify"})
LIST_OPTS = frozenset({"exclude", "home", "ecosystems"})


def sources_registry() -> dict:
    from . import sources  # noqa: F401  (registers)
    from .sources.base import REGISTRY
    return REGISTRY


def collectors_registry() -> dict:
    from . import collectors  # noqa: F401  (registers)
    from .collectors.base import REGISTRY
    return REGISTRY


def parse_opts(items: list[str] | None) -> dict:
    """`key=value` strings (CLI `-o`, UI scan form) -> collector kwargs. Values stay strings, except: true/false/yes/no
    for known boolean keys, comma lists for list keys (exclude, home, ecosystems); a repeated key accumulates into a
    list. Raises ValueError on an item without `=`."""
    out: dict[str, Any] = {}
    for item in items or []:
        key, sep, val = item.partition("=")
        if not sep or not key:
            raise ValueError(f"expected key=value, got {item!r}")
        low = val.lower()
        value: Any = val
        if key in BOOL_OPTS and low in ("true", "yes", "false", "no"):
            value = low in ("true", "yes")
        elif key in LIST_OPTS and "," in val:
            value = [v for v in val.split(",") if v]
        if key in out:
            prev = out[key] if isinstance(out[key], list) else [out[key]]
            out[key] = prev + (value if isinstance(value, list) else [value])
        else:
            out[key] = value
    return out


def expand_sources(names: list[str], reg: dict) -> list[str]:
    """'all' -> every source with in_all (SYNC_ALL_ORDER first); duplicates dropped, order kept."""
    out: list[str] = []
    for n in names:
        if n == "all":
            ordered = [x for x in SYNC_ALL_ORDER if x in reg] + sorted(x for x in reg if x not in SYNC_ALL_ORDER)
            out += [x for x in ordered if getattr(reg[x], "in_all", True)]
        else:
            out.append(n)
    return list(dict.fromkeys(out))


def sync_source(conn: sqlite3.Connection, name: str, cls: type, opts, *,
                on_exception: Callable[[BaseException], None] | None = None):
    """Run one source and record its state in `source_sync`. Never raises for a source failure: an exception becomes
    a SyncResult with status 'error' (the caller keeps going with the next source). Returns (result, seconds)."""
    from .sources.base import SyncResult

    t0 = time.monotonic()
    try:
        res = cls().sync(conn, opts)
    except Exception as e:  # noqa: BLE001  # one failing source must not stop the others
        if on_exception:
            on_exception(e)
        res = SyncResult(name, status="error", message=f"{type(e).__name__}: {e}")
    total = res.total if getattr(res, "total", None) is not None else res.records
    dbm.set_sync_state(conn, name, status=res.status, records=total, cursor=res.cursor, message=res.message)
    return res, time.monotonic() - t0


def collect(collector: str, target: str | None, opts: dict):
    """Run a collector and classify its components. KeyError for an unknown collector; collector errors
    (errors.COLLECT_ERRORS) propagate."""
    from .engine.classify import classify

    reg = collectors_registry()
    if collector not in reg:
        raise KeyError(collector)
    inv = reg[collector]().collect(target, **opts)
    for c in inv.components:
        classify(c)
    return inv


def expand_targets(collector: str, target: str | None, opts: dict) -> list[str | None]:
    """The collector's targets for one target spec (`Collector.expand_targets`: comma lists, globs, regexes…).
    KeyError for an unknown collector; ValueError when nothing matches; collector errors propagate."""
    reg = collectors_registry()
    if collector not in reg:
        raise KeyError(collector)
    fn = getattr(reg[collector](), "expand_targets", None)
    targets = list(fn(target, **opts)) if fn else [target]
    if not targets:
        raise ValueError(f"no {collector} target matches {target!r}")
    return targets


def save_and_match(conn: sqlite3.Connection, inv, *, min_confidence: float = 0.5) -> tuple[int, dict]:
    """Persist an inventory and match its asset (in an ephemeral overlay when the caller set one up)."""
    from .engine.inventory import save_inventory
    from .engine.match import match_asset

    scan_id = save_inventory(conn, inv)
    return scan_id, match_asset(conn, inv.asset.id, min_confidence=min_confidence)


# --------------------------------------------------------------------------- scans (one or many targets)

def scan_target(conn: sqlite3.Connection, collector: str, target: str | None, opts: dict, *, save: bool,
                min_confidence: float = 0.5, findings: dict | None = None,
                say: Callable[[str], None] | None = None,
                on_exception: Callable[[BaseException], None] | None = None) -> tuple[dict, Any]:
    """collect -> save -> match one target on `conn` (an overlay connection when not saving). Never raises for a
    target failure: the entry gets `error` and the caller goes on with the next target. `findings` = reports.findings
    filters for the entry's rows (default: the asset's open findings, at most 500). Returns (entry, inventory|None);
    entry = {target, asset, scan_id, stats, warnings, partial, findings[], counts, error}."""
    say = say or (lambda m: None)
    shown = redact_target(target)
    entry: dict[str, Any] = {"target": shown, "asset": None, "scan_id": None, "stats": {}, "warnings": [],
                             "partial": False, "findings": [], "counts": reports.priority_counts([]), "error": None}
    inv = None
    try:
        say(f"collecting with {collector}{' on ' + shown if shown else ''}…")
        inv = collect(collector, target, opts)
        partial = bool(getattr(inv, "partial", False))
        entry.update(asset=inv.asset.id, warnings=list(inv.warnings), partial=partial)
        say(f"{inv.asset.id}: {len(inv.components)} components")
        for w in inv.warnings:
            say(f"warning: {w}")
        if partial:
            say("partial inventory — previous components kept")
        say("matching against the local mirror…")
        scan_id, stats = save_and_match(conn, inv, min_confidence=min_confidence)
        rows = reports.findings(conn, asset=inv.asset.id, **(findings if findings is not None else {"limit": 500}))
        entry.update(scan_id=scan_id if save else None, stats=stats, findings=rows,
                     counts=reports.priority_counts(rows))
        say(" · ".join(f"{v} {k.replace('_', ' ')}" for k, v in stats.items()))
    except Exception as e:  # noqa: BLE001  # one failing target must not stop the others
        with contextlib.suppress(sqlite3.Error):
            conn.rollback()
        if on_exception:
            on_exception(e)
        from .collectors.base import scrub_text

        entry["error"] = scrub_text(f"{type(e).__name__}: {e}")
        say(f"error: {entry['error']}")
    return entry, inv


def scan_result(entries: list[dict], *, saved: bool) -> tuple[str, dict, str | None]:
    """Per-target entries -> (status, result, error). Status ok (every target ok), partial (a partial inventory, or
    some but not all targets failed), error (every target failed). result = {saved, targets, stats, counts} with
    stats and counts summed over the targets."""
    stats: dict[str, int] = {}
    counts = reports.priority_counts([])
    for e in entries:
        for k, v in (e.get("stats") or {}).items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                stats[k] = stats.get(k, 0) + v
        for k, v in (e.get("counts") or {}).items():
            counts[k] = counts.get(k, 0) + v
    failed = [e for e in entries if e.get("error")]
    if entries and len(failed) == len(entries):
        status = "error"
        error = failed[0]["error"] if len(failed) == 1 else f"all {len(failed)} targets failed: {failed[0]['error']}"
    else:
        status = "partial" if failed or any(e.get("partial") for e in entries) else "ok"
        error = None
    return status, {"saved": saved, "targets": entries, "stats": stats, "counts": counts}, error


# --------------------------------------------------------------------------- syncs

def sync_entry(name: str, res, secs: float) -> dict:
    return {"source": name, "status": res.status, "records": res.records, "seconds": round(secs, 1),
            "message": res.message}


def sync_status(entries: list[dict]) -> str:
    statuses = {r["status"] for r in entries}
    return "error" if "error" in statuses else "partial" if "partial" in statuses else "ok"


# --------------------------------------------------------------------------- run history (redacted parameters)

def redact_target(target: str | None) -> str | None:
    """A target as shown and stored: password, query and fragment of URLs dropped (the user name is kept, so the
    run can be repeated)."""
    from .collectors.base import strip_url_secrets

    return strip_url_secrets(target, keep_user=True) if target and "://" in target else target


def redact_opt_items(items: list[str] | None) -> list[str]:
    """`key=value` option strings with secret values masked (collectors.base.redact_option)."""
    from .collectors.base import redact_option

    out = []
    for item in items or []:
        key, sep, val = item.partition("=")
        out.append(f"{key}={redact_option(key, val)}" if sep else item)
    return out


def scan_title(collector: str, target: str | None) -> str:
    shown = redact_target(target)
    return f"scan {collector}{' ' + shown if shown else ''}"


def scan_params(collector: str, target: str | None, options: list[str] | None, *, save: bool,
                min_confidence: float) -> dict:
    return {"collector": collector, "target": redact_target(target), "options": redact_opt_items(options),
            "save": save, "min_confidence": float(min_confidence)}


def sync_title(names: list[str]) -> str:
    return f"sync {', '.join(names)}"


STORED_FINDINGS = 500     # findings kept per target in a stored scan result


def stored_result(kind: str, result: dict | None) -> dict | None:
    """A result as written to the history: per-target findings capped at STORED_FINDINGS, errors scrubbed of URL
    secrets (backstop: collectors already redact what they report)."""
    from .collectors.base import scrub_text

    if kind != "scan" or not isinstance(result, dict):
        return result
    targets = [{**t, "findings": (t.get("findings") or [])[:STORED_FINDINGS], "error": scrub_text(t.get("error"))}
               for t in result.get("targets") or []]
    return {**result, "targets": targets}


def finish_run(conn: sqlite3.Connection, job_id: int, kind: str, *, status: str, result: dict | None,
               error: str | None, log: list[str]) -> None:
    """Store a run's outcome (web jobs and CLI runs): capped, scrubbed result + its summary."""
    from .collectors.base import scrub_text

    stored = stored_result(kind, result)
    dbm.job_finish(conn, job_id, status=status, result=stored, error=scrub_text(error),
                   log=[scrub_text(x) or "" for x in log], summary=reports.job_summary(kind, stored))


@dataclass
class RunRecord:
    """A run being recorded in the history from this process (the CLI) on its own connection, so recording never
    commits the caller's work; `say` lines become the stored log."""
    conn: sqlite3.Connection
    id: int
    kind: str
    log: list[str] = field(default_factory=list)
    done: bool = False

    def say(self, msg: object) -> None:
        self.log.append(str(msg)[:500])

    def finish(self, status: str, result: dict | None = None, error: str | None = None) -> None:
        finish_run(self.conn, self.id, self.kind, status=status, result=result, error=error, log=self.log)
        self.done = True


class _Terminated(BaseException):
    """SIGTERM while a CLI run is recorded (raised by the handler record_run installs)."""


@contextlib.contextmanager
def _sigterm_as_exception() -> Iterator[None]:
    import signal
    import threading

    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "SIGTERM"):
        yield
        return

    def handler(signum, frame):
        raise _Terminated()

    prev = signal.signal(signal.SIGTERM, handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, prev)


@contextlib.contextmanager
def record_run(db_path, kind: str, origin: str, title: str, params: dict) -> Iterator[RunRecord]:
    """Insert a history row in the database at `db_path` (own connection), yield it. If the block ends without
    `finish()` the run is stored as an error: 'interrupted' for Ctrl-C / SIGTERM (SIGTERM then exits 143)."""
    conn = dbm.connect(db_path)
    try:
        rec = RunRecord(conn, dbm.job_insert(conn, kind=kind, origin=origin, title=title, params=params), kind)
        try:
            with _sigterm_as_exception():
                yield rec
        except BaseException as e:
            if not rec.done:
                stopped = isinstance(e, (KeyboardInterrupt, _Terminated))
                with contextlib.suppress(sqlite3.Error):
                    rec.finish("error", None, "interrupted" if stopped else f"{type(e).__name__}: {e}")
            if isinstance(e, _Terminated):
                raise SystemExit(143) from None
            raise
        finally:
            if not rec.done:
                with contextlib.suppress(sqlite3.Error):
                    rec.finish("error", None, "no result recorded")
    finally:
        conn.close()


def is_selector(collector: str, target: str | None) -> bool:
    """Whether a target spec names several targets (a comma list, or a docker-engine glob / `re:` pattern): the
    CLI then prints the multi-target document even when one target matched."""
    if not target:
        return False
    if "," in target:
        return True
    if collector == "docker-engine":
        from .collectors import docker_engine

        split = getattr(docker_engine, "split_selector", None)
        pattern = getattr(docker_engine, "is_pattern", None)
        if split and pattern:
            return any(pattern(item) for item in split(target))
    return False


# --------------------------------------------------------------------------- docker engine listings

def _docker_opts(host: str | None = None, context: str | None = None, socket: str | None = None) -> dict:
    return {k: v for k, v in (("host", host), ("context", context), ("socket", socket)) if v}


def docker_contexts(**opts: Any) -> list[dict]:
    """`docker context ls` rows {name, host, description, current} (host credentials stripped)."""
    from .collectors import docker_engine
    from .collectors.base import strip_url_secrets

    rows = docker_engine.list_contexts(**opts)
    return [{"name": r.get("name"), "host": strip_url_secrets(r.get("host")), "description": r.get("description"),
             "current": bool(r.get("current"))} for r in rows]


def docker_containers(*, host: str | None = None, context: str | None = None, socket: str | None = None,
                      all: bool = False, match: str | None = None, opts: dict | None = None) -> dict:
    """Containers of a Docker/Podman engine (local socket, `host` unix:// tcp:// ssh://, or a docker `context`),
    each with `matched` = selected by `match` (the docker-engine target syntax). `opts` = further docker-engine
    collector options (tls_ca / tls_cert / tls_key / tls_verify, identity, ssh_bin, timeout…; host / context / socket
    given explicitly win). ValueError on a bad selector; engine errors propagate. -> {"containers": [...], "engine"}."""
    from .collectors import docker_engine
    from .collectors.base import strip_url_secrets

    opts = {k: v for k, v in (opts or {}).items() if k != "all"} | _docker_opts(host, context, socket)
    host, context, socket = opts.get("host"), opts.get("context"), opts.get("socket")
    raw = docker_engine.list_containers(all=all, **opts)
    matched: set[str] | None = None
    if match:
        matched = set()
        split = getattr(docker_engine, "split_selector", None) or (lambda s: [x.strip() for x in s.split(",")])
        for item in split(match):
            try:
                matched |= set(docker_engine.select_containers(item, raw))
            except ValueError as e:      # a pattern matching nothing is a listing with no match, not an error
                if not str(e).startswith("no container matches"):
                    raise
    engine = strip_url_secrets(host) if host else f"context {context}" if context else socket or "local"
    return {"containers": reports.container_rows(raw, matched), "engine": engine}
