"""Operations shared by the CLI and the web UI's background jobs: collector options, source expansion,
one-source sync (with its `source_sync` bookkeeping) and collect -> save -> match.

The CLI wraps these with its own output (rich, exit codes); `web/jobs.py` with a job log. Neither re-implements them.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from typing import Any

from . import db as dbm

# `sync all` order: small authoritative feeds first, then bulk; any source not listed runs last, unless it sets
# `in_all = False` (e.g. one that needs credentials or a very large download).
SYNC_ALL_ORDER = ("kev", "epss", "osv", "cvelist", "nvd", "euvd", "msrc", "debian-tracker")
# Collector options that really are booleans / comma-separated lists (see parse_opts).
BOOL_OPTS = frozenset({"binaries", "sudo", "all_kegs", "use_brew_cli", "include_system",
                       "insecure_host_key", "xdev", "no_cache", "lang", "verbose",
                       "allow_agent", "look_for_keys"})
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


def save_and_match(conn: sqlite3.Connection, inv, *, min_confidence: float = 0.5) -> tuple[int, dict]:
    """Persist an inventory and match its asset (in an ephemeral overlay when the caller set one up)."""
    from .engine.inventory import save_inventory
    from .engine.match import match_asset

    scan_id = save_inventory(conn, inv)
    return scan_id, match_asset(conn, inv.asset.id, min_confidence=min_confidence)
