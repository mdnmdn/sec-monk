"""source.sync / source.ack / source.export (contracts.md (d), rust ADR-0010)."""

from __future__ import annotations

import contextlib
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..errors import Cancelled, WireError
from ..wire import Request
from . import TABLE, staging

BATCH_OPS = 5000                       # rows.schema.json: ops <= 5000 per batch
BATCH_BYTES = 2 * 1024 * 1024          # well below max_frame, whatever the row sizes

SYNC_OPTIONS = {"path": (str, type(None)), "ecosystems": list, "ids": list, "since": (str, type(None)),
                "full": bool, "limit": (int, type(None))}


def _sync_options(raw: dict[str, Any], secrets: dict[str, Any], ctx: Request):
    from secmonk.sources.base import SyncOptions

    unknown = sorted(set(raw) - set(SYNC_OPTIONS))
    if unknown:
        raise WireError("invalid-params", f"options: unknown key(s) {', '.join(unknown)}")
    for k, v in raw.items():
        types = SYNC_OPTIONS[k] if isinstance(SYNC_OPTIONS[k], tuple) else (SYNC_OPTIONS[k],)
        if not isinstance(v, types) or (isinstance(v, bool) and bool not in types):
            raise WireError("invalid-params", f"options.{k}: wrong type")
    for k in ("ecosystems", "ids"):
        if not all(isinstance(x, str) for x in raw.get(k, [])):
            raise WireError("invalid-params", f"options.{k}: expected an array of strings")
    if raw.get("limit") is not None and raw["limit"] < 1:
        raise WireError("invalid-params", "options.limit: expected >= 1")
    unknown = sorted(set(secrets) - {"api_key"})
    if unknown:
        raise WireError("invalid-params", f"secrets: unknown key(s) {', '.join(unknown)}")
    if secrets.get("api_key") is not None and not isinstance(secrets["api_key"], str):
        raise WireError("invalid-params", "secrets.api_key: expected a string")
    return SyncOptions(path=Path(raw["path"]) if raw.get("path") else None, ecosystems=list(raw.get("ecosystems", [])),
                       ids=list(raw.get("ids", [])), since=raw.get("since"), full=bool(raw.get("full", False)),
                       limit=raw.get("limit"), api_key=secrets.get("api_key"),
                       progress=lambda m: ctx.progress(str(m)))      # also the cancel point: raises Cancelled


def _check_source(name: str) -> type:
    from secmonk import ops

    reg = ops.sources_registry()
    if name not in reg:
        raise WireError("unknown-source", f"unknown source {name!r} (known: {', '.join(sorted(reg))})")
    return reg[name]


def _open(ctx: Request) -> sqlite3.Connection:
    try:
        return staging.open_staging(staging.staging_path(ctx.session.settings))
    except OSError as e:
        raise WireError("internal", f"cannot open the staging database: {type(e).__name__}") from None


def _event(src: str, seq: int, ops: list[dict[str, Any]], gen: str, acked: int) -> dict[str, Any]:
    """A `secmonk-mirror-rows/1` batch, bound to this staging file (`generation`) and to what the host acknowledged
    (`acked_through`): the host never skips a batch of another generation (rust ADR-0010)."""
    return {"kind": "rows", "seq": seq, "source": src, "ops": ops, "generation": gen, "acked_through": acked}


@TABLE.stream("source.sync", {"source": str, "options": dict, "secrets?": dict})
def sync(ctx: Request, p: dict) -> Iterator[dict[str, Any]]:
    """Run the unchanged source on the staging database, then stream what changed (replaying un-acknowledged batches
    first). A failing source is not an `err`: the `end` result carries its `entry` with status `error`."""
    from secmonk import ops

    name = p["source"]
    cls = _check_source(name)
    opts = _sync_options(p["options"], p.get("secrets") or {}, ctx)
    with staging.LOCK:
        conn = _open(ctx)
        try:
            staging.set_source(conn, name)
            res, secs = ops.sync_source(conn, name, cls, opts, on_exception=lambda e: ctx.log(
                "error", f"{name}: {type(e).__name__}"))
            entry = ops.sync_entry(name, res, secs)
            entry["message"] = _scrub(entry.get("message"))
            ctx.progress(f"{name}: {entry['status']}, {entry['records']} records in {entry['seconds']}s; streaming "
                         "the changes")
            batches = n_ops = last = 0
            gen, acked = staging.generation(conn), staging.acked_through(conn, name)
            for seq, batch_ops in staging.pending_batches(conn, name, max_ops=BATCH_OPS, max_bytes=BATCH_BYTES):
                yield _event(name, seq, batch_ops, gen, acked)
                batches, n_ops, last = batches + 1, n_ops + len(batch_ops), seq
            return {"entry": entry, "batches": batches, "last_seq": last, "ops": n_ops}
        except Cancelled:
            with contextlib.suppress(sqlite3.Error):
                conn.rollback()
            raise
        finally:
            with contextlib.suppress(sqlite3.Error):
                staging.set_source(conn, None)
            conn.close()


def _scrub(text: str | None) -> str | None:
    from secmonk.collectors.base import scrub_text

    return scrub_text(text)


@TABLE.unary("source.ack", {"source": str, "through_seq": int})
def ack(ctx: Request, p: dict) -> dict:
    """The host applied every batch up to `through_seq`: drop them from the change log."""
    _check_source(p["source"])
    if p["through_seq"] < 0:
        raise WireError("invalid-params", "through_seq: expected >= 0")
    with staging.LOCK:
        conn = _open(ctx)
        try:
            staging.ack(conn, p["source"], p["through_seq"])
        finally:
            conn.close()
    return {}


@TABLE.stream("source.export", {"source": str, "through_seq": int})
def export(ctx: Request, p: dict) -> Iterator[dict[str, Any]]:
    """Every staging row of a source as upserts, to rebuild the host's mirror (the repair path of rust ADR-0010).
    `through_seq` is not used: the export is always the whole current state. Changes not numbered yet are numbered
    first, so `high_water` (end) covers everything the exported state contains: the host records it as its applied
    seq and acknowledges through it, and a later replay of any older batch is skipped. Batch seqs count from 1."""
    name = p["source"]
    _check_source(name)
    t0 = time.monotonic()
    with staging.LOCK:
        conn = _open(ctx)
        try:
            staging.number_pending(conn, name, max_ops=BATCH_OPS, max_bytes=BATCH_BYTES)
            gen, acked, hw = staging.generation(conn), staging.acked_through(conn, name), staging.high_water(conn)
            batches = n_ops = 0
            for seq, batch_ops in staging.source_rows(conn, name, max_ops=BATCH_OPS, max_bytes=BATCH_BYTES):
                ctx.check()
                yield _event(name, seq, batch_ops, gen, acked)
                batches, n_ops = seq, n_ops + len(batch_ops)
            return {"entry": {"source": name, "status": "ok", "records": n_ops,
                              "seconds": round(time.monotonic() - t0, 1), "message": None},
                    "batches": batches, "last_seq": batches, "ops": n_ops, "generation": gen, "high_water": hw}
        finally:
            conn.close()
