"""py-procmon: the process monitor state (`web/api.py` `ProcessMonitor`) behind procmon.payload / watch / inventory.

Prototype exception (plan Q6): the module reads this machine (or a snapshot file, or an ssh:// host) and matches the
running software against the mirror read-only, in a TEMP overlay: nothing is written, saving is the host's job
(`procmon.inventory` -> store -> `engine.match`). The monitor itself is today's class; only its database access is
replaced by a read-only session.

Host settings (`hello.session.settings`): `process` = `{"target": <snapshot file | ssh://host | null>,
"options": ["key=value", ...]}` (the `ui.snapshot` of the config), `min_confidence`.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Any

from .common import inventory_to_dict, parse_options
from .db import read_session
from .errors import WireError
from .wire import MethodTable, ModuleDef, Request, Session

TABLE = MethodTable()
_state: dict[str, Any] = {"monitor": None}
_lock = threading.Lock()


def _monitor(session: Session):
    """The one monitor of this process (it owns the snapshot and the watch baseline)."""
    from secmonk.web.api import ProcessMonitor

    class ReadOnlyMonitor(ProcessMonitor):
        @contextlib.contextmanager
        def _overlay(self):
            from secmonk import db as dbm

            if session.db_read is None:
                yield None
                return
            try:
                with read_session(session, temp_writes=True) as (conn, _):
                    dbm.ephemeral_overlay(conn)
                    yield conn
            except WireError as e:
                if e.code != "no-db":
                    raise
                yield None

    with _lock:
        if _state["monitor"] is None:
            cfg = session.settings.get("process") if isinstance(session.settings.get("process"), dict) else {}
            opts = parse_options([x for x in cfg.get("options", []) if isinstance(x, str)])
            opts.pop("snapshot_out", None)                    # a module writes nothing outside its own directory
            conf = session.settings.get("min_confidence")
            _state["monitor"] = ReadOnlyMonitor(db_path=session.db_read["state"] if session.db_read else "",
                                                target=cfg.get("target") or None, opts=opts,
                                                min_confidence=float(conf) if isinstance(conf, (int, float)) else 0.5)
        return _state["monitor"]


def _call(ctx: Request, fn):
    """Run `fn(monitor)`; the monitor's `ApiError` (a collect failure, HTTP 503) becomes a wire error."""
    from secmonk.web.api import ApiError

    try:
        return fn(_monitor(ctx.session))
    except ApiError as e:
        unsupported = e.message.startswith("UnsupportedPlatformError")
        raise WireError("unsupported-platform" if unsupported else "collect-error", e.message, e.hint) from None


@TABLE.unary("procmon.payload", {"refresh?": bool})
def payload(ctx: Request, p: dict) -> dict[str, Any]:
    return _call(ctx, lambda m: m.payload(refresh=bool(p.get("refresh", False))))


@TABLE.unary("procmon.watch", {})
def watch(ctx: Request, p: dict) -> dict[str, Any]:
    return _call(ctx, lambda m: m.watch())


@TABLE.unary("procmon.inventory", {})
def inventory(ctx: Request, p: dict) -> dict[str, Any]:
    """The classified inventory of the current analysis, for the host to save (`ProcessMonitor.save` minus the write)."""
    def build(m):
        with m.lock:
            if m.snap is None:
                m._analyse()
            if m.dirty:
                m._rematch()
            return {"inventory": inventory_to_dict(m.inv, classified=True)}

    return _call(ctx, build)


def module() -> ModuleDef:
    return ModuleDef(name="py-procmon", kind="engine", capabilities=["local-system", "run-commands", "db-read", "stateful"],
                     max_inflight=1, methods=TABLE,
                     description="Process monitor state (snapshot, watch) for the Processes views; prototype exception: "
                                 "reads this machine and matches read-only")
