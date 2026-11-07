"""State and handlers behind the web API (phase 1: process monitor).

`ProcessMonitor` owns one analysis at a time (snapshot, inspector, views), matches it against the mirror in a
temporary overlay (nothing is written unless `save()`), keeps a `procmon.Watcher` for `/api/processes/watch`, and
builds the JSON payloads with the same helpers as the CLI (`procmon.snapshot_payload`, `procmon.event_dict`).
Also used by scripts/design_mock.py to generate the design mock, so the design renders real payloads.
"""

from __future__ import annotations

import contextlib
import threading
from pathlib import Path
from typing import Any

from .. import db as dbm
from .. import procmon
from ..collectors.process.collector import ProcessCollector


class ApiError(Exception):
    def __init__(self, status: int, message: str, hint: str | None = None):
        super().__init__(message)
        self.status, self.message, self.hint = status, message, hint


class ProcessMonitor:
    def __init__(self, *, db_path: Path, target: str | None = None, opts: dict[str, Any] | None = None,
                 min_confidence: float = 0.5):
        self.db_path = Path(db_path)
        self.target = target
        self.opts = dict(opts or {})
        self.min_confidence = min_confidence
        self.collector = ProcessCollector()
        self.lock = threading.RLock()
        self.snap = self.inspector = self.views = None
        self.inv = None
        self.fmap: dict = {}
        self.matched = False
        self.dirty = False          # views changed by a watch tick: rebuild inventory + match on next payload()
        self.watcher: procmon.Watcher | None = None

    # ------------------------------------------------------------------ helpers
    @property
    def source(self) -> str:
        return "snapshot" if self.target else "live"

    def _collect_error(self, e: Exception) -> ApiError:
        msg = f"{type(e).__name__}: {e}"
        hint = None
        if "not implemented" in str(e):
            hint = ("Live process snapshots exist only on macOS so far. Start the UI with a snapshot file: "
                    "secmonk ui --snapshot snap.json (take one on a Mac with `secmonk procs --snapshot-out snap.json`).")
        return ApiError(503, msg, hint)

    @contextlib.contextmanager
    def _overlay(self):
        """Connection to the mirror with the inventory tables shadowed (nothing persisted); None without a DB."""
        if not self.db_path.exists():
            yield None
            return
        conn = dbm.connect(self.db_path)
        try:
            dbm.ephemeral_overlay(conn)
            yield conn
        finally:
            conn.close()

    def _inventory(self):
        from ..engine.classify import classify

        inv = self.collector.inventory(self.snap, self.inspector, self.views, self.opts)
        for c in inv.components:
            classify(c)
        return inv

    def _analyse(self) -> None:
        from ..cli import COLLECT_ERRORS

        try:
            snap, inspector, views = self.collector.analyse(self.target, **self.opts)
        except COLLECT_ERRORS as e:
            raise self._collect_error(e) from e
        self.snap, self.inspector, self.views = snap, inspector, views
        self.watcher = None                                  # a new baseline
        self._rematch()

    def _rematch(self) -> None:
        self.inv = self._inventory()
        with self._overlay() as conn:
            self.matched = conn is not None
            self.fmap = procmon.match_inventory(conn, self.inv, self.min_confidence) if conn is not None else {}
        self.dirty = False

    # ------------------------------------------------------------------ endpoints
    def payload(self, refresh: bool = False) -> dict[str, Any]:
        with self.lock:
            if refresh or self.snap is None:
                self._analyse()
            elif self.dirty:
                self._rematch()
            return procmon.snapshot_payload(self.snap, self.views, self.inv, self.fmap,
                                            source=self.source, matched=self.matched)

    def watch(self) -> dict[str, Any]:
        """One watch tick. The first call primes the watcher with the current snapshot (no events)."""
        from ..cli import COLLECT_ERRORS

        with self.lock:
            if self.snap is None:
                self._analyse()
            if self.watcher is None:
                self.watcher = procmon.Watcher(self.inspector)
                self.watcher.tick(self.snap)
                return {"events": [], "taken_at": self.snap.taken_at, "baseline": True}
            try:
                snap = self.collector.snapshot(self.target, **{k: v for k, v in self.opts.items() if k != "snapshot_out"})
            except COLLECT_ERRORS as e:
                raise self._collect_error(e) from e
            views, events = self.watcher.tick(snap)
            fmap: dict = {}
            fresh = [e.data["view"] for e in events if e.kind in ("new-executable", "changed-executable")]
            if fresh:
                with self._overlay() as conn:
                    if conn is not None:
                        inc = self.collector.inventory(snap, self.inspector, fresh, self.opts)
                        inc.asset.id += "#watch"
                        fmap = procmon.match_inventory(conn, inc, self.min_confidence)
            self.snap, self.views, self.dirty = snap, views, True
            return {"events": [procmon.event_dict(e, fmap) for e in events], "taken_at": snap.taken_at,
                    "baseline": False}

    def save(self) -> dict[str, Any]:
        """Persist the current inventory + findings to the database (creates it if needed)."""
        from ..engine.inventory import save_inventory
        from ..engine.match import match_asset

        with self.lock:
            if self.snap is None:
                self._analyse()
            if self.dirty:
                self._rematch()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = dbm.connect(self.db_path)
            try:
                scan_id = save_inventory(conn, self.inv)
                stats = match_asset(conn, self.inv.asset.id, min_confidence=self.min_confidence)
            finally:
                conn.close()
            return {"asset": self.inv.asset.id, "scan_id": scan_id, "stats": stats}
