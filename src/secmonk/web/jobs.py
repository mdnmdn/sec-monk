"""Background jobs of the web UI: `sync` (sources -> mirror) and `scan` (collect -> save -> match).

They can take minutes, so `POST /api/jobs` starts one in a thread and returns at once; the client polls
`GET /api/jobs/<id>` for its log and result. One job at a time (both write the database); the last
`KEEP` jobs stay listed until the server stops. A running job cannot be cancelled (Python threads cannot be
interrupted): stop the server to abort. The steps are `secmonk.ops`, the same ones the CLI runs.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import db as dbm
from .. import ops, reports
from .api import ApiError

KEEP = 20
MAX_LOG = 1000
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


@dataclass
class Job:
    id: int
    kind: str                       # sync | scan
    title: str
    params: dict[str, Any]
    started: str = field(default_factory=dbm.now)
    status: str = "running"         # running | ok | partial | error
    finished: str | None = None
    log: list[str] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def say(self, msg: object) -> None:
        line = _CTRL.sub("", str(msg))[:500]
        with self.lock:
            self.log.append(line)
            del self.log[:-MAX_LOG]

    def to_dict(self, *, log: bool = True) -> dict[str, Any]:
        with self.lock:
            d = {"id": self.id, "kind": self.kind, "title": self.title, "params": self.params,
                 "started": self.started, "finished": self.finished, "status": self.status, "error": self.error,
                 "result": self.result, "log_lines": len(self.log)}
            if log:
                d["log"] = list(self.log)
            return d


def _str_list(v: Any, name: str) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [x for x in v.split(",") if x.strip()]          # comma separated: names may contain spaces
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ApiError(400, f"{name}: expected a list of strings")
    return [x.strip() for x in v if x.strip()]


def _opt_str(v: Any, name: str) -> str | None:
    if v is None or v == "":
        return None
    if not isinstance(v, str):
        raise ApiError(400, f"{name}: expected a string")
    return v.strip() or None


class JobRunner:
    def __init__(self, db_path: Path, *, min_confidence: float = 0.5, enabled: bool = True):
        self.db_path = Path(db_path)
        self.min_confidence = min_confidence
        self.enabled = enabled
        self.jobs: list[Job] = []
        self.lock = threading.Lock()
        self.seq = 0

    # ------------------------------------------------------------------ API
    @property
    def busy(self) -> bool:
        with self.lock:
            return any(j.status == "running" for j in self.jobs)

    def refuse_writes_while_busy(self) -> None:
        """Other writers (re-match, process save) wait for the job instead of failing on a locked database."""
        if self.busy:
            raise ApiError(409, "a job is writing to the database", "Try again when it has finished (Jobs).")

    def list(self) -> list[dict[str, Any]]:
        with self.lock:
            return [j.to_dict(log=False) for j in reversed(self.jobs)]

    def get(self, job_id: int) -> dict[str, Any]:
        with self.lock:
            job = next((j for j in self.jobs if j.id == job_id), None)
        if job is None:
            raise ApiError(404, f"no job {job_id}")
        return job.to_dict()

    def start(self, body: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            raise ApiError(403, "actions are disabled on this server",
                           "The UI listens on a non-loopback address: start it with --allow-actions to run scans and "
                           "syncs from the browser.")
        kind = body.get("kind")
        if kind == "sync":
            title, params, fn = self._prepare_sync(body)
        elif kind == "scan":
            title, params, fn = self._prepare_scan(body)
        else:
            raise ApiError(400, "kind: expected 'sync' or 'scan'")
        with self.lock:
            if any(j.status == "running" for j in self.jobs):
                raise ApiError(409, "another job is running", "Wait for it to finish (Jobs in the sidebar).")
            self.seq += 1
            job = Job(self.seq, kind, title, params)
            self.jobs.append(job)
            del self.jobs[:-KEEP]
        threading.Thread(target=self._run, args=(job, fn), name=f"secmonk-job-{job.id}", daemon=True).start()
        return job.to_dict()

    # ------------------------------------------------------------------ preparation (validation, in the request)
    def _prepare_sync(self, body: dict[str, Any]):
        reg = ops.sources_registry()
        names = ops.expand_sources(_str_list(body.get("sources"), "sources"), reg)
        if not names:
            raise ApiError(400, "sources: choose at least one source (or 'all')")
        unknown = [n for n in names if n not in reg]
        if unknown:
            raise ApiError(400, f"unknown source {', '.join(unknown)} (known: {', '.join(sorted(reg))})")
        limit = body.get("limit")
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
            raise ApiError(400, "limit: expected a positive integer")
        path = _opt_str(body.get("path"), "path")
        if path is not None and not Path(path).expanduser().exists():
            raise ApiError(400, f"path: {path} does not exist (on the machine running secmonk ui)")
        params = {"sources": names, "ecosystems": _str_list(body.get("ecosystems"), "ecosystems"),
                  "since": _opt_str(body.get("since"), "since"), "full": bool(body.get("full")), "limit": limit,
                  "path": path}
        return f"sync {', '.join(names)}", params, lambda job: self._sync(job, reg, params)

    def _prepare_scan(self, body: dict[str, Any]):
        reg = ops.collectors_registry()
        collector = _opt_str(body.get("collector"), "collector")
        if collector not in reg:
            raise ApiError(400, f"collector: expected one of {', '.join(sorted(reg))}")
        target = _opt_str(body.get("target"), "target")
        raw_opts = _str_list(body.get("options"), "options") if isinstance(body.get("options"), list) else \
            [x.strip() for x in (_opt_str(body.get("options"), "options") or "").splitlines() if x.strip()]
        try:
            opts = ops.parse_opts(raw_opts)
        except ValueError as e:
            raise ApiError(400, f"options: {e}") from None
        save = body.get("save", True) is not False
        mc = body.get("min_confidence", self.min_confidence)
        if not isinstance(mc, (int, float)) or isinstance(mc, bool) or not 0 <= mc <= 1:
            raise ApiError(400, "min_confidence: expected a number between 0 and 1")
        if not save and not self.db_path.exists():
            raise ApiError(409, f"no database at {self.db_path}",
                           "A scan without saving needs an existing mirror: sync first, or keep 'Save' on.")
        params = {"collector": collector, "target": target, "options": raw_opts, "save": save,
                  "min_confidence": float(mc)}
        return (f"scan {collector}{' ' + target if target else ''}", params,
                lambda job: self._scan(job, collector, target, opts, save, float(mc)))

    # ------------------------------------------------------------------ execution (worker thread)
    def _run(self, job: Job, fn) -> None:
        try:
            status, result = fn(job)
            error = None
        except Exception as e:  # noqa: BLE001 - collector errors and anything else: report, never kill the server
            status, result, error = "error", None, f"{type(e).__name__}: {e}"
        if error:
            job.say(f"error: {error}")
        with job.lock:
            job.status, job.result, job.error, job.finished = status, result, error, dbm.now()

    def _sync(self, job: Job, reg: dict, p: dict[str, Any]):
        from ..sources.base import SyncOptions

        results = []
        conn = dbm.connect(self.db_path)          # creates the mirror (per-user private dir by default)
        try:
            for name in p["sources"]:
                job.say(f"syncing {name}…")
                opts = SyncOptions(path=Path(p["path"]).expanduser() if p["path"] else None, ecosystems=p["ecosystems"],
                                   since=p["since"], full=p["full"], limit=p["limit"],
                                   api_key=os.environ.get("NVD_API_KEY"), progress=job.say)
                res, secs = ops.sync_source(conn, name, reg[name], opts)
                job.say(f"{name}: {res.status} — {res.records:,} records in {secs:.1f}s {res.message or ''}".rstrip())
                results.append({"source": name, "status": res.status, "records": res.records,
                                "seconds": round(secs, 1), "message": res.message})
        finally:
            conn.close()
        statuses = {r["status"] for r in results}
        status = "error" if "error" in statuses else "partial" if "partial" in statuses else "ok"
        return status, {"sources": results}

    def _scan(self, job: Job, collector: str, target: str | None, opts: dict, save: bool, min_confidence: float):
        job.say(f"collecting with {collector}{' on ' + target if target else ''}…")
        inv = ops.collect(collector, target, opts)
        job.say(f"{inv.asset.id}: {len(inv.components)} components")
        for w in inv.warnings:
            job.say(f"warning: {w}")
        if getattr(inv, "partial", False):
            job.say("partial inventory — previous components kept")
        conn = dbm.connect(self.db_path)
        try:
            if not save:
                dbm.ephemeral_overlay(conn)       # nothing persisted
            job.say("matching against the local mirror…")
            scan_id, stats = ops.save_and_match(conn, inv, min_confidence=min_confidence)
            rows = reports.findings(conn, asset=inv.asset.id, limit=500)
        finally:
            conn.close()
        job.say(" · ".join(f"{v} {k.replace('_', ' ')}" for k, v in stats.items()))
        return "ok", {"asset": inv.asset.id, "saved": save, "scan_id": scan_id if save else None, "stats": stats,
                      "warnings": inv.warnings, "partial": bool(getattr(inv, "partial", False)),
                      "findings": rows, "counts": reports.priority_counts(rows)}
