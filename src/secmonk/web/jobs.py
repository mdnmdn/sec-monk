"""Background jobs of the web UI: `sync` (sources -> mirror) and `scan` (targets -> collect -> save -> match).

They can take minutes, so `POST /api/jobs` starts one in a thread and returns at once; the client polls
`GET /api/jobs/<id>` for its log and result. One job at a time (both write the database). Every job is also a row of
the run history (table `job`, shared with the CLI's runs): its id is the row id, the row is written when the job
starts and when it ends, so `GET /api/jobs` lists the runs of earlier servers and of the CLI too. The last `KEEP`
jobs of this server stay in memory (live log). A running job cannot be cancelled (Python threads cannot be
interrupted): stop the server to abort; the next server shows such a run as an error, "interrupted".
The steps are `secmonk.ops`, the same ones the CLI runs.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import db as dbm
from .. import ops, reports
from ..collectors.base import scrub_text
from .api import ApiError

KEEP = 20
MAX_LOG = 1000
LIST_MAX = 200
# collector options a scan started from the browser may not set: they choose what runs on this machine (the CLI keeps
# them); the same policy as GET /api/discover
WEB_FORBIDDEN_SCAN_OPTS = frozenset({"ssh_bin", "transport", "ssh_option"})


def _web_item(collector: Any, target: Any, options: Any, where: str, id: Any = None):
    """ops.scan_item + the web policy (WEB_FORBIDDEN_SCAN_OPTS); ApiError 400 prefixed with `where`."""
    try:
        item = ops.scan_item(collector, target, options, id)
    except ValueError as e:
        raise ApiError(400, f"{where}: {e}") from None
    bad = sorted(set(item.opts) & WEB_FORBIDDEN_SCAN_OPTS)
    if bad:
        raise ApiError(400, f"{where}: option not accepted from the browser: {', '.join(bad)}",
                       "Run scans that need a custom ssh binary, transport or ssh_option with the secmonk CLI.")
    return item


# docker-engine options the containers listing accepts from the browser (no `socket`, no `ssh_bin`: a path to run)
DOCKER_LIST_OPTS = frozenset({"tls_ca", "tls_cert", "tls_key", "tls_verify", "identity", "timeout", "connect_timeout"})
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


@dataclass
class Job:
    id: int
    kind: str                       # sync | scan
    title: str
    params: dict[str, Any]          # redacted (what is shown and stored)
    origin: str = "ui"
    started: str = field(default_factory=dbm.now)
    status: str = "running"         # running | ok | partial | error
    finished: str | None = None
    log: list[str] = field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def say(self, msg: object) -> None:
        line = scrub_text(_CTRL.sub("", str(msg)))[:500]
        with self.lock:
            self.log.append(line)
            del self.log[:-MAX_LOG]

    def to_dict(self, *, log: bool = True) -> dict[str, Any]:
        with self.lock:
            return reports.job_payload(id=self.id, kind=self.kind, origin=self.origin, title=self.title,
                                       params=self.params, started=self.started, finished=self.finished,
                                       status=self.status, error=self.error, result=self.result, log=self.log,
                                       include_log=log)


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
        self.starting = False                 # a start() between its check and its job being listed
        self.discovering = threading.Lock()   # one host discovery at a time (it runs ssh / probes)
        if enabled and self.db_path.exists():
            # runs whose process is gone (dead server, killed CLI) -> error "interrupted"; lists show them so anyway
            # (reports.job_dict), this only makes it permanent. Never blocks the server from starting.
            try:
                conn = dbm.connect(self.db_path)
                try:
                    dbm.job_mark_interrupted(conn)
                finally:
                    conn.close()
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------------ API
    @property
    def busy(self) -> bool:
        with self.lock:
            return self.starting or any(j.status == "running" for j in self.jobs)

    def refuse_writes_while_busy(self) -> None:
        """Other writers (re-match, process save) wait for the job instead of failing on a locked database."""
        if self.busy:
            raise ApiError(409, "a job is writing to the database", "Try again when it has finished (Jobs).")

    def require_actions(self) -> None:
        if not self.enabled:
            raise ApiError(403, "actions are disabled on this server",
                           "The UI listens on a non-loopback address: start it with --allow-actions to run scans, "
                           "syncs and docker queries from the browser.")

    def list(self, kind: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """This server's jobs merged with the stored history (CLI runs, earlier servers), newest first."""
        if kind not in (None, "scan", "sync"):
            raise ApiError(400, "kind: expected 'scan' or 'sync'")
        if not 1 <= limit <= LIST_MAX:
            raise ApiError(400, f"limit: expected 1..{LIST_MAX}")
        out: dict[int, dict[str, Any]] = {}
        if self.db_path.exists():
            conn = dbm.connect(self.db_path)
            try:
                for r in dbm.job_rows(conn, kind=kind, limit=limit):
                    out[r["id"]] = reports.job_dict(r, include_log=False)
            finally:
                conn.close()
        with self.lock:
            live = [j for j in self.jobs if kind is None or j.kind == kind]
        for j in live:                         # live state wins over the stored row
            out[j.id] = j.to_dict(log=False)
        return [out[i] for i in sorted(out, reverse=True)[:limit]]

    def get(self, job_id: int) -> dict[str, Any]:
        with self.lock:
            job = next((j for j in self.jobs if j.id == job_id), None)
        if job is not None:
            return job.to_dict()
        row = None
        if self.db_path.exists():
            conn = dbm.connect(self.db_path)
            try:
                row = dbm.job_row(conn, job_id)
            finally:
                conn.close()
        if row is None:
            raise ApiError(404, f"no job {job_id}")
        return reports.job_dict(row)

    def start(self, body: dict[str, Any]) -> dict[str, Any]:
        self.require_actions()
        kind = body.get("kind")
        if kind == "sync":
            title, params, fn = self._prepare_sync(body)
        elif kind == "scan":
            title, params, fn = self._prepare_scan(body)
        else:
            raise ApiError(400, "kind: expected 'sync' or 'scan'")
        with self.lock:
            if self.starting or any(j.status == "running" for j in self.jobs):
                raise ApiError(409, "another job is running", "Wait for it to finish (Jobs in the sidebar).")
            self.starting = True              # holds the slot while the history row is written (outside the lock)
        try:
            job = Job(0, kind, title, params)
            conn = dbm.connect(self.db_path)  # the history row (creates the mirror, as the job itself would)
            try:
                job.id = dbm.job_insert(conn, kind=kind, origin=job.origin, title=title, params=params,
                                        started_at=job.started)
            finally:
                conn.close()
        except sqlite3.Error as e:
            with self.lock:
                self.starting = False
            raise ApiError(503, f"cannot record the job: {type(e).__name__}: {e}", "Try again in a moment.") from None
        with self.lock:
            self.jobs.append(job)
            del self.jobs[:-KEEP]
            self.starting = False
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
        return ops.sync_title(names), params, lambda job: self._sync(job, reg, params)

    def _scan_common(self, body: dict[str, Any]) -> tuple[bool, float]:
        save = body.get("save", True) is not False
        mc = body.get("min_confidence", self.min_confidence)
        if not isinstance(mc, (int, float)) or isinstance(mc, bool) or not 0 <= mc <= 1:
            raise ApiError(400, "min_confidence: expected a number between 0 and 1")
        if not save and not self.db_path.exists():
            raise ApiError(409, f"no database at {self.db_path}",
                           "A scan without saving needs an existing mirror: sync first, or keep 'Save' on.")
        return save, float(mc)

    def _prepare_scan(self, body: dict[str, Any]):
        if body.get("items") is not None:
            return self._prepare_batch(body)
        reg = ops.collectors_registry()
        collector = _opt_str(body.get("collector"), "collector")
        if collector not in reg:
            raise ApiError(400, f"collector: expected one of {', '.join(sorted(reg))}")
        target = _opt_str(body.get("target"), "target")
        raw_opts = _str_list(body.get("options"), "options") if isinstance(body.get("options"), list) else \
            [x.strip() for x in (_opt_str(body.get("options"), "options") or "").splitlines() if x.strip()]
        item = _web_item(collector, target, raw_opts, "options")
        save, mc = self._scan_common(body)
        params = ops.scan_params(collector, target, raw_opts, save=save, min_confidence=mc)
        return (ops.scan_title(collector, target), params,
                lambda job: self._scan(job, [item], save, mc, strict_expand=True))

    def _prepare_batch(self, body: dict[str, Any]):
        """Host mode: {kind: scan, items: [{collector, target, options}], save, min_confidence, host}."""
        raw = body.get("items")
        if not isinstance(raw, list) or not raw:
            raise ApiError(400, "items: expected a non-empty list of {collector, target, options}")
        if len(raw) > ops.MAX_ITEMS:
            raise ApiError(400, f"items: at most {ops.MAX_ITEMS} per scan")
        items = []
        for n, it in enumerate(raw, 1):
            if not isinstance(it, dict):
                raise ApiError(400, f"items[{n}]: expected an object {{collector, target, options}}")
            items.append(_web_item(it.get("collector"), it.get("target"), it.get("options"), f"items[{n}]",
                                   it.get("id")))
        host = _opt_str(body.get("host"), "host")
        save, mc = self._scan_common(body)
        params = ops.batch_params(items, save=save, min_confidence=mc, host=host)
        return (ops.batch_title(host, [i.id or i.collector for i in items]), params,
                lambda job: self._scan(job, items, save, mc))

    # ------------------------------------------------------------------ execution (worker thread)
    def _run(self, job: Job, fn) -> None:
        try:
            out = fn(job)
            status, result = out[0], out[1]
            error = out[2] if len(out) > 2 else None
        except Exception as e:  # noqa: BLE001 - collector errors and anything else: report, never kill the server
            status, result, error = "error", None, f"{type(e).__name__}: {e}"
        error = scrub_text(error)
        if error:
            job.say(f"error: {error}")
        with job.lock:
            log = list(job.log)
        try:                                   # stored before the job shows as finished
            conn = dbm.connect(self.db_path)
            try:
                ops.finish_run(conn, job.id, job.kind, status=status, result=result, error=error, log=log)
            finally:
                conn.close()
        except Exception as e:  # noqa: BLE001 - the in-memory job still reports the outcome
            job.say(f"could not record the run in the history: {type(e).__name__}: {e}")
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
                results.append(ops.sync_entry(name, res, secs))
        finally:
            conn.close()
        return ops.sync_status(results), {"sources": results}

    def _scan(self, job: Job, items: list, save: bool, min_confidence: float, *, strict_expand: bool = False):
        """ops.scan_items: a single-collector job fails as a whole when its target matches nothing
        (strict_expand); in a batch that item gets an error entry and the others run."""
        conn = dbm.connect(self.db_path)
        try:
            if not save:
                dbm.ephemeral_overlay(conn)       # nothing persisted (the history row lives on the real table)
            entries = ops.scan_items(conn, items, save=save, min_confidence=min_confidence, say=job.say,
                                     strict_expand=strict_expand)
        finally:
            conn.close()
        return ops.scan_result(entries, saved=save)

    # ------------------------------------------------------------------ host discovery (contacts the host)
    def discover(self, *, target: str | None, options: list[str]) -> dict[str, Any]:
        self.require_actions()
        try:
            opts = ops.parse_opts(options)
        except ValueError as e:
            raise ApiError(400, f"opt: {e}") from None
        bad = sorted(set(opts) - ops.DISCOVER_WEB_OPTS)
        if bad:
            raise ApiError(400, f"opt: not accepted here: {', '.join(bad)}",
                           f"Allowed: {', '.join(sorted(ops.DISCOVER_WEB_OPTS))}.")
        if not self.discovering.acquire(blocking=False):
            raise ApiError(409, "a discovery is already running", "Wait for it to finish, then try again.")
        try:
            return ops.discover_host(target, opts)
        except ValueError as e:
            raise ApiError(400, scrub_text(f"{type(e).__name__}: {e}") or "invalid request",
                           "Expected nothing (this machine) or [ssh://]user@host[:port].") from None
        except Exception as e:  # noqa: BLE001
            raise ApiError(502, f"cannot explore the host ({type(e).__name__})",
                           "Is the host reachable over ssh with a key (no password prompt) from the machine running "
                           "secmonk ui? `secmonk discover <target>` shows the full error.") from None
        finally:
            self.discovering.release()

    # ------------------------------------------------------------------ docker engine (contacts other hosts)
    def docker_contexts(self) -> list[dict]:
        self.require_actions()
        try:
            return ops.docker_contexts()
        except Exception as e:  # noqa: BLE001
            raise _engine_error(e) from None

    def docker_containers(self, *, host: str | None, context: str | None, all: bool, match: str | None,
                          options: list[str] | None = None) -> dict[str, Any]:
        """`options`: docker-engine `key=value` options, only DOCKER_LIST_OPTS (TLS material, ssh identity, timeouts)."""
        self.require_actions()
        try:
            opts = ops.parse_opts(options)
        except ValueError as e:
            raise ApiError(400, f"opt: {e}") from None
        bad = sorted(set(opts) - DOCKER_LIST_OPTS)
        if bad:
            raise ApiError(400, f"opt: not accepted here: {', '.join(bad)}",
                           f"Allowed: {', '.join(sorted(DOCKER_LIST_OPTS))}; use the host, context and all parameters.")
        try:
            return ops.docker_containers(host=host, context=context, all=all, match=match, opts=opts)
        except Exception as e:  # noqa: BLE001
            raise _engine_error(e) from None


def _engine_error(e: Exception) -> ApiError:
    """Bad input -> 400 with our own message; anything from the engine -> 502 with a generic message (an engine's
    reply body is never echoed to the browser; `secmonk containers -v` shows the details)."""
    if isinstance(e, ValueError):
        return ApiError(400, scrub_text(f"{type(e).__name__}: {e}") or "invalid request",
                        "Check the host (unix:// tcp:// ssh://user@host), the context name and the selector "
                        "(names, globs, re:<regex>, comma separated).")
    return ApiError(502, f"cannot reach the Docker engine ({type(e).__name__})",
                    "Is the Docker/Podman engine running and reachable from the machine running secmonk ui? For ssh:// "
                    "hosts the key must be usable without a prompt. `secmonk containers` with the same host / context "
                    "shows the engine's own error.")
