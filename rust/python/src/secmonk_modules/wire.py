"""secmonk-wire/1: framing, envelope, hello, dispatch, cancel, caps (contracts.md (a)).

One server per module process. The main thread reads frames; every request runs on its own daemon thread (at most
`max_inflight` at a time); a lock serializes frame writes. A frame is a 4-byte big-endian length plus one UTF-8 JSON
object. Nothing in here imports the `secmonk` package.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import sys
import threading
import time
import traceback
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from . import PROTOCOL, __version__
from .errors import Cancelled, ProtocolError, WireError

log = logging.getLogger("secmonk_modules.wire")

HARD_MAX_FRAME = 64 * 1024 * 1024
DEFAULT_MAX_FRAME = 16 * 1024 * 1024
MIN_MAX_FRAME = 65536
CHUNK_ITEMS = 1000
MAX_ID = 9007199254740991
_METHOD = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$")


# --------------------------------------------------------------------------- stdio ownership

_claimed: tuple[BinaryIO, BinaryIO] | None = None


def claim_stdio() -> tuple[BinaryIO, BinaryIO]:
    """Take private copies of the original stdin / stdout descriptors for frames, then point fd 0 at the null
    device and fd 1 / `sys.stdout` at stderr: a stray `print` (or a C library, or a subprocess that inherited fd 0
    or 1) can neither corrupt the frames nor consume them. Idempotent. Returns (frames in, frames out)."""
    global _claimed
    if _claimed is not None:
        return _claimed
    in_fd, out_fd = os.dup(0), os.dup(1)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    os.dup2(2, 1)
    if sys.platform == "win32":  # pragma: no cover  (frames are binary)
        import msvcrt

        msvcrt.setmode(in_fd, os.O_BINARY)
        msvcrt.setmode(out_fd, os.O_BINARY)
    sys.stdout = sys.stderr
    sys.stdin = io.TextIOWrapper(io.BufferedReader(io.FileIO(os.devnull, "rb")))
    for stream in (sys.stderr,):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace", line_buffering=True)
        except (AttributeError, ValueError):  # pragma: no cover
            pass
    _claimed = (os.fdopen(in_fd, "rb"), os.fdopen(out_fd, "wb", buffering=0))
    return _claimed


class LogFormatter(logging.Formatter):
    """`LEVEL logger: message`, one line per record (newlines in a message are escaped: a target's file name must
    not forge a log line)."""

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        if record.exc_info:
            msg += " | " + "".join(traceback.format_exception_only(*record.exc_info[:2])).strip()
        return f"{record.levelname} {record.name}: " + msg.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")


def setup_logging(level: str | None = None) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(LogFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel((level or os.environ.get("SECMONK_MODULE_LOG") or "INFO").upper())


# --------------------------------------------------------------------------- framing

def _nan(token: str) -> Any:
    raise ValueError(f"non-finite number {token}")


def decode_frame(body: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(body.decode("utf-8"), parse_constant=_nan)
    except UnicodeDecodeError as e:
        raise ProtocolError(f"frame is not valid UTF-8: {e.reason}") from None
    except (ValueError, RecursionError) as e:
        raise ProtocolError(f"frame is not valid JSON: {str(e)[:100]}") from None
    if not isinstance(obj, dict):
        raise ProtocolError("frame is not a JSON object")
    return obj


def encode_frame(obj: dict[str, Any], max_frame: int) -> bytes:
    """Frame bytes. Unknown Python types are stringified; lone surrogates (undecodable file names) are replaced.
    A frame above `max_frame` is refused (the caller turns that into an `internal` error)."""
    try:
        text = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False, default=str)
    except ValueError as e:
        raise WireError("internal", f"result is not JSON: {e}") from None
    body = text.encode("utf-8", "replace")
    if len(body) > max_frame:
        raise WireError("internal", f"frame of {len(body)} bytes exceeds max_frame {max_frame}")
    return len(body).to_bytes(4, "big") + body


def read_exact(stream: BinaryIO, n: int) -> bytes | None:
    """`n` bytes, or None at a clean EOF before the first byte; a short read raises ProtocolError."""
    data = stream.read(n)
    if not data and n:
        return None
    if len(data) < n:
        raise ProtocolError("truncated frame")
    return data


def read_frame(stream: BinaryIO, max_frame: int) -> dict[str, Any] | None:
    hdr = stream.read(4)
    if not hdr:
        return None
    if len(hdr) < 4:
        raise ProtocolError("truncated frame header")
    n = int.from_bytes(hdr, "big")
    if n > max_frame:
        raise ProtocolError(f"frame of {n} bytes exceeds max_frame {max_frame}")
    body = stream.read(n) if n else b""
    if len(body) < n:
        raise ProtocolError("truncated frame")
    return decode_frame(body)


# --------------------------------------------------------------------------- params

def check_params(spec: dict[str, Any] | None, params: dict[str, Any]) -> dict[str, Any]:
    """Light validation of a request's params against a method's spec: `{"name": type | (types...)}`, a name
    ending in `?` is optional. Unknown keys and wrong types are `invalid-params` (value rules live in handlers; the
    JSON Schemas of rust/contracts are checked by the conformance tests)."""
    if spec is None:
        return params
    allowed: dict[str, tuple[bool, tuple[type, ...]]] = {}
    for key, typ in spec.items():
        optional = key.endswith("?")
        allowed[key.rstrip("?")] = (not optional, typ if isinstance(typ, tuple) else (typ,))
    unknown = sorted(set(params) - set(allowed))
    if unknown:
        raise WireError("invalid-params", f"unknown parameter(s): {', '.join(unknown)}")
    for name, (required, types) in allowed.items():
        if name not in params:
            if required:
                raise WireError("invalid-params", f"{name}: required")
            continue
        v = params[name]
        ok = any(isinstance(v, t) and not (isinstance(v, bool) and t in (int, float)) for t in types)
        if not ok and float in types and isinstance(v, int) and not isinstance(v, bool):
            ok = True
        if not ok and type(None) in types and v is None:
            ok = True
        if not ok:
            names = "|".join("null" if t is type(None) else t.__name__ for t in types)
            raise WireError("invalid-params", f"{name}: expected {names}")
    return params


# --------------------------------------------------------------------------- module description

@dataclass
class Method:
    name: str
    handler: Callable[..., Any]
    stream: bool = False
    params: dict[str, Any] | None = None


class MethodTable:
    """Registry of one module's methods: `@table.unary("a.b", {"x": str})`, `@table.stream(...)` (a generator;
    its `return` value is the `end` result)."""

    def __init__(self) -> None:
        self.methods: dict[str, Method] = {}

    def _add(self, name: str, stream: bool, params: dict[str, Any] | None) -> Callable[[Callable], Callable]:
        def deco(fn: Callable) -> Callable:
            assert name not in self.methods and _METHOD.match(name), name
            self.methods[name] = Method(name, fn, stream, params)
            return fn

        return deco

    def unary(self, name: str, params: dict[str, Any] | None = None) -> Callable[[Callable], Callable]:
        return self._add(name, False, params)

    def stream(self, name: str, params: dict[str, Any] | None = None) -> Callable[[Callable], Callable]:
        return self._add(name, True, params)


@dataclass
class ModuleDef:
    name: str
    kind: str
    description: str
    capabilities: list[str]
    methods: MethodTable
    max_inflight: int = 4
    provides_extra: Callable[[], dict[str, Any]] | None = None   # collectors / sources / sync_all_order
    on_session: Callable[[Session], None] | None = None

    def provides(self) -> dict[str, Any]:
        out = dict(self.provides_extra()) if self.provides_extra else {}
        out["methods"] = sorted(self.methods.methods)
        return out


@dataclass
class Session:
    """What the host's `hello` tells the module (contracts.md (a), hello and capabilities)."""

    module: str | None = None
    grants: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    max_frame: int = DEFAULT_MAX_FRAME

    @property
    def db_read(self) -> dict[str, Any] | None:
        g = self.grants.get("db_read")
        return g if isinstance(g, dict) and g.get("state") and g.get("mirror") else None


class Request:
    """What a handler sees: ids, params, the session, cancellation and progress."""

    def __init__(self, server: Server, req_id: int, method: str, params: dict[str, Any], deadline_ms: int | None):
        self.server, self.id, self.method, self.params = server, req_id, method, params
        self.session = server.session
        self.cancelled = threading.Event()
        self.deadline = time.monotonic() + deadline_ms / 1000 if deadline_ms else None

    @property
    def chunk_items(self) -> int:
        return CHUNK_ITEMS

    @property
    def max_frame(self) -> int:
        return self.session.max_frame

    def check(self) -> None:
        """Cooperative cancellation point: raises Cancelled (host cancel, or the server is shutting down) or a
        `timeout` WireError (deadline_ms passed). Long loops call it between items."""
        if self.cancelled.is_set() or self.server.stopping.is_set():
            raise Cancelled()
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise WireError("timeout", "deadline exceeded")

    def progress(self, message: str | None = None, done: int | None = None, total: int | None = None,
                 unit: str | None = None) -> None:
        """An advisory `progress` frame (the host appends `message` to the job log)."""
        self.check()
        frame: dict[str, Any] = {"type": "progress", "id": self.id}
        if message is not None:
            frame["message"] = message[:2000]
        if done is not None:
            frame["done"] = done
        if total is not None:
            frame["total"] = total
        if unit is not None:
            frame["unit"] = unit
        self.server.send(frame, best_effort=True)

    def log(self, level: str, message: str) -> None:
        """A structured `notify log` tied to this request (also written to stderr)."""
        logging.getLogger("secmonk_modules.request").log(getattr(logging, level.upper(), logging.INFO), message)
        self.server.send({"type": "notify", "method": "log",
                          "params": {"level": level, "message": message[:2000], "request": self.id}},
                         best_effort=True)


# --------------------------------------------------------------------------- server

class Server:
    def __init__(self, module: ModuleDef, stdin: BinaryIO, stdout: BinaryIO, *, max_frame: int = DEFAULT_MAX_FRAME):
        if not MIN_MAX_FRAME <= max_frame <= HARD_MAX_FRAME:
            raise ValueError(f"max_frame must be {MIN_MAX_FRAME}..{HARD_MAX_FRAME}")
        self.module, self.stdin, self.stdout = module, stdin, stdout
        self.own_max_frame = max_frame
        self.session = Session(max_frame=max_frame)
        self.wlock = threading.Lock()
        self.stopping = threading.Event()
        self.inflight: dict[int, Request] = {}
        self.used_ids: set[int] = set()
        self.threads: list[threading.Thread] = []

    # ---- output
    def send(self, frame: dict[str, Any], *, best_effort: bool = False) -> None:
        """Write one frame (serialized). `best_effort` frames (progress, notify) are dropped when too large or the
        peer is gone; others raise WireError(internal) when oversize."""
        try:
            data = encode_frame(frame, self.session.max_frame)
        except WireError:
            if best_effort:
                return
            raise
        with self.wlock:
            try:
                self.stdout.write(data)
                self.stdout.flush()
            except (BrokenPipeError, OSError, ValueError):
                self.stopping.set()

    def _hello(self) -> dict[str, Any]:
        return {"type": "hello", "protocol": PROTOCOL, "role": "module", "name": self.module.name,
                "version": __version__, "runtime": "python", "runtime_version": sys.version.split()[0],
                "pid": os.getpid(), "codecs": ["json"],
                "limits": {"max_frame": self.own_max_frame, "max_inflight": self.module.max_inflight,
                           "chunk_items": CHUNK_ITEMS},
                "provides": self.module.provides(), "capabilities": list(self.module.capabilities)}

    # ---- main loop
    def serve(self) -> int:
        """Run until stdin closes (0) or the peer breaks the protocol (3). Returns the exit code."""
        try:
            self.send(self._hello())
            if not self._read_host_hello():
                return 0
            while not self.stopping.is_set():
                frame = read_frame(self.stdin, self.own_max_frame)
                if frame is None:
                    log.info("stdin closed, exiting")
                    return 0
                self._dispatch(frame)
            return 0
        except ProtocolError as e:
            log.error("protocol error: %s", e)
            self.send(e.frame(None), best_effort=True)
            return 3
        finally:
            self._shutdown()

    def _read_host_hello(self) -> bool:
        frame = read_frame(self.stdin, self.own_max_frame)
        if frame is None:
            return False
        if frame.get("type") != "hello" or frame.get("role") != "host":
            raise ProtocolError("expected the host's hello before any other message")
        proto = frame.get("protocol")
        if not isinstance(proto, str) or proto.split(".")[0] != PROTOCOL.split(".")[0]:
            raise ProtocolError(f"unsupported protocol {proto!r}; this module speaks {PROTOCOL}")
        limits = frame.get("limits") if isinstance(frame.get("limits"), dict) else {}
        theirs = limits.get("max_frame")
        if isinstance(theirs, int) and not isinstance(theirs, bool) and theirs >= MIN_MAX_FRAME:
            self.session.max_frame = min(self.own_max_frame, theirs, HARD_MAX_FRAME)
        sess = frame.get("session") if isinstance(frame.get("session"), dict) else {}
        if sess.get("module") not in (None, self.module.name):
            raise ProtocolError(f"session is for module {sess.get('module')!r}, this is {self.module.name!r}")
        self.session.module = self.module.name
        self.session.grants = sess.get("grants") if isinstance(sess.get("grants"), dict) else {}
        self.session.settings = sess.get("settings") if isinstance(sess.get("settings"), dict) else {}
        if self.session.db_read and "db-read" not in self.module.capabilities:
            raise ProtocolError("the host granted db_read to a module that does not declare db-read")
        if self.module.on_session:
            self.module.on_session(self.session)
        return True

    def _dispatch(self, frame: dict[str, Any]) -> None:
        typ = frame.get("type")
        if typ == "req":
            self._on_req(frame)
        elif typ == "cancel":
            rid = frame.get("id")
            req = self.inflight.get(rid) if isinstance(rid, int) else None
            if req is not None:
                req.cancelled.set()          # unknown / finished id: ignored (the callee already answered)
        elif typ == "notify":
            return                           # the host sends none in v1; unknown notifications are ignored
        else:
            raise ProtocolError(f"unexpected message type {typ!r}")

    def _on_req(self, frame: dict[str, Any]) -> None:
        rid, method = frame.get("id"), frame.get("method")
        if not isinstance(rid, int) or isinstance(rid, bool) or not 1 <= rid <= MAX_ID:
            raise ProtocolError("req: id must be a positive integer")
        if rid in self.used_ids:
            raise ProtocolError(f"req: id {rid} was already used on this connection")
        self.used_ids.add(rid)
        if not isinstance(method, str) or not _METHOD.match(method):
            raise ProtocolError("req: method must be a dotted name")
        params = frame.get("params", {})
        deadline = frame.get("deadline_ms")
        if deadline is not None and (not isinstance(deadline, int) or isinstance(deadline, bool) or deadline < 1):
            raise ProtocolError("req: deadline_ms must be a positive integer")
        spec = self.module.methods.methods.get(method)
        if spec is None:
            self.send(WireError("unknown-method", f"unknown method {method!r}").frame(rid))
            return
        if not isinstance(params, dict):
            self.send(WireError("invalid-params", "params must be an object").frame(rid))
            return
        if len(self.inflight) >= self.module.max_inflight:
            self.send(WireError("busy", f"{len(self.inflight)} requests in flight (max {self.module.max_inflight})")
                      .frame(rid))
            return
        req = Request(self, rid, method, params, deadline)
        self.inflight[rid] = req
        t = threading.Thread(target=self._run, args=(req, spec), name=f"req-{rid}", daemon=True)
        self.threads = [x for x in self.threads if x.is_alive()] + [t]
        t.start()

    # ---- one request
    def _run(self, req: Request, spec: Method) -> None:
        # The final frame (res / end / err) is built here and sent only after the request left `inflight`: a host
        # that sends its next call as soon as it reads the answer must never get `busy` (max_inflight = 1).
        final: dict[str, Any] | None = None
        best_effort = True
        try:
            try:
                req.check()
                params = check_params(spec.params, req.params)
                if spec.stream:
                    final = self._run_stream(req, spec, params)
                else:
                    final = {"type": "res", "id": req.id, "result": spec.handler(req, params)}
                best_effort = False
            except Cancelled:
                final = WireError("cancelled", "cancelled").frame(req.id)
            except WireError as e:
                final = e.frame(req.id)
            except Exception as e:  # noqa: BLE001  # a bug in a handler: `internal`, never a traceback on the wire
                log.error("request %s %s failed:\n%s", req.id, req.method, traceback.format_exc())
                final = WireError("internal", scrub(f"{type(e).__name__}: {e}")).frame(req.id)
        finally:
            self.inflight.pop(req.id, None)
            if final is not None:
                try:
                    self.send(final, best_effort=best_effort)
                except WireError as e:                       # an oversize res / end: the caller gets `internal`
                    self.send(e.frame(req.id), best_effort=True)

    def _run_stream(self, req: Request, spec: Method, params: dict[str, Any]) -> dict[str, Any]:
        """Send the events; return the `end` frame (sent by `_run` once the request left `inflight`)."""
        gen: Iterator[Any] = iter(spec.handler(req, params))
        seq, result = 0, None
        try:
            while True:
                req.check()
                try:
                    item = next(gen)
                except StopIteration as stop:
                    result = stop.value
                    break
                seq += 1
                self.send({"type": "event", "id": req.id, "seq": seq, "data": item})
        finally:
            close = getattr(gen, "close", None)
            if close:
                close()
        end: dict[str, Any] = {"type": "end", "id": req.id}
        if result is not None:
            end["result"] = result
        return end

    # ---- shutdown
    def _shutdown(self) -> None:
        self.stopping.set()
        for req in list(self.inflight.values()):
            req.cancelled.set()
        deadline = time.monotonic() + 2.0
        for t in self.threads:
            t.join(max(0.0, deadline - time.monotonic()))


def scrub(text: str) -> str:
    """URL credentials out of an error text (the `secmonk` helper when it is loaded, else a local copy)."""
    if "://" not in text:
        return text[:2000]
    return re.sub(r"(\b[a-z][a-z0-9+.-]*://)([^/@\s]*@)?([^\s'\"<>?#]*)[^\s'\"<>]*",
                  lambda m: m.group(1) + (m.group(2).split(":")[0] + "@" if m.group(2) else "") + m.group(3),
                  text)[:2000]


def run_stdio(module: ModuleDef, *, max_frame: int = DEFAULT_MAX_FRAME) -> int:
    """Serve `module` on the process's own stdin / stdout (after `claim_stdio`)."""
    stdin, stdout = claim_stdio()
    setup_logging()
    pyc = os.environ.get("PYTHONPYCACHEPREFIX")        # `-I` ignores PYTHON*; the host passes it, set it in code
    if pyc:
        sys.pycache_prefix = pyc
    return Server(module, stdin, stdout, max_frame=max_frame).serve()
