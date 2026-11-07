"""Local web server for `secmonk ui`: static files + JSON API, Python stdlib only (ADR-0008).

Local and unauthenticated by design, hardened for that setting:
  * binds 127.0.0.1 unless told otherwise;
  * `Host` header must be one of the addresses we listen on (blocks DNS-rebinding pages from reaching the API);
  * state-changing endpoints are POST and need `X-SecMonk-Request: 1` (a cross-origin page cannot add that header
    without a CORS preflight, which is never answered);
  * strict Content-Security-Policy; static files resolved inside the static directory only.

Routes: GET / (app), GET /static/*, GET /api/meta, GET /api/processes[?refresh=1], GET /api/processes/watch,
POST /api/processes/save. See _docs/tech/web-ui.md.
"""

from __future__ import annotations

import json
import mimetypes
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .. import __version__
from .api import ApiError, ProcessMonitor

STATIC = Path(__file__).parent / "static"
CDN = "https://unpkg.com"
CSP = ("default-src 'self'; "
       f"script-src 'self' 'unsafe-eval' {CDN}; "        # unsafe-eval: Vue's in-browser template compiler
       "style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")
CSRF_HEADER = "X-SecMonk-Request"


class UIServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: tuple[str, int], monitor: ProcessMonitor, *, mode: str):
        super().__init__(addr, Handler)
        self.monitor = monitor
        self.mode = mode
        host, port = self.server_address[:2]
        self.port = port
        names = {"127.0.0.1", "localhost", "[::1]", host if ":" not in host else f"[{host}]"}
        self.allowed_hosts = {f"{n}:{port}" for n in names}

    @property
    def bind(self) -> str:
        return f"http://{self.server_address[0]}:{self.port}"


class Handler(BaseHTTPRequestHandler):
    server: UIServer
    server_version = "secmonk-ui"
    sys_version = ""

    # ------------------------------------------------------------------ plumbing
    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default; `secmonk -v ui` logs requests
        if getattr(self.server, "verbose", False):
            sys.stderr.write("ui: " + (fmt % args) + "\n")

    def _headers(self, status: int, ctype: str, length: int, *, cache: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cache-Control", "no-cache" if cache else "no-store")
        self.end_headers()

    def _json(self, status: int, body: Any) -> None:
        data = json.dumps(body, default=str).encode()
        self._headers(status, "application/json; charset=utf-8", len(data))
        self.wfile.write(data)

    def _error(self, status: int, message: str, hint: str | None = None) -> None:
        self._json(status, {"error": message, **({"hint": hint} if hint else {})})

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        if host in self.server.allowed_hosts:
            return True
        self._error(421, "unexpected Host header", "the UI only answers on the address it listens on")
        return False

    # ------------------------------------------------------------------ verbs
    def do_GET(self) -> None:
        if not self._host_ok():
            return
        url = urlsplit(self.path)
        path, query = url.path, parse_qs(url.query)
        try:
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path == "/api/meta":
                return self._json(200, self._meta())
            if path == "/api/processes":
                return self._json(200, self.server.monitor.payload(refresh=query.get("refresh") == ["1"]))
            if path == "/api/processes/watch":
                return self._json(200, self.server.monitor.watch())
            if path.startswith("/api/"):
                return self._error(404, f"no such endpoint {path}")
            return self._error(404, "not found")
        except ApiError as e:
            return self._error(e.status, e.message, e.hint)
        except Exception as e:  # noqa: BLE001 - never leak a traceback page; report the type + message
            return self._error(500, f"{type(e).__name__}: {e}")

    def do_POST(self) -> None:
        if not self._host_ok():
            return
        if self.headers.get(CSRF_HEADER) != "1":
            return self._error(403, f"missing {CSRF_HEADER} header")
        path = urlsplit(self.path).path
        try:
            if path == "/api/processes/save":
                return self._json(200, self.server.monitor.save())
            return self._error(404, f"no such endpoint {path}")
        except ApiError as e:
            return self._error(e.status, e.message, e.hint)
        except Exception as e:  # noqa: BLE001
            return self._error(500, f"{type(e).__name__}: {e}")

    def do_PUT(self) -> None:
        self._error(405, "method not allowed")

    do_DELETE = do_PATCH = do_PUT

    # ------------------------------------------------------------------ handlers
    def _static(self, rel: str) -> None:
        root = STATIC.resolve()
        try:
            p = (root / rel).resolve()
        except (OSError, ValueError):
            return self._error(404, "not found")
        if root not in p.parents or not p.is_file():
            return self._error(404, "not found")
        data = p.read_bytes()
        ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self._headers(200, ctype, len(data), cache=True)
        self.wfile.write(data)

    def _meta(self) -> dict[str, Any]:
        m = self.server.monitor
        from ..collectors.process.backend import current_platform

        return {"version": __version__, "mode": self.server.mode, "platform": current_platform(),
                "db": {"path": str(m.db_path), "exists": m.db_path.exists()}, "bind": self.server.bind,
                "features": ["processes"]}


def make_server(monitor: ProcessMonitor, host: str = "127.0.0.1", port: int = 8765, *, mode: str = "live",
                verbose: bool = False) -> UIServer:
    srv = UIServer((host, port), monitor, mode=mode)
    srv.verbose = verbose  # type: ignore[attr-defined]
    return srv


def serve_in_thread(srv: UIServer) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, name="secmonk-ui", daemon=True)
    t.start()
    return t
