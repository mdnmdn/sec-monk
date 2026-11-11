"""A minimal host-side client of secmonk-wire/1 for tests, golden recording and scripts (the Rust host is the real one).

Spawns `python -I -m secmonk_modules serve <module> --stdio` with a cleared environment (like the host, see
rust/_docs/tech/configuration.md "Module process environment") and speaks the protocol over its pipes.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self

from .wire import PROTOCOL, decode_frame

DEFAULT_TIMEOUT = 120.0


class ModuleError(Exception):
    """An `err` frame."""

    def __init__(self, frame: dict[str, Any]):
        super().__init__(f"{frame.get('code')}: {frame.get('error')}")
        self.frame, self.code = frame, frame.get("code")


@dataclass
class Reply:
    id: int
    items: list[Any] = field(default_factory=list)        # event.data in order (stream methods)
    seqs: list[int] = field(default_factory=list)
    progress: list[dict] = field(default_factory=list)
    notifies: list[dict] = field(default_factory=list)
    frames: list[dict] = field(default_factory=list)      # every frame of this request, in order
    result: Any = None                                    # res.result, or end.result
    error: dict | None = None                             # the err frame

    def ok(self) -> Reply:
        if self.error is not None:
            raise ModuleError(self.error)
        return self


def isolated_env(home: Path, *, extra: dict[str, str] | None = None) -> dict[str, str]:
    """What the host gives a module: user context passed through, state redirected into `home` (a data_dir)."""
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
    env.update({"HOME": str(home / "home"), "USERPROFILE": str(home / "home"),
                "SECMONK_HOME": str(home / "python-home"), "SECMONK_CACHE": str(home / "cache" / "secmonk"),
                "SECMONK_DB": str(home / "python-home" / "forbidden.db"), "TMPDIR": str(home / "tmp"),
                "TEMP": str(home / "tmp"), "TMP": str(home / "tmp"), "DOCKER_CONFIG": str(home / "home" / "docker")})
    for d in ("home", "python-home", "cache/secmonk", "tmp"):
        (home / d).mkdir(parents=True, exist_ok=True)
    env.update(extra or {})
    return env


class ModuleClient:
    def __init__(self, module: str, *, env: dict[str, str] | None = None, grants: dict[str, Any] | None = None,
                 settings: dict[str, Any] | None = None, host_max_frame: int = 16 * 1024 * 1024,
                 args: list[str] | None = None, cmd: list[str] | None = None, send_host_hello: bool = True,
                 cwd: str | None = None):
        self.module, self.grants, self.settings = module, grants or {}, settings or {}
        self.host_max_frame, self.send_host_hello = host_max_frame, send_host_hello
        self.cmd = cmd or [sys.executable, "-I", "-m", "secmonk_modules", "serve", module, "--stdio", *(args or [])]
        self.env, self.cwd = env if env is not None else dict(os.environ), cwd
        self.proc: subprocess.Popen | None = None
        self.hello: dict[str, Any] = {}
        self.stderr_lines: list[str] = []
        self._frames: queue.Queue = queue.Queue()
        self._next_id = 0
        self.stray: list[dict] = []

    # ---- lifecycle
    def start(self) -> ModuleClient:
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=self.env, cwd=self.cwd)
        threading.Thread(target=self._pump_out, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()
        self.hello = self.recv(60)
        if self.hello.get("type") != "hello":
            raise RuntimeError(f"expected a hello, got {self.hello}")
        if self.send_host_hello:
            self.send_hello()
        return self

    def send_hello(self, **overrides: Any) -> None:
        hello = {"type": "hello", "protocol": PROTOCOL, "role": "host", "name": "secmonk-test-host", "version": "0",
                 "codecs": ["json"], "codec": "json", "limits": {"max_frame": self.host_max_frame},
                 "session": {"module": self.module, "grants": self.grants, "settings": self.settings}}
        hello.update(overrides)
        self.send(hello)

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self, timeout: float = 10.0) -> int | None:
        """Close stdin (the module must exit on EOF) and return its exit code."""
        if self.proc is None:
            return None
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait()
        finally:
            for s in (self.proc.stdout, self.proc.stderr):
                if s:
                    s.close()

    # ---- raw frames
    def send_raw(self, data: bytes) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def send(self, obj: dict[str, Any]) -> None:
        import json

        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_raw(len(body).to_bytes(4, "big") + body)

    def _pump_out(self) -> None:
        assert self.proc and self.proc.stdout
        out = self.proc.stdout
        while True:
            hdr = out.read(4)
            if len(hdr) < 4:
                self._frames.put(None)
                return
            n = int.from_bytes(hdr, "big")
            body = out.read(n)
            if len(body) < n:
                self._frames.put(None)
                return
            self._frames.put(decode_frame(body))

    def _pump_err(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            self.stderr_lines.append(line.decode("utf-8", "replace").rstrip("\n"))

    def recv(self, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
        """The next frame, None when the module closed stdout (exited)."""
        try:
            return self._frames.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("no frame from the module") from None

    # ---- requests
    def new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def start_request(self, method: str, params: dict[str, Any] | None = None, *, deadline_ms: int | None = None,
                      req_id: int | None = None) -> int:
        rid = req_id or self.new_id()
        frame: dict[str, Any] = {"type": "req", "id": rid, "method": method, "params": params or {}}
        if deadline_ms:
            frame["deadline_ms"] = deadline_ms
        self.send(frame)
        return rid

    def collect(self, rid: int, timeout: float = DEFAULT_TIMEOUT) -> Reply:
        """Read frames until request `rid` finishes (res / end / err); frames of other requests go to `.stray`."""
        reply, deadline = Reply(rid), time.monotonic() + timeout
        while True:
            f = self.recv(max(0.1, deadline - time.monotonic()))
            if f is None:
                raise EOFError("the module exited before answering")
            if f.get("id") != rid and f.get("type") != "notify":
                self.stray.append(f)
                continue
            reply.frames.append(f)
            t = f.get("type")
            if t == "event":
                reply.items.append(f["data"])
                reply.seqs.append(f["seq"])
            elif t == "progress":
                reply.progress.append(f)
            elif t == "notify":
                reply.notifies.append(f)
            elif t in ("res", "end"):
                reply.result = f.get("result")
                return reply
            elif t == "err":
                reply.error = f
                return reply

    def request(self, method: str, params: dict[str, Any] | None = None, *, timeout: float = DEFAULT_TIMEOUT,
                deadline_ms: int | None = None) -> Reply:
        return self.collect(self.start_request(method, params, deadline_ms=deadline_ms), timeout)

    def call(self, method: str, params: dict[str, Any] | None = None, **kw: Any) -> Any:
        """The result of a unary method (raises ModuleError on `err`)."""
        return self.request(method, params, **kw).ok().result
