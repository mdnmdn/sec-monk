"""How sec-monk reaches a Docker engine: endpoints, Docker CLI contexts, TLS and `ssh://` (stdlib only).

`docker_engine.find_endpoint` decides *which* engine to talk to; this module holds the pieces it uses:

* `Endpoint`: one engine address (unix socket, tcp with optional TLS, ssh) plus the `label` used in asset ids;
* Docker CLI contexts (`~/.docker/contexts/meta/<sha256(name)>/meta.json`, TLS material under
  `~/.docker/contexts/tls/<sha256(name)>/docker/`), read with size caps and type checks;
* `TLSConfig` -> `ssl.SSLContext` for `http.client.HTTPSConnection`;
* `SSHHTTPConnection`: HTTP/1.1 over the stdin/stdout of `ssh ... -- host docker system dial-stdio`, the same
  mechanism the Docker CLI uses for `ssh://` hosts. The ssh argv is the fixed one of the SSH collector
  (`OpenSSHTransport.argv`: BatchMode, ConnectTimeout, no forwarding), never run through a shell.

See _docs/tech/collectors/docker-engine.md.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import select
import socket
import ssl
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .base import strip_url_secrets
from .ssh import OpenSSHTransport, SSHTarget, _Drain, _stderr_text, parse_target, ssh_asset_id

MAX_JSON = 1 << 20          # config.json / meta.json
MAX_PEM = 1 << 20           # ca/cert/key files
MAX_CONTEXTS = 1000
SSH_DIAL_COMMAND = "docker system dial-stdio"
# docker CLIs outside a non-interactive ssh PATH (macOS: Homebrew, Docker Desktop); the only values `remote_docker`
# accepts, so the remote command stays fixed
REMOTE_DOCKER_PATHS = ("/usr/local/bin/docker", "/opt/homebrew/bin/docker",
                       "/Applications/Docker.app/Contents/Resources/bin/docker")
DEFAULT_SSH_PORT = 22


# --------------------------------------------------------------------------- small helpers

def as_bool(v: Any, default: bool | None = None) -> bool | None:
    """Option value -> bool (CLI `-o key=value` values may arrive as strings)."""
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"expected a boolean, got {v!r}")


def _check_file(path: str | Path, what: str, cap: int = MAX_PEM) -> str:
    p = Path(path).expanduser()
    try:
        st = p.stat()
    except OSError as e:
        raise RuntimeError(f"{what} {p}: {e.strerror or e}") from e
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"{what} {p} is not a regular file")
    if st.st_size > cap:
        raise RuntimeError(f"{what} {p} is larger than {cap} bytes")
    return str(p)


def _read_json_object(path: Path, what: str) -> dict:
    _check_file(path, what, MAX_JSON)
    try:
        with open(path, "rb") as f:
            data = json.loads(f.read(MAX_JSON + 1)[:MAX_JSON])
    except (OSError, ValueError) as e:
        raise RuntimeError(f"cannot read {what} {path}: {e}") from e
    if isinstance(data, dict):
        return data
    raise RuntimeError(f"{what} {path} is not a JSON object")


# --------------------------------------------------------------------------- TLS

@dataclass
class TLSConfig:
    ca: str | None = None
    cert: str | None = None
    key: str | None = None
    verify: bool = True

    def ssl_context(self) -> ssl.SSLContext:
        """Docker semantics: with verification the CA file (when given) is the only trust anchor; without it the
        server certificate and name are not checked. A client cert (+ key) is presented when given."""
        try:
            if self.verify:
                ca = _check_file(self.ca, "TLS CA file") if self.ca else None
                ctx = ssl.create_default_context(cafile=ca)
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            if self.cert:
                key = _check_file(self.key, "TLS key file") if self.key else None
                ctx.load_cert_chain(_check_file(self.cert, "TLS certificate file"), key)
        except ssl.SSLError as e:
            raise RuntimeError(f"invalid TLS material: {e}") from e
        return ctx


def tls_files(directory: str | Path) -> dict[str, str]:
    """{ca, cert, key} -> path for the `ca.pem`, `cert.pem`, `key.pem` files present in `directory`."""
    d = Path(directory).expanduser()
    return {k: str(d / f"{k}.pem") for k in ("ca", "cert", "key") if (d / f"{k}.pem").is_file()}


# --------------------------------------------------------------------------- endpoint

@dataclass
class Endpoint:
    unix: str | None = None
    host: str | None = None          # tcp host
    port: int | None = None          # tcp port
    ssh: SSHTarget | None = None
    tls: TLSConfig | None = None
    context: str | None = None       # Docker context name it came from, if any
    source: str = ""                 # where it was requested (for messages): --socket, DOCKER_HOST, context ...
    ssh_bin: str | None = None
    identity: str | None = None
    connect_timeout: int = 15
    ssh_options: list[str] = field(default_factory=list)   # `-o` values, as the SSH collector's ssh_option
    insecure_host_key: bool = False
    remote_docker: str | None = None                 # one of REMOTE_DOCKER_PATHS, else `docker` from PATH
    scheme: str = field(default="")

    def __post_init__(self) -> None:
        if not self.scheme:
            self.scheme = "unix" if self.unix else "ssh" if self.ssh else "tcp"

    @property
    def label(self) -> str | None:
        """Engine part of asset ids: None for a local unix socket, `host:port` for tcp, the ssh host (port only
        when not 22, never the user) for ssh."""
        if self.scheme == "unix":
            return None
        if self.scheme == "ssh" and self.ssh:
            return ssh_asset_id(self.ssh).removeprefix("ssh:")
        h = f"[{self.host}]" if self.host and ":" in self.host else self.host
        return f"{h}:{self.port}"

    def __str__(self) -> str:
        if self.scheme == "unix":
            return f"unix://{self.unix}"
        if self.scheme == "ssh":
            return f"ssh://{self.ssh}"
        h = f"[{self.host}]" if self.host and ":" in self.host else self.host
        return f"tcp://{h}:{self.port}"


def parse_host(value: str) -> Endpoint | None:
    """`unix:///path`, `/path`, `tcp://host[:port]` (`http://` accepted), `ssh://[user@]host[:port]`; None when
    the scheme is not supported. A tcp port left out is filled in later (2376 with TLS, 2375 without)."""
    value = value.strip()
    if value.startswith("unix://"):
        return Endpoint(unix=value[len("unix://"):])
    if value.startswith("/"):
        return Endpoint(unix=value)
    if value.startswith(("tcp://", "http://")):
        try:
            u = urlsplit(value.replace("tcp://", "http://", 1))
            port = u.port
        except ValueError as e:
            raise ValueError(f"invalid Docker host {strip_url_secrets(value)!r}: {e}") from e
        if not u.hostname or u.hostname.startswith("-"):
            raise ValueError(f"invalid Docker host {strip_url_secrets(value)!r}")
        return Endpoint(host=u.hostname, port=port, scheme="tcp")
    if value.startswith("ssh://"):
        rest = value[len("ssh://"):].split("/", 1)[0]
        if rest.rpartition("@")[2].startswith("-"):
            raise ValueError(f"invalid ssh host in {strip_url_secrets(value)!r} (starts with '-')")
        return Endpoint(ssh=parse_target(value), scheme="ssh")
    return None


# --------------------------------------------------------------------------- Docker CLI contexts

def config_dir() -> Path:
    """`$DOCKER_CONFIG` or `~/.docker`."""
    env = os.environ.get("DOCKER_CONFIG")
    return Path(env).expanduser() if env else Path.home() / ".docker"


def context_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def current_context() -> str | None:
    """`currentContext` of `config.json`: None when unset, the key is not a string, or the file is missing or cannot
    be opened (permissions, macOS privacy prompts): nothing was requested then. Malformed JSON is an error."""
    path = config_dir() / "config.json"
    try:
        if not path.is_file():
            return None
        with open(path, "rb"):
            pass
    except OSError:
        return None
    cur = _read_json_object(path, "Docker config").get("currentContext")
    return cur if isinstance(cur, str) and cur.strip() else None


@dataclass
class ContextInfo:
    name: str
    host: str | None
    description: str = ""
    skip_tls_verify: bool = False
    tls: dict[str, str] = field(default_factory=dict)    # ca/cert/key -> path


def _context_from_meta(data: dict, meta_path: Path) -> ContextInfo:
    name = data.get("Name")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise RuntimeError(f"Docker context {meta_path}: missing or invalid Name")
    md = data.get("Metadata")
    desc = md.get("Description") if isinstance(md, dict) else None
    eps = data.get("Endpoints")
    dock = eps.get("docker") if isinstance(eps, dict) else None
    host = dock.get("Host") if isinstance(dock, dict) else None
    skip = dock.get("SkipTLSVerify") if isinstance(dock, dict) else None
    tls_dir = config_dir() / "contexts" / "tls" / context_id(name) / "docker"
    return ContextInfo(name=name, host=host if isinstance(host, str) and host else None,
                       description=desc if isinstance(desc, str) else "",
                       skip_tls_verify=skip is True, tls=tls_files(tls_dir) if tls_dir.is_dir() else {})


def load_context(name: str) -> ContextInfo:
    """The named Docker context; RuntimeError when it does not exist or its metadata is unusable."""
    if not isinstance(name, str) or not name or len(name) > 256:
        raise RuntimeError(f"invalid Docker context name {name!r}")
    meta = config_dir() / "contexts" / "meta" / context_id(name) / "meta.json"
    if not meta.exists():
        raise RuntimeError(f"Docker context {name!r} not found ({meta.parent.parent} has no entry for it)")
    info = _context_from_meta(_read_json_object(meta, "Docker context metadata"), meta)
    if info.name != name:
        raise RuntimeError(f"Docker context metadata {meta} names {info.name!r}, expected {name!r}")
    return info


def iter_contexts() -> list[tuple[str, ContextInfo | None, str]]:
    """Every context under `contexts/meta/`: (directory id, info or None, error)."""
    root = config_dir() / "contexts" / "meta"
    out: list[tuple[str, ContextInfo | None, str]] = []
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir())[:MAX_CONTEXTS]:
        meta = d / "meta.json"
        if not meta.is_file():
            continue
        try:
            out.append((d.name, _context_from_meta(_read_json_object(meta, "Docker context metadata"), meta), ""))
        except RuntimeError as e:
            out.append((d.name, None, str(e)))
    return out


# --------------------------------------------------------------------------- ssh:// (docker system dial-stdio)

def _spawn(argv: list[str]) -> subprocess.Popen:
    """Start the ssh process (replaced in tests). argv is a list: no shell ever parses it."""
    return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def ssh_argv(ep: Endpoint) -> list[str]:
    """`ssh <fixed options> [-o user options] [-p port] [-l user] [-i identity] -- host docker system dial-stdio`.
    The argv is the SSH collector's (`OpenSSHTransport.argv`), so the same ssh options mean the same thing."""
    assert ep.ssh is not None
    if ep.ssh.host.startswith("-"):
        raise ValueError("invalid ssh host (starts with '-')")
    t = OpenSSHTransport(ep.ssh, ssh_bin=ep.ssh_bin, identity=ep.identity, connect_timeout=ep.connect_timeout,
                         ssh_options=ep.ssh_options, insecure_host_key=ep.insecure_host_key)
    if ep.remote_docker and ep.remote_docker not in REMOTE_DOCKER_PATHS:
        raise ValueError(f"remote_docker must be one of {', '.join(REMOTE_DOCKER_PATHS)}")
    cmd = f"{ep.remote_docker} system dial-stdio" if ep.remote_docker else SSH_DIAL_COMMAND
    return t.argv(cmd)


class _TimeoutPipe(io.RawIOBase):
    """Raw reader over a pipe fd that waits at most `timeout` seconds for each chunk (like a socket timeout):
    select() before os.read, TimeoutError when nothing arrives in time."""

    def __init__(self, fd: int, timeout: float | None):
        super().__init__()
        self._fd, self._timeout = fd, timeout

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if self._timeout is not None:
            try:
                ready, _, _ = select.select([self._fd], [], [], self._timeout)
            except (OSError, ValueError):     # select() on pipes is POSIX-only: fall back to a blocking read
                ready = [self._fd]
            if not ready:
                raise TimeoutError(f"no data from the remote engine for {self._timeout:g}s")
        data = os.read(self._fd, len(b))
        b[:len(data)] = data
        return len(data)


class _PipeReader(io.BufferedReader):
    """The child's stdout as the response `fp`: http.client may close the connection (killing ssh, closing the
    pipe) before it flushes/closes the response, so flush is a no-op and close tolerates a closed pipe."""

    def flush(self) -> None:
        pass

    def close(self) -> None:
        try:
            super().close()
        except (OSError, ValueError):
            pass


class _PipeSocket:
    """The minimum of the socket API http.client uses (sendall, makefile, settimeout, close) over a child's
    pipes. Reads honour the timeout; stderr is drained in the background for error messages."""

    def __init__(self, proc: Any, timeout: float | None = None):
        self.proc, self.timeout = proc, timeout
        err = proc.stderr
        self._err = _Drain(err.read1 if hasattr(err, "read1") else err.read)
        self._err.start()

    def sendall(self, data: bytes) -> None:
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError) as e:
            raise ConnectionResetError(f"ssh connection closed: {e}") from e

    def makefile(self, mode: str = "rb", *args: Any, **kwargs: Any) -> Any:
        return _PipeReader(_TimeoutPipe(self.proc.stdout.fileno(), self.timeout))

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def stderr_text(self, wait: float = 1) -> str:
        """What ssh wrote on stderr so far (waits at most `wait` seconds for the drain to finish)."""
        self._err.join(wait)
        return _stderr_text(bytes(self._err.buf))

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self._err.join(1)                   # the drain ends at EOF of stderr once ssh is gone
        for f in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                f.close()
            except (OSError, ValueError):
                pass


class SSHHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 to a remote engine through `ssh host docker system dial-stdio`: one ssh process per connection,
    killed on close; `timeout` bounds every wait for data; ssh's stderr is kept for errors (`diagnostics()`)."""

    def __init__(self, endpoint: Endpoint, timeout: float | None = 30):
        super().__init__("localhost", timeout=timeout)
        self.endpoint = endpoint
        self._pipe: _PipeSocket | None = None

    def connect(self) -> None:
        argv = ssh_argv(self.endpoint)
        try:
            proc = _spawn(argv)
        except OSError as e:
            raise ConnectionError(f"cannot run {argv[0]}: {e}") from e
        self._pipe = _PipeSocket(proc, self.timeout)
        self.sock = self._pipe  # type: ignore[assignment]

    def diagnostics(self) -> str:
        """ssh's stderr (connection refused, auth failure, `docker: command not found` ...), if any. Call it after
        close(): ssh is gone then and its stderr complete."""
        return self._pipe.stderr_text() if self._pipe else ""

    def close(self) -> None:
        super().close()
        if self._pipe:
            self._pipe.close()


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 over an AF_UNIX stream socket."""

    def __init__(self, path: str, timeout: float | None = 30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)
