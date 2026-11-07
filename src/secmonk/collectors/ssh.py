"""Agentless SSH collector: inventory a remote Linux/macOS machine over SSH, read-only.

Flow (see _docs/tech/collectors/ssh.md):
  1. one command identifies the remote OS            (harvest.detect_script)
  2. one read-only `find | tar` pipeline streams back the metadata files sec-monk needs (harvest.build_script)
  3. the stream is safely extracted into a private temp dir
  4. the existing collector runs on that dir: rootfs `collect_from_view` (Linux) / `MacOSCollector` (macOS)
  5. the asset is rewritten to `ssh:<host>` and the temp dir removed

The only commands ever executed remotely are the fixed scripts above (fed to `sh -s` on stdin, so the remote
login shell never parses them), optionally under `sudo -n`.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import Asset, Inventory
from . import harvest
from .base import Collector, register
from .harvest import HarvestLimitExceeded, HarvestSpec, opts_int
from .macos import MacOSCollector
from .rootfs import DirView, collect_from_view

log = logging.getLogger("secmonk.ssh")

MAX_RUN_OUTPUT = 4 * harvest.MB
MAX_STDERR = 64 * 1024
MAX_PREAMBLE = 64 * 1024
PASSWORD_ENV = "SECMONK_SSH_PASSWORD"
PASSPHRASE_ENV = "SECMONK_SSH_KEY_PASSPHRASE"


class SSHError(RuntimeError):
    """Connection/authentication/command failure."""


# --------------------------------------------------------------------------- target parsing

@dataclass(frozen=True)
class SSHTarget:
    host: str
    user: str | None = None
    port: int | None = None

    def __str__(self) -> str:
        u = f"{self.user}@" if self.user else ""
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{u}{h}" + (f":{self.port}" if self.port else "")


_HOST_RE = re.compile(r"^[A-Za-z0-9_:][A-Za-z0-9._:%-]*$")
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@\\-]*$")


def parse_target(target: str) -> SSHTarget:
    """`[ssh://][user@]host[:port]`, IPv6 as `[::1]` (optionally `[::1]:2222`)."""
    s = (target or "").strip()
    s = s.removeprefix("ssh://")
    s = s.split("/", 1)[0]
    if not s:
        raise ValueError("ssh target is empty (expected user@host[:port])")
    user = None
    if "@" in s:
        user, _, s = s.rpartition("@")
        if not _USER_RE.match(user):
            raise ValueError(f"invalid ssh user {user!r}")
    port = None
    if s.startswith("["):
        host, sep, rest = s[1:].partition("]")
        if not sep:
            raise ValueError(f"unterminated IPv6 address in {target!r}")
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"invalid ssh target {target!r}")
            port_s = rest[1:]
        else:
            port_s = ""
    elif s.count(":") == 1:
        host, _, port_s = s.partition(":")
    else:                                        # no port, or a bare IPv6 address
        host, port_s = s, ""
    if port_s:
        if not port_s.isdigit() or not (0 < int(port_s) < 65536):
            raise ValueError(f"invalid ssh port {port_s!r}")
        port = int(port_s)
    if not host or not _HOST_RE.match(host):
        raise ValueError(f"invalid ssh host {host!r}")
    return SSHTarget(host=host, user=user or None, port=port)


# --------------------------------------------------------------------------- transports

class Stream(ABC):
    """Remote stdout of one running command."""

    timed_out: bool = False

    @abstractmethod
    def read(self, n: int = -1) -> bytes:
        """Up to `n` bytes (all when n < 0); b'' at EOF (or after a timeout, see `timed_out`)."""

    @abstractmethod
    def finish(self, abort: bool = False) -> tuple[int, bytes]:
        """Wait for the command (or kill it when `abort`) and return (exit status, stderr)."""


class Transport(ABC):
    name: str = "?"

    @abstractmethod
    def stream(self, cmd: str, timeout: float = 60, stdin: bytes | None = None) -> Stream:
        """Start `cmd` on the remote, feed `stdin`, return its stdout as a stream (total time <= timeout)."""

    def run(self, cmd: str, timeout: float = 60, stdin: bytes | None = None) -> tuple[int, bytes, bytes]:
        """Run to completion: (exit status, stdout, stderr). Output is capped at MAX_RUN_OUTPUT."""
        s = self.stream(cmd, timeout, stdin)
        out = bytearray()
        try:
            while len(out) < MAX_RUN_OUTPUT:
                chunk = s.read(65536)
                if not chunk:
                    break
                out += chunk
        except BaseException:
            s.finish(abort=True)
            raise
        rc, err = s.finish(abort=len(out) >= MAX_RUN_OUTPUT)
        if s.timed_out:
            raise TimeoutError(f"remote command timed out after {timeout}s")
        return rc, bytes(out), err

    def close(self) -> None:
        pass


class _Drain(threading.Thread):
    """Collect a pipe/channel's stderr in the background so the remote never blocks on a full window."""

    def __init__(self, read: Callable[[int], bytes]):
        super().__init__(daemon=True)
        self._read, self.buf = read, bytearray()

    def run(self) -> None:
        try:
            while True:
                chunk = self._read(4096)
                if not chunk:
                    return
                if len(self.buf) < MAX_STDERR:
                    self.buf += chunk
        except Exception:  # noqa: BLE001
            return


class _ProcStream(Stream):
    def __init__(self, proc: subprocess.Popen, timeout: float, stdin: bytes | None):
        self.proc = proc
        self.timed_out = False
        self._err = _Drain(proc.stderr.read1 if hasattr(proc.stderr, "read1") else proc.stderr.read)  # type: ignore[union-attr]
        self._err.start()
        self._timer = threading.Timer(timeout, self._expire)
        self._timer.daemon = True
        self._timer.start()
        self._writer = threading.Thread(target=self._feed, args=(stdin,), daemon=True)
        self._writer.start()

    def _feed(self, data: bytes | None) -> None:
        try:
            if data:
                self.proc.stdin.write(data)  # type: ignore[union-attr]
        except OSError:
            pass
        finally:
            try:
                self.proc.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass

    def _expire(self) -> None:
        self.timed_out = True
        self.proc.kill()

    def read(self, n: int = -1) -> bytes:
        data = self.proc.stdout.read(n) if n >= 0 else self.proc.stdout.read()  # type: ignore[union-attr]
        return data or b""

    def finish(self, abort: bool = False) -> tuple[int, bytes]:
        try:
            if abort and self.proc.poll() is None:
                self.proc.kill()
            elif not abort:
                try:
                    while self.proc.stdout.read(1 << 16):  # type: ignore[union-attr]
                        pass
                except (OSError, ValueError):
                    pass
            rc = self.proc.wait()
        finally:
            self._timer.cancel()
            try:
                self.proc.stdout.close()  # type: ignore[union-attr]
            except OSError:
                pass
        self._err.join(2)
        return rc, bytes(self._err.buf)


class OpenSSHTransport(Transport):
    """System `ssh` binary: honours ~/.ssh/config, ssh-agent, ProxyJump, ControlMaster, known_hosts."""

    name = "openssh"

    def __init__(self, target: SSHTarget, *, ssh_bin: str | None = None, identity: str | None = None,
                 connect_timeout: int = 15, ssh_options: list[str] | None = None,
                 insecure_host_key: bool = False):
        self.target = target
        self.ssh_bin = ssh_bin or shutil.which("ssh") or "ssh"
        self.identity, self.connect_timeout = identity, connect_timeout
        self.ssh_options = list(ssh_options or [])
        self.insecure_host_key = insecure_host_key

    def argv(self, cmd: str) -> list[str]:
        t = self.target
        argv = [self.ssh_bin]
        for o in self.ssh_options:                        # user options first: ssh keeps the first value
            argv += ["-o", o]
        if self.insecure_host_key:
            argv += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
        argv += ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.connect_timeout}",
                 "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                 "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                 "-o", "PermitLocalCommand=no", "-o", "LogLevel=ERROR", "-T"]
        if t.port:
            argv += ["-p", str(t.port)]
        if t.user:
            argv += ["-l", t.user]
        if self.identity:
            argv += ["-i", self.identity]
        return [*argv, "--", t.host, cmd]

    def stream(self, cmd: str, timeout: float = 60, stdin: bytes | None = None) -> Stream:
        argv = self.argv(cmd)
        log.debug("ssh argv: %s", argv)
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        except OSError as e:
            raise SSHError(f"cannot run {argv[0]}: {e}") from e
        return _ProcStream(proc, timeout, stdin)


class _ChanStream(Stream):
    def __init__(self, chan: Any, timeout: float):
        self.chan = chan
        self.timed_out = False
        self._deadline = time.monotonic() + timeout
        self._eof = False
        self._err = _Drain(lambda n: chan.recv_stderr(n))
        self._err.start()

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            parts = []
            while chunk := self.read(65536):
                parts.append(chunk)
            return b"".join(parts)
        if self._eof:
            return b""
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            self.timed_out = True
            return b""
        self.chan.settimeout(min(remaining, 60))
        try:
            data = self.chan.recv(n)
        except TimeoutError:
            if time.monotonic() >= self._deadline:
                self.timed_out = True
            return b""
        if not data:
            self._eof = True
        return data

    def finish(self, abort: bool = False) -> tuple[int, bytes]:
        rc = -1
        try:
            if not abort and not self.timed_out:
                while self.read(1 << 16):
                    pass
                if self.chan.status_event.wait(10):
                    rc = self.chan.exit_status
        finally:
            try:
                self.chan.close()
            except Exception:  # noqa: BLE001, S110
                pass
        self._err.join(2)
        return rc, bytes(self._err.buf)


class ParamikoTransport(Transport):
    """Pure-Python SSH (paramiko). Host keys are verified against known_hosts unless `insecure_host_key`."""

    name = "paramiko"

    def __init__(self, target: SSHTarget, *, identity: str | None = None, known_hosts: str | None = None,
                 insecure_host_key: bool = False, connect_timeout: int = 15, password: str | None = None,
                 passphrase: str | None = None, allow_agent: bool = True, look_for_keys: bool = True,
                 ssh_config: str | None = None):
        self.target = target
        self.identity, self.known_hosts = identity, known_hosts
        self.insecure_host_key, self.connect_timeout = insecure_host_key, connect_timeout
        self.password = password if password is not None else os.environ.get(PASSWORD_ENV)
        self.passphrase = passphrase if passphrase is not None else os.environ.get(PASSPHRASE_ENV)
        self.allow_agent, self.look_for_keys = allow_agent, look_for_keys
        self.ssh_config = ssh_config
        self._client: Any = None

    def _connect(self) -> Any:
        import paramiko

        t = self.target
        host, port, user = t.host, t.port, t.user
        keys = [self.identity] if self.identity else []
        sock = None
        cfg_path = Path(self.ssh_config).expanduser() if self.ssh_config else Path.home() / ".ssh/config"
        if cfg_path.is_file():
            try:
                c = paramiko.SSHConfig.from_path(str(cfg_path)).lookup(t.host)
                host = c.get("hostname", host)
                port = port or (int(c["port"]) if c.get("port") else None)
                user = user or c.get("user")
                if not self.identity:
                    keys += c.get("identityfile", [])
                if c.get("proxycommand"):
                    sock = paramiko.ProxyCommand(c["proxycommand"])
            except Exception as e:  # noqa: BLE001
                log.debug("ignoring unreadable ssh config %s: %s", cfg_path, e)
        client = paramiko.SSHClient()
        if self.known_hosts:
            client.load_host_keys(self.known_hosts)
        else:
            try:
                client.load_system_host_keys()
            except OSError:
                pass
        if self.insecure_host_key:
            log.warning("insecure_host_key: remote host key of %s is NOT verified", t.host)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                hostname=host, port=port or 22, username=user or os.environ.get("USER") or None,
                password=self.password, passphrase=self.passphrase, key_filename=keys or None,
                allow_agent=self.allow_agent, look_for_keys=self.look_for_keys,
                timeout=self.connect_timeout, banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout, sock=sock)
        except paramiko.BadHostKeyException as e:
            raise SSHError(f"HOST KEY MISMATCH for {t.host}: {e}") from e
        except paramiko.AuthenticationException as e:
            raise SSHError(f"authentication failed for {t}: {e} (key/agent/{PASSWORD_ENV} ?)") from e
        except paramiko.SSHException as e:
            hint = " (add it to known_hosts, or -o insecure_host_key=true: UNSAFE)" \
                if "known_hosts" in str(e) else ""
            raise SSHError(f"ssh connection to {t} failed: {e}{hint}") from e
        except OSError as e:
            raise SSHError(f"cannot connect to {t}: {e}") from e
        tr = client.get_transport()
        if tr is not None:
            tr.set_keepalive(15)
        return client

    def stream(self, cmd: str, timeout: float = 60, stdin: bytes | None = None) -> Stream:
        if self._client is None:
            self._client = self._connect()
        log.debug("paramiko exec: %s", cmd)
        chan = self._client.get_transport().open_session(timeout=self.connect_timeout)
        chan.exec_command(cmd)
        if stdin:
            chan.sendall(stdin)
        chan.shutdown_write()
        return _ChanStream(chan, timeout)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def _as_list(v: Any) -> list[str]:
    if v is None or v == "":
        return []
    return [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]


def make_transport(target: SSHTarget, opts: dict[str, Any]) -> Transport:
    """transport=openssh|paramiko|auto (default): system ssh when installed (and no password given)."""
    choice = str(opts.get("transport") or "auto").lower()
    ct = opts_int(opts, "connect_timeout", 15)
    insecure = bool(opts.get("insecure_host_key"))
    identity = opts.get("identity")
    if choice == "auto":
        choice = "openssh" if shutil.which("ssh") and not os.environ.get(PASSWORD_ENV) else "paramiko"
    if choice == "openssh":
        return OpenSSHTransport(target, ssh_bin=opts.get("ssh_bin"), identity=identity, connect_timeout=ct,
                                ssh_options=_as_list(opts.get("ssh_option")), insecure_host_key=insecure)
    if choice == "paramiko":
        return ParamikoTransport(
            target, identity=identity, known_hosts=opts.get("known_hosts"), insecure_host_key=insecure,
            connect_timeout=ct, allow_agent=opts.get("allow_agent", True),
            look_for_keys=opts.get("look_for_keys", True), ssh_config=opts.get("ssh_config"))
    raise ValueError(f"unknown ssh transport {choice!r} (openssh | paramiko | auto)")


# --------------------------------------------------------------------------- stream handling

def _skip_to_marker(stream: Stream, marker: bytes, limit: int = MAX_PREAMBLE) -> bool:
    """Consume `stream` up to and including `marker`; False if it never appears (stream ended / too long)."""
    tail = b""
    for _ in range(limit):
        b = stream.read(1)
        if not b:
            return False
        tail = (tail + b)[-len(marker):]
        if tail == marker:
            return True
    return False


class _Reader:
    """File-like adapter (`read(n)`) over a Stream for tarfile."""

    def __init__(self, stream: Stream):
        self.stream = stream

    def read(self, n: int = -1) -> bytes:
        return self.stream.read(n)


def _stderr_text(err: bytes, limit: int = 600) -> str:
    return " | ".join(ln.strip() for ln in err.decode("utf-8", "replace").splitlines() if ln.strip())[:limit]


def _enable_verbose() -> None:
    if not any(isinstance(h, logging.StreamHandler) for h in log.handlers):
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("[ssh] %(message)s"))
        log.addHandler(h)
    log.setLevel(logging.DEBUG)


# --------------------------------------------------------------------------- collector

@register
class SSHCollector(Collector):
    name = "ssh"
    description = "Remote Linux/macOS host over SSH (agentless, read-only): `secmonk scan ssh user@host[:port]`"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        if not target:
            raise ValueError("ssh collector needs a target: user@host[:port] or ssh://user@host:port")
        if opts.get("verbose"):
            _enable_verbose()
        t = parse_target(target)
        injected = opts.get("transport")
        transport: Transport = injected if isinstance(injected, Transport) else make_transport(t, opts)
        try:
            return self._collect(t, transport, opts)
        finally:
            if transport is not injected:
                transport.close()

    # ------------------------------------------------------------------
    def _collect(self, t: SSHTarget, transport: Transport, opts: dict[str, Any]) -> Inventory:
        root = str(opts.get("root") or "/")
        timeout = opts_int(opts, "timeout", 900)
        sudo = bool(opts.get("sudo"))
        warnings: list[str] = []

        # 1. detect (Windows OpenSSH starts cmd.exe/PowerShell, where `sh -s` fails -> PowerShell path)
        if str(opts.get("os", "")).lower() == "windows":
            return self._collect_windows(t, transport, opts, timeout)
        script = harvest.detect_script(root)
        log.debug("remote command: sh -s <<'EOF'\n%sEOF", script)
        try:
            rc, out, err = transport.run("sh -s", timeout=min(timeout, 60), stdin=script.encode())
        except TimeoutError as e:
            raise SSHError(f"OS detection on {t} timed out: {e}") from e
        try:
            info = harvest.parse_detect(out.decode("utf-8", "replace"))
        except ValueError as e:
            if not opts.get("os") and self._is_windows(transport, timeout):
                return self._collect_windows(t, transport, opts, timeout)
            raise SSHError(f"{e} on {t} (rc={rc}): {_stderr_text(err) or 'no stderr'}") from e
        family = str(opts["os"]).lower() if opts.get("os") else info.family
        if family in ("darwin", "mac", "osx"):
            family = "macos"
        if family not in ("linux", "macos"):
            raise SSHError(f"unsupported remote OS {info.kernel!r} on {t} (supported: Linux, macOS, Windows)")

        # 2./3. harvest + extract
        spec = HarvestSpec(
            os=family, root=root, lang=bool(opts.get("lang", True)), binaries=bool(opts.get("binaries", False)),
            max_binary_bytes=opts_int(opts, "max_binary_mb", 50) * harvest.MB,
            xdev=opts.get("xdev") if "xdev" in opts else None,
            exclude=tuple(_as_list(opts.get("exclude"))))
        hscript = harvest.build_script(spec)
        remote_cmd = "sudo -n sh -s" if sudo else "sh -s"
        log.debug("remote command: %s <<'EOF'\n%sEOF", remote_cmd, hscript)
        tmp = tempfile.mkdtemp(prefix="secmonk-ssh-")
        os.chmod(tmp, 0o700)
        try:
            stats, trc, terr = self._harvest(transport, remote_cmd, hscript, tmp, timeout, opts, warnings)
            if stats.files == 0 and trc not in (0, 1):
                raise SSHError(f"remote harvest on {t} failed (rc={trc}): {_stderr_text(terr) or 'no stderr'}"
                               + (" (sudo needs a NOPASSWD rule: sudo -n)" if sudo else ""))
            if trc not in (0, 1) and terr:
                warnings.append(f"remote tar exited {trc} (some files unreadable?): {_stderr_text(terr)}")
            for r in stats.rejected[:20]:
                warnings.append(f"harvest: rejected tar entry {r}")
            if stats.limit:
                warnings.append(f"harvest truncated: {stats.limit}; inventory is partial "
                                "(raise -o max_mb / -o max_files or narrow with -o exclude=...)")
            # 4. reuse the existing collectors
            inv = self._inventory(family, tmp, t, info, stats, warnings, opts)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        # 5. rewrite the asset
        a = inv.asset
        a.id, a.name = f"ssh:{t.host}", t.host
        a.type = "server" if family == "linux" else "desktop"
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(info.arch, info.arch or "unknown")
        a.platform = f"{'linux' if family == 'linux' else 'darwin'}/{arch}"
        a.meta.update({
            "transport": transport.name, "user": t.user, "port": t.port or 22, "remote_os": info.description,
            "remote_hostname": info.hostname or None, "harvested_files": stats.files,
            "harvested_bytes": stats.bytes, "sudo": sudo, "truncated": bool(stats.limit)})
        if root != "/":
            a.meta["root"] = root
        inv.collector = self.name
        inv.warnings = warnings
        return inv

    # ------------------------------------------------------------------ Windows (OpenSSH server)
    PS = "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -"

    def _is_windows(self, transport: Transport, timeout: int) -> bool:
        try:
            rc, out, _ = transport.run(
                'powershell -NoProfile -NonInteractive -Command "[Environment]::OSVersion.Platform"',
                timeout=min(timeout, 60))
        except Exception:  # noqa: BLE001 - any failure means "not a Windows host we can drive"
            return False
        return rc == 0 and b"Win32NT" in out

    def _collect_windows(self, t: SSHTarget, transport: Transport, opts: dict[str, Any],
                         timeout: int) -> Inventory:
        """Run the read-only PowerShell inventory script (fed on stdin) and parse its JSON."""
        from . import windows

        script = windows.inventory_script(compact=True)
        log.debug("remote command: %s  (stdin: secmonk-inventory.ps1, %d bytes)", self.PS, len(script))
        rc, out, err = transport.run(self.PS, timeout=timeout, stdin=script.encode("utf-8"))
        text = out.decode("utf-8-sig", "replace")
        start = text.find("{")
        if start < 0:
            raise SSHError(f"Windows inventory on {t} produced no JSON (rc={rc}): "
                           f"{_stderr_text(err) or 'no stderr'}")
        try:
            data = json.loads(text[start:text.rfind("}") + 1])
        except ValueError as e:
            raise SSHError(f"Windows inventory on {t} returned invalid JSON: {e}") from e
        inv = windows.parse_inventory_json(data, include_system=opts.get("include_system", True))
        a = inv.asset
        a.meta.update({"transport": transport.name, "user": t.user, "port": t.port or 22,
                       "remote_os": "windows", "remote_hostname": a.name})
        a.id, a.name = f"ssh:{t.host}", t.host
        inv.collector = self.name
        if rc not in (0, None) and err:
            inv.warnings.append(f"powershell exited {rc}: {_stderr_text(err)}")
        return inv

    def _harvest(self, transport: Transport, cmd: str, script: str, tmp: str, timeout: int,
                 opts: dict[str, Any], warnings: list[str]):
        max_files = opts_int(opts, "max_files", 200_000)
        max_bytes = opts_int(opts, "max_mb", 512) * harvest.MB
        stream = transport.stream(cmd, timeout=timeout, stdin=script.encode())
        aborted = False
        stats = harvest.ExtractStats()
        try:
            if not _skip_to_marker(stream, (harvest.STREAM_MARKER + "\n").encode()):
                rc, err = stream.finish(abort=True)
                aborted = True
                if stream.timed_out:
                    raise SSHError(f"remote harvest timed out after {timeout}s")
                raise SSHError(f"remote harvest produced no archive (rc={rc}): {_stderr_text(err) or 'no stderr'}"
                               + (" (sudo needs a NOPASSWD rule: sudo -n)" if opts.get("sudo") else ""))
            try:
                harvest.safe_extract(_Reader(stream), tmp, max_files=max_files, max_bytes=max_bytes, stats=stats)
            except HarvestLimitExceeded:
                aborted = True                    # partial stats kept; abort the remote command
            except Exception as e:
                if stream.timed_out:
                    raise SSHError(f"remote harvest timed out after {timeout}s") from e
                aborted = True
                warnings.append(f"harvest stream ended abnormally: {type(e).__name__}: {e}; inventory may be partial")
            rc, err = stream.finish(abort=aborted)
        except BaseException:
            if not aborted:
                stream.finish(abort=True)
            raise
        if stream.timed_out:
            warnings.append(f"remote harvest hit the {timeout}s timeout; inventory is partial")
        return stats, (0 if aborted else rc), err

    @staticmethod
    def _inventory(family: str, tmp: str, t: SSHTarget, info: harvest.RemoteInfo, stats: Any,
                   warnings: list[str], opts: dict[str, Any]) -> Inventory:
        if family == "linux":
            asset = Asset(id=f"ssh:{t.host}", type="server", name=t.host)
            w: list[str] = []
            comps = collect_from_view(DirView(tmp), asset, w)
            warnings.extend(w)
            return Inventory(asset=asset, collector="ssh", components=comps)
        inv = MacOSCollector().collect(
            tmp, hostname=t.host, include_system=opts.get("include_system", True))
        warnings.extend(inv.warnings)
        return inv
