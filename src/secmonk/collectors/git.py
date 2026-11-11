"""`git` collector: dependency inventory of a git repository, cloned from a remote or read in place.

    secmonk scan git https://github.com/org/repo
    secmonk scan git git@github.com:org/repo.git -o ref=v1.2.0
    secmonk scan git git+ssh://git@git.example.com:2222/team/app.git -o identity=~/.ssh/ci_key
    secmonk scan git ./checkout                  # a local working tree, read in place (no git command runs)

Remote targets are fetched with the system `git` (fixed argv, hardened `-c` settings, no hooks, no submodules, no
LFS smudge, protocol allow-list, time and disk caps) into a private per-user cache directory, scanned with the
shared lang registry (`walk_dir`) and deleted (unless `keep=true`). `detect_projects()` tells what kind of projects
the tree holds (node, rust, go, dotnet, java, python, swift, dart, php, ruby) and which lack a lockfile.
See _docs/features/inventory-git.md and _docs/tech/collectors/git.md.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from ..models import Asset, Inventory
from ..paths import cache_subdir
from .base import Collector, read_within, register, strip_url_secrets
from .fs import _bool, _find_gitdirs, _git_info
from .lang import base as lang_base
from .lang.walk import SKIP_DIRS, WalkLimits, walk_dir

DEFAULT_TIMEOUT = 600            # seconds for the whole clone (fetch + checkout)
DEFAULT_MAX_MB = 2048            # clone directory cap (objects + checked-out tree)
CACHE_TTL = 15 * 60              # a clone left by `discover` is reused by a scan within this many seconds
STALE_WORK_SECS = 6 * 3600       # crashed work dirs older than this are removed
MAX_STDERR = 8 * 1024
META_FILE = "secmonk-clone.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_DETECT_FILES = 500_000
MAX_PROJECTS = 1000
MAX_MEMBERS = 50


class GitError(RuntimeError):
    """A clone failed (git error, timeout, size cap)."""


# --------------------------------------------------------------------------- target grammar

@dataclass(frozen=True)
class GitTarget:
    kind: str                     # https | ssh | scp | file | local
    url: str | None               # what git fetches from (https may carry credentials: never stored or shown)
    host: str | None = None       # lowercased
    port: int | None = None
    user: str | None = None
    path: str = ""                # repository path on the server, or the absolute local path
    shown: str = ""               # for display and asset meta: no password (https: no user name either)

    @property
    def remote(self) -> bool:
        return self.kind != "local"


_HELPER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*::")          # <transport>::<address> (ext::, fd::, …)
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_HOST_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_])?$")
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@\\-]*$")       # the ssh collector's rule
_SCP_RE = re.compile(r"^(?:([^@/:]+)@)?(\[[0-9A-Fa-f:.]+\]|[^@/:\[\]]+):(.*)$")
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REFNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/+-]*$")
DEFAULT_PORTS = {"https": 443, "ssh": 22}


def _check_host(host: str, target: str) -> str:
    h = host.strip("[]")
    if ":" in h:
        try:
            ipaddress.IPv6Address(h)
        except ValueError:
            raise ValueError(f"invalid host in git target {target!r}") from None
        return h.lower()
    if not _HOST_RE.match(h):
        raise ValueError(f"invalid host in git target {target!r}")
    return h.lower()


def _check_path(path: str, target: str) -> str:
    if not path or path.startswith("-") or "\x00" in path:
        raise ValueError(f"invalid repository path in git target {target!r}")
    return path


def parse_git_target(target: str | None) -> GitTarget:
    """Parse a git target.

    remote: `https://host[:port]/path`, `ssh://[user@]host[:port]/path`, scp-like `[user@]host:path`, each optionally
    prefixed `git+` (`git+https://…`, `git+ssh://…`), and `file:///abs/path` (a clone of a local repository);
    local: a filesystem path to a working tree, optionally prefixed `git:` (`git:./checkout`).
    Refused: a leading `-`, control characters, remote-helper transports (`ext::…`, `fd::…`), and any other scheme
    (`http://` and `git://` are unauthenticated and unencrypted). ValueError on anything invalid; a password is
    never echoed."""
    s = (target or "").strip()
    if not s:
        raise ValueError("git target is empty (expected a URL, user@host:path or a local working tree)")
    if any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise ValueError("git target contains control characters")
    if s.startswith("-"):
        raise ValueError("git target must not start with '-'")
    low = s.lower()
    if low.startswith("git:") and not low.startswith("git://"):
        return _local_target(s[4:])
    if low.startswith("git+"):
        s, low = s[4:], low[4:]
    if _HELPER_RE.match(s):
        raise ValueError("remote-helper transports (<name>::<address>, e.g. ext::) are refused")
    m = _SCHEME_RE.match(s)
    if m:
        scheme = m.group(1).lower()
        if scheme == "file":
            return _file_target(s)
        if scheme not in ("https", "ssh"):
            raise ValueError(f"unsupported git transport {scheme}:// (use https://, ssh://, user@host:path or file://;"
                             " http:// and git:// are unauthenticated)")
        return _url_target(scheme, s)
    if s.startswith(("/", "./", "../", "~", ".")) or ":" not in s:
        return _local_target(s)
    m = _SCP_RE.match(s)
    if m and "/" not in s.split(":", 1)[0] and len(m.group(2)) > 1:   # `C:\…` is a Windows path, not a host
        user, host, path = m.group(1), m.group(2), m.group(3)
        if user is not None and not _USER_RE.match(user):
            if ":" in user:
                raise ValueError("invalid user in git target (passwords are not accepted in ssh targets)")
            raise ValueError("invalid user in git target")
        host = _check_host(host, s)
        path = _check_path(path, s)
        shown = f"{user + '@' if user else ''}{'[' + host + ']' if ':' in host else host}:{path}"
        return GitTarget("scp", url=s, host=host, user=user, path=path, shown=shown)
    return _local_target(s)


def _url_target(scheme: str, s: str) -> GitTarget:
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError:
        raise ValueError(f"invalid git URL {strip_url_secrets(s)!r} (bad port?)") from None
    shown_err = strip_url_secrets(s)
    host = _check_host(parts.hostname or "", shown_err or "")
    path = _check_path(parts.path.rstrip("/") if parts.path not in ("", "/") else "", shown_err or "")
    user = parts.username
    if scheme == "ssh":
        if parts.password is not None:
            raise ValueError("passwords are not accepted in ssh:// git targets (use a key or ssh-agent)")
        if user is not None and not _USER_RE.match(user):
            raise ValueError("invalid user in git target")
    netloc = parts.netloc.rpartition("@")[2]
    url = f"{scheme}://{parts.netloc}{parts.path}"                # query and fragment dropped
    shown = f"{scheme}://{(user + '@') if user and scheme == 'ssh' else ''}{netloc}{parts.path}"
    return GitTarget(scheme, url=url, host=host, port=port, user=user if scheme == "ssh" else None, path=path,
                     shown=shown)


def _file_target(s: str) -> GitTarget:
    parts = urlsplit(s)
    if parts.netloc not in ("", "localhost"):
        raise ValueError("file:// git targets must be local (file:///path)")
    path = unquote(parts.path)
    if not path.startswith("/") or "\x00" in path:
        raise ValueError("file:// git targets need an absolute path (file:///path)")
    path = str(Path(path).resolve())
    return GitTarget("file", url=Path(path).as_uri(), path=path, shown=f"file://{path}")


def _local_target(s: str) -> GitTarget:
    if not s.strip() or "\x00" in s:
        raise ValueError("git target: empty local path")
    p = Path(s).expanduser().resolve()
    return GitTarget("local", url=None, path=str(p), shown=str(p))


def is_git_target(target: str | None) -> bool:
    """Is `target` (as typed for `secmonk discover`) a git repository rather than a host? `git+…`, `git:<path>`,
    `https://…`, `file://…`, `ssh://…/path.git`, and scp-like `[user@]host:path` whose path is not a port number."""
    s = (target or "").strip()
    low = s.lower()
    if low.startswith(("git+", "https://", "file://")) or (low.startswith("git:") and not low.startswith("git://")):
        return True
    if low.startswith("ssh://"):
        return urlsplit(s).path.rstrip("/").endswith(".git")
    if "://" in s or s.startswith(("/", ".", "~", "[")):
        return False
    m = _SCP_RE.match(s)
    return bool(m and "/" not in s.split(":", 1)[0] and m.group(3) and not m.group(3).isdigit()
                and len(m.group(2)) > 1)


def repo_key(t: GitTarget) -> str:
    """`host[:port]/path` (lowercased host, default port, user, `.git`, `~/` and slashes dropped): the same repository
    reached over https, ssh or scp-like gets the same key. `file:<path>` for file:// clones."""
    path = t.path.strip("/")
    path = path.removeprefix("~/")
    path = re.sub(r"\.git$", "", path).rstrip("/")
    if t.kind == "file":
        return "file:" + (re.sub(r"/?\.git$", "", t.path) or t.path)
    host = f"[{t.host}]" if t.host and ":" in t.host else (t.host or "")
    port = f":{t.port}" if t.port and t.port != DEFAULT_PORTS.get(t.kind) else ""
    return f"{host}{port}/{path}"


def repo_name(t: GitTarget) -> str:
    return re.sub(r"\.git$", "", t.path.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]) or (t.host or "repo")


def check_ref(ref: Any) -> tuple[str | None, bool]:
    """(ref, is_commit). A full 40/64-hex id is a commit (fetched by id); anything else must be a valid branch or
    tag name (no leading '-', no `..`, `@{`, `//`, trailing `/`, `.` or `.lock`)."""
    if ref is None or str(ref).strip() == "":
        return None, False
    r = str(ref).strip()
    if _SHA_RE.match(r.lower()):
        return r.lower(), True
    if (len(r) > 255 or not _REFNAME_RE.match(r) or ".." in r or "@{" in r or "//" in r
            or r.endswith(("/", ".", ".lock"))):
        raise ValueError(f"invalid git ref {r!r} (a branch, a tag or a full commit id)")
    return r, False


# --------------------------------------------------------------------------- hardened git invocation

def hardening_config(*, allow_file: bool) -> list[str]:
    """`-c` settings on every git command: nothing a repository or a stray config can make run (hooks, fsmonitor,
    submodules, ext:: transports, background gc), objects checked on receipt, symlinks checked out as plain files."""
    cfg = [
        f"core.hooksPath={os.devnull}",
        "core.fsmonitor=false",
        "core.symlinks=false",
        "protocol.allow=never",
        "protocol.https.allow=always",
        "protocol.ssh.allow=always",
        f"protocol.file.allow={'always' if allow_file else 'never'}",
        "protocol.ext.allow=never",
        "submodule.recurse=false",
        "fetch.recurseSubmodules=false",
        "transfer.fsckObjects=true",
        "fetch.fsckObjects=true",
        "gc.auto=0",
        "maintenance.auto=false",
        "advice.detachedHead=false",
        "init.defaultBranch=secmonk",
    ]
    out: list[str] = []
    for c in cfg:
        out += ["-c", c]
    return out


_KEEP_GIT_ENV = frozenset({"GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
                           "GIT_PROXY_COMMAND"})


def git_env(*, user_config: bool, ssh_command: str | None = None) -> dict[str, str]:
    """Environment of every git command: no prompts (terminal, askpass, ssh), LFS smudge skipped, inherited GIT_*
    variables that could redirect git (GIT_DIR, GIT_CONFIG_*, …) dropped. `user_config=False` also ignores the
    system and global git configuration (credential helpers, insteadOf, proxies are then unavailable)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k in _KEEP_GIT_ENV}
    false = shutil.which("false") or "/usr/bin/false"
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": false, "SSH_ASKPASS": false,
                "SSH_ASKPASS_REQUIRE": "never", "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never",
                "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    if not user_config:
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    if ssh_command:
        env["GIT_SSH_COMMAND"] = ssh_command
        env["GIT_SSH_VARIANT"] = "ssh"
    return env


def _as_list(v: Any) -> list[str]:
    if v is None or v == "":
        return []
    return [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]


def ssh_command(opts: dict[str, Any]) -> str | None:
    """GIT_SSH_COMMAND for the ssh options (identity, known_hosts, insecure_host_key, ssh_option, connect_timeout),
    every value shell-quoted (git runs it through `sh -c`). None when no ssh option is given: the user's own ssh /
    `core.sshCommand` setup is then used as is (BatchMode comes from the missing terminal and SSH_ASKPASS)."""
    keys = ("identity", "known_hosts", "insecure_host_key", "ssh_option", "connect_timeout")
    if not any(opts.get(k) not in (None, "", False, []) for k in keys):
        return None
    argv = [shutil.which("ssh") or "ssh"]
    for o in _as_list(opts.get("ssh_option")):                  # user options first: ssh keeps the first value
        if "\n" in o or "\r" in o:
            raise ValueError("ssh_option must not contain newlines")
        argv += ["-o", o]
    if _bool(opts.get("insecure_host_key"), False):
        argv += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=" + os.devnull]
    elif opts.get("known_hosts"):
        argv += ["-o", "UserKnownHostsFile=" + str(Path(str(opts["known_hosts"])).expanduser())]
    ct = _int_opt(opts, "connect_timeout", 15, 1, 600)
    argv += ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={ct}", "-o", "ClearAllForwardings=yes",
             "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "PermitLocalCommand=no", "-o", "LogLevel=ERROR"]
    if opts.get("identity"):
        argv += ["-o", "IdentitiesOnly=yes", "-i", str(Path(str(opts["identity"])).expanduser())]
    return " ".join(shlex.quote(a) for a in argv)


def _int_opt(opts: dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    v = opts.get(key)
    if v is None or v == "":
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"option {key} must be an integer") from None
    if not lo <= n <= hi:
        raise ValueError(f"option {key} must be between {lo} and {hi}")
    return n


def _dir_size(path: Path, limit: int) -> int:
    """Bytes under `path` (no symlink following); stops counting once over `limit`."""
    total = 0
    for dirpath, _dirs, files in os.walk(path, followlinks=False):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                continue
        if total > limit:
            break
    return total


def _kill(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        pass


def _run(argv: list[str], *, env: dict[str, str], timeout: float, cwd: str | None = None,
         watch: Path | None = None, max_bytes: int | None = None) -> tuple[int, str]:
    """Run one git command (no shell, stdin closed, own process group): (exit code, stderr tail). The whole group is
    killed on timeout or when `watch` grows over `max_bytes`."""
    with tempfile.TemporaryFile() as errf:
        kw: dict[str, Any] = {"start_new_session": True} if os.name == "posix" else \
            {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errf,
                                    env=env, cwd=cwd, **kw)
        except OSError as e:
            raise GitError(f"cannot run {argv[0]}: {e}") from e
        deadline = time.monotonic() + timeout
        next_check = time.monotonic() + 1
        try:
            while True:
                try:
                    rc = proc.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    pass
                now = time.monotonic()
                if now > deadline:
                    raise GitError(f"git timed out after {int(timeout)} s")
                if watch is not None and max_bytes and now >= next_check:
                    next_check = now + 2
                    if _dir_size(watch, max_bytes) > max_bytes:
                        raise GitError(f"clone exceeds max_mb={max_bytes // (1024 * 1024)}; aborted")
        except BaseException:
            _kill(proc)
            raise
        errf.seek(0, os.SEEK_END)
        size = errf.tell()
        errf.seek(max(0, size - MAX_STDERR))
        err = errf.read().decode("utf-8", "replace")
    return rc, err


def _git_bin(opts: dict[str, Any]) -> str:
    git = shutil.which("git")
    if not git:
        raise GitError("git is not installed (needed to clone remote repositories)")
    return git


def _stderr_line(err: str, url: str | None) -> str:
    """Last meaningful stderr lines, credentials of the URL never echoed."""
    lines = [ln.strip() for ln in err.splitlines() if ln.strip()]
    text = " | ".join(lines[-3:])[:600]
    if url and "@" in url:
        text = text.replace(url, strip_url_secrets(url) or "")
    from .base import scrub_text

    return scrub_text(text) or ""


# --------------------------------------------------------------------------- clone + cache

@dataclass
class Clone:
    tree: Path                    # working tree root (holds .git)
    work: Path                    # cache entry directory (tree + META_FILE)
    commit: str | None
    reused: bool = False
    meta: dict[str, Any] = field(default_factory=dict)


def cache_root() -> Path:
    return cache_subdir("git")


def cache_key(t: GitTarget, ref: str | None, depth: int) -> str:
    return hashlib.sha256(f"{t.shown}\0{ref or ''}\0{depth}".encode()).hexdigest()[:32]


def _rmtree(path: Path) -> None:
    def onexc(func, p, _exc):          # read-only pack files on Windows
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    if path.exists() or path.is_symlink():
        shutil.rmtree(path, onexc=onexc)


def _read_meta(entry: Path) -> dict | None:
    try:
        d = json.loads((entry / META_FILE).read_text())
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def prune_cache(root: Path | None = None, *, now: float | None = None) -> list[str]:
    """Remove expired clones: entries without `keep` older than CACHE_TTL, work dirs of crashed runs older than
    STALE_WORK_SECS. Returns the removed names."""
    root = root or cache_root()
    now = now or time.time()
    removed = []
    try:
        entries = list(root.iterdir())
    except OSError:
        return removed
    for e in entries:
        try:
            if e.is_symlink() or not e.is_dir():
                continue
            if e.name.endswith(".work"):
                if now - e.stat().st_mtime > STALE_WORK_SECS:
                    _rmtree(e)
                    removed.append(e.name)
                continue
            meta = _read_meta(e)
            if meta is None or (not meta.get("keep") and now - float(meta.get("created", 0)) > CACHE_TTL):
                _rmtree(e)
                removed.append(e.name)
        except OSError:
            continue
    return removed


def _claim_cached(root: Path, key: str, now: float) -> Path | None:
    """Atomically take a fresh cache entry (rename to a private work name) so two scans never share one."""
    entry = root / key
    meta = _read_meta(entry)
    if meta is None or now - float(meta.get("created", 0)) > CACHE_TTL or not (entry / "tree").is_dir():
        return None
    work = root / f"{key}.{uuid.uuid4().hex[:12]}.work"
    try:
        os.rename(entry, work)
    except OSError:
        return None
    return work


def acquire_clone(t: GitTarget, *, ref: str | None, is_commit: bool, depth: int, opts: dict[str, Any],
                  reuse: bool = True) -> Clone:
    """A checked-out clone of `t` at `ref` in a private work dir under the cache: a fresh entry left by `discover`
    (same URL, ref and depth, younger than CACHE_TTL) is taken over, else the repository is fetched."""
    root = cache_root()
    prune_cache(root)
    key = cache_key(t, ref, depth)
    now = time.time()
    if reuse and not _bool(opts.get("fresh"), False):
        work = _claim_cached(root, key, now)
        if work is not None:
            meta = _read_meta(work) or {}
            return Clone(tree=work / "tree", work=work, commit=meta.get("commit"), reused=True, meta=meta)
    work = root / f"{key}.{uuid.uuid4().hex[:12]}.work"
    work.mkdir(mode=0o700)
    try:
        commit = _fetch_checkout(t, work / "tree", ref=ref, is_commit=is_commit, depth=depth, opts=opts)
    except BaseException:
        _rmtree(work)
        raise
    meta = {"url": t.shown, "ref": ref, "depth": depth, "commit": commit, "created": now, "keep": False}
    (work / META_FILE).write_text(json.dumps(meta))
    return Clone(tree=work / "tree", work=work, commit=commit, meta=meta)


def release_clone(c: Clone, *, keep: bool = False, park: bool = False) -> Path | None:
    """Delete the clone, or (keep / park) move it to its cache entry name: `keep` survives pruning (path returned),
    `park` (discover) is reused by a scan within CACHE_TTL."""
    if not (keep or park):
        _rmtree(c.work)
        return None
    root = c.work.parent
    key = c.work.name.split(".", 1)[0]
    meta = dict(c.meta)
    meta["keep"] = bool(keep)
    if park and not c.reused:
        meta["created"] = time.time()
    (c.work / META_FILE).write_text(json.dumps(meta))
    dest = root / key
    _rmtree(dest)
    try:
        os.rename(c.work, dest)
    except OSError:
        _rmtree(c.work)
        return None
    return dest / "tree"


def _fetch_checkout(t: GitTarget, tree: Path, *, ref: str | None, is_commit: bool, depth: int,
                    opts: dict[str, Any]) -> str | None:
    git = _git_bin(opts)
    timeout = float(_int_opt(opts, "timeout", DEFAULT_TIMEOUT, 1, 24 * 3600))
    max_bytes = _int_opt(opts, "max_mb", DEFAULT_MAX_MB, 1, 1024 * 1024) * 1024 * 1024
    user_config = _bool(opts.get("user_config"), True)
    hard = hardening_config(allow_file=t.kind == "file")
    local_env = git_env(user_config=False)                       # init / checkout: no user config needed
    net_env = git_env(user_config=user_config, ssh_command=ssh_command(opts) if t.kind in ("ssh", "scp") else None)
    start = time.monotonic()

    def left() -> float:
        rest = timeout - (time.monotonic() - start)
        if rest <= 0:
            raise GitError(f"git timed out after {int(timeout)} s")
        return rest

    rc, err = _run([git, *hard, "init", "-q", "--template=", "--", str(tree)], env=local_env, timeout=left())
    if rc != 0:
        raise GitError(f"git init failed: {_stderr_line(err, None)}")
    refspec = ref or "HEAD"
    fetch = [git, *hard, "-C", str(tree), "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
             "--no-auto-gc"]
    if depth > 0:
        fetch.append(f"--depth={depth}")
    fetch += ["--", t.url or "", refspec]
    rc, err = _run(fetch, env=net_env, timeout=left(), watch=tree, max_bytes=max_bytes)
    if rc != 0:
        hint = ""
        if ref and not is_commit and re.fullmatch(r"[0-9a-fA-F]{7,39}", ref):
            hint = " (a commit must be given as a full 40-hex id)"
        elif is_commit:
            hint = " (the server may refuse fetching a commit by id; try the branch or tag that contains it)"
        raise GitError(f"git fetch of {t.shown} failed (exit {rc}): {_stderr_line(err, t.url)}{hint}")
    rc, err = _run([git, *hard, "-C", str(tree), "checkout", "-q", "--detach", "FETCH_HEAD"],
                   env=local_env, timeout=left(), watch=tree, max_bytes=max_bytes)
    if rc != 0:
        raise GitError(f"git checkout failed: {_stderr_line(err, t.url)}")
    if _dir_size(tree, max_bytes) > max_bytes:
        raise GitError(f"clone exceeds max_mb={max_bytes // (1024 * 1024)}; aborted")
    return _git_info(tree).get("commit")


# --------------------------------------------------------------------------- project detection

@dataclass(frozen=True)
class KindRule:
    rule: str                                  # rule id (one entry per directory and rule)
    kind: str                                  # node, rust, go, dotnet, java, python, swift, dart, php, ruby
    manifests: tuple[str, ...]                 # basenames or fnmatch patterns
    lockfiles: tuple[tuple[str, str], ...]     # (basename, package manager)
    package_manager: str | None
    lock_concept: str = "lockfile"             # lockfile | manifest-pins (go.mod) | none (maven)


RULES: tuple[KindRule, ...] = (
    KindRule("node", "node", ("package.json",),
             (("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm"), ("yarn.lock", "yarn"),
              ("pnpm-lock.yaml", "pnpm"), ("bun.lock", "bun"), ("bun.lockb", "bun")), "npm"),
    KindRule("rust", "rust", ("Cargo.toml",), (("Cargo.lock", "cargo"),), "cargo"),
    KindRule("go", "go", ("go.mod", "go.work"), (("go.sum", "go"),), "go", lock_concept="manifest-pins"),
    KindRule("dotnet", "dotnet", ("*.csproj", "*.fsproj", "*.vbproj", "*.sln", "*.slnx", "Directory.Packages.props",
                                  "Directory.Build.props", "global.json"),
             (("packages.lock.json", "nuget"), ("packages.config", "nuget")), "nuget"),
    KindRule("maven", "java", ("pom.xml",), (), "maven", lock_concept="none"),
    KindRule("gradle", "java", ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"),
             (("gradle.lockfile", "gradle"), ("buildscript-gradle.lockfile", "gradle"),
              ("gradle/verification-metadata.xml", "gradle")), "gradle"),
    KindRule("python", "python", ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "requirements*.txt",
                                  "requirements/*.txt", "environment.yml"),
             (("poetry.lock", "poetry"), ("uv.lock", "uv"), ("Pipfile.lock", "pipenv"), ("pdm.lock", "pdm"),
              ("pylock.toml", "pip")), "pip"),
    KindRule("swiftpm", "swift", ("Package.swift",), (("Package.resolved", "swiftpm"),), "swiftpm"),
    KindRule("cocoapods", "swift", ("Podfile",), (("Podfile.lock", "cocoapods"),), "cocoapods"),
    KindRule("dart", "dart", ("pubspec.yaml",), (("pubspec.lock", "pub"),), "pub"),
    KindRule("php", "php", ("composer.json",), (("composer.lock", "composer"),), "composer"),
    KindRule("ruby", "ruby", ("Gemfile", "gems.rb", "*.gemspec"), (("Gemfile.lock", "bundler"), ("gems.locked", "bundler")),
             "bundler"),
)

# directories that hold someone else's code, build output or caches: not walked for projects (vendoring: backlog)
VENDOR_DIRS = frozenset({"node_modules", "vendor", "third_party", "third-party", "bower_components", "jspm_packages",
                         "site-packages", "dist-packages", "Pods", "Carthage", ".cargo", ".pub-cache"})
DETECT_SKIP_DIRS = SKIP_DIRS | VENDOR_DIRS | frozenset({
    ".venv", "venv", "__pypackages__", "target", "obj", ".build", ".dart_tool", ".yarn", ".pnpm-store",
    ".next", ".nuxt", ".svelte-kit", ".expo", "DerivedData", "SourcePackages", ".swiftpm"})


def _rule_match(rel: str) -> list[tuple[KindRule, str, str | None]]:
    """(rule, project dir, package manager when it is a lockfile) for one tracked file path."""
    parts = rel.split("/")
    name = parts[-1]
    parent = "/".join(parts[:-1])
    out: list[tuple[KindRule, str, str | None]] = []
    for r in RULES:
        for lock, pm in r.lockfiles:
            if "/" in lock:                                         # gradle/verification-metadata.xml
                sub, base = lock.rsplit("/", 1)
                if name == base and parent.split("/")[-1] == sub:
                    out.append((r, "/".join(parts[:-2]), pm))
            elif name == lock:
                if r.rule == "swiftpm" and (".xcodeproj/" in rel or ".xcworkspace/" in rel):   # Xcode's copy
                    out.append((r, _xcode_dir(parts), pm))
                else:
                    out.append((r, parent, pm))
        for pat in r.manifests:
            if "/" in pat:                                          # requirements/*.txt -> the parent project
                sub, base = pat.rsplit("/", 1)
                if parent.split("/")[-1] == sub and fnmatch.fnmatchcase(name, base):
                    out.append((r, "/".join(parts[:-2]), None))
            elif fnmatch.fnmatchcase(name, pat):
                out.append((r, parent, None))
    return out


def _xcode_dir(parts: list[str]) -> str:
    for i, p in enumerate(parts):
        if p.endswith((".xcodeproj", ".xcworkspace")):
            return "/".join(parts[:i])
    return "/".join(parts[:-1])


def _walk_tree(root: Path, limit: int = MAX_DETECT_FILES) -> tuple[list[str], list[str], bool]:
    """(relative file paths, vendored dirs seen, truncated); symlinks are never followed, VCS / vendor / build dirs
    are pruned. Xcode bundles are entered (Package.resolved lives inside)."""
    files: list[str] = []
    vendored: list[str] = []
    for dirpath, dirs, names in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        keep = []
        for d in sorted(dirs):
            sub = f"{rel_dir}/{d}" if rel_dir else d
            if d in VENDOR_DIRS:
                if len(vendored) < 200:
                    vendored.append(sub)
            elif d not in DETECT_SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)):
                keep.append(d)
        dirs[:] = keep
        for n in sorted(names):
            files.append(f"{rel_dir}/{n}" if rel_dir else n)
            if len(files) >= limit:
                return files, vendored, True
    return files, vendored, False


def _read(root: Path, rel: str) -> bytes | None:
    try:
        return read_within(root / rel, root, MAX_MANIFEST_BYTES)
    except (OSError, ValueError):
        return None


def _toml(root: Path, rel: str) -> dict:
    data = _read(root, rel)
    if not data:
        return {}
    try:
        d = tomllib.loads(data.decode("utf-8", "replace"))
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def _json(root: Path, rel: str) -> dict:
    data = _read(root, rel)
    if not data:
        return {}
    try:
        d = json.loads(data)
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def _strs(v: Any) -> list[str]:
    return [str(x)[:200] for x in v][:MAX_MEMBERS] if isinstance(v, list) else []


def _yaml_list(text: str, key: str) -> list[str] | None:
    """Items of a top-level `key:` block list in simple YAML (pnpm-workspace.yaml packages, pubspec workspace)."""
    out: list[str] | None = None
    inside = False
    for line in text.splitlines():
        if re.match(rf"^{re.escape(key)}\s*:", line):
            inside, out = True, []
            continue
        if inside:
            m = re.match(r"^\s+-\s*['\"]?([^'\"#]+?)['\"]?\s*(?:#.*)?$", line)
            if m:
                out.append(m.group(1)[:200])            # type: ignore[union-attr]
            elif line.strip() and not line.startswith((" ", "\t", "#")):
                inside = False
    return out[:MAX_MEMBERS] if out is not None else None


def _pinned_requirements(root: Path, rels: list[str]) -> bool:
    """Every requirement line of these files pins one version with `==` (pip-compile output, a hand-pinned list)."""
    reqs = 0
    for rel in rels:
        data = _read(root, rel)
        if data is None:
            return False
        for line in data.decode("utf-8", "replace").splitlines():
            s = line.split("#", 1)[0].strip().rstrip("\\").strip()
            if not s or s.startswith(("-", "--")):
                continue
            reqs += 1
            spec = s.split(";", 1)[0]
            if "==" not in spec or any(op in spec.replace("==", "") for op in ("<", ">", "~=", "!=", "*")):
                return False
    return reqs > 0


def _workspace(root: Path, rule: KindRule, d: str, names: set[str]) -> dict | None:
    """Workspace / multi-module hints of one project directory (plain info: monorepo handling is backlog)."""
    def rel(n: str) -> str:
        return f"{d}/{n}" if d else n

    if rule.rule == "node":
        ws: dict[str, Any] = {}
        pj = _json(root, rel("package.json"))
        w = pj.get("workspaces")
        members = _strs(w.get("packages") if isinstance(w, dict) else w)
        if members:
            ws.update(tool="workspaces", members=members)
        if "pnpm-workspace.yaml" in names:
            data = _read(root, rel("pnpm-workspace.yaml"))
            ws.update(tool="pnpm-workspace", members=_yaml_list((data or b"").decode("utf-8", "replace"),
                                                                 "packages") or [])
        tools = [t for t, f in (("lerna", "lerna.json"), ("nx", "nx.json"), ("turbo", "turbo.json"),
                                ("rush", "rush.json")) if f in names]
        if tools:
            ws["tools"] = tools
        return ws or None
    if rule.rule == "rust":
        w = _toml(root, rel("Cargo.toml")).get("workspace")
        if isinstance(w, dict):
            return {"tool": "cargo-workspace", "members": _strs(w.get("members"))}
    if rule.rule == "go" and "go.work" in names:
        data = (_read(root, rel("go.work")) or b"").decode("utf-8", "replace")
        uses = re.findall(r"^\s*(?:use\s+)?(\.{1,2}/[^\s)]*|\.)\s*$", data, re.MULTILINE)
        return {"tool": "go.work", "members": uses[:MAX_MEMBERS]}
    if rule.rule == "python":
        uv = ((_toml(root, rel("pyproject.toml")).get("tool") or {}).get("uv") or {}) \
            if "pyproject.toml" in names else {}
        w = uv.get("workspace") if isinstance(uv, dict) else None
        if isinstance(w, dict):
            return {"tool": "uv-workspace", "members": _strs(w.get("members"))}
    if rule.rule == "gradle":
        for n in ("settings.gradle", "settings.gradle.kts"):
            if n in names:
                text = (_read(root, rel(n)) or b"").decode("utf-8", "replace")
                inc = []
                for line in re.findall(r"^\s*include\b(.*)$", text, re.MULTILINE):
                    inc += re.findall(r"['\"]([^'\"]+)['\"]", line)
                return {"tool": "gradle-settings", "members": inc[:MAX_MEMBERS]}
    if rule.rule == "maven" and "pom.xml" in names:
        text = (_read(root, rel("pom.xml")) or b"").decode("utf-8", "replace")
        mods = re.findall(r"<module>\s*([^<\s]+)\s*</module>", text)
        if mods:
            return {"tool": "maven-modules", "members": mods[:MAX_MEMBERS]}
    if rule.rule == "dotnet":
        projs: list[str] = []
        for n in sorted(names):
            if n.lower().endswith((".sln",)):
                text = (_read(root, rel(n)) or b"").decode("utf-8", "replace")
                projs += [p.replace("\\", "/") for p in
                          re.findall(r'^Project\("[^"]*"\)\s*=\s*"[^"]*",\s*"([^"]+\.(?:cs|fs|vb)proj)"', text,
                                     re.MULTILINE)]
        if projs:
            return {"tool": "sln", "members": projs[:MAX_MEMBERS]}
    if rule.rule == "dart" and "pubspec.yaml" in names:
        members = _yaml_list((_read(root, rel("pubspec.yaml")) or b"").decode("utf-8", "replace"), "workspace")
        if members:
            return {"tool": "pub-workspace", "members": members}
    return None


def _python_pm(root: Path, d: str, names: set[str], manifests: list[str]) -> str:
    rel = f"{d}/pyproject.toml" if d else "pyproject.toml"
    if "pyproject.toml" in names:
        py = _toml(root, rel)
        tool = py.get("tool") if isinstance(py.get("tool"), dict) else {}
        for key, pm in (("poetry", "poetry"), ("uv", "uv"), ("pdm", "pdm"), ("hatch", "hatch")):
            if key in tool:
                return pm
        if "Pipfile" in names:
            return "pipenv"
        backend = str((py.get("build-system") or {}).get("build-backend") or "") \
            if isinstance(py.get("build-system"), dict) else ""
        for key, pm in (("poetry", "poetry"), ("pdm", "pdm"), ("hatchling", "hatch"), ("flit", "flit"),
                        ("setuptools", "setuptools"), ("maturin", "maturin")):
            if key in backend:
                return pm
    if "Pipfile" in names:
        return "pipenv"
    if "environment.yml" in names and not any(m.rsplit("/", 1)[-1].startswith("requirements") for m in manifests):
        return "conda"
    if "setup.py" in names or "setup.cfg" in names:
        return "setuptools"
    return "pip"


def detect_projects(root: Path | str, *, files: list[str] | None = None) -> list[dict]:
    """The projects of a source tree: one entry per directory and build system, sorted by path.

    `{path, kind, package_manager, manifests, lockfiles, unparsed, lockfile_missing, lockfile_from?, workspace?,
    workspace_root?, note?}` with paths relative to `root` (`.` = the top). `unparsed` lists lockfiles no registered lang parser reads
    (their dependencies are not inventoried). `lockfile_missing` means only declared dependencies (pinned ones) can
    be matched; a project below a workspace root of the same kind is a member (`workspace_root`) and shares the
    root's lockfile (`lockfile_from`) or its gap. Pure: reads only
    small manifests below `root` (read_within, 1 MiB cap), never runs anything."""
    root = Path(root)
    if files is None:
        files, _vendored, _trunc = _walk_tree(root)
    by_dir: dict[str, set[str]] = {}
    for f in files:
        d, _, n = f.rpartition("/")
        by_dir.setdefault(d, set()).add(n)
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for f in files:
        if len(found) >= MAX_PROJECTS:
            break
        for rule, d, pm in _rule_match(f):
            e = found.setdefault((d, rule.rule), {"rule": rule, "dir": d, "manifests": [], "lockfiles": [],
                                                  "pms": []})
            if pm:
                e["lockfiles"].append(f)
                e["pms"].append(pm)
            else:
                e["manifests"].append(f)
    out: list[dict] = []
    for (d, _rid), e in sorted(found.items()):
        rule: KindRule = e["rule"]
        names = by_dir.get(d, set())
        manifests, lockfiles = sorted(set(e["manifests"])), sorted(set(e["lockfiles"]))
        pms = list(dict.fromkeys(e["pms"]))
        if pms:
            pm = pms[0]
        elif rule.rule == "node":
            pmf = str(_json(root, f"{d}/package.json" if d else "package.json").get("packageManager") or "")
            pm = pmf.split("@", 1)[0] if pmf.split("@", 1)[0] in ("npm", "yarn", "pnpm", "bun") else "npm"
        elif rule.rule == "python":
            pm = _python_pm(root, d, names, manifests)
        else:
            pm = rule.package_manager
        entry: dict[str, Any] = {"path": d or ".", "kind": rule.kind, "package_manager": pm,
                                 "manifests": manifests, "lockfiles": lockfiles,
                                 "unparsed": [lf for lf in lockfiles if not lang_base.parsers_for(lf)]}
        if len(pms) > 1:
            entry["package_managers"] = pms
        missing = not lockfiles
        if rule.lock_concept == "manifest-pins":
            missing = False
            entry["note"] = "go.mod lists the full module build list (go >= 1.17)"
        elif rule.lock_concept == "none":
            entry["note"] = "Maven has no lockfile: literal versions in pom.xml are read, transitive ones are not"
        elif missing and rule.rule == "python":
            reqs = [m for m in manifests if m.rsplit("/", 1)[-1].startswith("requirements")
                    or "/requirements/" in f"/{m}"]
            if reqs and _pinned_requirements(root, reqs):
                missing = False
                entry["note"] = "requirements files pin every dependency with =="
        entry["lockfile_missing"] = missing
        ws = _workspace(root, rule, d, names)
        if ws:
            entry["workspace"] = ws
        out.append(entry)
    # a workspace member (a project below a workspace root of the same kind) shares the root's lockfile; members of a
    # workspace without one are reported once, through the root
    for p in out:
        if p["path"] == ".":
            continue
        anc = p["path"]
        while anc != ".":
            anc = anc.rsplit("/", 1)[0] if "/" in anc else "."
            roots = [q for q in out if q["path"] == anc and q["kind"] == p["kind"] and q.get("workspace")]
            if roots:
                p["workspace_root"] = roots[0]["path"]
                if p["lockfile_missing"]:
                    p["lockfile_missing"] = roots[0]["lockfile_missing"]
                    if roots[0]["lockfiles"]:
                        p["lockfile_from"] = roots[0]["path"]
                break
    return out


def lockfile_warning(projects: list[dict]) -> str | None:
    gaps = [f"{p['path']} ({p['kind']}/{p['package_manager']})" for p in projects
            if p["lockfile_missing"] and not p.get("workspace_root")]
    if not gaps:
        return None
    shown = ", ".join(gaps[:10]) + (f" … (+{len(gaps) - 10})" if len(gaps) > 10 else "")
    return (f"{len(gaps)} project(s) without a lockfile: only direct dependencies with pinned versions can be matched;"
            f" version ranges are skipped: {shown}")


def _submodules(root: Path) -> list[str]:
    data = _read(root, ".gitmodules")
    if not data:
        return []
    return re.findall(r"^\s*path\s*=\s*(.+?)\s*$", data.decode("utf-8", "replace"), re.MULTILINE)[:MAX_MEMBERS]


def tree_facts(root: Path) -> tuple[dict[str, Any], list[str]]:
    """Asset meta facts about a source tree (projects, kinds, lockfile gaps, vendored dirs, submodules) + warnings."""
    files, vendored, truncated = _walk_tree(root)
    projects = detect_projects(root, files=files)
    warnings = []
    if truncated:
        warnings.append(f"project detection stopped after {MAX_DETECT_FILES} files")
    if w := lockfile_warning(projects):
        warnings.append(w)
    unparsed = sorted({u for p in projects for u in p["unparsed"]})
    if unparsed:
        warnings.append("lockfiles without a parser (not inventoried): " + ", ".join(unparsed[:10])
                        + (" …" if len(unparsed) > 10 else ""))
    subs = _submodules(root)
    if subs:
        warnings.append(f"{len(subs)} git submodule(s) not fetched or scanned: " + ", ".join(subs[:10]))
    facts: dict[str, Any] = {
        "projects": projects[:200],
        "project_kinds": sorted({p["kind"] for p in projects}),
        "lockfile_gaps": [p["path"] for p in projects if p["lockfile_missing"] and not p.get("workspace_root")][:200],
    }
    if len(projects) > 200:
        facts["projects_truncated"] = len(projects)
    if vendored:
        facts["vendored_dirs"] = vendored[:50]
    if subs:
        facts["submodules"] = subs
    return facts, warnings


# --------------------------------------------------------------------------- collector

def _find_worktree(path: Path) -> Path | None:
    """The working tree containing `path` (its own `.git`, or the closest parent with one)."""
    for p in (path, *path.parents):
        if _find_gitdirs(p) is not None:
            return p
    return None


def _is_bare(path: Path) -> bool:
    return (path / "HEAD").is_file() and (path / "objects").is_dir() and (path / "refs").is_dir() \
        and not (path / ".git").exists()


@register
class GitCollector(Collector):
    name = "git"
    description = "Git repository (https, ssh, local): project kinds + lockfiles/manifests of every ecosystem"

    def collect(self, target: str | None = None, **opts: Any) -> Inventory:
        t = parse_git_target(target or ".")
        limits = WalkLimits(binaries=_bool(opts.get("binaries"), False),
                            max_files=_int_opt(opts, "max_files", WalkLimits.max_files, 1, 10_000_000))
        if t.kind == "local":
            return self._collect_local(t, limits, opts)
        ref, is_commit = check_ref(opts.get("ref"))
        depth = _int_opt(opts, "depth", 1, 0, 1_000_000)
        keep = _bool(opts.get("keep"), False)
        clone = acquire_clone(t, ref=ref, is_commit=is_commit, depth=depth, opts=opts)
        kept: Path | None = None
        try:
            inv = self._inventory(clone.tree, limits, asset_id=opts.get("asset_id") or
                                  (f"git:{repo_key(t)}" + (f"@{ref}" if ref else "")),
                                  name=repo_name(t),
                                  meta={"url": t.shown, "source": "clone", "ref": ref, "commit": clone.commit,
                                        "depth": depth, "reused_clone": clone.reused})
        finally:
            kept = release_clone(clone, keep=keep)
        if kept is not None:
            inv.asset.meta["clone_dir"] = str(kept)
            inv.warnings.append(f"clone kept in {kept} (keep=true)")
        return inv

    def _collect_local(self, t: GitTarget, limits: WalkLimits, opts: dict[str, Any]) -> Inventory:
        path = Path(t.path)
        if not path.is_dir():
            raise NotADirectoryError(f"{path}: not a directory (remote repositories: https://, ssh:// or "
                                     "user@host:path)")
        if _is_bare(path):
            raise ValueError(f"{path} is a bare repository: scan it as file://{path} (cloned), or a working tree")
        wt = _find_worktree(path)
        if wt is None:
            raise ValueError(f"{path} is not inside a git working tree (use `secmonk scan fs` for a plain folder)")
        git = _git_info(wt)                    # file reads only: no git command runs in a local checkout
        meta: dict[str, Any] = {"path": str(path), "source": "local", "git": git, "commit": git.get("commit"),
                                "branch": git.get("branch")}
        if git.get("remote"):
            meta["url"] = git["remote"]
        if wt != path:
            meta["worktree"] = str(wt)
        return self._inventory(path, limits, asset_id=opts.get("asset_id") or f"repo:{path}", name=path.name,
                               meta=meta)

    def _inventory(self, tree: Path, limits: WalkLimits, *, asset_id: str, name: str,
                   meta: dict[str, Any]) -> Inventory:
        res = walk_dir(tree, limits=limits)
        facts, warns = tree_facts(tree)
        asset = Asset(id=asset_id, type="repo", name=name,
                      meta={**{k: v for k, v in meta.items() if v is not None}, "files_parsed": res.files_parsed,
                            **facts})
        return Inventory(asset=asset, collector=self.name, components=res.components,
                         warnings=[*res.warnings, *warns], partial=res.truncated,
                         partial_reason="dependency file cap reached" if res.truncated else None)
