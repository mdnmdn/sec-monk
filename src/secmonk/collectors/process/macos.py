"""macOS backend of the process monitor.

* snapshot (live only): `ps` (pid, ppid, uid, user, start time, executable), `proc_pidpath()` for the exact
  image path, `launchctl list` (pid -> launchd job label), launchd plists of the system and of every user.
* inspector (live or a copied tree under `root`): executable -> software identity (Homebrew keg, outermost
  `.app` bundle, macOS system path, pkgutil receipt, embedded `__info_plist`, Go/Rust build info) and
  provenance facts (code signature, quarantine xattr + LaunchServices QuarantineEventsV2 entry,
  `kMDItemWhereFroms`, Homebrew receipt, pkgutil install time, file times, hash).

Nothing is executed on the machine except fixed read-only commands: `ps`, `launchctl list`, `codesign -dv`,
`pkgutil --file-info`, `spctl --assess` (opt-in). See _docs/tech/collectors/process.md.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import hashlib
import os
import plistlib
import re
import socket
import sqlite3
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ...engine import purl as purls
from ...models import CAT_APPLICATION, CAT_PACKAGE, CAT_SYSTEM_APP, Component
from ..base import REDACTED, read_within, redact_command, resolve_within, strip_url_secrets
from .backend import Inspector, Resolution
from .model import LaunchItem, ProcessRecord, Snapshot

CMD_TIMEOUT = 30
MAX_PLIST_BYTES = 1024 * 1024
DEFAULT_MAX_BINARY = 128 * 1024 * 1024
CF_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)        # CFAbsoluteTime / QuarantineEventsV2 timestamps

# where launchd reads job definitions: (dir relative to root or home, mechanism, system-scope?)
LAUNCHD_DIRS = (
    ("Library/LaunchDaemons", "launchd-daemon"),
    ("Library/LaunchAgents", "launchd-agent"),
    ("System/Library/LaunchDaemons", "launchd-system-daemon"),
    ("System/Library/LaunchAgents", "launchd-system-agent"),
)
SYSTEM_PREFIXES = ("/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/bin/", "/sbin/",
                   "/Library/Apple/", "/private/var/db/com.apple.")
# writable by an ordinary user: binaries running from here deserve a second look
USER_WRITABLE = ("/Users/", "/tmp/", "/private/tmp/", "/private/var/folders/", "/var/folders/", "/Volumes/",
                 "/Users/Shared/")


# ============================================================================ parsers (pure, tested on fixtures)

def _lstart(tokens: list[str]) -> str | None:
    """'Thu Nov  7 10:00:00 2026' (C locale) -> '2026-11-07T10:00:00' (local time, no zone)."""
    try:
        return datetime.strptime(" ".join(tokens), "%a %b %d %H:%M:%S %Y").isoformat()
    except ValueError:
        return None


def parse_ps(text: str) -> list[ProcessRecord]:
    """`ps -axww -o pid=,ppid=,uid=,user=,lstart=,comm=` (LC_ALL=C). comm is the executable path on macOS
    and may contain spaces, so it is the rest of the line."""
    out: list[ProcessRecord] = []
    for line in text.splitlines():
        f = line.split(None, 9)
        if len(f) < 10 or not f[0].isdigit() or not f[1].isdigit():
            continue
        pid, ppid, uid, user = int(f[0]), int(f[1]), f[2], f[3]
        comm = f[9].strip()
        exe = comm if comm.startswith("/") else None
        out.append(ProcessRecord(pid=pid, ppid=ppid, uid=int(uid) if uid.lstrip("-").isdigit() else None,
                                 user=user, started=_lstart(f[4:9]), exe=exe,
                                 name=os.path.basename(comm) if comm else None))
    return out


def parse_ps_args(text: str) -> dict[int, list[str]]:
    """`ps -axww -o pid=,args=` -> pid -> redacted argv (split on whitespace: ps joins argv with spaces,
    so arguments containing spaces cannot be recovered exactly)."""
    out: dict[int, list[str]] = {}
    for line in text.splitlines():
        f = line.strip().split(None, 1)
        if len(f) == 2 and f[0].isdigit():
            out[int(f[0])] = _over_redact(list(redact_command(f[1].split()[:64]) or []))
    return out


def _over_redact(args: list[str]) -> list[str]:
    """ps joins argv with spaces, so `--password "a b"` arrives as 3 tokens: after a redacted value, hide every
    following token up to the next option (over-redaction is the safe side)."""
    out: list[str] = []
    hiding = False
    for a in args:
        if hiding and not a.startswith("-"):
            out.append(REDACTED)
            continue
        hiding = a == REDACTED
        out.append(a)
    return out


def parse_launchctl_list(text: str) -> dict[int, str]:
    """`launchctl list`: 'PID\\tStatus\\tLabel' rows; PID '-' = not running."""
    out: dict[int, str] = {}
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) >= 3 and f[0].strip().isdigit():
            out[int(f[0])] = f[2].strip()
    return out


def parse_launchd_plist(d: dict, source: str, mechanism: str, scope: str) -> LaunchItem | None:
    label = d.get("Label")
    if not isinstance(label, str) or not label:
        return None
    args = d.get("ProgramArguments") if isinstance(d.get("ProgramArguments"), list) else []
    args = [a for a in args if isinstance(a, str)]
    program = d.get("Program") if isinstance(d.get("Program"), str) else (args[0] if args else None)
    keep_alive = d.get("KeepAlive")
    meta = {k: d[k] for k in ("StartInterval", "WatchPaths", "UserName", "BundleProgram", "AssociatedBundleIdentifiers")
            if k in d and isinstance(d[k], (str, int, list))}
    if "StartCalendarInterval" in d:
        meta["StartCalendarInterval"] = True
    if isinstance(d.get("MachServices"), dict):
        meta["MachServices"] = sorted(d["MachServices"])[:10]
    return LaunchItem(mechanism=mechanism, label=label, program=program,
                      args=list(redact_command(args[1:32]) or []), source=source, scope=scope,
                      run_at_load=d.get("RunAtLoad") if isinstance(d.get("RunAtLoad"), bool) else None,
                      keep_alive=bool(keep_alive) if keep_alive is not None else None,
                      disabled=d.get("Disabled") if isinstance(d.get("Disabled"), bool) else None, meta=meta)


_PLIST_CACHE: dict[tuple, LaunchItem | None] = {}


def index_launch_items(root: Path, homes: list[Path], include_system: bool = True) -> tuple[list[LaunchItem], list[str]]:
    """Every launchd plist under root (system dirs) and under each home (`~/Library/LaunchAgents`)."""
    boundary = root.resolve()
    items: list[LaunchItem] = []
    warnings: list[str] = []
    dirs: list[tuple[Path, str, str, Path]] = []
    for rel, mech in LAUNCHD_DIRS:
        if mech.startswith("launchd-system") and not include_system:
            continue
        dirs.append((root / rel, mech, "system", boundary))
    for h in homes:
        dirs.append((h / "Library/LaunchAgents", "launchd-agent", f"user:{h.name}", h.resolve()))
    for d, mech, scope, bound in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.plist")):
            try:
                st = p.stat()
                key = (str(p), str(bound), mech, scope, st.st_ino, st.st_size, st.st_mtime_ns)
                if key in _PLIST_CACHE:          # --watch re-indexes every tick: parse only changed plists
                    it = _PLIST_CACHE[key]
                else:
                    data = plistlib.loads(read_within(p, bound, MAX_PLIST_BYTES))
                    if not isinstance(data, dict):
                        raise ValueError("not a dictionary")
                    it = parse_launchd_plist(data, _target_path(p, root), mech, scope)
                    if len(_PLIST_CACHE) > 20_000:
                        _PLIST_CACHE.clear()
                    _PLIST_CACHE[key] = it
                if it:
                    items.append(it)
            except Exception as e:  # noqa: BLE001 - one bad plist must not hide the others
                warnings.append(f"cannot read launchd plist {_target_path(p, root)}: {e}")
    return items, warnings


def parse_quarantine(value: str | bytes | None) -> dict[str, Any] | None:
    """`com.apple.quarantine` = 'flags;hex-unix-time;agent;event-uuid' (e.g. '0083;6727a1b2;Safari;9F0C...')."""
    if not value:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    f = value.strip("\x00").split(";")
    out: dict[str, Any] = {"raw_flags": f[0]}
    with contextlib.suppress(ValueError, IndexError, OverflowError):
        out["time"] = datetime.fromtimestamp(int(f[1], 16), UTC).isoformat()
    if len(f) > 2 and f[2]:
        out["agent"] = f[2]
    if len(f) > 3 and f[3]:
        out["event_id"] = f[3]
    with contextlib.suppress(ValueError):
        flags = int(f[0], 16)
        out["user_approved"] = bool(flags & 0x0040)   # opened once after the Gatekeeper prompt
    return out


def parse_where_froms(data: bytes | None) -> list[str]:
    """`com.apple.metadata:kMDItemWhereFroms`: binary plist list [download URL, referrer page]."""
    if not data:
        return []
    try:
        v = plistlib.loads(data)
    except Exception:  # noqa: BLE001
        return []
    return [strip_url_secrets(u) or u for u in (v if isinstance(v, list) else []) if isinstance(u, str)][:4]


def quarantine_event(db: Path, event_id: str) -> dict[str, Any] | None:
    """Row of `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` for one event id."""
    if not db.is_file():
        return None
    from urllib.parse import quote

    uri = f"file:{quote(str(db))}?mode=ro&immutable=1"
    try:
        with contextlib.closing(sqlite3.connect(uri, uri=True)) as conn:
            r = conn.execute(
                """SELECT LSQuarantineTimeStamp, LSQuarantineAgentBundleIdentifier, LSQuarantineAgentName,
                          LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName
                   FROM LSQuarantineEvent WHERE LSQuarantineEventIdentifier = ? COLLATE NOCASE""",
                (event_id,)).fetchone()
    except sqlite3.Error:
        return None
    if r is None:
        return None
    ts = None
    with contextlib.suppress(TypeError, ValueError, OverflowError):
        ts = (CF_EPOCH + timedelta(seconds=float(r[0]))).isoformat()
    ev = {"time": ts, "agent_bundle_id": r[1], "agent": r[2], "data_url": strip_url_secrets(r[3]),
          "origin_url": strip_url_secrets(r[4]), "sender": r[5]}
    return {k: v for k, v in ev.items() if v}


def parse_codesign(text: str, returncode: int = 0) -> dict[str, Any]:
    """stderr of `codesign -dv --verbose=2 <path>`: what the signature *claims* (display only, nothing is
    verified; see `parse_codesign_verify`). A failure that is not about the signature (missing file,
    permission) is `{"unknown": ...}`, never "invalid"."""
    if "not signed at all" in text:
        return {"signed": False}
    if returncode not in (0, None):
        last = text.strip().splitlines()[-1][:200] if text.strip() else f"exit {returncode}"
        return {"unknown": last}
    out: dict[str, Any] = {"signed": True}
    authorities: list[str] = []
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        v = v.strip()
        if k == "Identifier":
            out["identifier"] = v
        elif k == "Authority":
            authorities.append(v)
        elif k == "TeamIdentifier" and v != "not set":
            out["team_id"] = v
        elif k == "Timestamp":
            out["timestamp"] = v
        elif k == "Signature" and v == "adhoc":
            out["adhoc"] = True
        elif k == "CodeDirectory v" or line.startswith("CodeDirectory"):
            m = re.search(r"flags=0x[0-9a-f]+\(([^)]*)\)", line)
            if m:
                out["flags"] = [x for x in m.group(1).split(",") if x and x != "none"]
                if "runtime" in out["flags"]:
                    out["hardened_runtime"] = True
    if authorities:
        out["authority"] = authorities
        leaf = authorities[0]
        if leaf.startswith(("Apple Mac OS Application Signing", "Apple iPhone OS Application Signing")):
            out["mac_app_store"] = True          # before the generic Apple check: MAS leaves start with "Apple"
        elif leaf.startswith("Developer ID Application"):
            out["developer_id"] = True
        elif leaf.startswith("Software Signing") or (leaf.startswith("Apple") and "Apple Root CA" in authorities):
            out["apple"] = True
    return out


# messages of `codesign --verify` that mean the signature itself is broken (vs. cannot be checked)
_VERIFY_BAD = ("invalid signature", "sealed resource", "code has no resources but signature indicates",
               "not valid", "has been modified", "code object is not signed at all", "invalid Info.plist",
               "nested code is modified", "CSSMERR_TP_CERT_REVOKED", "CSSMERR_TP_NOT_TRUSTED")


def parse_codesign_verify(text: str, returncode: int) -> dict[str, Any] | None:
    """`codesign --verify --strict <path>`: {"verified": True}, {"verified": False, "error": ...} when the
    signature is broken or revoked, None when the check itself could not run (missing file, permission)."""
    if returncode == 0:
        return {"verified": True}
    msg = text.strip().splitlines()[-1][:200] if text.strip() else f"exit {returncode}"
    if any(b.lower() in text.lower() for b in _VERIFY_BAD):
        return {"verified": False, "error": msg}
    return None


def parse_pkgutil_file_info(text: str) -> list[dict[str, Any]]:
    """`pkgutil --file-info <path>`: header (volume, path) then one block per owning package."""
    out: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if not sep:
            continue
        if k == "pkgid":
            cur = {"pkgid": v}
            out.append(cur)
        elif cur is not None and k == "pkg-version":
            cur["version"] = v
        elif cur is not None and k == "install-time" and v.isdigit():
            cur["install_time"] = datetime.fromtimestamp(int(v), UTC).isoformat()
    return out


def embedded_info_plist(data: bytes) -> dict | None:
    """Info.plist embedded in a Mach-O `__TEXT,__info_plist` section (privileged helpers, CLI tools)."""
    start = data.find(b"<?xml")
    while start != -1:
        end = data.find(b"</plist>", start)
        if end == -1 or end - start > 256 * 1024:
            return None
        chunk = data[start:end + len(b"</plist>")]
        if b"CFBundle" in chunk:
            with contextlib.suppress(Exception):
                v = plistlib.loads(chunk)
                return v if isinstance(v, dict) else None
        start = data.find(b"<?xml", end)
    return None


def _target_path(p: Path, root: Path) -> str:
    try:
        return "/" + p.relative_to(root).as_posix()
    except ValueError:
        return str(p)


# ============================================================================ live snapshot

def _run(cmd: list[str], timeout: int = CMD_TIMEOUT) -> subprocess.CompletedProcess:
    """Fixed read-only command. Output decoded leniently: one non-UTF-8 byte in a process name must not
    abort the snapshot."""
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, check=False, env={**os.environ, "LC_ALL": "C"})


def _try(cmd: list[str], timeout: int = CMD_TIMEOUT) -> subprocess.CompletedProcess | None:
    """`_run`, but a timeout / missing binary yields None instead of an exception outside COLLECT_ERRORS."""
    try:
        return _run(cmd, timeout)
    except (OSError, subprocess.SubprocessError):
        return None


_LIBPROC = None


def pid_path(pid: int) -> str | None:
    """Exact executable path of a pid via libproc's proc_pidpath (macOS only)."""
    global _LIBPROC
    if sys.platform != "darwin":
        return None
    if _LIBPROC is None:
        try:
            _LIBPROC = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")
        except OSError:
            _LIBPROC = False
    if not _LIBPROC:
        return None
    buf = ctypes.create_string_buffer(4096)
    n = _LIBPROC.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(4096))
    return buf.value[:n].decode("utf-8", "replace") if n > 0 else None


def home_dirs(root: Path, homes: Any = None) -> list[Path]:
    if homes:
        return [Path(h) for h in (homes if isinstance(homes, list) else [homes])]
    users = root / "Users"
    if not users.is_dir():
        return []
    return [p for p in sorted(users.iterdir()) if p.is_dir() and not p.is_symlink() and p.name != "Shared"]


def os_info(root: Path) -> dict[str, Any]:
    sv = root / "System/Library/CoreServices/SystemVersion.plist"
    try:
        d = plistlib.loads(read_within(sv, root.resolve(), MAX_PLIST_BYTES))
        return {"name": "macOS", "version": d.get("ProductVersion"), "build": d.get("ProductBuildVersion")}
    except Exception:  # noqa: BLE001
        return {"name": "macOS"}


def take_snapshot(root: Path, opts: dict[str, Any]) -> Snapshot:
    """Live process snapshot of this Mac."""
    warnings: list[str] = []
    r = _try(["ps", "-axww", "-o", "pid=,ppid=,uid=,user=,lstart=,comm="])
    if r is None or r.returncode != 0:
        raise RuntimeError(f"ps failed: {(r.stderr.strip()[:200] if r else 'timeout or not runnable')}")
    procs = parse_ps(r.stdout)
    if opts.get("args", True):
        a = _try(["ps", "-axww", "-o", "pid=,args="])
        args = parse_ps_args(a.stdout) if a is not None and a.returncode == 0 else {}
        for p in procs:
            p.args = args.get(p.pid, [])
    for p in procs:
        exact = pid_path(p.pid)
        if exact:
            p.exe = exact
    lc = _try(["launchctl", "list"])
    labels = parse_launchctl_list(lc.stdout) if lc is not None and lc.returncode == 0 else {}
    if lc is None or lc.returncode != 0:
        warnings.append("launchctl list failed: launch labels unavailable")
    for p in procs:
        p.label = labels.get(p.pid)
    if os.geteuid() != 0:
        warnings.append("not running as root: other users' process paths and system launchd labels may be missing")
    items, w = index_launch_items(root, home_dirs(root, opts.get("home")), opts.get("include_system", True))
    warnings.extend(w)
    return Snapshot(platform="darwin", host=opts.get("hostname") or socket.gethostname(),
                    taken_at=datetime.now(UTC).replace(microsecond=0).isoformat(), processes=procs,
                    launch_items=items, os=os_info(root), warnings=warnings)


# ============================================================================ executable inspector

def _sha256(path: Path, cap: int) -> str:
    """Streamed hash (no 128 MB buffer per binary)."""
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise ValueError(f"{path} is not a regular file")
        done = 0
        while done < cap and (chunk := fh.read(min(1 << 20, cap - done))):
            h.update(chunk)
            done += len(chunk)
    return h.hexdigest()


def _getxattr(path: Path, name: str) -> bytes | None:
    if hasattr(os, "getxattr"):          # Linux (copied trees on a Linux analyst box)
        try:
            return os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            return None
    if sys.platform != "darwin":
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    fn = libc.getxattr
    fn.restype = ctypes.c_ssize_t
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    p, n = os.fsencode(path), name.encode()
    size = fn(p, n, None, 0, 0, 0x0001)          # XATTR_NOFOLLOW
    if size <= 0 or size > 1024 * 1024:
        return None
    buf = ctypes.create_string_buffer(size)
    got = fn(p, n, buf, size, 0, 0x0001)
    return buf.raw[:got] if got > 0 else None


class MacOSInspector(Inspector):
    """Executable -> identity + provenance facts.

    `root` is `/` for a live Mac or a copied tree (tests, mounted disk); None = analyse a snapshot taken
    elsewhere without reading any file (identity from the path alone: Homebrew keg, system path, bundle name).
    """

    def __init__(self, snap: Snapshot, root: Path | None, opts: dict[str, Any], warnings: list[str]):
        super().__init__(snap, opts, warnings)
        self.root = root
        self.fs = root is not None
        self.boundary = root.resolve() if root is not None else None
        self.live = root is not None and str(root) == "/" and sys.platform == "darwin"
        self.max_binary = int(opts.get("max_binary_mb", DEFAULT_MAX_BINARY // (1024 * 1024))) * 1024 * 1024
        self._facts: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ paths
    def local(self, target: str) -> Path:
        assert self.root is not None
        return Path(target) if str(self.root) == "/" else self.root / target.lstrip("/")

    def target(self, local: Path) -> str:
        assert self.root is not None and self.boundary is not None
        return str(local) if str(self.root) == "/" else _target_path(local, self.boundary)

    def real_target(self, target: str) -> str | None:
        """Symlinks resolved, never leaving the scanned tree; None when missing, escaping or without fs."""
        if not self.fs:
            return None
        try:
            return self.target(resolve_within(self.local(target), self.boundary))
        except ValueError:
            return None

    # ------------------------------------------------------------------ identity
    def _resolve(self, exe: str) -> Resolution:
        real = self.real_target(exe) or exe
        for fn in (self._brew, self._bundle, self._system, self._pkgutil, self._binary):
            res = fn(real)
            if res is not None:
                if real != exe:
                    res.notes["resolved_from"] = exe
                return res
        return Resolution("none", [self.unidentified(real)])

    def _brew(self, path: str) -> Resolution | None:
        from ..homebrew import _cask_component, _formula_component, _keg_component

        m = re.match(r"^(?P<prefix>.*?)/Cellar/(?P<name>[^/]+)/(?P<ver>[^/]+)/", path)
        if m:
            keg_t = path[:m.end() - 1]
            if not self.fs:
                c = _formula_component(m["name"], m["ver"], None)
                c.source_path = keg_t
                return Resolution("brew-keg", [c], anchor=keg_t, notes={"identity": "path-only"})
            prefix, keg = self.local(m["prefix"] or "/"), self.local(keg_t)
            c = _keg_component(prefix, None if str(self.root) == "/" else self.root, m["name"], keg, True, False,
                               self.warnings, self.boundary)
            return Resolution("brew-keg", [c], anchor=keg_t)
        m = re.match(r"^(?P<prefix>.*?)/Caskroom/(?P<token>[^/]+)/(?P<ver>[^/]+)/", path)
        if m:
            return Resolution("brew-cask", [_cask_component(m["token"], m["ver"])], anchor=path[:m.end() - 1])
        return None

    def _bundle(self, path: str) -> Resolution | None:
        from ..macos import MacOSCollector

        parts = path.split("/")
        idx = next((i for i, p in enumerate(parts) if p.endswith(".app")), None)
        if idx is None:
            return None
        bundle_t = "/".join(parts[:idx + 1])
        system = bundle_t.startswith("/System/")
        cat = CAT_SYSTEM_APP if system else CAT_APPLICATION
        notes: dict[str, Any] = {}
        inner = [p for p in parts[idx + 1:] if p.endswith((".app", ".xpc", ".appex", ".framework"))]
        if inner:
            notes["helper"] = inner[-1]
        if not self.fs:
            name = parts[idx][:-4]
            notes["identity"] = "path-only"
            return Resolution("path-only", [Component(name=name, version=None, category=cat, source_path=bundle_t,
                                                      meta={"identity": "path-only"})], anchor=bundle_t, notes=notes)
        comps = MacOSCollector()._read_bundle(self.local(bundle_t), self.root, cat, self.boundary)
        return Resolution("app-bundle", comps, anchor=bundle_t, notes=notes)

    def _system(self, path: str) -> Resolution | None:
        if not path.startswith(SYSTEM_PREFIXES) or path.startswith("/usr/local/"):
            return None
        osc = self.os_component()
        return Resolution("os", [osc] if osc else [], notes={"os_binary": True})

    def _pkgutil(self, path: str) -> Resolution | None:
        if not self.live or not self.opts.get("pkgutil", True) or self.user_writable(path):
            return None
        try:
            r = _run(["pkgutil", "--file-info", path])
        except (OSError, subprocess.SubprocessError):
            return None
        pkgs = parse_pkgutil_file_info(r.stdout) if r.returncode == 0 else []
        if not pkgs:
            return None
        comps = []
        for p in pkgs:
            pid, ver = p["pkgid"], p.get("version")
            parts = pid.split(".")
            hint = "apple" if pid.startswith("com.apple.") else (parts[1].lower() if len(parts) >= 3 else None)
            comps.append(Component(name=pid, version=ver, category=CAT_PACKAGE, purl=purls.build("generic", pid, ver),
                                   source_path=path, meta={k: v for k, v in {
                                       "pkg_id": pid, "install_date": p.get("install_time"),
                                       "vendor_hint": hint}.items() if v}))
        return Resolution("pkgutil", comps, notes={"pkg_install_time": pkgs[0].get("install_time")})

    def _binary(self, path: str) -> Resolution | None:
        if not self.fs or not self.opts.get("binaries", True):
            return None
        data = self._read(path)
        if not data:
            return None
        from ..lang import golang, rust

        comps, warns = golang.parse_go_binary_ex(path, data)
        self.warnings.extend(f"{path}: {w}" for w in warns)
        if comps:
            main = [c for c in comps if c.meta.get("main")]
            return Resolution("go-binary", main + [c for c in comps if not c.meta.get("main")])
        with contextlib.suppress(Exception):
            rc = rust.parse_auditable(path, data)
            if rc:
                return Resolution("rust-binary", rc)
        info = embedded_info_plist(data[:16 * 1024 * 1024])
        if info and info.get("CFBundleIdentifier"):
            bid = str(info["CFBundleIdentifier"])
            ver = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
            ver = str(ver) if ver else None
            name = str(info.get("CFBundleName") or bid.rsplit(".", 1)[-1])
            parts = bid.split(".")
            hint = parts[1].lower() if len(parts) >= 3 else None
            c = Component(name=name, version=ver, category=CAT_APPLICATION,
                          purl=purls.build("generic", name, ver, namespace=hint, qualifiers={"bundle_id": bid}),
                          source_path=path, meta={"bundle_id": bid, "vendor_hint": hint, "evidence": "info-plist"})
            return Resolution("info-plist", [c])
        return None

    def _read(self, path: str) -> bytes | None:
        try:
            st = self.local(path).stat()
            if not stat.S_ISREG(st.st_mode) or st.st_size > self.max_binary:
                return None
            return read_within(self.local(path), self.boundary, self.max_binary)
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ provenance
    def facts(self, exe: str) -> dict[str, Any]:
        """Provenance and trust facts about an executable (cached). Snapshot-provided facts win."""
        if exe in self._facts:
            return self._facts[exe]
        f = super().facts(exe)
        f.pop("identity", None)
        if not f and self.fs:
            try:
                f = self._facts_fs(exe)
            except Exception as e:  # noqa: BLE001
                self.warnings.append(f"cannot inspect {exe}: {type(e).__name__}: {e}")
        self._facts[exe] = f
        return f

    def _facts_fs(self, exe: str) -> dict[str, Any]:
        f: dict[str, Any] = {}
        lp = self.local(exe)
        try:
            lp.lstat()
        except OSError:
            return {"exists": False}
        try:                                       # a copied tree: never follow a link onto the analyst's host
            real = resolve_within(lp, self.boundary)
            st = real.stat()
        except ValueError:
            return {"outside_root": True}
        except OSError:
            return {"exists": False}               # dangling link
        f["exists"] = True
        f["size"] = st.st_size
        f["mtime"] = datetime.fromtimestamp(st.st_mtime, UTC).replace(microsecond=0).isoformat()
        bt = getattr(st, "st_birthtime", None)
        if bt:
            f["created"] = datetime.fromtimestamp(bt, UTC).replace(microsecond=0).isoformat()
        f["owner_uid"] = st.st_uid
        if st.st_mode & stat.S_IWOTH:
            f["world_writable"] = True
        if self.opts.get("hash", True) and stat.S_ISREG(st.st_mode) and st.st_size <= self.max_binary:
            with contextlib.suppress(OSError, ValueError):
                f["sha256"] = _sha256(real, self.max_binary)
        res = self.resolve(exe)
        real_t = self.target(real)
        # quarantine / where-froms live on the downloaded item: the bundle for apps, the file otherwise
        cands = list(dict.fromkeys(c for c in (res.anchor, real_t) if c))
        for cand in cands:
            q = parse_quarantine(_getxattr(self.local(cand), "com.apple.quarantine"))
            if q:
                ev = self._quarantine_event(q.get("event_id"))
                if ev:
                    q["event"] = ev
                f["quarantine"] = {**q, "on": cand}
                break
        for cand in cands:
            wf = parse_where_froms(_getxattr(self.local(cand), "com.apple.metadata:kMDItemWhereFroms"))
            if wf:
                f["where_froms"] = wf
                break
        # signature of the executable itself (a swapped helper inside a signed bundle must not inherit the
        # bundle's identity). Sealed system paths are skipped by default: one subprocess each, no information.
        sign = self.live and self.opts.get("codesign", True) and (
            self.opts.get("codesign_system", False) or not real_t.startswith(SYSTEM_PREFIXES))
        if sign:
            r = _try(["codesign", "-dv", "--verbose=2", real_t])
            if r is not None:
                f["signature"] = parse_codesign(r.stderr, r.returncode)
            if self.opts.get("verify", False) and f.get("signature", {}).get("signed"):
                v = _try(["codesign", "--verify", "--strict", real_t], timeout=120)
                ver = parse_codesign_verify(v.stderr, v.returncode) if v is not None else None
                if ver:
                    f["signature"].update(ver)
        if self.live and self.opts.get("gatekeeper", False):
            r = _try(["spctl", "--assess", "--type", "execute", "-vv", res.anchor or real_t])
            if r is not None:
                m = re.search(r"source=(.+)", r.stderr)
                f["gatekeeper"] = {"accepted": r.returncode == 0, "source": m.group(1).strip() if m else None}
        return f

    # ------------------------------------------------------------------ change detection (--watch)
    def stamp(self, exe: str) -> tuple | None:
        """Cheap identity of the file at `exe` (inode, size, mtime): changes when it is replaced or rewritten."""
        if not self.fs:
            return None
        try:
            st = resolve_within(self.local(exe), self.boundary).stat()
        except (OSError, ValueError):
            return ("missing",)
        return (st.st_ino, st.st_size, st.st_mtime_ns)

    def forget(self, exe: str) -> None:
        super().forget(exe)
        self._facts.pop(exe, None)

    def _quarantine_event(self, event_id: str | None) -> dict[str, Any] | None:
        if not event_id or not self.opts.get("quarantine_db", True) or self.root is None:
            return None
        for h in home_dirs(self.root, self.opts.get("home")):
            ev = quarantine_event(h / "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", event_id)
            if ev:
                return ev
        return None

    def user_writable(self, path: str) -> bool:
        return path.startswith(USER_WRITABLE) or "/AppTranslocation/" in path
